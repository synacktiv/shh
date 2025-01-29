//! Summarize program syscalls into higher level action

use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Display},
    num::NonZeroU16,
    ops::{Add, RangeInclusive, Sub},
    os::fd::RawFd,
    path::PathBuf,
    slice,
    sync::LazyLock,
};

use anyhow::Context as _;

use crate::{
    strace::{
        BufferExpression, BufferType, Expression, IntegerExpression, IntegerExpressionValue,
        Syscall,
    },
    systemd::{SocketFamily, SocketProtocol},
};

mod handlers;

/// A high level program runtime action
/// This does *not* map 1-1 with a syscall, and does *not* necessarily respect chronology
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) enum ProgramAction {
    /// Path was accessed (open, stat'ed, read...)
    Read(PathBuf),
    /// Path was written to (data, metadata, path removal...)
    Write(PathBuf),
    /// Path was created
    Create(PathBuf),
    /// Path was exec'd
    Exec(PathBuf),
    /// Network (socket) activity
    NetworkActivity(NetworkActivity),
    /// Memory mapping with write and execute bits
    WriteExecuteMemoryMapping,
    /// Set scheduler to a real time one
    SetRealtimeScheduler,
    /// Inhibit suspend
    Wakeup,
    /// Create special files
    MknodSpecial,
    /// Set privileged timer alarm
    SetAlarm,
    /// Names of the syscalls made by the program
    Syscalls(HashSet<String>),
}

/// Network (socket) activity
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct NetworkActivity {
    pub af: SetSpecifier<SocketFamily>,
    pub proto: SetSpecifier<SocketProtocol>,
    pub kind: SetSpecifier<NetworkActivityKind>,
    pub local_port: CountableSetSpecifier<NetworkPort>,
}

/// Quantify something that is done or denied
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) enum SetSpecifier<T> {
    None,
    One(T),
    Some(Vec<T>),
    All,
}

impl<T: Eq + Clone> SetSpecifier<T> {
    fn contains_one(&self, needle: &T) -> bool {
        match self {
            Self::None => false,
            Self::One(e) => e == needle,
            Self::Some(es) => es.contains(needle),
            Self::All => true,
        }
    }

    pub(crate) fn intersects(&self, other: &Self) -> bool {
        match self {
            Self::None => false,
            Self::One(e) => other.contains_one(e),
            Self::Some(es) => es.iter().any(|e| other.contains_one(e)),
            Self::All => !matches!(other, Self::None),
        }
    }

    pub(crate) fn elements(&self) -> &[T] {
        match self {
            SetSpecifier::None => &[],
            SetSpecifier::One(e) => slice::from_ref(e),
            SetSpecifier::Some(es) => es.as_slice(),
            SetSpecifier::All => unimplemented!(),
        }
    }
}

pub(crate) trait ValueCounted {
    fn value_count() -> usize;

    fn min_value() -> Self;

    fn max_value() -> Self;

    fn one() -> Self;
}

/// Quantify something that is done or denied
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) enum CountableSetSpecifier<T> {
    None,
    One(T),
    // Elements must be ordered
    Some(Vec<T>),
    // Elements must be ordered
    AllExcept(Vec<T>),
    All,
}

impl<T: Eq + Ord + Clone + Display + ValueCounted + Sub<Output = T> + Add<Output = T>>
    CountableSetSpecifier<T>
{
    fn contains_one(&self, needle: &T) -> bool {
        match self {
            Self::None => false,
            Self::One(e) => e == needle,
            Self::Some(es) => es.contains(needle),
            Self::AllExcept(es) => !es.contains(needle),
            Self::All => true,
        }
    }

    pub(crate) fn intersects(&self, other: &Self) -> bool {
        match self {
            Self::None => false,
            Self::One(e) => other.contains_one(e),
            Self::Some(es) => es.iter().any(|e| other.contains_one(e)),
            Self::AllExcept(excs) => match other {
                Self::None => false,
                Self::One(e) => !excs.contains(e),
                Self::Some(es) => es.iter().any(|e| !excs.contains(e)),
                Self::AllExcept(other_excs) => excs != other_excs,
                Self::All => excs.len() < T::value_count(),
            },
            Self::All => !matches!(other, Self::None),
        }
    }

    /// Remove a single element from the set
    /// The element to remove **must** be in the set, otherwise may panic
    #[expect(clippy::unwrap_used)]
    pub(crate) fn remove(&mut self, to_rm: &T) {
        debug_assert!(self.contains_one(to_rm));
        match self {
            Self::None => unreachable!(),
            Self::One(_) => {
                *self = Self::None;
            }
            Self::Some(es) => {
                let idx = es.iter().position(|e| e == to_rm).unwrap();
                es.remove(idx);
            }
            Self::AllExcept(excs) => {
                let idx = excs.binary_search(to_rm).unwrap_err();
                excs.insert(idx, to_rm.to_owned());
            }
            Self::All => {
                *self = Self::AllExcept(vec![to_rm.to_owned()]);
            }
        }
    }

    pub(crate) fn ranges(&self) -> Vec<RangeInclusive<T>> {
        match self {
            CountableSetSpecifier::None => vec![],
            CountableSetSpecifier::One(e) => vec![e.to_owned()..=e.to_owned()],
            CountableSetSpecifier::Some(es) => {
                // Build single element ranges, we could merge adjacent elements, but
                // the effort has very little upsides
                es.iter().map(|e| e.to_owned()..=e.to_owned()).collect()
            }
            CountableSetSpecifier::AllExcept(excs) => {
                let mut ranges = Vec::with_capacity(excs.len() + 1);
                let mut start = None;
                for exc in excs {
                    if *exc != T::min_value() {
                        let cur_start = start.unwrap_or_else(|| T::min_value());
                        let cur_end = exc.to_owned() - T::one();
                        let r = cur_start..=cur_end;
                        if !r.is_empty() {
                            ranges.push(r);
                        }
                    }
                    if *exc == T::max_value() {
                        start = None;
                    } else {
                        start = Some(exc.to_owned() + T::one());
                    }
                }
                if let Some(start) = start {
                    let r = start..=T::max_value();
                    if !r.is_empty() {
                        ranges.push(r);
                    }
                }
                ranges
            }
            CountableSetSpecifier::All => vec![T::min_value()..=T::max_value()],
        }
    }
}

/// Socket activity
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) enum NetworkActivityKind {
    SocketCreation,
    Bind,
    // TODO
    // Connect,
    // Send,
    // Recv,
}

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct NetworkPort(NonZeroU16);

impl ValueCounted for NetworkPort {
    fn value_count() -> usize {
        // 0 is excluded
        u16::MAX as usize - u16::MIN as usize
    }

    fn one() -> Self {
        #[expect(clippy::unwrap_used)]
        Self(1_u16.try_into().unwrap())
    }

    fn min_value() -> Self {
        #[expect(clippy::unwrap_used)]
        Self(1_u16.try_into().unwrap())
    }

    fn max_value() -> Self {
        #[expect(clippy::unwrap_used)]
        Self(u16::MAX.try_into().unwrap())
    }
}

impl Sub<NetworkPort> for NetworkPort {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        #[expect(clippy::unwrap_used)]
        Self(self.0.get().sub(rhs.0.get()).try_into().unwrap())
    }
}

impl Add<NetworkPort> for NetworkPort {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        #[expect(clippy::unwrap_used)]
        Self(self.0.get().add(rhs.0.get()).try_into().unwrap())
    }
}

impl Display for NetworkPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug)]
enum FdOrPath<T> {
    Fd(T),
    Path(T),
}

/// Meta structure to group syscalls that have similar summary handling
/// and store arguments
enum SyscallArgsInfo<T> {
    Chdir(FdOrPath<T>),
    EpollCtl {
        op: T,
        event: T,
    },
    Exec {
        relfd: Option<T>,
        path: T,
    },
    Mkdir {
        relfd: Option<T>,
        path: T,
    },
    Mknod {
        mode: T,
    },
    Mmap {
        prot: T,
    },
    Network {
        fd: T,
        sockaddr: T,
    },
    Open {
        relfd: Option<T>,
        path: T,
        flags: T,
    },
    Rename {
        relfd_src: Option<T>,
        path_src: T,
        relfd_dst: Option<T>,
        path_dst: T,
        flags: Option<T>,
    },
    SetScheduler {
        policy: T,
    },
    Socket {
        af: T,
        flags: T,
    },
    StatFd {
        fd: T,
    },
    StatPath {
        relfd: Option<T>,
        path: T,
    },
    TimerCreate {
        clockid: T,
    },
}

/// Syscall argument indexes
type SyscallArgsIndex = SyscallArgsInfo<usize>;
/// Syscall arguments
type SyscallArgs<'a> = SyscallArgsInfo<&'a Expression>;

impl SyscallArgsIndex {
    /// Extract arguments from indexes
    #[expect(clippy::shadow_unrelated)]
    fn extract_args<'a>(&self, sc: &'a Syscall) -> anyhow::Result<SyscallArgs<'a>> {
        let args = match self {
            Self::Chdir(p) => SyscallArgsInfo::Chdir(match p {
                FdOrPath::Fd(i) => FdOrPath::Fd(Self::extract_arg(sc, *i)?),
                FdOrPath::Path(i) => FdOrPath::Path(Self::extract_arg(sc, *i)?),
            }),
            Self::EpollCtl { op, event } => SyscallArgs::EpollCtl {
                op: Self::extract_arg(sc, *op)?,
                event: Self::extract_arg(sc, *event)?,
            },
            Self::Exec { relfd, path } => SyscallArgs::Exec {
                relfd: relfd
                    .map(|relfd| Self::extract_arg(sc, relfd))
                    .transpose()?,
                path: Self::extract_arg(sc, *path)?,
            },
            Self::Mkdir { relfd, path } => SyscallArgs::Mkdir {
                relfd: relfd
                    .map(|relfd| Self::extract_arg(sc, relfd))
                    .transpose()?,
                path: Self::extract_arg(sc, *path)?,
            },
            Self::Mknod { mode } => SyscallArgs::Mknod {
                mode: Self::extract_arg(sc, *mode)?,
            },
            Self::Mmap { prot } => SyscallArgs::Mmap {
                prot: Self::extract_arg(sc, *prot)?,
            },
            Self::Network { fd, sockaddr } => SyscallArgs::Network {
                fd: Self::extract_arg(sc, *fd)?,
                sockaddr: Self::extract_arg(sc, *sockaddr)?,
            },
            Self::Open { relfd, path, flags } => SyscallArgs::Open {
                relfd: relfd
                    .map(|relfd| Self::extract_arg(sc, relfd))
                    .transpose()?,
                path: Self::extract_arg(sc, *path)?,
                flags: Self::extract_arg(sc, *flags)?,
            },
            Self::Rename {
                relfd_src,
                path_src,
                relfd_dst,
                path_dst,
                flags,
            } => SyscallArgs::Rename {
                relfd_src: relfd_src
                    .map(|relfd_src| Self::extract_arg(sc, relfd_src))
                    .transpose()?,
                path_src: Self::extract_arg(sc, *path_src)?,
                relfd_dst: relfd_dst
                    .map(|relfd_dst| Self::extract_arg(sc, relfd_dst))
                    .transpose()?,
                path_dst: Self::extract_arg(sc, *path_dst)?,
                flags: flags
                    .map(|flags| Self::extract_arg(sc, flags))
                    .transpose()?,
            },
            Self::SetScheduler { policy } => SyscallArgs::SetScheduler {
                policy: Self::extract_arg(sc, *policy)?,
            },
            Self::Socket { af, flags } => SyscallArgs::Socket {
                af: Self::extract_arg(sc, *af)?,
                flags: Self::extract_arg(sc, *flags)?,
            },
            Self::StatFd { fd } => SyscallArgs::StatFd {
                fd: Self::extract_arg(sc, *fd)?,
            },
            Self::StatPath { relfd, path } => SyscallArgs::StatPath {
                relfd: relfd
                    .map(|relfd| Self::extract_arg(sc, relfd))
                    .transpose()?,
                path: Self::extract_arg(sc, *path)?,
            },
            Self::TimerCreate { clockid } => SyscallArgsInfo::TimerCreate {
                clockid: Self::extract_arg(sc, *clockid)?,
            },
        };
        Ok(args)
    }

    fn extract_arg(sc: &Syscall, index: usize) -> anyhow::Result<&Expression> {
        sc.args.get(index).ok_or_else(|| {
            anyhow::anyhow!(
                "Unable to extract syscall argument {} for {:?}",
                index,
                sc.name
            )
        })
    }
}

//
// For some reference on syscalls, see:
// - https://man7.org/linux/man-pages/man2/syscalls.2.html
// - https://filippo.io/linux-syscall-table/
// - https://linasm.sourceforge.net/docs/syscalls/filesystem.php
//
static SYSCALL_MAP: LazyLock<HashMap<&'static str, SyscallArgsIndex>> = LazyLock::new(|| {
    HashMap::from([
        // chdir
        ("chdir", SyscallArgsIndex::Chdir(FdOrPath::Path(0))),
        ("fchdir", SyscallArgsIndex::Chdir(FdOrPath::Fd(0))),
        // epoll_ctl
        ("epoll_ctl", SyscallArgsIndex::EpollCtl { op: 1, event: 3 }),
        // execve
        (
            "execve",
            SyscallArgsIndex::Exec {
                relfd: None,
                path: 0,
            },
        ),
        (
            "execveat",
            SyscallArgsIndex::Exec {
                relfd: Some(0),
                path: 1,
            },
        ),
        // mkdir
        (
            "mkdir",
            SyscallArgsIndex::Mkdir {
                path: 0,
                relfd: None,
            },
        ),
        (
            "mkdirat",
            SyscallArgsIndex::Mkdir {
                path: 1,
                relfd: Some(0),
            },
        ),
        // mknod
        ("mknod", SyscallArgsIndex::Mknod { mode: 1 }),
        ("mknodat", SyscallArgsIndex::Mknod { mode: 2 }),
        // mmap
        ("mmap", SyscallArgsIndex::Mmap { prot: 2 }),
        ("mmap2", SyscallArgsIndex::Mmap { prot: 2 }),
        ("shmat", SyscallArgsIndex::Mmap { prot: 2 }),
        ("mprotect", SyscallArgsIndex::Mmap { prot: 2 }),
        ("pkey_mprotect", SyscallArgsIndex::Mmap { prot: 2 }),
        // network
        ("connect", SyscallArgsIndex::Network { fd: 0, sockaddr: 1 }),
        ("bind", SyscallArgsIndex::Network { fd: 0, sockaddr: 1 }),
        ("recvfrom", SyscallArgsIndex::Network { fd: 0, sockaddr: 4 }),
        ("sendto", SyscallArgsIndex::Network { fd: 0, sockaddr: 4 }),
        // TODO send/recv/recvmsg/sendmsg

        // open
        (
            "open",
            SyscallArgsIndex::Open {
                relfd: None,
                path: 0,
                flags: 1,
            },
        ),
        (
            "openat",
            SyscallArgsIndex::Open {
                relfd: Some(0),
                path: 1,
                flags: 2,
            },
        ),
        // rename
        (
            "rename",
            SyscallArgsIndex::Rename {
                relfd_src: None,
                path_src: 0,
                relfd_dst: None,
                path_dst: 1,
                flags: None,
            },
        ),
        (
            "renameat",
            SyscallArgsIndex::Rename {
                relfd_src: Some(0),
                path_src: 1,
                relfd_dst: Some(2),
                path_dst: 3,
                flags: None,
            },
        ),
        (
            "renameat2",
            SyscallArgsIndex::Rename {
                relfd_src: Some(0),
                path_src: 1,
                relfd_dst: Some(2),
                path_dst: 3,
                flags: Some(4),
            },
        ),
        // set scheduler
        (
            "sched_setscheduler",
            SyscallArgsIndex::SetScheduler { policy: 1 },
        ),
        // socket
        ("socket", SyscallArgsIndex::Socket { af: 0, flags: 1 }),
        // stat fd
        ("fstat", SyscallArgsIndex::StatFd { fd: 0 }),
        ("getdents", SyscallArgsIndex::StatFd { fd: 0 }),
        // stat path
        (
            "stat",
            SyscallArgsIndex::StatPath {
                relfd: None,
                path: 0,
            },
        ),
        (
            "lstat",
            SyscallArgsIndex::StatPath {
                relfd: None,
                path: 0,
            },
        ),
        (
            "newfstatat",
            SyscallArgsIndex::StatPath {
                relfd: Some(0),
                path: 1,
            },
        ),
        // timer_create
        ("timer_create", SyscallArgsIndex::TimerCreate { clockid: 0 }),
    ])
});

/// Information that persists between syscalls and that we need to handle
/// Obviously, keeping this to a minimum is a goal
#[derive(Debug, Default)]
struct ProgramState {
    /// Keep known socket protocols (per process) for bind handling, we don't care for the socket closings
    /// because the fd will be reused or never bound again
    known_sockets_proto: HashMap<(u32, RawFd), SocketProtocol>,
    /// Current working directory
    // TODO initialize with startup current dir?
    cur_dir: Option<PathBuf>,
}

pub(crate) fn summarize<I>(syscalls: I) -> anyhow::Result<Vec<ProgramAction>>
where
    I: IntoIterator<Item = anyhow::Result<Syscall>>,
{
    let mut actions = Vec::new();
    let mut stats: HashMap<String, u64> = HashMap::new();
    let mut program_state = ProgramState::default();
    for syscall in syscalls {
        let syscall = syscall?;
        log::trace!("{syscall:?}");
        stats
            .entry(syscall.name.clone())
            .and_modify(|c| *c += 1)
            .or_insert(1);
        let name = syscall.name.as_str();

        if let Some(arg_indexes) = SYSCALL_MAP.get(name) {
            let args = arg_indexes.extract_args(&syscall)?;
            handlers::summarize_syscall(&syscall, args, &mut actions, &mut program_state)
                .with_context(|| format!("Failed to summarize syscall {syscall:?}"))?;
        }
    }

    // Almost free optimization
    actions.dedup();

    // Create single action with all syscalls for efficient handling of seccomp filters
    actions.push(ProgramAction::Syscalls(stats.keys().cloned().collect()));

    // Report stats
    let mut syscall_names = stats.keys().collect::<Vec<_>>();
    syscall_names.sort_unstable();
    for syscall_name in syscall_names {
        #[expect(clippy::unwrap_used)]
        let count = stats.get(syscall_name).unwrap();
        log::debug!("{:24} {: >12}", format!("{syscall_name}:"), count);
    }

    Ok(actions)
}

#[expect(clippy::unreadable_literal, clippy::shadow_unrelated)]
#[cfg(test)]
mod tests {
    use std::os::unix::ffi::OsStrExt as _;

    use super::*;
    use crate::strace::*;

    #[test]
    fn test_relative_rename() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir_src = tempfile::tempdir().unwrap();
        let temp_dir_dst = tempfile::tempdir().unwrap();
        let syscalls = [Ok(Syscall {
            pid: 1068781,
            rel_ts: 0.000083,
            name: "renameat".to_owned(),
            args: vec![
                Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::NamedConst("AT_FDCWD".to_owned()),
                    metadata: Some(temp_dir_src.path().as_os_str().as_bytes().to_vec()),
                }),
                Expression::Buffer(BufferExpression {
                    value: "a".as_bytes().to_vec(),
                    type_: BufferType::Unknown,
                }),
                Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::NamedConst("AT_FDCWD".to_owned()),
                    metadata: Some(temp_dir_dst.path().as_os_str().as_bytes().to_vec()),
                }),
                Expression::Buffer(BufferExpression {
                    value: "b".as_bytes().to_vec(),
                    type_: BufferType::Unknown,
                }),
                Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::NamedConst("RENAME_NOREPLACE".to_owned()),
                    metadata: None,
                }),
            ],
            ret_val: 0,
        })];
        assert_eq!(
            summarize(syscalls).unwrap(),
            vec![
                ProgramAction::Read(temp_dir_src.path().join("a")),
                ProgramAction::Write(temp_dir_src.path().join("a")),
                ProgramAction::Create(temp_dir_dst.path().join("b")),
                ProgramAction::Write(temp_dir_dst.path().join("b")),
                ProgramAction::Syscalls(["renameat".to_owned()].into())
            ]
        );
    }

    #[test]
    fn test_connect_uds() {
        let _ = simple_logger::SimpleLogger::new().init();

        let syscalls = [Ok(Syscall {
            pid: 598056,
            rel_ts: 0.000036,
            name: "connect".to_owned(),
            args: vec![
                Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::Literal(4),
                    metadata: Some("/run/user/1000/systemd/private".as_bytes().to_vec()),
                }),
                Expression::Struct(HashMap::from([
                    (
                        "sa_family".to_owned(),
                        Expression::Integer(IntegerExpression {
                            value: IntegerExpressionValue::NamedConst("AF_UNIX".to_owned()),
                            metadata: None,
                        }),
                    ),
                    (
                        "sun_path".to_owned(),
                        Expression::Buffer(BufferExpression {
                            value: "/run/user/1000/systemd/private".as_bytes().to_vec(),
                            type_: BufferType::Unknown,
                        }),
                    ),
                ])),
                Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::Literal(33),
                    metadata: None,
                }),
            ],
            ret_val: 0,
        })];
        assert_eq!(
            summarize(syscalls).unwrap(),
            vec![
                ProgramAction::Read("/run/user/1000/systemd/private".into()),
                ProgramAction::Syscalls(["connect".to_owned()].into())
            ]
        );
    }

    #[test]
    fn test_set_ranges() {
        let port = |p: u16| NetworkPort(p.try_into().unwrap());
        let set: CountableSetSpecifier<NetworkPort> = CountableSetSpecifier::None;
        assert_eq!(set.ranges(), vec![]);

        for v in [1, 1234, u16::MAX] {
            let set: CountableSetSpecifier<NetworkPort> = CountableSetSpecifier::One(port(v));
            assert_eq!(set.ranges(), vec![port(v)..=port(v)]);
        }

        for v in [1, 1234, u16::MAX] {
            let set: CountableSetSpecifier<NetworkPort> =
                CountableSetSpecifier::Some(vec![port(v)]);
            assert_eq!(set.ranges(), vec![port(v)..=port(v)]);
        }

        let set: CountableSetSpecifier<NetworkPort> =
            CountableSetSpecifier::Some(vec![port(1234), port(5678)]);
        assert_eq!(
            set.ranges(),
            vec![port(1234)..=port(1234), port(5678)..=port(5678)]
        );

        let set: CountableSetSpecifier<NetworkPort> =
            CountableSetSpecifier::AllExcept(vec![port(1)]);
        assert_eq!(set.ranges(), vec![port(2)..=port(u16::MAX)]);

        let set: CountableSetSpecifier<NetworkPort> =
            CountableSetSpecifier::AllExcept(vec![port(u16::MAX)]);
        assert_eq!(set.ranges(), vec![port(1)..=port(u16::MAX - 1)]);

        let set: CountableSetSpecifier<NetworkPort> =
            CountableSetSpecifier::AllExcept(vec![port(1), port(u16::MAX)]);
        assert_eq!(set.ranges(), vec![port(2)..=port(u16::MAX - 1)]);

        let set: CountableSetSpecifier<NetworkPort> =
            CountableSetSpecifier::AllExcept(vec![port(1234), port(5678)]);
        assert_eq!(
            set.ranges(),
            vec![
                port(1)..=port(1233),
                port(1235)..=port(5677),
                port(5679)..=port(65535)
            ]
        );

        let set: CountableSetSpecifier<NetworkPort> =
            CountableSetSpecifier::AllExcept(vec![port(1), port(1234), port(5678), port(u16::MAX)]);
        assert_eq!(
            set.ranges(),
            vec![
                port(2)..=port(1233),
                port(1235)..=port(5677),
                port(5679)..=port(65534)
            ]
        );

        let set: CountableSetSpecifier<NetworkPort> = CountableSetSpecifier::All;
        assert_eq!(set.ranges(), vec![port(1)..=port(u16::MAX)]);
    }
}
