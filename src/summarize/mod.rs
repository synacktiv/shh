//! Summarize program syscalls into higher level action

use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Display},
    net::IpAddr,
    num::NonZeroU16,
    os::fd::RawFd,
    path::PathBuf,
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
    /// Mount propagated to host
    MountToHost,
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
    pub local_port: SetSpecifier<NetworkPort>,
    // Note: this account for source and destination addresses
    pub address: SetSpecifier<NetworkAddress>,
}

/// Quantify something that is done or denied
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) enum SetSpecifier<T> {
    None,
    One(T),
    Some(Vec<T>),
    AllExcept(Vec<T>),
    All,
}

impl<T: Eq + Clone> SetSpecifier<T> {
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
                Self::All => true, // this is incorrect, but unless excs has the whole address/port space, we should be good
            },
            Self::All => !matches!(other, Self::None),
        }
    }

    pub(crate) fn excluded_elements(&self) -> Vec<T> {
        match self {
            Self::AllExcept(vec) => vec.to_owned(),
            _ => unimplemented!(),
        }
    }

    /// Remove a single element from the set
    /// The element to remove **must** be in the set, otherwise may panic
    #[expect(clippy::unwrap_used, clippy::panic)]
    pub(crate) fn remove(&mut self, to_rm: &T) {
        debug_assert!(self.contains_one(to_rm));
        match self {
            Self::None => panic!(),
            Self::One(_) => {
                *self = Self::None;
            }
            Self::Some(es) => {
                let idx = es.iter().position(|e| e == to_rm).unwrap();
                es.remove(idx);
            }
            Self::AllExcept(excs) => {
                debug_assert!(!excs.contains(to_rm));
                excs.push(to_rm.to_owned());
            }
            Self::All => {
                *self = Self::AllExcept(vec![to_rm.to_owned()]);
            }
        }
    }
}

/// Socket activity
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) enum NetworkActivityKind {
    SocketCreation,
    Bind,
    Connect,
    Accept,
    SendRecv,
}

impl NetworkActivityKind {
    /// All kinds that are linked with one or more addresses
    pub(crate) const ADDRESSED: [Self; 4] = [
        NetworkActivityKind::Bind,
        NetworkActivityKind::Connect,
        NetworkActivityKind::Accept,
        NetworkActivityKind::SendRecv,
    ];

    /// Get kind from syscall name, panic if it fails
    fn from_sc_name(sc: &str) -> Self {
        match sc {
            "socket" => NetworkActivityKind::SocketCreation,
            "bind" => NetworkActivityKind::Bind,
            "connect" => NetworkActivityKind::Connect,
            "accept" | "accept4" => NetworkActivityKind::Accept,
            "sendto" | "recvfrom" => NetworkActivityKind::SendRecv,
            _ => unreachable!("{:?}", sc),
        }
    }
}

// TODO review Derive
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct NetworkPort(NonZeroU16);

impl Display for NetworkPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct NetworkAddress(IpAddr);

impl From<IpAddr> for NetworkAddress {
    fn from(value: IpAddr) -> Self {
        Self(value)
    }
}

impl Display for NetworkAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
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
        fd: Option<T>,
    },
    Mount {
        flags: T,
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
            Self::Mmap { prot, fd } => SyscallArgs::Mmap {
                prot: Self::extract_arg(sc, *prot)?,
                fd: fd.map(|fd| Self::extract_arg(sc, fd)).transpose()?,
            },
            Self::Mount { flags } => SyscallArgs::Mount {
                flags: Self::extract_arg(sc, *flags)?,
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
        (
            "mmap",
            SyscallArgsIndex::Mmap {
                prot: 2,
                fd: Some(4),
            },
        ),
        (
            "mmap2",
            SyscallArgsIndex::Mmap {
                prot: 2,
                fd: Some(4),
            },
        ),
        ("mprotect", SyscallArgsIndex::Mmap { prot: 2, fd: None }),
        (
            "pkey_mprotect",
            SyscallArgsIndex::Mmap { prot: 2, fd: None },
        ),
        // mount
        ("mount", SyscallArgsIndex::Mount { flags: 3 }),
        // network
        // We don't track other send/recv variants because, we can track activity we need
        // from other syscalls
        ("accept", SyscallArgsIndex::Network { fd: 0, sockaddr: 1 }),
        ("accept4", SyscallArgsIndex::Network { fd: 0, sockaddr: 1 }),
        ("bind", SyscallArgsIndex::Network { fd: 0, sockaddr: 1 }),
        ("connect", SyscallArgsIndex::Network { fd: 0, sockaddr: 1 }),
        ("recvfrom", SyscallArgsIndex::Network { fd: 0, sockaddr: 4 }),
        ("sendto", SyscallArgsIndex::Network { fd: 0, sockaddr: 4 }),
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

pub(crate) fn summarize<I>(syscalls: I, env_paths: &[PathBuf]) -> anyhow::Result<Vec<ProgramAction>>
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

    // Directories in PATH env var need to be accessible, otherwise systemd errors
    actions.extend(env_paths.iter().cloned().map(ProgramAction::Read));

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

#[expect(clippy::unreadable_literal)]
#[cfg(test)]
mod tests {
    use std::os::unix::ffi::OsStrExt as _;

    use super::*;
    use crate::strace::*;

    #[test]
    fn test_relative_rename() {
        let _ = simple_logger::SimpleLogger::new().init();

        let env_paths = [
            PathBuf::from("/path/from/env/1"),
            PathBuf::from("/path/from/env/2"),
        ];

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
            ret_val: IntegerExpression {
                value: IntegerExpressionValue::Literal(0),
                metadata: None,
            },
        })];
        assert_eq!(
            summarize(syscalls, &env_paths).unwrap(),
            vec![
                ProgramAction::Read(temp_dir_src.path().join("a")),
                ProgramAction::Write(temp_dir_src.path().join("a")),
                ProgramAction::Create(temp_dir_dst.path().join("b")),
                ProgramAction::Write(temp_dir_dst.path().join("b")),
                ProgramAction::Syscalls(["renameat".to_owned()].into()),
                ProgramAction::Read("/path/from/env/1".into()),
                ProgramAction::Read("/path/from/env/2".into()),
            ]
        );
    }

    #[test]
    fn test_connect_uds() {
        let _ = simple_logger::SimpleLogger::new().init();

        let env_paths = [
            PathBuf::from("/path/from/env/1"),
            PathBuf::from("/path/from/env/2"),
        ];

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
            ret_val: IntegerExpression {
                value: IntegerExpressionValue::Literal(0),
                metadata: None,
            },
        })];
        assert_eq!(
            summarize(syscalls, &env_paths).unwrap(),
            vec![
                ProgramAction::Read("/run/user/1000/systemd/private".into()),
                ProgramAction::Syscalls(["connect".to_owned()].into()),
                ProgramAction::Read("/path/from/env/1".into()),
                ProgramAction::Read("/path/from/env/2".into()),
            ]
        );
    }
}
