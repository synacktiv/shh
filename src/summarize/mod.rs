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
use nix::libc::pid_t;

use crate::{
    strace::{SyscallItem, SyscallName},
    systemd::{SocketFamily, SocketProtocol},
};

mod handlers;

use handlers::{
    ChdirHandler, EpollCtlHandler, ExecHandler, KillHandler, MemfdCreateHandler, MkdirHandler,
    MknodHandler, MmapHandler, MountHandler, NetworkHandler, OpenHandler, RenameHandler,
    SetSchedulerHandler, ShmCtlHandler, SocketHandler, StatFdHandler, StatPathHandler,
    SyscallHandler, TimerCreateHandler,
};

/// A high level program runtime action
/// This does *not* map 1-1 with a syscall, and does *not* necessarily respect chronology
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) enum ProgramAction {
    /// Path was created
    Create(PathBuf),
    /// Path was exec'd
    Exec(PathBuf),
    /// Memory mapping with huge pages
    HugePageMemoryMapping,
    /// Send signal to other process ("other" being defined as requiring `CAP_KILL`)
    KillOther,
    /// Lock memory mapping
    LockMemoryMapping,
    /// Create special files
    MknodSpecial,
    /// Mount propagated to host
    MountToHost,
    /// Network (socket) activity
    NetworkActivity(Box<NetworkActivity>),
    /// Path was accessed (open, stat'ed, read...)
    Read(PathBuf),
    /// Set privileged timer alarm
    SetAlarm,
    /// Set scheduler to a real time one
    SetRealtimeScheduler,
    /// Names of the syscalls made by the program
    Syscalls(HashSet<SyscallName>),
    /// Inhibit suspend
    Wakeup,
    /// Path was written to (data, metadata, path removal...)
    Write(PathBuf),
    /// Memory mapping with write and execute bits, or execute bit added
    /// after initial mapping
    WriteExecuteMemoryMapping,
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

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct NetworkPort(NonZeroU16);

impl Display for NetworkPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct NetworkAddress(IpAddr);

impl NetworkAddress {
    pub(crate) fn is_ipv6_unspecified(&self) -> bool {
        matches!(self.0, IpAddr::V6(addr) if addr.is_unspecified())
    }
}

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
#[cfg_attr(test, derive(Eq, PartialEq))]
enum FdOrPath<T> {
    Fd(T),
    Path(T),
}

//
// For some reference on syscalls, see:
// - https://man7.org/linux/man-pages/man2/syscalls.2.html
// - https://filippo.io/linux-syscall-table/
// - https://linasm.sourceforge.net/docs/syscalls/filesystem.php
//
static SYSCALL_MAP: LazyLock<HashMap<&'static str, Box<dyn SyscallHandler>>> =
    LazyLock::new(|| {
        let mut m: HashMap<&'static str, Box<dyn SyscallHandler>> = HashMap::new();
        // chdir
        m.insert(
            "chdir",
            Box::new(ChdirHandler {
                path: FdOrPath::Path(0),
            }),
        );
        m.insert(
            "fchdir",
            Box::new(ChdirHandler {
                path: FdOrPath::Fd(0),
            }),
        );
        // epoll_ctl
        m.insert("epoll_ctl", Box::new(EpollCtlHandler { op: 1, event: 3 }));
        // execve
        m.insert(
            "execve",
            Box::new(ExecHandler {
                relfd: None,
                path: 0,
            }),
        );
        m.insert(
            "execveat",
            Box::new(ExecHandler {
                relfd: Some(0),
                path: 1,
            }),
        );
        // kill
        m.insert("kill", Box::new(KillHandler { pid: 0, sig: 1 }));
        // memfd_create
        m.insert("memfd_create", Box::new(MemfdCreateHandler { flags: 1 }));
        // mkdir
        m.insert(
            "mkdir",
            Box::new(MkdirHandler {
                relfd: None,
                path: 0,
            }),
        );
        m.insert(
            "mkdirat",
            Box::new(MkdirHandler {
                relfd: Some(0),
                path: 1,
            }),
        );
        // mknod
        m.insert(
            "mknod",
            Box::new(MknodHandler {
                path: FdOrPath::Path(0),
                mode: 1,
            }),
        );
        m.insert(
            "mknodat",
            Box::new(MknodHandler {
                path: FdOrPath::Fd(1),
                mode: 2,
            }),
        );
        // mmap
        m.insert(
            "mmap",
            Box::new(MmapHandler {
                prot: 2,
                flags: Some(3),
                fd: Some(4),
            }),
        );
        m.insert(
            "mmap2",
            Box::new(MmapHandler {
                prot: 2,
                flags: Some(3),
                fd: Some(4),
            }),
        );
        m.insert(
            "mprotect",
            Box::new(MmapHandler {
                prot: 2,
                flags: None,
                fd: None,
            }),
        );
        m.insert(
            "pkey_mprotect",
            Box::new(MmapHandler {
                prot: 2,
                flags: None,
                fd: None,
            }),
        );
        // mount
        m.insert("mount", Box::new(MountHandler { flags: 3 }));
        // network
        // We don't track other send/recv variants because, we can track activity we need
        // from other syscalls
        m.insert("accept", Box::new(NetworkHandler { fd: 0, sockaddr: 1 }));
        m.insert("accept4", Box::new(NetworkHandler { fd: 0, sockaddr: 1 }));
        m.insert("bind", Box::new(NetworkHandler { fd: 0, sockaddr: 1 }));
        m.insert("connect", Box::new(NetworkHandler { fd: 0, sockaddr: 1 }));
        m.insert("recvfrom", Box::new(NetworkHandler { fd: 0, sockaddr: 4 }));
        m.insert("sendto", Box::new(NetworkHandler { fd: 0, sockaddr: 4 }));
        // open
        m.insert(
            "open",
            Box::new(OpenHandler {
                relfd: None,
                path: 0,
                flags: 1,
            }),
        );
        m.insert(
            "openat",
            Box::new(OpenHandler {
                relfd: Some(0),
                path: 1,
                flags: 2,
            }),
        );
        // rename
        m.insert(
            "rename",
            Box::new(RenameHandler {
                relfd_src: None,
                path_src: 0,
                relfd_dst: None,
                path_dst: 1,
                flags: None,
            }),
        );
        m.insert(
            "renameat",
            Box::new(RenameHandler {
                relfd_src: Some(0),
                path_src: 1,
                relfd_dst: Some(2),
                path_dst: 3,
                flags: None,
            }),
        );
        m.insert(
            "renameat2",
            Box::new(RenameHandler {
                relfd_src: Some(0),
                path_src: 1,
                relfd_dst: Some(2),
                path_dst: 3,
                flags: Some(4),
            }),
        );
        // set scheduler
        m.insert(
            "sched_setscheduler",
            Box::new(SetSchedulerHandler { policy: 1 }),
        );
        // shmctl
        m.insert("shmctl", Box::new(ShmCtlHandler { op: 1 }));
        // socket
        m.insert("socket", Box::new(SocketHandler { af: 0, flags: 1 }));
        // stat fd
        m.insert("fstat", Box::new(StatFdHandler { fd: 0 }));
        m.insert("getdents", Box::new(StatFdHandler { fd: 0 }));
        // stat path
        m.insert(
            "stat",
            Box::new(StatPathHandler {
                relfd: None,
                path: 0,
            }),
        );
        m.insert(
            "lstat",
            Box::new(StatPathHandler {
                relfd: None,
                path: 0,
            }),
        );
        m.insert(
            "newfstatat",
            Box::new(StatPathHandler {
                relfd: Some(0),
                path: 1,
            }),
        );
        // timer_create
        m.insert("timer_create", Box::new(TimerCreateHandler { clockid: 0 }));
        m
    });

/// Information that persists between syscalls and that we need to handle
/// Obviously, keeping this to a minimum is a goal
#[derive(Debug)]
pub(crate) struct ProgramState {
    /// Keep known socket protocols (per process) for bind handling, we don't care for the socket closings
    /// because the fd will be reused or never bound again
    known_sockets_proto: HashMap<(pid_t, RawFd), SocketProtocol>,
    /// Current working directory
    cur_dir: PathBuf,
}

impl ProgramState {
    pub(crate) fn new<P>(cur_dir: P) -> Self
    where
        P: Into<PathBuf>,
    {
        Self {
            known_sockets_proto: HashMap::new(),
            cur_dir: cur_dir.into(),
        }
    }
}

/// Returns the set of syscall names that have handlers
pub(crate) fn handled_syscall_names() -> HashSet<&'static str> {
    SYSCALL_MAP.keys().copied().collect()
}

pub(crate) fn summarize<I>(
    syscalls: I,
    env_paths: &[PathBuf],
    mut program_state: ProgramState,
) -> anyhow::Result<Vec<ProgramAction>>
where
    I: IntoIterator<Item = anyhow::Result<SyscallItem>>,
{
    let mut actions = Vec::new();
    let mut stats: HashMap<SyscallName, u64> = HashMap::new();
    for item in syscalls {
        let item = item?;
        match item {
            SyscallItem::NameOnly(name) => {
                stats.entry(name).and_modify(|c| *c += 1).or_insert(1);
            }
            SyscallItem::Complete(syscall) => {
                log::trace!("{syscall:?}");
                stats
                    .entry(syscall.name.clone())
                    .and_modify(|c| *c += 1)
                    .or_insert(1);
                let name = syscall.name.as_str();

                if let Some(handler) = SYSCALL_MAP.get(name) {
                    handler
                        .handle(syscall.as_ref(), &mut actions, &mut program_state)
                        .with_context(|| format!("Failed to summarize syscall {syscall:?}"))?;
                }
            }
        }
    }

    // Almost free optimization
    actions.dedup();

    // Create single action with all syscalls for efficient handling of seccomp filters
    actions.push(ProgramAction::Syscalls(stats.keys().cloned().collect()));

    // Directories in PATH env var need to be accessible, otherwise systemd errors
    actions.extend(env_paths.iter().cloned().map(ProgramAction::Read));

    // Report stats
    if log::log_enabled!(log::Level::Debug) {
        let mut syscall_names = stats.keys().collect::<Vec<_>>();
        syscall_names.sort_unstable();
        for syscall_name in syscall_names {
            #[expect(clippy::unwrap_used)]
            let count = stats.get(syscall_name).unwrap();
            log::debug!("{:24} {: >12}", format!("{syscall_name}:"), count);
        }
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
    fn relative_rename() {
        let _ = simple_logger::SimpleLogger::new().init();

        let env_paths = [
            PathBuf::from("/path/from/env/1"),
            PathBuf::from("/path/from/env/2"),
        ];
        let state = ProgramState::new("/");

        let temp_dir_src = tempfile::tempdir().unwrap();
        let temp_dir_dst = tempfile::tempdir().unwrap();
        let syscalls = [Ok(SyscallItem::Complete(Box::new(Syscall {
            pid: 1068781,
            rel_ts: 0.000083,
            name: "renameat".into(),
            args: vec![
                Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::NamedSymbol("AT_FDCWD".to_owned()),
                    metadata: Some(temp_dir_src.path().as_os_str().as_bytes().to_vec()),
                }),
                Expression::Buffer(BufferExpression {
                    value: "a".as_bytes().to_vec(),
                    type_: BufferType::Unknown,
                }),
                Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::NamedSymbol("AT_FDCWD".to_owned()),
                    metadata: Some(temp_dir_dst.path().as_os_str().as_bytes().to_vec()),
                }),
                Expression::Buffer(BufferExpression {
                    value: "b".as_bytes().to_vec(),
                    type_: BufferType::Unknown,
                }),
                Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::NamedSymbol("RENAME_NOREPLACE".to_owned()),
                    metadata: None,
                }),
            ],
            ret_val: Some(IntegerExpression {
                value: IntegerExpressionValue::Literal(0),
                metadata: None,
            }),
        })))];
        assert_eq!(
            summarize(syscalls, &env_paths, state).unwrap(),
            vec![
                ProgramAction::Read(temp_dir_src.path().join("a")),
                ProgramAction::Write(temp_dir_src.path().join("a")),
                ProgramAction::Create(temp_dir_dst.path().join("b")),
                ProgramAction::Write(temp_dir_dst.path().join("b")),
                ProgramAction::Syscalls(["renameat".into()].into()),
                ProgramAction::Read("/path/from/env/1".into()),
                ProgramAction::Read("/path/from/env/2".into()),
            ]
        );
    }

    #[test]
    fn connect_uds() {
        let _ = simple_logger::SimpleLogger::new().init();

        let env_paths = [
            PathBuf::from("/path/from/env/1"),
            PathBuf::from("/path/from/env/2"),
        ];
        let state = ProgramState::new("/");

        let syscalls = [Ok(SyscallItem::Complete(Box::new(Syscall {
            pid: 598056,
            rel_ts: 0.000036,
            name: "connect".into(),
            args: vec![
                Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::Literal(4),
                    metadata: Some("/run/user/1000/systemd/private".as_bytes().to_vec()),
                }),
                Expression::Struct(HashMap::from([
                    (
                        "sa_family".to_owned(),
                        Expression::Integer(IntegerExpression {
                            value: IntegerExpressionValue::NamedSymbol("AF_UNIX".to_owned()),
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
            ret_val: Some(IntegerExpression {
                value: IntegerExpressionValue::Literal(0),
                metadata: None,
            }),
        })))];
        assert_eq!(
            summarize(syscalls, &env_paths, state).unwrap(),
            vec![
                ProgramAction::Read("/run/user/1000/systemd/private".into()),
                ProgramAction::Syscalls(["connect".into()].into()),
                ProgramAction::Read("/path/from/env/1".into()),
                ProgramAction::Read("/path/from/env/2".into()),
            ]
        );
    }

    #[test]
    fn fstat_unknown() {
        let _ = simple_logger::SimpleLogger::new().init();

        let state = ProgramState::new("/");

        let syscalls = [Ok(SyscallItem::Complete(Box::new(Syscall {
            pid: 498133,
            rel_ts: 7.5e-5,
            name: "fstat".into(),
            args: vec![
                Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::Literal(3),
                    metadata: None,
                }),
                Expression::Struct(
                    [
                        (
                            "st_dev".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Macro {
                                    name: "makedev".to_owned(),
                                    args: vec![
                                        Expression::Integer(IntegerExpression {
                                            value: IntegerExpressionValue::Literal(0),
                                            metadata: None,
                                        }),
                                        Expression::Integer(IntegerExpression {
                                            value: IntegerExpressionValue::Literal(101),
                                            metadata: None,
                                        }),
                                    ],
                                },
                                metadata: None,
                            }),
                        ),
                        (
                            "st_ctime_nsec".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(381300641),
                                metadata: None,
                            }),
                        ),
                        (
                            "st_size".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(49962383),
                                metadata: None,
                            }),
                        ),
                        (
                            "st_mtime".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(1759308185),
                                metadata: None,
                            }),
                        ),
                        (
                            "st_mtime_nsec".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(0),
                                metadata: None,
                            }),
                        ),
                        (
                            "st_ctime".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(1761822274),
                                metadata: None,
                            }),
                        ),
                        (
                            "st_blksize".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(4096),
                                metadata: None,
                            }),
                        ),
                        (
                            "st_ino".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(5369),
                                metadata: None,
                            }),
                        ),
                        (
                            "st_uid".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(1000),
                                metadata: None,
                            }),
                        ),
                        (
                            "st_gid".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(1000),
                                metadata: None,
                            }),
                        ),
                        (
                            "st_blocks".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(97584),
                                metadata: None,
                            }),
                        ),
                        (
                            "st_nlink".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(1),
                                metadata: None,
                            }),
                        ),
                        (
                            "st_mode".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::BinaryOr(vec![
                                    IntegerExpressionValue::NamedSymbol("S_IFREG".to_owned()),
                                    IntegerExpressionValue::Literal(493),
                                ]),
                                metadata: None,
                            }),
                        ),
                        (
                            "st_atime".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(1761822274),
                                metadata: None,
                            }),
                        ),
                        (
                            "st_atime_nsec".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(486303215),
                                metadata: None,
                            }),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ],
            ret_val: Some(IntegerExpression {
                value: IntegerExpressionValue::Literal(0),
                metadata: None,
            }),
        })))];
        assert_eq!(
            summarize(syscalls, &[], state).unwrap(),
            vec![ProgramAction::Syscalls(
                ["fstat".into()].into_iter().collect()
            )]
        );
    }
}
