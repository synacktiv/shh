//! Summarize program syscalls into higher level action

use std::{
    collections::{HashMap, HashSet},
    ffi::OsStr,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::LazyLock,
};

use crate::{
    strace::{
        BufferExpression, BufferType, Expression, IntegerExpression, IntegerExpressionValue,
        Syscall,
    },
    systemd::{SocketFamily, SocketProtocol},
};

/// A high level program runtime action
/// This does *not* map 1-1 with a syscall, and does *not* necessarily respect chronology
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ProgramAction {
    /// Path was accessed (open, stat'ed, read...)
    Read(PathBuf),
    /// Path was written to (data, metadata, path removal...)
    Write(PathBuf),
    /// Path was created
    Create(PathBuf),
    /// Network (socket) activity
    NetworkActivity(NetworkActivity),
    /// Memory mapping with write and execute bits
    WriteExecuteMemoryMapping,
    /// Set scheduler to a real time one
    SetRealtimeScheduler,
    /// Inhibit suspend
    Wakeup,
    /// Names of the syscalls made by the program
    Syscalls(HashSet<String>),
}

/// Network (socket) activity
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct NetworkActivity {
    pub af: SetSpecifier<SocketFamily>,
    pub proto: SetSpecifier<SocketProtocol>,
    pub kind: SetSpecifier<NetworkActivityKind>,
}

/// Quantify something that is done or denied
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum SetSpecifier<T> {
    None,
    One(T),
    Some(Vec<T>),
    All,
}

impl<T: Eq> SetSpecifier<T> {
    fn contains_one(&self, needle: &T) -> bool {
        match self {
            SetSpecifier::None => false,
            SetSpecifier::One(e) => e == needle,
            SetSpecifier::Some(es) => es.contains(needle),
            SetSpecifier::All => true,
        }
    }

    pub fn intersects(&self, other: &Self) -> bool {
        match self {
            SetSpecifier::None => false,
            SetSpecifier::One(e) => other.contains_one(e),
            SetSpecifier::Some(es) => es.iter().any(|e| other.contains_one(e)),
            SetSpecifier::All => !matches!(other, SetSpecifier::None),
        }
    }
}

/// Socket activity
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum NetworkActivityKind {
    SocketCreation,
    Bind,
    // TODO
    // Connect,
    // Send,
    // Recv,
}

/// Meta structure to group syscalls that have similar summary handling
/// and store argument indexes
enum SyscallInfo {
    Mmap {
        prot_idx: usize,
    },
    Network {
        sockaddr_idx: usize,
    },
    Open {
        relfd_idx: Option<usize>,
        path_idx: usize,
        flags_idx: usize,
    },
    Rename {
        relfd_src_idx: Option<usize>,
        path_src_idx: usize,
        relfd_dst_idx: Option<usize>,
        path_dst_idx: usize,
        flags_idx: Option<usize>,
    },
    SetScheduler,
    Socket,
    StatFd {
        fd_idx: usize,
    },
    StatPath {
        relfd_idx: Option<usize>,
        path_idx: usize,
    },
}

//
// For some reference on syscalls, see:
// - https://man7.org/linux/man-pages/man2/syscalls.2.html
// - https://filippo.io/linux-syscall-table/
// - https://linasm.sourceforge.net/docs/syscalls/filesystem.php
//
static SYSCALL_MAP: LazyLock<HashMap<&'static str, SyscallInfo>> = LazyLock::new(|| {
    HashMap::from([
        // mmap
        ("mmap", SyscallInfo::Mmap { prot_idx: 2 }),
        ("mmap2", SyscallInfo::Mmap { prot_idx: 2 }),
        ("shmat", SyscallInfo::Mmap { prot_idx: 2 }),
        ("mprotect", SyscallInfo::Mmap { prot_idx: 2 }),
        ("pkey_mprotect", SyscallInfo::Mmap { prot_idx: 2 }),
        // network
        ("connect", SyscallInfo::Network { sockaddr_idx: 1 }),
        ("bind", SyscallInfo::Network { sockaddr_idx: 1 }),
        ("recvfrom", SyscallInfo::Network { sockaddr_idx: 4 }),
        ("sendto", SyscallInfo::Network { sockaddr_idx: 4 }),
        // TODO recvmsg/sendmsg

        // open
        (
            "open",
            SyscallInfo::Open {
                relfd_idx: None,
                path_idx: 0,
                flags_idx: 1,
            },
        ),
        (
            "openat",
            SyscallInfo::Open {
                relfd_idx: Some(0),
                path_idx: 1,
                flags_idx: 2,
            },
        ),
        // rename
        (
            "rename",
            SyscallInfo::Rename {
                relfd_src_idx: None,
                path_src_idx: 0,
                relfd_dst_idx: None,
                path_dst_idx: 1,
                flags_idx: None,
            },
        ),
        (
            "renameat",
            SyscallInfo::Rename {
                relfd_src_idx: Some(0),
                path_src_idx: 1,
                relfd_dst_idx: Some(2),
                path_dst_idx: 3,
                flags_idx: None,
            },
        ),
        (
            "renameat2",
            SyscallInfo::Rename {
                relfd_src_idx: Some(0),
                path_src_idx: 1,
                relfd_dst_idx: Some(2),
                path_dst_idx: 3,
                flags_idx: Some(4),
            },
        ),
        // set scheduler
        ("sched_setscheduler", SyscallInfo::SetScheduler),
        // socket
        ("socket", SyscallInfo::Socket),
        // stat fd
        ("fstat", SyscallInfo::StatFd { fd_idx: 0 }),
        ("getdents", SyscallInfo::StatFd { fd_idx: 0 }),
        // stat path
        (
            "stat",
            SyscallInfo::StatPath {
                relfd_idx: None,
                path_idx: 0,
            },
        ),
        (
            "lstat",
            SyscallInfo::StatPath {
                relfd_idx: None,
                path_idx: 0,
            },
        ),
        (
            "newfstatat",
            SyscallInfo::StatPath {
                relfd_idx: Some(0),
                path_idx: 1,
            },
        ),
    ])
});

/// Resolve relative path if possible, and normalize it
fn resolve_path(path: &Path, relfd_idx: Option<usize>, syscall: &Syscall) -> Option<PathBuf> {
    let path = if path.is_relative() {
        let metadata = relfd_idx
            .and_then(|idx| syscall.args.get(idx))
            .and_then(|a| a.metadata());
        if let Some(metadata) = metadata {
            if is_fd_pseudo_path(metadata) {
                return None;
            }
            let rel_path = PathBuf::from(OsStr::from_bytes(metadata));
            rel_path.join(path)
        } else {
            return None;
        }
    } else {
        path.to_path_buf()
    };
    // TODO APPROXIMATION
    // canonicalize relies on the FS state at profiling time which may have changed
    // and may follow links, therefore lead to different filesystem actions
    Some(path.canonicalize().unwrap_or(path))
}

static FD_PSEUDO_PATH_REGEX: LazyLock<regex::bytes::Regex> =
    LazyLock::new(|| regex::bytes::Regex::new(r"^[a-z]+:\[[0-9a-z]+\]/?$").unwrap());

fn is_fd_pseudo_path(path: &[u8]) -> bool {
    FD_PSEUDO_PATH_REGEX.is_match(path)
}

/// Extract path for socket address structure if it's a non abstract one
fn socket_address_uds_path(
    members: &HashMap<String, Expression>,
    syscall: &Syscall,
) -> Option<PathBuf> {
    if let Some(Expression::Buffer(BufferExpression {
        value: b,
        type_: BufferType::Unknown,
    })) = members.get("sun_path")
    {
        resolve_path(&PathBuf::from(OsStr::from_bytes(b)), None, syscall)
    } else {
        None
    }
}

pub fn summarize<I>(syscalls: I) -> anyhow::Result<Vec<ProgramAction>>
where
    I: IntoIterator<Item = anyhow::Result<Syscall>>,
{
    let mut actions = Vec::new();
    let mut stats: HashMap<String, u64> = HashMap::new();
    // Keep known socket protocols (per process) for bind handling, we don't care for the socket closings
    // because the fd will be reused or never bound again
    let mut known_sockets_proto: HashMap<(u32, i128), SocketProtocol> = HashMap::new();
    for syscall in syscalls {
        let syscall = syscall?;
        log::trace!("{syscall:?}");
        stats
            .entry(syscall.name.clone())
            .and_modify(|c| *c += 1)
            .or_insert(1);
        let name = syscall.name.as_str();

        match SYSCALL_MAP.get(name) {
            Some(SyscallInfo::Open {
                relfd_idx,
                path_idx,
                flags_idx,
            }) => {
                let (mut path, flags) = if let (
                    Some(Expression::Buffer(BufferExpression {
                        value: b,
                        type_: BufferType::Unknown,
                    })),
                    Some(Expression::Integer(IntegerExpression { value: e, .. })),
                ) =
                    (syscall.args.get(*path_idx), syscall.args.get(*flags_idx))
                {
                    (PathBuf::from(OsStr::from_bytes(b)), e)
                } else {
                    anyhow::bail!("Unexpected args for {}: {:?}", name, syscall.args);
                };

                path = if let Some(path) = resolve_path(&path, *relfd_idx, &syscall) {
                    path
                } else {
                    continue;
                };

                if flags.is_flag_set("O_CREAT") {
                    actions.push(ProgramAction::Create(path.clone()));
                }
                if flags.is_flag_set("O_WRONLY")
                    || flags.is_flag_set("O_RDWR")
                    || flags.is_flag_set("O_TRUNC")
                {
                    actions.push(ProgramAction::Write(path.clone()));
                }
                if !flags.is_flag_set("O_WRONLY") {
                    actions.push(ProgramAction::Read(path));
                }
            }
            Some(SyscallInfo::Rename {
                relfd_src_idx,
                path_src_idx,
                relfd_dst_idx,
                path_dst_idx,
                flags_idx,
            }) => {
                let (mut path_src, mut path_dst) = if let (
                    Some(Expression::Buffer(BufferExpression {
                        value: b1,
                        type_: BufferType::Unknown,
                    })),
                    Some(Expression::Buffer(BufferExpression {
                        value: b2,
                        type_: BufferType::Unknown,
                    })),
                ) = (
                    syscall.args.get(*path_src_idx),
                    syscall.args.get(*path_dst_idx),
                ) {
                    (
                        PathBuf::from(OsStr::from_bytes(b1)),
                        PathBuf::from(OsStr::from_bytes(b2)),
                    )
                } else {
                    anyhow::bail!("Unexpected args for {}: {:?}", name, syscall.args);
                };

                (path_src, path_dst) = if let (Some(path_src), Some(path_dst)) = (
                    resolve_path(&path_src, *relfd_src_idx, &syscall),
                    resolve_path(&path_dst, *relfd_dst_idx, &syscall),
                ) {
                    (path_src, path_dst)
                } else {
                    continue;
                };

                let exchange = if let Some(flags_idx) = flags_idx {
                    let flags = if let Some(Expression::Integer(IntegerExpression {
                        value: flags,
                        ..
                    })) = syscall.args.get(*flags_idx)
                    {
                        flags
                    } else {
                        anyhow::bail!("Unexpected args for {}: {:?}", name, syscall.args);
                    };

                    flags.is_flag_set("RENAME_EXCHANGE")
                } else {
                    false
                };

                actions.push(ProgramAction::Read(path_src.clone()));
                actions.push(ProgramAction::Write(path_src.clone()));
                if exchange {
                    actions.push(ProgramAction::Read(path_dst.clone()));
                } else {
                    actions.push(ProgramAction::Create(path_dst.clone()));
                }
                actions.push(ProgramAction::Write(path_dst.clone()));
            }
            Some(SyscallInfo::StatFd { fd_idx }) => {
                let mut path = syscall
                    .args
                    .get(*fd_idx)
                    .and_then(|a| a.metadata())
                    .map(|m| PathBuf::from(OsStr::from_bytes(m)))
                    .ok_or_else(|| anyhow::anyhow!("Unexpected args for {name}"))?;
                path = if let Some(path) = resolve_path(&path, None, &syscall) {
                    path
                } else {
                    continue;
                };
                actions.push(ProgramAction::Read(path));
            }
            Some(SyscallInfo::StatPath {
                relfd_idx,
                path_idx,
            }) => {
                let mut path = if let Some(Expression::Buffer(BufferExpression {
                    value: b,
                    type_: BufferType::Unknown,
                })) = syscall.args.get(*path_idx)
                {
                    PathBuf::from(OsStr::from_bytes(b))
                } else {
                    anyhow::bail!("Unexpected args for {}: {:?}", name, syscall.args);
                };
                path = if let Some(path) = resolve_path(&path, *relfd_idx, &syscall) {
                    path
                } else {
                    continue;
                };
                actions.push(ProgramAction::Read(path));
            }
            Some(SyscallInfo::Network { sockaddr_idx }) => {
                let (af, addr) =
                    if let Some(Expression::Struct(members)) = syscall.args.get(*sockaddr_idx) {
                        let af = if let Some(Expression::Integer(IntegerExpression {
                            value: IntegerExpressionValue::NamedConst(af),
                            ..
                        })) = members.get("sa_family")
                        {
                            af
                        } else {
                            anyhow::bail!("Unexpected args for {}: {:?}", name, syscall.args);
                        };
                        (af.as_str(), members)
                    } else {
                        // Can be NULL in some cases, ie AF_NETLINK sockets
                        continue;
                    };

                #[allow(clippy::single_match)]
                match af {
                    "AF_UNIX" => {
                        if let Some(path) = socket_address_uds_path(addr, &syscall) {
                            actions.push(ProgramAction::Read(path));
                        };
                    }
                    _ => (),
                }

                if name == "bind" {
                    let fd = if let Some(Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(fd),
                        ..
                    })) = syscall.args.first()
                    {
                        fd
                    } else {
                        anyhow::bail!("Unexpected args for {}: {:?}", name, syscall.args);
                    };
                    let af = af
                        .parse()
                        .map_err(|_| anyhow::anyhow!("Unable to parse socket family {af:?}"))?;
                    if let Some(proto) = known_sockets_proto.get(&(syscall.pid, *fd)) {
                        actions.push(ProgramAction::NetworkActivity(NetworkActivity {
                            af: SetSpecifier::One(af),
                            proto: SetSpecifier::One(proto.to_owned()),
                            kind: SetSpecifier::One(NetworkActivityKind::Bind),
                        }));
                    }
                }
            }
            Some(SyscallInfo::SetScheduler) => {
                let policy = if let Some(Expression::Integer(IntegerExpression { value, .. })) =
                    syscall.args.get(1)
                {
                    value
                } else {
                    anyhow::bail!("Unexpected args for {}: {:?}", name, syscall.args);
                };
                if policy.is_flag_set("SCHED_FIFO") | policy.is_flag_set("SCHED_RR") {
                    actions.push(ProgramAction::SetRealtimeScheduler);
                }
            }
            Some(SyscallInfo::Socket) => {
                let af = if let Some(Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::NamedConst(af),
                    ..
                })) = syscall.args.first()
                {
                    af.parse()
                        .map_err(|_| anyhow::anyhow!("Unable to parse socket family {af:?}"))?
                } else {
                    anyhow::bail!("Unexpected args for {}: {:?}", name, syscall.args);
                };

                let flags = if let Some(Expression::Integer(IntegerExpression { value, .. })) =
                    syscall.args.get(1)
                {
                    value.flags()
                } else {
                    anyhow::bail!("Unexpected args for {}: {:?}", name, syscall.args);
                };
                let proto_flag =
                    flags
                        .iter()
                        .find(|f| f.starts_with("SOCK_"))
                        .ok_or_else(|| {
                            anyhow::anyhow!("Unable to parse socket protocol from flags {flags:?}")
                        })?;
                let proto = proto_flag.parse::<SocketProtocol>().map_err(|_e| {
                    anyhow::anyhow!("Unable to parse socket protocol {proto_flag:?}")
                })?;
                known_sockets_proto.insert((syscall.pid, syscall.ret_val), proto.clone());

                actions.push(ProgramAction::NetworkActivity(NetworkActivity {
                    af: SetSpecifier::One(af),
                    proto: SetSpecifier::One(proto),
                    kind: SetSpecifier::One(NetworkActivityKind::SocketCreation),
                }));
            }
            Some(SyscallInfo::Mmap { prot_idx }) => {
                let prot =
                    if let Some(Expression::Integer(IntegerExpression { value: prot, .. })) =
                        syscall.args.get(*prot_idx)
                    {
                        prot
                    } else {
                        anyhow::bail!("Unexpected args for {}: {:?}", name, syscall.args);
                    };
                if prot.is_flag_set("PROT_WRITE") && prot.is_flag_set("PROT_EXEC") {
                    actions.push(ProgramAction::WriteExecuteMemoryMapping);
                }
            }
            #[expect(clippy::single_match)]
            None => match name {
                "epoll_ctl" => {
                    if syscall.args.get(1).is_some_and(|op| {
                        matches!(op, Expression::Integer(IntegerExpression {
                            value: IntegerExpressionValue::NamedConst(op_name),
                            ..
                        }) if op_name == "EPOLL_CTL_ADD")
                    }) {
                        // Get the event
                        let evt_arg = syscall
                            .args
                            .get(3)
                            .ok_or_else(|| anyhow::anyhow!("Missing epoll event argument"))?;
                        let evt_flags = if let Expression::Struct(evt_struct) = evt_arg {
                            let evt_member = evt_struct.get("events").ok_or_else(|| {
                                anyhow::anyhow!("Missing epoll events struct member")
                            })?;
                            if let Expression::Integer(ie) = evt_member {
                                ie
                            } else {
                                anyhow::bail!("Invalid epoll struct member");
                            }
                        } else {
                            anyhow::bail!("Invalid epoll event argument");
                        };
                        if evt_flags.value.is_flag_set("EPOLLWAKEUP") {
                            actions.push(ProgramAction::Wakeup);
                        }
                    }
                }
                _ => {}
            },
        }
    }

    // Almost free optimization
    actions.dedup();

    // Create single action with all syscalls for efficient handling of seccomp filters
    actions.push(ProgramAction::Syscalls(stats.keys().cloned().collect()));

    // Report stats
    let mut syscall_names = stats.keys().collect::<Vec<_>>();
    syscall_names.sort();
    for syscall_name in syscall_names {
        let count = stats.get(syscall_name).unwrap();
        log::debug!("{:24} {: >12}", format!("{syscall_name}:"), count);
    }

    Ok(actions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strace::*;

    #[test]
    fn test_is_socket_or_pipe_pseudo_path() {
        assert!(!is_fd_pseudo_path("plop".as_bytes()));
        assert!(is_fd_pseudo_path("pipe:[12334]".as_bytes()));
        assert!(is_fd_pseudo_path("socket:[1234]/".as_bytes()));
    }

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
}
