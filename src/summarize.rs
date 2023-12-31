//! Summarize program syscalls into higher level action

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use lazy_static::lazy_static;

use crate::strace::{BufferType, IntegerExpression, Syscall, SyscallArg};
use crate::systemd::{SocketFamily, SocketProtocol};

/// A high level program runtime action
/// This does *not* map 1-1 with a syscall, and does *not* necessarily respect chronology
#[derive(Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ProgramAction {
    /// Path was accessed (open, stat'ed, read...)
    Read(PathBuf),
    /// Path was written to (data, metadata, path removal...)
    Write(PathBuf),
    /// Path was created
    Create(PathBuf),
    /// Generic network (socket) activity
    NetworkActivity { af: String },
    /// Memory mapping with write and execute bits
    WriteExecuteMemoryMapping,
    /// Set scheduler to a real time one
    SetRealtimeScheduler,
    /// Bind socket
    SocketBind {
        af: SocketFamily,
        proto: SocketProtocol,
    },
    /// Names of the syscalls made by the program
    Syscalls(HashSet<String>),
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

lazy_static! {
    //
    // For some reference on syscalls, see:
    // - https://man7.org/linux/man-pages/man2/syscalls.2.html
    // - https://filippo.io/linux-syscall-table/
    // - https://linasm.sourceforge.net/docs/syscalls/filesystem.php
    //
    static ref SYSCALL_MAP: HashMap<&'static str, SyscallInfo> = HashMap::from([
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
        ("stat", SyscallInfo::StatPath { relfd_idx: None, path_idx: 0 }),
        ("lstat", SyscallInfo::StatPath { relfd_idx: None, path_idx: 0 }),
        ("newfstatat", SyscallInfo::StatPath { relfd_idx: Some(0), path_idx: 1 }),
    ]);
}

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

lazy_static! {
    static ref FD_PSEUDO_PATH_REGEX: regex::bytes::Regex =
        regex::bytes::Regex::new(r"^[a-z]+:\[[0-9a-z]+\]/?$").unwrap();
}

fn is_fd_pseudo_path(path: &[u8]) -> bool {
    FD_PSEUDO_PATH_REGEX.is_match(path)
}

/// Extract path for socket address structure if it's a non abstract one
fn socket_address_uds_path(
    members: &HashMap<String, SyscallArg>,
    syscall: &Syscall,
) -> Option<PathBuf> {
    if let Some(SyscallArg::Buffer {
        value: b,
        type_: BufferType::Unknown,
    }) = members.get("sun_path")
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
                    Some(SyscallArg::Buffer {
                        value: b,
                        type_: BufferType::Unknown,
                    }),
                    Some(SyscallArg::Integer { value: e, .. }),
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
                    Some(SyscallArg::Buffer {
                        value: b1,
                        type_: BufferType::Unknown,
                    }),
                    Some(SyscallArg::Buffer {
                        value: b2,
                        type_: BufferType::Unknown,
                    }),
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
                    let flags = if let Some(SyscallArg::Integer { value: flags, .. }) =
                        syscall.args.get(*flags_idx)
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
                let mut path = if let Some(SyscallArg::Buffer {
                    value: b,
                    type_: BufferType::Unknown,
                }) = syscall.args.get(*path_idx)
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
                    if let Some(SyscallArg::Struct(members)) = syscall.args.get(*sockaddr_idx) {
                        let af = if let Some(SyscallArg::Integer {
                            value: IntegerExpression::NamedConst(af),
                            ..
                        }) = members.get("sa_family")
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
                    let fd = if let Some(SyscallArg::Integer {
                        value: IntegerExpression::Literal(fd),
                        ..
                    }) = syscall.args.get(0)
                    {
                        fd
                    } else {
                        anyhow::bail!("Unexpected args for {}: {:?}", name, syscall.args);
                    };
                    if let (Some(af), Some(proto)) = (
                        SocketFamily::from_syscall_arg(af),
                        known_sockets_proto.get(&(syscall.pid, *fd)),
                    ) {
                        actions.push(ProgramAction::SocketBind {
                            af,
                            proto: proto.clone(),
                        });
                    }
                }
            }
            Some(SyscallInfo::SetScheduler) => {
                let policy = if let Some(SyscallArg::Integer { value, .. }) = syscall.args.get(1) {
                    value
                } else {
                    anyhow::bail!("Unexpected args for {}: {:?}", name, syscall.args);
                };
                if policy.is_flag_set("SCHED_FIFO") | policy.is_flag_set("SCHED_RR") {
                    actions.push(ProgramAction::SetRealtimeScheduler);
                }
            }
            Some(SyscallInfo::Socket) => {
                let af = if let Some(SyscallArg::Integer {
                    value: IntegerExpression::NamedConst(af),
                    ..
                }) = syscall.args.get(0)
                {
                    af.to_string()
                } else {
                    anyhow::bail!("Unexpected args for {}: {:?}", name, syscall.args);
                };
                actions.push(ProgramAction::NetworkActivity { af });

                let proto_flags =
                    if let Some(SyscallArg::Integer { value, .. }) = syscall.args.get(1) {
                        value.flags()
                    } else {
                        anyhow::bail!("Unexpected args for {}: {:?}", name, syscall.args);
                    };
                for proto in proto_flags {
                    if let Some(known_proto) = SocketProtocol::from_syscall_arg(&proto) {
                        known_sockets_proto.insert((syscall.pid, syscall.ret_val), known_proto);
                        break;
                    }
                }
            }
            Some(SyscallInfo::Mmap { prot_idx }) => {
                let prot = if let Some(SyscallArg::Integer { value: prot, .. }) =
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
            None => (),
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
            name: "renameat".to_string(),
            args: vec![
                SyscallArg::Integer {
                    value: IntegerExpression::NamedConst("AT_FDCWD".to_string()),
                    metadata: Some(temp_dir_src.path().as_os_str().as_bytes().to_vec()),
                },
                SyscallArg::Buffer {
                    value: "a".as_bytes().to_vec(),
                    type_: BufferType::Unknown,
                },
                SyscallArg::Integer {
                    value: IntegerExpression::NamedConst("AT_FDCWD".to_string()),
                    metadata: Some(temp_dir_dst.path().as_os_str().as_bytes().to_vec()),
                },
                SyscallArg::Buffer {
                    value: "b".as_bytes().to_vec(),
                    type_: BufferType::Unknown,
                },
                SyscallArg::Integer {
                    value: IntegerExpression::NamedConst("RENAME_NOREPLACE".to_string()),
                    metadata: None,
                },
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
                ProgramAction::Syscalls(["renameat".to_string()].into())
            ]
        );
    }

    #[test]
    fn test_connect_uds() {
        let _ = simple_logger::SimpleLogger::new().init();

        let syscalls = [Ok(Syscall {
            pid: 598056,
            rel_ts: 0.000036,
            name: "connect".to_string(),
            args: vec![
                SyscallArg::Integer {
                    value: IntegerExpression::Literal(4),
                    metadata: Some("/run/user/1000/systemd/private".as_bytes().to_vec()),
                },
                SyscallArg::Struct(HashMap::from([
                    (
                        "sa_family".to_string(),
                        SyscallArg::Integer {
                            value: IntegerExpression::NamedConst("AF_UNIX".to_string()),
                            metadata: None,
                        },
                    ),
                    (
                        "sun_path".to_string(),
                        SyscallArg::Buffer {
                            value: "/run/user/1000/systemd/private".as_bytes().to_vec(),
                            type_: BufferType::Unknown,
                        },
                    ),
                ])),
                SyscallArg::Integer {
                    value: IntegerExpression::Literal(33),
                    metadata: None,
                },
            ],
            ret_val: 0,
        })];
        assert_eq!(
            summarize(syscalls).unwrap(),
            vec![
                ProgramAction::Read("/run/user/1000/systemd/private".into()),
                ProgramAction::Syscalls(["connect".to_string()].into())
            ]
        );
    }
}
