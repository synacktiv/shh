//! Summarize program syscalls into higher level action

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use lazy_static::lazy_static;

use crate::strace::{BufferType, IntegerExpression, Syscall, SyscallArg};

/// A high level program runtime action
/// This does *not* map 1-1 with a syscall, and does *not* necessarily respect chronology
#[derive(Debug, Eq, PartialEq)]
pub enum ProgramAction {
    /// Path was accessed (open, stat'ed, read...)
    Read(PathBuf),
    /// Path was written to (data, metadata, path removal...)
    Write(PathBuf),
    /// Path was created
    Create(PathBuf),
    /// Network (socket) activity
    NetworkActivity { af: String },
    /// Names of the syscalls made by the program
    Syscalls(HashSet<String>),
}

struct OpenSyscallInfo {
    relfd_idx: Option<usize>,
    path_idx: usize,
    flags_idx: usize,
}

struct RenameSyscallInfo {
    relfd_src_idx: Option<usize>,
    path_src_idx: usize,
    relfd_dst_idx: Option<usize>,
    path_dst_idx: usize,
    flags_idx: Option<usize>,
}

lazy_static! {
    //
    // For some reference on syscalls, see:
    // - https://man7.org/linux/man-pages/man2/syscalls.2.html
    // - https://filippo.io/linux-syscall-table/
    // - https://linasm.sourceforge.net/docs/syscalls/filesystem.php
    //
    static ref OPEN_SYSCALL: HashMap<&'static str, OpenSyscallInfo> = HashMap::from([
        (
            "open",
            OpenSyscallInfo {
                relfd_idx: None,
                path_idx: 0,
                flags_idx: 1
            }
        ),
        (
            "openat",
            OpenSyscallInfo {
                relfd_idx: Some(0),
                path_idx: 1,
                flags_idx: 2
            }
        )
    ]);
    static ref RENAME_SYSCALL: HashMap<&'static str, RenameSyscallInfo> = HashMap::from([
        (
            "rename",
            RenameSyscallInfo {
                relfd_src_idx: None,
                path_src_idx: 0,
                relfd_dst_idx: None,
                path_dst_idx: 1,
                flags_idx: None,
            }
        ),
        (
            "renameat",
            RenameSyscallInfo {
                relfd_src_idx: Some(0),
                path_src_idx: 1,
                relfd_dst_idx: Some(2),
                path_dst_idx: 3,
                flags_idx: None,
            }
        ),
        (
            "renameat2",
            RenameSyscallInfo {
                relfd_src_idx: Some(0),
                path_src_idx: 1,
                relfd_dst_idx: Some(2),
                path_dst_idx: 3,
                flags_idx: Some(4),
            }
        )
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
    for syscall in syscalls {
        let syscall = syscall?;
        log::trace!("{syscall:?}");
        stats
            .entry(syscall.name.clone())
            .and_modify(|c| *c += 1)
            .or_insert(1);
        let name = syscall.name.as_str();

        if let Some(open_info) = OPEN_SYSCALL.get(name) {
            let (mut path, flags) = if let (
                Some(SyscallArg::Buffer {
                    value: b,
                    type_: BufferType::Unknown,
                }),
                Some(SyscallArg::Integer { value: e, .. }),
            ) = (
                syscall.args.get(open_info.path_idx),
                syscall.args.get(open_info.flags_idx),
            ) {
                (PathBuf::from(OsStr::from_bytes(b)), e)
            } else {
                anyhow::bail!("Unexpected args for {}: {:?}", name, syscall.args);
            };

            path = if let Some(path) = resolve_path(&path, open_info.relfd_idx, &syscall) {
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
        } else if let Some(rename_info) = RENAME_SYSCALL.get(name) {
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
                syscall.args.get(rename_info.path_src_idx),
                syscall.args.get(rename_info.path_dst_idx),
            ) {
                (
                    PathBuf::from(OsStr::from_bytes(b1)),
                    PathBuf::from(OsStr::from_bytes(b2)),
                )
            } else {
                anyhow::bail!("Unexpected args for {}: {:?}", name, syscall.args);
            };

            (path_src, path_dst) = if let (Some(path_src), Some(path_dst)) = (
                resolve_path(&path_src, rename_info.relfd_src_idx, &syscall),
                resolve_path(&path_dst, rename_info.relfd_dst_idx, &syscall),
            ) {
                (path_src, path_dst)
            } else {
                continue;
            };

            let exchange = if let Some(flags_idx) = rename_info.flags_idx {
                let flags = if let Some(SyscallArg::Integer { value: flags, .. }) =
                    syscall.args.get(flags_idx)
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
        } else if name.starts_with("getdents") {
            // TODO factorize with newfstatat, handle other stat variants?
            let mut path = syscall
                .args
                .get(0)
                .and_then(|a| a.metadata())
                .map(|m| PathBuf::from(OsStr::from_bytes(m)))
                .ok_or_else(|| anyhow::anyhow!("Unexpected args for {name}"))?;
            path = if let Some(path) = resolve_path(&path, None, &syscall) {
                path
            } else {
                continue;
            };
            actions.push(ProgramAction::Read(path));
        } else if name.starts_with("newfstatat") {
            let mut path = if let Some(SyscallArg::Buffer {
                value: b,
                type_: BufferType::Unknown,
            }) = syscall.args.get(1)
            {
                PathBuf::from(OsStr::from_bytes(b))
            } else {
                anyhow::bail!("Unexpected args for {}: {:?}", name, syscall.args);
            };
            path = if let Some(path) = resolve_path(&path, Some(0), &syscall) {
                path
            } else {
                continue;
            };
            actions.push(ProgramAction::Read(path));
        } else if ["bind", "connect"].contains(&name) {
            // TODO other network syscalls that can handle UDS (sendto, sendmsg, recvfrom, recvmsg)

            let (af, addr) = if let Some(SyscallArg::Struct(members)) = syscall.args.get(1) {
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
                anyhow::bail!("Unexpected args for {}: {:?}", name, syscall.args);
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
        } else if name == "socket" {
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
        log::debug!("{:20} {: >12}", format!("{syscall_name}:"), count);
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
