//! Syscall handlers, producing summary

use std::{
    any::{type_name, type_name_of_val},
    collections::HashMap,
    ffi::OsStr,
    fs::{self, File},
    io::{self, BufRead as _, BufReader},
    net::IpAddr,
    os::{
        fd::RawFd,
        unix::{ffi::OsStrExt as _, fs::FileTypeExt as _},
    },
    path::{Path, PathBuf},
    str,
    sync::LazyLock,
};

use goblin::elf;
use path_clean::PathClean as _;

use super::{
    BufferExpression, BufferType, Expression, FdOrPath, IntegerExpression, IntegerExpressionValue,
    NetworkActivity, NetworkActivityKind, NetworkPort, ProgramAction, ProgramState, SetSpecifier,
    SocketFamily, SocketProtocol, Syscall, SyscallArgs, SyscallArgsInfo,
};

#[derive(thiserror::Error, Debug)]
pub(crate) enum HandlerError {
    #[error("Unexpected {sc_name:?} argument type: {arg:?}")]
    ArgTypeMismatch { sc_name: String, arg: Expression },
    #[error("Failed to parse {src:?} as {type_}")]
    ParsingFailed { src: String, type_: &'static str },
    #[error("Failed to convert value {src:?} (type_src) into {type_dst}")]
    ConversionFailed {
        src: String,
        type_src: &'static str,
        type_dst: &'static str,
    },
    #[error("Missing member {member:?} in struct {struct_:?}")]
    MissingStructMember {
        member: &'static str,
        struct_: HashMap<String, Expression>,
    },
    #[error("System error: {0}")]
    SystemError(#[from] io::Error),
}

pub(crate) fn summarize_syscall(
    sc: &Syscall,
    args: SyscallArgs,
    actions: &mut Vec<ProgramAction>,
    state: &mut ProgramState,
) -> Result<(), HandlerError> {
    match args {
        SyscallArgsInfo::Chdir(p) => handle_chdir(&sc.name, p, actions, state),
        SyscallArgsInfo::EpollCtl { op, event } => handle_epoll_ctl(&sc.name, op, event, actions),
        SyscallArgsInfo::Exec { relfd, path } => handle_exec(&sc.name, relfd, path, actions, state),
        SyscallArgsInfo::Mkdir { relfd, path } => {
            handle_mkdir(&sc.name, relfd, path, actions, state)
        }
        SyscallArgsInfo::Mknod { mode } => handle_mknod(&sc.name, mode, actions),
        SyscallArgsInfo::Mmap { prot, fd } => handle_mmap(&sc.name, prot, fd, actions),
        SyscallArgsInfo::Mount { flags } => handle_mount(&sc.name, flags, actions),
        SyscallArgsInfo::Network { fd, sockaddr } => {
            handle_network(&sc.name, sc.pid, fd, sockaddr, actions, state)
        }
        SyscallArgsInfo::Open { relfd, path, flags } => {
            handle_open(&sc.name, relfd, path, flags, &sc.ret_val, actions, state)
        }
        SyscallArgsInfo::Rename {
            relfd_src,
            path_src,
            relfd_dst,
            path_dst,
            flags,
        } => handle_rename(
            &sc.name, relfd_src, path_src, relfd_dst, path_dst, flags, actions, state,
        ),
        SyscallArgsInfo::SetScheduler { policy } => handle_setscheduler(&sc.name, policy, actions),
        SyscallArgsInfo::Socket { af, flags } => {
            handle_socket(&sc.name, sc.pid, &sc.ret_val, af, flags, actions, state)
        }
        SyscallArgsInfo::StatFd { fd } => handle_stat_fd(&sc.name, fd, actions, state),
        SyscallArgsInfo::StatPath { relfd, path } => {
            handle_stat_path(&sc.name, relfd, path, actions, state)
        }
        SyscallArgsInfo::TimerCreate { clockid } => handle_timer_create(&sc.name, clockid, actions),
    }
}

/// Handle chdir-like syscall
#[expect(clippy::needless_pass_by_value)]
fn handle_chdir(
    name: &str,
    path: FdOrPath<&Expression>,
    actions: &mut Vec<ProgramAction>,
    state: &mut ProgramState,
) -> Result<(), HandlerError> {
    let dir = match path {
        FdOrPath::Fd(fd) => resolve_path(Path::new(""), Some(fd), state.cur_dir.as_ref()),
        FdOrPath::Path(Expression::Buffer(BufferExpression {
            value: b,
            type_: BufferType::Unknown,
        })) => {
            let p = Path::new(OsStr::from_bytes(b));
            resolve_path(p, None, state.cur_dir.as_ref())
        }
        FdOrPath::Path(e) => {
            return Err(HandlerError::ArgTypeMismatch {
                sc_name: name.to_owned(),
                arg: e.to_owned(),
            });
        }
    };
    if let Some(mut dir) = dir {
        traverse_symlinks(&mut dir, actions);
        debug_assert!(dir.is_absolute());
        state.cur_dir = Some(dir);
    }
    Ok(())
}

/// Handle `epoll_ctl` syscall
fn handle_epoll_ctl(
    name: &str,
    op: &Expression,
    event: &Expression,
    actions: &mut Vec<ProgramAction>,
) -> Result<(), HandlerError> {
    let Expression::Integer(IntegerExpression {
        value: IntegerExpressionValue::NamedConst(op_name),
        ..
    }) = op
    else {
        return Err(HandlerError::ArgTypeMismatch {
            sc_name: name.to_owned(),
            arg: op.to_owned(),
        });
    };

    if op_name == "EPOLL_CTL_ADD" {
        let evt_flags = if let Expression::Struct(evt_struct) = event {
            let evt_member =
                evt_struct
                    .get("events")
                    .ok_or_else(|| HandlerError::MissingStructMember {
                        member: "events",
                        struct_: evt_struct.to_owned(),
                    })?;
            if let Expression::Integer(ie) = evt_member {
                ie
            } else {
                return Err(HandlerError::ArgTypeMismatch {
                    sc_name: name.to_owned(),
                    arg: evt_member.to_owned(),
                });
            }
        } else {
            return Err(HandlerError::ArgTypeMismatch {
                sc_name: name.to_owned(),
                arg: event.to_owned(),
            });
        };
        if evt_flags.value.is_flag_set("EPOLLWAKEUP") {
            actions.push(ProgramAction::Wakeup);
        }
    }
    Ok(())
}

/// Handle exec-like syscalls
fn handle_exec(
    name: &str,
    relfd: Option<&Expression>,
    path: &Expression,
    actions: &mut Vec<ProgramAction>,
    state: &ProgramState,
) -> Result<(), HandlerError> {
    let path = if let Expression::Buffer(BufferExpression {
        value: b,
        type_: BufferType::Unknown,
    }) = path
    {
        PathBuf::from(OsStr::from_bytes(b))
    } else {
        return Err(HandlerError::ArgTypeMismatch {
            sc_name: name.to_owned(),
            arg: path.to_owned(),
        });
    };
    if let Some(mut path) = resolve_path(&path, relfd, state.cur_dir.as_ref()) {
        traverse_symlinks(&mut path, actions);
        actions.push(ProgramAction::Exec(path.clone()));
        let mut cur_path_opt = Some(path);
        while let Some(cur_path) = cur_path_opt {
            if let Some(mut elf_interpreter) = read_elf_interpreter(&cur_path) {
                traverse_symlinks(&mut elf_interpreter, actions);
                actions.push(ProgramAction::Exec(elf_interpreter.clone()));
                cur_path_opt = Some(elf_interpreter);
            } else if let Some(mut shebang_interpreter) = read_shebang_interpreter(&cur_path) {
                traverse_symlinks(&mut shebang_interpreter, actions);
                actions.push(ProgramAction::Exec(shebang_interpreter.clone()));
                cur_path_opt = Some(shebang_interpreter);
            } else {
                cur_path_opt = None;
            }
        }
    }
    Ok(())
}

/// Handle mkdir-like syscalls
fn handle_mkdir(
    name: &str,
    relfd: Option<&Expression>,
    path: &Expression,
    actions: &mut Vec<ProgramAction>,
    state: &ProgramState,
) -> Result<(), HandlerError> {
    let path = if let Expression::Buffer(BufferExpression {
        value: b,
        type_: BufferType::Unknown,
    }) = path
    {
        PathBuf::from(OsStr::from_bytes(b))
    } else {
        return Err(HandlerError::ArgTypeMismatch {
            sc_name: name.to_owned(),
            arg: path.to_owned(),
        });
    };
    if let Some(mut path) = resolve_path(&path, relfd, state.cur_dir.as_ref()) {
        traverse_symlinks(&mut path, actions);
        actions.push(ProgramAction::Create(path));
    }
    Ok(())
}

/// Handle mknod-like syscalls
fn handle_mknod(
    name: &str,
    mode: &Expression,
    actions: &mut Vec<ProgramAction>,
) -> Result<(), HandlerError> {
    const PRIVILEGED_ST_MODES: [&str; 2] = ["S_IFBLK", "S_IFCHR"];
    let Expression::Integer(mode) = mode else {
        return Err(HandlerError::ArgTypeMismatch {
            sc_name: name.to_owned(),
            arg: mode.to_owned(),
        });
    };
    if PRIVILEGED_ST_MODES
        .iter()
        .any(|pm| mode.value.is_flag_set(pm))
    {
        actions.push(ProgramAction::MknodSpecial);
    }
    Ok(())
}

/// Handle mmap-like syscalls
fn handle_mmap(
    name: &str,
    prot: &Expression,
    fd: Option<&Expression>,
    actions: &mut Vec<ProgramAction>,
) -> Result<(), HandlerError> {
    let Expression::Integer(IntegerExpression {
        value: prot_val, ..
    }) = prot
    else {
        return Err(HandlerError::ArgTypeMismatch {
            sc_name: name.to_owned(),
            arg: prot.to_owned(),
        });
    };
    let path = fd
        .and_then(|e| e.metadata())
        .map(|m| PathBuf::from(OsStr::from_bytes(m)));
    if prot_val.is_flag_set("PROT_EXEC") {
        if let Some(mut path) = path {
            traverse_symlinks(&mut path, actions);
            actions.push(ProgramAction::Exec(path));
        }
        if prot_val.is_flag_set("PROT_WRITE") {
            actions.push(ProgramAction::WriteExecuteMemoryMapping);
        }
    }
    Ok(())
}

/// Handle mount
fn handle_mount(
    name: &str,
    flags: &Expression,
    actions: &mut Vec<ProgramAction>,
) -> Result<(), HandlerError> {
    let Expression::Integer(IntegerExpression {
        value: mount_flags, ..
    }) = flags
    else {
        return Err(HandlerError::ArgTypeMismatch {
            sc_name: name.to_owned(),
            arg: flags.to_owned(),
        });
    };
    if mount_flags.is_flag_set("MS_SHARED") {
        actions.push(ProgramAction::MountToHost);
    }
    Ok(())
}

/// Handle network syscalls
fn handle_network(
    name: &str,
    pid: u32,
    fd: &Expression,
    sockaddr: &Expression,
    actions: &mut Vec<ProgramAction>,
    state: &mut ProgramState,
) -> Result<(), HandlerError> {
    let (af_str, addr_struct) = if let Expression::Struct(members) = sockaddr {
        let Some(Expression::Integer(IntegerExpression {
            value: IntegerExpressionValue::NamedConst(af),
            ..
        })) = members.get("sa_family")
        else {
            return Err(HandlerError::MissingStructMember {
                member: "sa_family",
                struct_: members.to_owned(),
            });
        };
        (af.as_str(), members)
    } else {
        // Can be NULL in some cases, ie AF_NETLINK sockets
        return Ok(());
    };
    #[expect(clippy::single_match)]
    match af_str {
        "AF_UNIX" => {
            if let Some(path) = socket_address_uds_path(addr_struct, state.cur_dir.as_ref()) {
                actions.push(ProgramAction::Read(path));
            }
        }
        _ => (),
    }
    let af = af_str.parse().map_err(|()| HandlerError::ParsingFailed {
        src: af_str.to_owned(),
        type_: type_name::<SocketFamily>(),
    })?;

    let Expression::Integer(IntegerExpression {
        value: IntegerExpressionValue::Literal(fd_val),
        ..
    }) = fd
    else {
        return Err(HandlerError::ArgTypeMismatch {
            sc_name: name.to_owned(),
            arg: fd.to_owned(),
        });
    };

    let ip_addr = match addr_struct
        .iter()
        .find_map(|(k, v)| ["sin_addr", "sin6_addr"].contains(&k.as_str()).then_some(v))
    {
        Some(Expression::Integer(IntegerExpression {
            value:
                IntegerExpressionValue::Macro {
                    name: macro_name,
                    args,
                },
            ..
        })) if macro_name == "inet_addr" => match args.first() {
            Some(Expression::Buffer(BufferExpression { value, .. })) => {
                let ip_str = str::from_utf8(value).map_err(|_| HandlerError::ConversionFailed {
                    src: format!("{value:?}"),
                    type_src: type_name_of_val(value),
                    type_dst: type_name::<&str>(),
                })?;
                let ip = ip_str
                    .parse::<IpAddr>()
                    .map_err(|_| HandlerError::ConversionFailed {
                        src: ip_str.to_owned(),
                        type_src: type_name_of_val(ip_str),
                        type_dst: type_name::<IpAddr>(),
                    })?;
                SetSpecifier::One(ip.into())
            }
            _ => unreachable!(),
        },
        Some(Expression::Integer(IntegerExpression {
            value:
                IntegerExpressionValue::Macro {
                    name: macro_name,
                    args,
                },
            ..
        })) if macro_name == "inet_pton" => match args.get(1) {
            Some(Expression::Buffer(BufferExpression { value, .. })) => {
                let ip_str = str::from_utf8(value).map_err(|_| HandlerError::ConversionFailed {
                    src: format!("{value:?}"),
                    type_src: type_name_of_val(value),
                    type_dst: type_name::<&str>(),
                })?;
                let ip = ip_str
                    .parse::<IpAddr>()
                    .map_err(|_| HandlerError::ConversionFailed {
                        src: ip_str.to_owned(),
                        type_src: type_name_of_val(ip_str),
                        type_dst: type_name::<IpAddr>(),
                    })?;
                SetSpecifier::One(ip.into())
            }
            _ => unreachable!(),
        },
        _ => SetSpecifier::None,
    };

    let local_port = if name == "bind" {
        match addr_struct
            .iter()
            .find_map(|(k, v)| k.ends_with("_port").then_some(v))
        {
            Some(Expression::Integer(IntegerExpression {
                value:
                    IntegerExpressionValue::Macro {
                        name: macro_name,
                        args,
                    },
                ..
            })) if macro_name == "htons" => match args.first() {
                Some(Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::Literal(port_val),
                    ..
                })) => {
                    if *port_val == 0 {
                        // 0 means bind random port, we don't know which one, but this is not
                        // denied by SocketBindDeny
                        SetSpecifier::None
                    } else {
                        SetSpecifier::One(NetworkPort(
                            TryInto::<u16>::try_into(*port_val)
                                .ok()
                                .and_then(|i| i.try_into().ok())
                                .ok_or_else(|| HandlerError::ConversionFailed {
                                    src: port_val.to_string(),
                                    type_src: type_name_of_val(port_val),
                                    type_dst: type_name::<NetworkPort>(),
                                })?,
                        ))
                    }
                }
                _ => unreachable!(),
            },
            _ => SetSpecifier::None,
        }
    } else {
        SetSpecifier::All
    };

    if let Some(proto) = state.known_sockets_proto.get(&(
        pid,
        TryInto::<RawFd>::try_into(*fd_val).map_err(|_| HandlerError::ConversionFailed {
            src: fd_val.to_string(),
            type_src: type_name_of_val(fd_val),
            type_dst: type_name::<RawFd>(),
        })?,
    )) {
        actions.push(ProgramAction::NetworkActivity(
            NetworkActivity {
                af: SetSpecifier::One(af),
                proto: SetSpecifier::One(proto.to_owned()),
                kind: SetSpecifier::One(NetworkActivityKind::from_sc_name(name)),
                local_port,
                address: ip_addr,
            }
            .into(),
        ));
    }

    Ok(())
}

/// Handle open-like syscalls
fn handle_open(
    name: &str,
    relfd: Option<&Expression>,
    path: &Expression,
    flags: &Expression,
    ret_val: &IntegerExpression,
    actions: &mut Vec<ProgramAction>,
    state: &ProgramState,
) -> Result<(), HandlerError> {
    let mut path = if let Expression::Buffer(BufferExpression {
        value: b,
        type_: BufferType::Unknown,
    }) = path
    {
        PathBuf::from(OsStr::from_bytes(b))
    } else {
        return Err(HandlerError::ArgTypeMismatch {
            sc_name: name.to_owned(),
            arg: path.to_owned(),
        });
    };
    let Expression::Integer(IntegerExpression {
        value: flags_val, ..
    }) = flags
    else {
        return Err(HandlerError::ArgTypeMismatch {
            sc_name: name.to_owned(),
            arg: flags.to_owned(),
        });
    };

    path = if let Some(path) = resolve_path(&path, relfd, state.cur_dir.as_ref()) {
        path
    } else {
        return Ok(());
    };

    // Add actions for traversed symlinks
    traverse_symlinks(&mut path, actions);

    // Returned fd has normalized path, use it if we can
    let ret_path = ret_val
        .metadata
        .as_ref()
        .map(|b| PathBuf::from(OsStr::from_bytes(b)));
    path = ret_path.unwrap_or(path);

    if !is_pseudo_path(&path) {
        // Set actions from flags
        if flags_val.is_flag_set("O_CREAT") {
            actions.push(ProgramAction::Create(path.clone()));
        }
        if (flags_val.is_flag_set("O_WRONLY")
        || flags_val.is_flag_set("O_RDWR")
        || flags_val.is_flag_set("O_TRUNC"))
        // char devices can be written to, even if filesystem is mounted read only
        && !path.metadata().ok().is_some_and(|m| m.file_type().is_char_device())
        {
            actions.push(ProgramAction::Write(path.clone()));
        }
        if flags_val.is_flag_set("O_RDONLY") || !flags_val.is_flag_set("O_WRONLY") {
            assert!(!path.to_str().is_some_and(|p| p.starts_with("net:")));
            actions.push(ProgramAction::Read(path.clone()));
        }
    }

    Ok(())
}

/// Handle rename-like syscalls
#[expect(clippy::too_many_arguments)]
fn handle_rename(
    name: &str,
    relfd_src: Option<&Expression>,
    path_src: &Expression,
    relfd_dst: Option<&Expression>,
    path_dst: &Expression,
    flags: Option<&Expression>,
    actions: &mut Vec<ProgramAction>,
    state: &ProgramState,
) -> Result<(), HandlerError> {
    let path_src = if let Expression::Buffer(BufferExpression {
        value: b1,
        type_: BufferType::Unknown,
    }) = path_src
    {
        PathBuf::from(OsStr::from_bytes(b1))
    } else {
        return Err(HandlerError::ArgTypeMismatch {
            sc_name: name.to_owned(),
            arg: path_src.to_owned(),
        });
    };
    let path_dst = if let Expression::Buffer(BufferExpression {
        value: b2,
        type_: BufferType::Unknown,
    }) = path_dst
    {
        PathBuf::from(OsStr::from_bytes(b2))
    } else {
        return Err(HandlerError::ArgTypeMismatch {
            sc_name: name.to_owned(),
            arg: path_dst.to_owned(),
        });
    };

    let (Some(mut path_src), Some(mut path_dst)) = (
        resolve_path(&path_src, relfd_src, state.cur_dir.as_ref()),
        resolve_path(&path_dst, relfd_dst, state.cur_dir.as_ref()),
    ) else {
        return Ok(());
    };

    let exchange = match flags {
        Some(Expression::Integer(IntegerExpression { value, .. })) => {
            value.is_flag_set("RENAME_EXCHANGE")
        }
        Some(other) => {
            return Err(HandlerError::ArgTypeMismatch {
                sc_name: name.to_owned(),
                arg: other.to_owned(),
            });
        }
        None => false,
    };

    traverse_symlinks(&mut path_src, actions);
    traverse_symlinks(&mut path_dst, actions);
    actions.push(ProgramAction::Read(path_src.clone()));
    actions.push(ProgramAction::Write(path_src.clone()));
    if exchange {
        actions.push(ProgramAction::Read(path_dst.clone()));
    } else {
        actions.push(ProgramAction::Create(path_dst.clone()));
    }
    actions.push(ProgramAction::Write(path_dst.clone()));
    Ok(())
}

/// Handle `sched_setscheduler` syscall
fn handle_setscheduler(
    name: &str,
    policy: &Expression,
    actions: &mut Vec<ProgramAction>,
) -> Result<(), HandlerError> {
    const RT_SCHEDULERS: [&str; 2] = ["SCHED_FIFO", "SCHED_RR"];
    let Expression::Integer(IntegerExpression {
        value: policy_val, ..
    }) = policy
    else {
        return Err(HandlerError::ArgTypeMismatch {
            sc_name: name.to_owned(),
            arg: policy.to_owned(),
        });
    };
    if RT_SCHEDULERS.iter().any(|s| policy_val.is_flag_set(s)) {
        actions.push(ProgramAction::SetRealtimeScheduler);
    }
    Ok(())
}

/// Handle socket syscall
fn handle_socket(
    name: &str,
    pid: u32,
    ret_val: &IntegerExpression,
    af: &Expression,
    flags: &Expression,
    actions: &mut Vec<ProgramAction>,
    state: &mut ProgramState,
) -> Result<(), HandlerError> {
    let af = if let Expression::Integer(IntegerExpression {
        value: IntegerExpressionValue::NamedConst(af_name),
        ..
    }) = af
    {
        af_name.parse().map_err(|()| HandlerError::ParsingFailed {
            src: af_name.to_owned(),
            type_: type_name::<SocketFamily>(),
        })?
    } else {
        return Err(HandlerError::ArgTypeMismatch {
            sc_name: name.to_owned(),
            arg: af.to_owned(),
        });
    };

    let flags = if let Expression::Integer(IntegerExpression { value, .. }) = flags {
        value.flags()
    } else {
        return Err(HandlerError::ArgTypeMismatch {
            sc_name: name.to_owned(),
            arg: flags.to_owned(),
        });
    };
    let proto_flag = flags
        .iter()
        .find(|f| f.starts_with("SOCK_"))
        .ok_or_else(|| HandlerError::ParsingFailed {
            src: format!("{flags:?}"),
            type_: type_name::<SocketProtocol>(),
        })?;
    let proto = proto_flag
        .parse::<SocketProtocol>()
        .map_err(|_e| HandlerError::ParsingFailed {
            src: proto_flag.to_owned(),
            type_: type_name::<SocketProtocol>(),
        })?;
    let ret_fd = ret_val.value().ok_or_else(|| HandlerError::ParsingFailed {
        src: format!("{ret_val:?}"),
        type_: type_name::<i128>(),
    })?;

    state.known_sockets_proto.insert(
        (
            pid,
            TryInto::<RawFd>::try_into(ret_fd).map_err(|_| HandlerError::ConversionFailed {
                src: ret_fd.to_string(),
                type_src: type_name_of_val(&ret_val),
                type_dst: type_name::<RawFd>(),
            })?,
        ),
        proto.clone(),
    );

    actions.push(ProgramAction::NetworkActivity(
        NetworkActivity {
            af: SetSpecifier::One(af),
            proto: SetSpecifier::One(proto),
            kind: SetSpecifier::One(NetworkActivityKind::SocketCreation),
            local_port: SetSpecifier::All,
            address: SetSpecifier::All,
        }
        .into(),
    ));
    Ok(())
}

/// Handle stat-like syscalls operating on file descriptors
fn handle_stat_fd(
    name: &str,
    fd: &Expression,
    actions: &mut Vec<ProgramAction>,
    state: &ProgramState,
) -> Result<(), HandlerError> {
    let path = fd
        .metadata()
        .map(|m| PathBuf::from(OsStr::from_bytes(m)))
        .ok_or_else(|| HandlerError::ArgTypeMismatch {
            sc_name: name.to_owned(),
            arg: fd.to_owned(),
        })?;
    if let Some(mut path) = resolve_path(&path, None, state.cur_dir.as_ref()) {
        traverse_symlinks(&mut path, actions);
        actions.push(ProgramAction::Read(path));
    }
    Ok(())
}

/// Handle stat-like syscalls operating on a path possibly relative to a file descriptor
fn handle_stat_path(
    name: &str,
    relfd: Option<&Expression>,
    path: &Expression,
    actions: &mut Vec<ProgramAction>,
    state: &ProgramState,
) -> Result<(), HandlerError> {
    let path = if let Expression::Buffer(BufferExpression {
        value: b,
        type_: BufferType::Unknown,
    }) = path
    {
        PathBuf::from(OsStr::from_bytes(b))
    } else {
        return Err(HandlerError::ArgTypeMismatch {
            sc_name: name.to_owned(),
            arg: path.to_owned(),
        });
    };
    if let Some(mut path) = resolve_path(&path, relfd, state.cur_dir.as_ref()) {
        traverse_symlinks(&mut path, actions);
        actions.push(ProgramAction::Read(path));
    }
    Ok(())
}

/// Handle `timer_create` syscall
fn handle_timer_create(
    name: &str,
    clockid: &Expression,
    actions: &mut Vec<ProgramAction>,
) -> Result<(), HandlerError> {
    const PRIVILEGED_CLOCK_NAMES: [&str; 2] = ["CLOCK_REALTIME_ALARM", "CLOCK_BOOTTIME_ALARM"];
    let Expression::Integer(IntegerExpression {
        value: IntegerExpressionValue::NamedConst(clock_name),
        ..
    }) = clockid
    else {
        return Err(HandlerError::ArgTypeMismatch {
            sc_name: name.to_owned(),
            arg: clockid.to_owned(),
        });
    };
    if PRIVILEGED_CLOCK_NAMES.contains(&clock_name.as_str()) {
        actions.push(ProgramAction::SetAlarm);
    }
    Ok(())
}

/// Extract path for socket address structure if it's a non abstract one
fn socket_address_uds_path(
    members: &HashMap<String, Expression>,
    cur_dir: Option<&PathBuf>,
) -> Option<PathBuf> {
    if let Some(Expression::Buffer(BufferExpression {
        value: b,
        type_: BufferType::Unknown,
    })) = members.get("sun_path")
    {
        resolve_path(&PathBuf::from(OsStr::from_bytes(b)), None, cur_dir)
    } else {
        None
    }
}

/// Resolve relative path if possible, and normalize it
/// Does not access filesystem to resolve symlinks
fn resolve_path(
    path: &Path,
    relfd: Option<&Expression>,
    cur_dir: Option<&PathBuf>,
) -> Option<PathBuf> {
    let path = if path.is_relative() {
        let metadata = relfd.and_then(|a| a.metadata());
        if let Some(metadata) = metadata {
            if is_fd_pseudo_path(metadata) {
                return None;
            }
            let rel_path = PathBuf::from(OsStr::from_bytes(metadata));
            rel_path.join(path)
        } else if let Some(cur_dir) = cur_dir {
            cur_dir.join(path)
        } else {
            return None;
        }
    } else {
        path.to_path_buf()
    };
    Some(path.clean())
}

/// Add actions for traversed symlinks, set symlink target of current path if it is one
fn traverse_symlinks(in_path: &mut PathBuf, actions: &mut Vec<ProgramAction>) {
    actions.extend(
        path_symlinks(in_path)
            .unwrap_or_default()
            .into_iter()
            .map(ProgramAction::Read),
    );
}

/// Get all symlinks paths that need to be followed to access a path
fn path_symlinks(in_path: &mut PathBuf) -> io::Result<Vec<PathBuf>> {
    /// Max number of links to follow before giving up (likely a loop)
    const MAX_LINK_COUNT: usize = 10;

    debug_assert!(in_path.is_absolute());
    let mut links = Vec::new();

    let mut cur_level_path: Option<PathBuf> = None;
    for component in in_path.components() {
        let mut cur_path = if let Some(cur_level_path) = &cur_level_path {
            cur_level_path.join(component).clean()
        } else {
            PathBuf::from(&component)
        };
        let mut link_count = 0;
        while let Ok(mut link_target) = cur_path.read_link() {
            if link_count > MAX_LINK_COUNT {
                // TODO use ErrorKind::FilesystemLoop when stabilized
                return Err(io::Error::other("Too many symlinks"));
            }
            links.push(cur_path.clone());

            if is_pseudo_path(&link_target) {
                // Pseudo file, ie /proc/[PID]/ns/net
                return Ok(links);
            }
            #[expect(clippy::unwrap_used)]
            if link_target.is_relative() {
                link_target = cur_path
                    .parent()
                    .or(cur_level_path.as_deref())
                    .unwrap()
                    .join(link_target);
            }

            cur_path = link_target.clean();
            link_count += 1;
        }
        cur_level_path = Some(cur_path);
    }

    if let Some(cur_level_path) = cur_level_path {
        *in_path = cur_level_path;
    }

    Ok(links)
}

fn is_fd_pseudo_path(path: &[u8]) -> bool {
    #[expect(clippy::unwrap_used)]
    static FD_PSEUDO_PATH_REGEX_BYTES: LazyLock<regex::bytes::Regex> =
        LazyLock::new(|| regex::bytes::Regex::new(r"^[a-z]+:\[[0-9a-z]+\]/?$").unwrap());
    FD_PSEUDO_PATH_REGEX_BYTES.is_match(path)
}

fn is_pseudo_path(path: &Path) -> bool {
    #[expect(clippy::unwrap_used)]
    static FD_PSEUDO_PATH_REGEX_STR: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"^[a-z]+:\[[0-9a-z]+\]/?$").unwrap());
    path.to_str()
        .is_some_and(|p| FD_PSEUDO_PATH_REGEX_STR.is_match(p))
}

/// Parse ELF and return interpreter path if we can
fn read_elf_interpreter(path: &Path) -> Option<PathBuf> {
    // TODO Find a way to parse opnly the first few pages
    let buf = fs::read(path).ok()?;
    let elf = elf::Elf::parse(&buf).ok()?;
    elf.interpreter.map(PathBuf::from)
}

/// Parse shebang and return interpreter path if we can
fn read_shebang_interpreter(path: &Path) -> Option<PathBuf> {
    let mut file = BufReader::new(File::open(path).ok()?);
    let mut line = String::new();
    file.read_line(&mut line).ok()?;
    line.strip_prefix("#!")
        .and_then(shlex::split)
        .and_then(|a| a.first().cloned())
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, File},
        os::unix,
    };

    use super::*;

    #[test]
    fn test_is_socket_or_pipe_pseudo_path() {
        assert!(!is_fd_pseudo_path("plop".as_bytes()));
        assert!(is_fd_pseudo_path("pipe:[12334]".as_bytes()));
        assert!(is_fd_pseudo_path("socket:[1234]/".as_bytes()));
    }

    #[test]
    fn test_path_symlinks_lib() {
        let tmp_dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp_dir.path().join("usr/lib/x86_64-linux-gnu")).unwrap();
        unix::fs::symlink(tmp_dir.path().join("usr/lib"), tmp_dir.path().join("lib")).unwrap();
        File::create(
            tmp_dir
                .path()
                .join("usr/lib/x86_64-linux-gnu/libselinux.so.1"),
        )
        .unwrap();
        unix::fs::symlink(
            tmp_dir
                .path()
                .join("usr/lib/x86_64-linux-gnu/libselinux.so.1"),
            tmp_dir
                .path()
                .join("usr/lib/x86_64-linux-gnu/libselinux.so"),
        )
        .unwrap();

        let mut in_path = tmp_dir.path().join("lib/x86_64-linux-gnu/libselinux.so");
        assert_eq!(
            path_symlinks(&mut in_path).unwrap(),
            vec![
                tmp_dir.path().join("lib"),
                tmp_dir
                    .path()
                    .join("usr/lib/x86_64-linux-gnu/libselinux.so")
            ]
        );
        assert_eq!(
            in_path,
            tmp_dir
                .path()
                .join("usr/lib/x86_64-linux-gnu/libselinux.so.1")
        );
    }

    #[test]
    fn test_path_symlinks_parent() {
        let tmp_dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp_dir.path().join("a/b")).unwrap();
        fs::create_dir_all(tmp_dir.path().join("d/e")).unwrap();
        unix::fs::symlink(
            tmp_dir.path().join("a/b/c/../.."),
            tmp_dir.path().join("a/b/c"),
        )
        .unwrap();

        let mut in_path = tmp_dir.path().join("a/b/c/e");
        assert_eq!(
            path_symlinks(&mut in_path).unwrap(),
            vec![tmp_dir.path().join("a/b/c"),]
        );
        assert_eq!(in_path, tmp_dir.path().join("a/e"));
    }
}
