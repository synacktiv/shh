//! Syscall handlers, producing summary

use std::{
    any::{type_name, type_name_of_val},
    borrow::ToOwned,
    collections::HashMap,
    ffi::OsStr,
    fs::{self, File},
    io::{self, BufRead as _, BufReader, Read},
    net::IpAddr,
    os::{
        fd::RawFd,
        unix::{ffi::OsStrExt as _, fs::FileTypeExt as _},
    },
    path::{Path, PathBuf},
    str,
    sync::LazyLock,
};

use anyhow::Context as _;
use goblin::elf;
use itertools::Itertools as _;
use nix::libc::{pid_t, uid_t};
use path_clean::PathClean as _;

use super::{
    FdOrPath, NetworkActivity, NetworkActivityKind, NetworkAddress, NetworkPort, ProgramAction,
    ProgramState, SetSpecifier,
};
use crate::{
    strace::{
        BufferExpression, BufferType, Expression, IntegerExpression, IntegerExpressionValue,
        Syscall, SyscallName,
    },
    systemd::{SocketFamily, SocketProtocol},
};

#[derive(thiserror::Error, Debug)]
pub(crate) enum HandlerError {
    #[error("Unexpected {sc_name:?} argument type: {arg:?}")]
    ArgTypeMismatch {
        sc_name: SyscallName,
        arg: Expression,
    },
    #[error("Missing argument at index {index} for syscall {sc_name:?}")]
    ArgIndexOutOfBounds { sc_name: SyscallName, index: usize },
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

/// Trait for handling a syscall and producing summary actions
pub(crate) trait SyscallHandler: Send + Sync {
    /// Handle a syscall and append resulting actions
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        state: &mut ProgramState,
    ) -> Result<(), HandlerError>;
}

/// Trait for extracting a syscall argument from an index
trait ExtractArg {
    type Output<'a>;

    fn extract<'a>(&self, sc: &'a Syscall) -> Result<Self::Output<'a>, HandlerError>;
}

impl ExtractArg for usize {
    type Output<'a> = &'a Expression;

    fn extract<'a>(&self, sc: &'a Syscall) -> Result<&'a Expression, HandlerError> {
        sc.args
            .get(*self)
            .ok_or_else(|| HandlerError::ArgIndexOutOfBounds {
                sc_name: sc.name.clone(),
                index: *self,
            })
    }
}

impl ExtractArg for Option<usize> {
    type Output<'a> = Option<&'a Expression>;

    fn extract<'a>(&self, sc: &'a Syscall) -> Result<Option<&'a Expression>, HandlerError> {
        self.map(|i| i.extract(sc)).transpose()
    }
}

impl ExtractArg for FdOrPath<usize> {
    type Output<'a> = FdOrPath<&'a Expression>;

    fn extract<'a>(&self, sc: &'a Syscall) -> Result<FdOrPath<&'a Expression>, HandlerError> {
        match self {
            FdOrPath::Fd(i) => Ok(FdOrPath::Fd(i.extract(sc)?)),
            FdOrPath::Path(i) => Ok(FdOrPath::Path(i.extract(sc)?)),
        }
    }
}

impl FdOrPath<&Expression> {
    /// Resolve an fd-or-path reference to an optional absolute path
    fn resolve(
        self,
        sc_name: &SyscallName,
        cur_dir: &Path,
    ) -> Result<Option<PathBuf>, HandlerError> {
        match self {
            FdOrPath::Fd(fd) => Ok(resolve_path(Path::new(""), Some(fd), cur_dir)),
            FdOrPath::Path(Expression::Buffer(BufferExpression {
                value: b,
                type_: BufferType::Unknown,
            })) => {
                let p = Path::new(OsStr::from_bytes(b));
                Ok(resolve_path(p, None, cur_dir))
            }
            FdOrPath::Path(e) => Err(HandlerError::ArgTypeMismatch {
                sc_name: sc_name.to_owned(),
                arg: e.to_owned(),
            }),
        }
    }
}

/// Handle chdir-like syscalls
pub(crate) struct ChdirHandler {
    pub path: FdOrPath<usize>,
}

impl SyscallHandler for ChdirHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        let dir = self
            .path
            .extract(sc)?
            .resolve(&sc.name, state.cur_dir.as_ref())?;
        if let Some(mut dir) = dir {
            traverse_symlinks(&mut dir, actions);
            debug_assert!(dir.is_absolute());
            state.cur_dir = dir;
        }
        Ok(())
    }
}

/// Handle `epoll_ctl` syscall
pub(crate) struct EpollCtlHandler {
    pub op: usize,
    pub event: usize,
}

impl SyscallHandler for EpollCtlHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        _state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        let op = self.op.extract(sc)?;
        let event = self.event.extract(sc)?;

        let Expression::Integer(IntegerExpression {
            value: IntegerExpressionValue::NamedSymbol(op_name),
            ..
        }) = op
        else {
            return Err(HandlerError::ArgTypeMismatch {
                sc_name: sc.name.clone(),
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
                        sc_name: sc.name.clone(),
                        arg: evt_member.to_owned(),
                    });
                }
            } else {
                return Err(HandlerError::ArgTypeMismatch {
                    sc_name: sc.name.clone(),
                    arg: event.to_owned(),
                });
            };
            if evt_flags.value.is_flag_set("EPOLLWAKEUP") {
                actions.push(ProgramAction::Wakeup);
            }
        }
        Ok(())
    }
}

/// Handle exec-like syscalls
pub(crate) struct ExecHandler {
    pub relfd: Option<usize>,
    pub path: usize,
}

impl SyscallHandler for ExecHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        let relfd = self.relfd.extract(sc)?;
        let path_expr = self.path.extract(sc)?;

        let path = if let Expression::Buffer(BufferExpression {
            value: b,
            type_: BufferType::Unknown,
        }) = path_expr
        {
            PathBuf::from(OsStr::from_bytes(b))
        } else {
            return Err(HandlerError::ArgTypeMismatch {
                sc_name: sc.name.clone(),
                arg: path_expr.to_owned(),
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
}

/// Handle kill syscall
pub(crate) struct KillHandler {
    pub pid: usize,
    pub sig: usize,
}

impl SyscallHandler for KillHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        _state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        let pid = self.pid.extract(sc)?;
        let sig = self.sig.extract(sc)?;

        let pid_val = match pid {
            Expression::Integer(IntegerExpression {
                value: IntegerExpressionValue::Literal(pid_val),
                ..
            }) => pid_t::try_from(*pid_val).map_err(|_| HandlerError::ConversionFailed {
                src: format!("{pid_val:?}"),
                type_src: type_name_of_val(pid_val),
                type_dst: type_name::<pid_t>(),
            })?,
            _ => {
                return Err(HandlerError::ArgTypeMismatch {
                    sc_name: sc.name.clone(),
                    arg: pid.to_owned(),
                });
            }
        };
        let sig_name = match sig {
            Expression::Integer(IntegerExpression {
                value: IntegerExpressionValue::NamedSymbol(sig_name),
                ..
            }) => Some(sig_name),
            Expression::Integer(IntegerExpression {
                value: IntegerExpressionValue::Literal(0),
                ..
            }) => None,
            _ => {
                return Err(HandlerError::ArgTypeMismatch {
                    sc_name: sc.name.clone(),
                    arg: pid.to_owned(),
                });
            }
        };
        // https://man7.org/linux/man-pages/man2/kill.2.html
        if pid_val > 0 {
            if sig_name.is_some_and(|s| s == "SIGCONT")
                && (nix::unistd::getsid(Some(nix::unistd::Pid::from_raw(pid_val)))
                    .and_then(|s| {
                        nix::unistd::getsid(Some(nix::unistd::Pid::from_raw(sc.pid)))
                            .map(|cs| s == cs)
                    })
                    .unwrap_or_default())
            {
                return Ok(());
            }
            // Note: for signals that stop the target process, most of the time we will
            // fail to parse target UIDs here because it is already dead,
            // which will lead to "under" hardening
            if process_uids(pid_val)
                .and_then(|u| {
                    process_uids(sc.pid).map(|cu| {
                        (cu.real == u.real)
                            || (cu.real == u.saved)
                            || (cu.effective == u.real)
                            || (cu.effective == u.saved)
                    })
                })
                .unwrap_or_default()
            {
                return Ok(());
            }
        }
        actions.push(ProgramAction::KillOther);
        Ok(())
    }
}

/// Handle `memfd_create` syscall
pub(crate) struct MemfdCreateHandler {
    pub flags: usize,
}

impl SyscallHandler for MemfdCreateHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        _state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        let flags = self.flags.extract(sc)?;

        let Expression::Integer(IntegerExpression { value: flags, .. }) = flags else {
            return Err(HandlerError::ArgTypeMismatch {
                sc_name: sc.name.clone(),
                arg: flags.to_owned(),
            });
        };
        if flags.is_flag_set("MFD_HUGETLB") {
            actions.push(ProgramAction::HugePageMemoryMapping);
        }
        Ok(())
    }
}

/// Handle mkdir-like syscalls
pub(crate) struct MkdirHandler {
    pub relfd: Option<usize>,
    pub path: usize,
}

impl SyscallHandler for MkdirHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        let relfd = self.relfd.extract(sc)?;
        let path = self.path.extract(sc)?;

        let path = if let Expression::Buffer(BufferExpression {
            value: b,
            type_: BufferType::Unknown,
        }) = path
        {
            PathBuf::from(OsStr::from_bytes(b))
        } else {
            return Err(HandlerError::ArgTypeMismatch {
                sc_name: sc.name.clone(),
                arg: path.to_owned(),
            });
        };
        if let Some(mut path) = resolve_path(&path, relfd, state.cur_dir.as_ref()) {
            traverse_symlinks(&mut path, actions);
            actions.push(ProgramAction::Create(path));
        }
        Ok(())
    }
}

/// Handle mknod-like syscalls
pub(crate) struct MknodHandler {
    pub path: FdOrPath<usize>,
    pub mode: usize,
}

impl SyscallHandler for MknodHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        const PRIVILEGED_ST_MODES: [&str; 2] = ["S_IFBLK", "S_IFCHR"];
        let mode = self.mode.extract(sc)?;
        let Expression::Integer(mode) = mode else {
            return Err(HandlerError::ArgTypeMismatch {
                sc_name: sc.name.clone(),
                arg: mode.to_owned(),
            });
        };
        let path = self
            .path
            .extract(sc)?
            .resolve(&sc.name, state.cur_dir.as_ref())?;

        if PRIVILEGED_ST_MODES
            .iter()
            .any(|pm| mode.value.is_flag_set(pm))
        {
            actions.push(ProgramAction::MknodSpecial);
        }
        if let Some(path) = path {
            actions.push(ProgramAction::Create(path));
        }
        Ok(())
    }
}

/// Handle mmap-like syscalls
pub(crate) struct MmapHandler {
    pub prot: usize,
    pub flags: Option<usize>,
    pub fd: Option<usize>,
}

impl SyscallHandler for MmapHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        _state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        let prot = self.prot.extract(sc)?;
        let flags = self.flags.extract(sc)?;
        let fd = self.fd.extract(sc)?;

        let Expression::Integer(IntegerExpression {
            value: prot_val, ..
        }) = prot
        else {
            return Err(HandlerError::ArgTypeMismatch {
                sc_name: sc.name.clone(),
                arg: prot.to_owned(),
            });
        };
        if let Some(flags) = flags {
            let Expression::Integer(IntegerExpression { value: flags, .. }) = flags else {
                return Err(HandlerError::ArgTypeMismatch {
                    sc_name: sc.name.clone(),
                    arg: flags.to_owned(),
                });
            };
            if flags.is_flag_set("MAP_HUGETLB") {
                actions.push(ProgramAction::HugePageMemoryMapping);
            }
            if flags.is_flag_set("MAP_LOCKED") {
                actions.push(ProgramAction::LockMemoryMapping);
            }
        }
        let path = fd
            .and_then(|e| e.metadata())
            .map(|m| PathBuf::from(OsStr::from_bytes(m)));
        if prot_val.is_flag_set("PROT_EXEC") {
            if let Some(mut path) = path {
                traverse_symlinks(&mut path, actions);
                actions.push(ProgramAction::Exec(path));
            }
            if sc.name.ends_with("mprotect") || prot_val.is_flag_set("PROT_WRITE") {
                actions.push(ProgramAction::WriteExecuteMemoryMapping);
            }
        }
        Ok(())
    }
}

/// Handle mount syscall
pub(crate) struct MountHandler {
    pub flags: usize,
}

impl SyscallHandler for MountHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        _state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        let flags = self.flags.extract(sc)?;

        let Expression::Integer(IntegerExpression {
            value: mount_flags, ..
        }) = flags
        else {
            return Err(HandlerError::ArgTypeMismatch {
                sc_name: sc.name.clone(),
                arg: flags.to_owned(),
            });
        };
        if mount_flags.is_flag_set("MS_SHARED") {
            actions.push(ProgramAction::MountToHost);
        }
        Ok(())
    }
}

/// Handle network syscalls
pub(crate) struct NetworkHandler {
    pub fd: usize,
    pub sockaddr: usize,
}

impl SyscallHandler for NetworkHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        let fd = self.fd.extract(sc)?;
        let sockaddr = self.sockaddr.extract(sc)?;

        let (af_str, addr_struct) = if let Expression::Struct(members) = sockaddr {
            let Some(Expression::Integer(IntegerExpression {
                value: IntegerExpressionValue::NamedSymbol(af),
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
                if let Some(path) = socket_address_uds_path(addr_struct, &state.cur_dir) {
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
                sc_name: sc.name.clone(),
                arg: fd.to_owned(),
            });
        };

        let ip_addr: SetSpecifier<NetworkAddress> =
            match addr_struct
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
                        let ip_str =
                            str::from_utf8(value).map_err(|_| HandlerError::ConversionFailed {
                                src: format!("{value:?}"),
                                type_src: type_name_of_val(value),
                                type_dst: type_name::<&str>(),
                            })?;
                        let ip = ip_str.parse::<IpAddr>().map_err(|_| {
                            HandlerError::ConversionFailed {
                                src: ip_str.to_owned(),
                                type_src: type_name_of_val(ip_str),
                                type_dst: type_name::<IpAddr>(),
                            }
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
                        let ip_str =
                            str::from_utf8(value).map_err(|_| HandlerError::ConversionFailed {
                                src: format!("{value:?}"),
                                type_src: type_name_of_val(value),
                                type_dst: type_name::<&str>(),
                            })?;
                        let ip = ip_str.parse::<IpAddr>().map_err(|_| {
                            HandlerError::ConversionFailed {
                                src: ip_str.to_owned(),
                                type_src: type_name_of_val(ip_str),
                                type_dst: type_name::<IpAddr>(),
                            }
                        })?;
                        SetSpecifier::One(ip.into())
                    }
                    _ => unreachable!(),
                },
                _ => SetSpecifier::None,
            };

        let local_port = if sc.name == "bind" {
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
            sc.pid,
            TryInto::<RawFd>::try_into(*fd_val).map_err(|_| HandlerError::ConversionFailed {
                src: fd_val.to_string(),
                type_src: type_name_of_val(fd_val),
                type_dst: type_name::<RawFd>(),
            })?,
        )) {
            let kind = SetSpecifier::One(NetworkActivityKind::from_sc_name(&sc.name));

            // When binding to [::] (IPv6 unspecified), the socket is typically dual-stack
            // and also serves IPv4 traffic, so emit an IPv4 bind action too
            let is_ipv6_unspecified_bind = sc.name == "bind"
                && af == SocketFamily::Ipv6
                && matches!(&ip_addr,
                    SetSpecifier::One(addr) if addr.is_ipv6_unspecified());
            if is_ipv6_unspecified_bind {
                actions.push(ProgramAction::NetworkActivity(
                    NetworkActivity {
                        af: SetSpecifier::One(SocketFamily::Ipv4),
                        proto: SetSpecifier::One(proto.to_owned()),
                        kind: kind.clone(),
                        local_port: local_port.clone(),
                        address: ip_addr.clone(),
                    }
                    .into(),
                ));
            }

            actions.push(ProgramAction::NetworkActivity(
                NetworkActivity {
                    af: SetSpecifier::One(af),
                    proto: SetSpecifier::One(proto.to_owned()),
                    kind,
                    local_port,
                    address: ip_addr,
                }
                .into(),
            ));
        }

        Ok(())
    }
}

/// Handle open-like syscalls
pub(crate) struct OpenHandler {
    pub relfd: Option<usize>,
    pub path: usize,
    pub flags: usize,
}

impl SyscallHandler for OpenHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        let relfd = self.relfd.extract(sc)?;
        let path_expr = self.path.extract(sc)?;
        let flags = self.flags.extract(sc)?;

        let mut path = if let Expression::Buffer(BufferExpression {
            value: b,
            type_: BufferType::Unknown,
        }) = path_expr
        {
            PathBuf::from(OsStr::from_bytes(b))
        } else {
            return Err(HandlerError::ArgTypeMismatch {
                sc_name: sc.name.clone(),
                arg: path_expr.to_owned(),
            });
        };
        let Expression::Integer(IntegerExpression {
            value: flags_val, ..
        }) = flags
        else {
            return Err(HandlerError::ArgTypeMismatch {
                sc_name: sc.name.clone(),
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

        if let Some(ret_val) = &sc.ret_val
            && ret_val.value().is_some_and(|v| v != -1)
        {
            // Returned fd has normalized path, use it if we can
            let ret_path = ret_val
                .metadata
                .as_ref()
                .map(|b| PathBuf::from(OsStr::from_bytes(b)));
            path = ret_path.unwrap_or(path);
        }

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
}

/// Handle rename-like syscalls
pub(crate) struct RenameHandler {
    pub relfd_src: Option<usize>,
    pub path_src: usize,
    pub relfd_dst: Option<usize>,
    pub path_dst: usize,
    pub flags: Option<usize>,
}

impl SyscallHandler for RenameHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        let relfd_src = self.relfd_src.extract(sc)?;
        let path_src_expr = self.path_src.extract(sc)?;
        let relfd_dst = self.relfd_dst.extract(sc)?;
        let path_dst_expr = self.path_dst.extract(sc)?;
        let flags = self.flags.extract(sc)?;

        let path_src = if let Expression::Buffer(BufferExpression {
            value: b1,
            type_: BufferType::Unknown,
        }) = path_src_expr
        {
            PathBuf::from(OsStr::from_bytes(b1))
        } else {
            return Err(HandlerError::ArgTypeMismatch {
                sc_name: sc.name.clone(),
                arg: path_src_expr.to_owned(),
            });
        };
        let path_dst = if let Expression::Buffer(BufferExpression {
            value: b2,
            type_: BufferType::Unknown,
        }) = path_dst_expr
        {
            PathBuf::from(OsStr::from_bytes(b2))
        } else {
            return Err(HandlerError::ArgTypeMismatch {
                sc_name: sc.name.clone(),
                arg: path_dst_expr.to_owned(),
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
                    sc_name: sc.name.clone(),
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
}

/// Handle `sched_setscheduler` syscall
pub(crate) struct SetSchedulerHandler {
    pub policy: usize,
}

impl SyscallHandler for SetSchedulerHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        _state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        const RT_SCHEDULERS: [&str; 2] = ["SCHED_FIFO", "SCHED_RR"];
        let policy = self.policy.extract(sc)?;
        let Expression::Integer(IntegerExpression {
            value: policy_val, ..
        }) = policy
        else {
            return Err(HandlerError::ArgTypeMismatch {
                sc_name: sc.name.clone(),
                arg: policy.to_owned(),
            });
        };
        if RT_SCHEDULERS.iter().any(|s| policy_val.is_flag_set(s)) {
            actions.push(ProgramAction::SetRealtimeScheduler);
        }
        Ok(())
    }
}

/// Handle `shmctl` syscall
pub(crate) struct ShmCtlHandler {
    pub op: usize,
}

impl SyscallHandler for ShmCtlHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        _state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        let op = self.op.extract(sc)?;

        let Expression::Integer(IntegerExpression { value: op, .. }) = op else {
            return Err(HandlerError::ArgTypeMismatch {
                sc_name: sc.name.clone(),
                arg: op.to_owned(),
            });
        };
        if op.is_flag_set("SHM_LOCK") || op.is_flag_set("SHM_UNLOCK") {
            actions.push(ProgramAction::LockMemoryMapping);
        }
        Ok(())
    }
}

/// Handle socket syscall
pub(crate) struct SocketHandler {
    pub af: usize,
    pub flags: usize,
}

impl SyscallHandler for SocketHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        let af = self.af.extract(sc)?;
        let flags = self.flags.extract(sc)?;

        let af = if let Expression::Integer(IntegerExpression {
            value: IntegerExpressionValue::NamedSymbol(af_name),
            ..
        }) = af
        {
            af_name.parse().map_err(|()| HandlerError::ParsingFailed {
                src: af_name.to_owned(),
                type_: type_name::<SocketFamily>(),
            })?
        } else {
            return Err(HandlerError::ArgTypeMismatch {
                sc_name: sc.name.clone(),
                arg: af.to_owned(),
            });
        };

        let flags = if let Expression::Integer(IntegerExpression { value, .. }) = flags {
            value.flags()
        } else {
            return Err(HandlerError::ArgTypeMismatch {
                sc_name: sc.name.clone(),
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
        let proto =
            proto_flag
                .parse::<SocketProtocol>()
                .map_err(|_e| HandlerError::ParsingFailed {
                    src: proto_flag.to_owned(),
                    type_: type_name::<SocketProtocol>(),
                })?;
        let Some(ret_val) = &sc.ret_val else {
            return Ok(());
        };
        let ret_fd = ret_val.value().ok_or_else(|| HandlerError::ParsingFailed {
            src: format!("{:?}", sc.ret_val),
            type_: type_name::<i64>(),
        })?;

        if ret_fd != -1 {
            state.known_sockets_proto.insert(
                (
                    sc.pid,
                    TryInto::<RawFd>::try_into(ret_fd).map_err(|_| {
                        HandlerError::ConversionFailed {
                            src: ret_fd.to_string(),
                            type_src: type_name_of_val(&sc.ret_val),
                            type_dst: type_name::<RawFd>(),
                        }
                    })?,
                ),
                proto.clone(),
            );
        }

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
}

/// Handle stat-like syscalls operating on file descriptors
pub(crate) struct StatFdHandler {
    pub fd: usize,
}

impl SyscallHandler for StatFdHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        let fd = self.fd.extract(sc)?;

        let Some(path) = fd.metadata().map(|m| PathBuf::from(OsStr::from_bytes(m))) else {
            return Ok(());
        };
        if let Some(mut path) = resolve_path(&path, None, state.cur_dir.as_ref()) {
            traverse_symlinks(&mut path, actions);
            actions.push(ProgramAction::Read(path));
        }
        Ok(())
    }
}

/// Handle stat-like syscalls operating on a path possibly relative to a file descriptor
pub(crate) struct StatPathHandler {
    pub relfd: Option<usize>,
    pub path: usize,
}

impl SyscallHandler for StatPathHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        let relfd = self.relfd.extract(sc)?;
        let path = self.path.extract(sc)?;

        let path = if let Expression::Buffer(BufferExpression {
            value: b,
            type_: BufferType::Unknown,
        }) = path
        {
            PathBuf::from(OsStr::from_bytes(b))
        } else {
            return Err(HandlerError::ArgTypeMismatch {
                sc_name: sc.name.clone(),
                arg: path.to_owned(),
            });
        };
        if let Some(mut path) = resolve_path(&path, relfd, state.cur_dir.as_ref()) {
            traverse_symlinks(&mut path, actions);
            actions.push(ProgramAction::Read(path));
        }
        Ok(())
    }
}

/// Handle `timer_create` syscall
pub(crate) struct TimerCreateHandler {
    pub clockid: usize,
}

impl SyscallHandler for TimerCreateHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        _state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        const PRIVILEGED_CLOCK_NAMES: [&str; 2] = ["CLOCK_REALTIME_ALARM", "CLOCK_BOOTTIME_ALARM"];
        let clockid = self.clockid.extract(sc)?;
        let Expression::Integer(IntegerExpression {
            value: IntegerExpressionValue::NamedSymbol(clock_name),
            ..
        }) = clockid
        else {
            return Err(HandlerError::ArgTypeMismatch {
                sc_name: sc.name.clone(),
                arg: clockid.to_owned(),
            });
        };
        if PRIVILEGED_CLOCK_NAMES.contains(&clock_name.as_str()) {
            actions.push(ProgramAction::SetAlarm);
        }
        Ok(())
    }
}

/// Extract path for socket address structure if it's a non abstract one
fn socket_address_uds_path(
    members: &HashMap<String, Expression>,
    cur_dir: &Path,
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
fn resolve_path(path: &Path, relfd: Option<&Expression>, cur_dir: &Path) -> Option<PathBuf> {
    if is_pseudo_path(path) {
        return None;
    }
    let path = if path.is_relative() {
        let metadata = relfd.and_then(|a| a.metadata());
        if let Some(metadata) = metadata {
            if is_fd_pseudo_path(metadata) {
                return None;
            }
            let rel_path = PathBuf::from(OsStr::from_bytes(metadata));
            rel_path.join(path)
        } else {
            cur_dir.join(path)
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
    // TODO Find a way to parse only the first few pages
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

#[derive(Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
struct ProcessUids {
    real: uid_t,
    effective: uid_t,
    saved: uid_t,
    _fs: uid_t,
}

/// Get process Uid
/// See <https://man7.org/linux/man-pages/man5/proc_pid_status.5.html>
fn process_uids(pid: pid_t) -> anyhow::Result<ProcessUids> {
    let path: PathBuf = ["/proc", pid.to_string().as_str(), "status"]
        .iter()
        .collect();
    let file = File::open(&path).with_context(|| format!("Failed to open {path:?}"))?;
    read_process_uids(file)
}

fn read_process_uids<R>(reader: R) -> anyhow::Result<ProcessUids>
where
    R: Read,
{
    let reader = BufReader::new(reader);
    let (real, effective, saved, fs) = reader
        .lines()
        .map_while(Result::ok)
        .find_map(|l| l.strip_prefix("Uid:").map(ToOwned::to_owned))
        .ok_or_else(|| anyhow::anyhow!("Failed to parse process status file"))?
        .split_ascii_whitespace()
        .map(str::parse::<uid_t>)
        .collect_tuple()
        .ok_or_else(|| anyhow::anyhow!("Failed to parse process status file UID line"))?;
    Ok(ProcessUids {
        real: real.context("Failed to parse process real UID")?,
        effective: effective.context("Failed to parse process effective UID")?,
        saved: saved.context("Failed to parse process saved UID")?,
        _fs: fs.context("Failed to parse process FS UID")?,
    })
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, File},
        os::unix,
    };

    use super::*;

    #[test]
    fn is_socket_or_pipe_pseudo_path() {
        assert!(!is_fd_pseudo_path("plop".as_bytes()));
        assert!(is_fd_pseudo_path("pipe:[12334]".as_bytes()));
        assert!(is_fd_pseudo_path("socket:[1234]/".as_bytes()));
    }

    #[test]
    fn path_symlinks_lib() {
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
    fn path_symlinks_parent() {
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

    #[test]
    fn read_process_uids_works() {
        let data = "Name:	bat
Umask:	0022
State:	R (running)
Tgid:	144479
Ngid:	0
Pid:	144479
PPid:	2725
TracerPid:	0
Uid:	1001	1002	1003	1004
Gid:	1000	1000	1000	1000
FDSize:	64
Groups:	50 964 968 998 1000
NStgid:	144479
NSpid:	144479
NSpgid:	144479
NSsid:	2725
Kthread:	0
VmPeak:	  151444 kB
VmSize:	   86016 kB
VmLck:	       0 kB
VmPin:	       0 kB
VmHWM:	    7468 kB
VmRSS:	    7468 kB
RssAnon:	    1288 kB
RssFile:	    6180 kB
RssShmem:	       0 kB
VmData:	    2620 kB
VmStk:	     144 kB
VmExe:	    2784 kB
VmLib:	    8388 kB
VmPTE:	      84 kB
VmSwap:	       0 kB
HugetlbPages:	       0 kB
CoreDumping:	0
THP_enabled:	1
untag_mask:	0xffffffffffffffff
Threads:	2
SigQ:	2/256555
SigPnd:	0000000000000000
ShdPnd:	0000000000000000
SigBlk:	0000000000000000
SigIgn:	0000000000001000
SigCgt:	0000000100000440
CapInh:	0000000800000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	000001ffffffffff
CapAmb:	0000000000000000
NoNewPrivs:	0
Seccomp:	0
Seccomp_filters:	0
Speculation_Store_Bypass:	thread vulnerable
SpeculationIndirectBranch:	conditional enabled
Cpus_allowed:	ffffffff
Cpus_allowed_list:	0-31
Mems_allowed:	00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000001
Mems_allowed_list:	0
voluntary_ctxt_switches:	0
nonvoluntary_ctxt_switches:	1
x86_Thread_features:
x86_Thread_features_locked:
".as_bytes();
        assert_eq!(
            read_process_uids(data).unwrap(),
            ProcessUids {
                real: 1001,
                effective: 1002,
                saved: 1003,
                _fs: 1004
            }
        );
    }

    // Helper to create a basic Syscall
    fn make_syscall(name: &str, args: Vec<Expression>, ret_val: i64) -> Syscall {
        Syscall {
            pid: 1000,
            rel_ts: 0.0,
            name: name.into(),
            args,
            ret_val: Some(IntegerExpression {
                value: IntegerExpressionValue::Literal(ret_val),
                metadata: None,
            }),
        }
    }

    // Helper to create a buffer expression
    fn buf_expr(content: &[u8]) -> Expression {
        Expression::Buffer(BufferExpression {
            value: content.to_vec(),
            type_: BufferType::Unknown,
        })
    }

    // Helper to create an integer expression from a literal
    fn int_literal(val: i64) -> Expression {
        Expression::Integer(IntegerExpression {
            value: IntegerExpressionValue::Literal(val),
            metadata: None,
        })
    }

    // Helper to create a named symbol integer expression
    fn named_symbol(name: &str) -> Expression {
        Expression::Integer(IntegerExpression {
            value: IntegerExpressionValue::NamedSymbol(name.to_owned()),
            metadata: None,
        })
    }

    // Helper to create a BinaryOr flag expression
    fn binary_or_flags(flags: &[&str]) -> Expression {
        Expression::Integer(IntegerExpression {
            value: IntegerExpressionValue::BinaryOr(
                flags
                    .iter()
                    .map(|f| IntegerExpressionValue::NamedSymbol(f.to_string()))
                    .collect(),
            ),
            metadata: None,
        })
    }

    #[test]
    fn chdir_handler_with_path() {
        let handler = ChdirHandler {
            path: FdOrPath::Path(0),
        };
        let sc = make_syscall("chdir", vec![buf_expr(b"/tmp")], 0);
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(state.cur_dir.to_str(), Some("/tmp"));
        assert!(actions.is_empty());
    }

    #[test]
    fn chdir_handler_wrong_arg_type() {
        let handler = ChdirHandler {
            path: FdOrPath::Path(0),
        };
        let sc = make_syscall("chdir", vec![int_literal(42)], 0);
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(matches!(result, Err(HandlerError::ArgTypeMismatch { .. })));
        assert!(actions.is_empty());
    }

    #[test]
    fn chdir_handler_missing_arg() {
        let handler = ChdirHandler {
            path: FdOrPath::Path(0),
        };
        let sc = make_syscall("chdir", vec![], 0);
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(matches!(
            result,
            Err(HandlerError::ArgIndexOutOfBounds { .. })
        ));
        assert!(actions.is_empty());
    }

    #[test]
    fn epoll_ctl_handler_add_with_wakeup() {
        let handler = EpollCtlHandler { op: 1, event: 3 };
        let event_struct = HashMap::from([(
            "events".to_owned(),
            Expression::Integer(IntegerExpression {
                value: IntegerExpressionValue::BinaryOr(vec![IntegerExpressionValue::NamedSymbol(
                    "EPOLLWAKEUP".to_owned(),
                )]),
                metadata: None,
            }),
        )]);
        let sc = make_syscall(
            "epoll_ctl",
            vec![
                int_literal(5),
                named_symbol("EPOLL_CTL_ADD"),
                int_literal(10),
                Expression::Struct(event_struct),
            ],
            0,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(actions, vec![ProgramAction::Wakeup]);
    }

    #[test]
    fn epoll_ctl_handler_add_without_wakeup() {
        let handler = EpollCtlHandler { op: 1, event: 3 };
        let event_struct = HashMap::from([(
            "events".to_owned(),
            Expression::Integer(IntegerExpression {
                value: IntegerExpressionValue::NamedSymbol("EPOLLIN".to_owned()),
                metadata: None,
            }),
        )]);
        let sc = make_syscall(
            "epoll_ctl",
            vec![
                int_literal(5),
                named_symbol("EPOLL_CTL_ADD"),
                int_literal(10),
                Expression::Struct(event_struct),
            ],
            0,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert!(actions.is_empty());
    }

    #[test]
    fn epoll_ctl_handler_del_no_wakeup() {
        let handler = EpollCtlHandler { op: 1, event: 3 };
        let event_struct = HashMap::from([(
            "events".to_owned(),
            Expression::Integer(IntegerExpression {
                value: IntegerExpressionValue::NamedSymbol("EPOLLWAKEUP".to_owned()),
                metadata: None,
            }),
        )]);
        let sc = make_syscall(
            "epoll_ctl",
            vec![
                int_literal(5),
                named_symbol("EPOLL_CTL_DEL"),
                int_literal(10),
                Expression::Struct(event_struct),
            ],
            0,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert!(actions.is_empty());
    }

    #[test]
    fn epoll_ctl_handler_missing_events_field() {
        let handler = EpollCtlHandler { op: 1, event: 3 };
        let event_struct = HashMap::from([]);
        let sc = make_syscall(
            "epoll_ctl",
            vec![
                int_literal(5),
                named_symbol("EPOLL_CTL_ADD"),
                int_literal(10),
                Expression::Struct(event_struct),
            ],
            0,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(matches!(
            result,
            Err(HandlerError::MissingStructMember { .. })
        ));
        assert!(actions.is_empty());
    }

    #[test]
    fn epoll_ctl_handler_wrong_op_type() {
        let handler = EpollCtlHandler { op: 1, event: 3 };
        let event_struct = HashMap::from([(
            "events".to_owned(),
            Expression::Integer(IntegerExpression {
                value: IntegerExpressionValue::NamedSymbol("EPOLLIN".to_owned()),
                metadata: None,
            }),
        )]);
        let sc = make_syscall(
            "epoll_ctl",
            vec![
                int_literal(5),
                int_literal(1),
                int_literal(10),
                Expression::Struct(event_struct),
            ],
            0,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(matches!(result, Err(HandlerError::ArgTypeMismatch { .. })));
        assert!(actions.is_empty());
    }

    #[test]
    fn epoll_ctl_handler_wrong_event_type() {
        let handler = EpollCtlHandler { op: 1, event: 3 };
        let sc = make_syscall(
            "epoll_ctl",
            vec![
                int_literal(5),
                named_symbol("EPOLL_CTL_ADD"),
                int_literal(10),
                int_literal(999),
            ],
            0,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(matches!(result, Err(HandlerError::ArgTypeMismatch { .. })));
        assert!(actions.is_empty());
    }

    #[test]
    fn memfd_create_handler_with_hugetlb() {
        let handler = MemfdCreateHandler { flags: 1 };
        let sc = make_syscall(
            "memfd_create",
            vec![buf_expr(b"test"), named_symbol("MFD_HUGETLB")],
            3,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(actions, vec![ProgramAction::HugePageMemoryMapping]);
    }

    #[test]
    fn memfd_create_handler_without_hugetlb() {
        let handler = MemfdCreateHandler { flags: 1 };
        let sc = make_syscall(
            "memfd_create",
            vec![buf_expr(b"test"), named_symbol("MFD_CLOEXEC")],
            3,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert!(actions.is_empty());
    }

    #[test]
    fn memfd_create_handler_wrong_flags_index() {
        let handler = MemfdCreateHandler { flags: 5 }; // Wrong index
        let sc = make_syscall("memfd_create", vec![buf_expr(b"test"), int_literal(4)], 3);
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(matches!(
            result,
            Err(HandlerError::ArgIndexOutOfBounds { .. })
        ));
        assert!(actions.is_empty());
    }

    #[test]
    fn memfd_create_handler_missing_flags() {
        let handler = MemfdCreateHandler { flags: 1 };
        let sc = make_syscall("memfd_create", vec![buf_expr(b"test")], 3);
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(matches!(
            result,
            Err(HandlerError::ArgIndexOutOfBounds { .. })
        ));
        assert!(actions.is_empty());
    }

    #[test]
    fn mkdir_handler() {
        let handler = MkdirHandler {
            relfd: None,
            path: 0,
        };
        let sc = make_syscall("mkdir", vec![buf_expr(b"/tmp/newdir")], 0);
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(actions, vec![ProgramAction::Create("/tmp/newdir".into())]);
    }

    #[test]
    fn mkdirat_handler() {
        let handler = MkdirHandler {
            relfd: Some(0),
            path: 1,
        };
        let sc = make_syscall("mkdirat", vec![int_literal(3), buf_expr(b"subdir")], 0);
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(actions, vec![ProgramAction::Create("/subdir".into())]);
    }

    #[test]
    fn mkdir_handler_wrong_path_type() {
        let handler = MkdirHandler {
            relfd: None,
            path: 0,
        };
        let sc = make_syscall("mkdir", vec![int_literal(42)], 0);
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(matches!(result, Err(HandlerError::ArgTypeMismatch { .. })));
        assert!(actions.is_empty());
    }

    #[test]
    fn mknod_handler_regular_file() {
        let handler = MknodHandler {
            path: FdOrPath::Path(0),
            mode: 1,
        };
        let sc = make_syscall(
            "mknod",
            vec![buf_expr(b"/tmp/file"), int_literal(0o100_644)],
            0,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(actions, vec![ProgramAction::Create("/tmp/file".into())]);
    }

    #[test]
    fn mknod_handler_block_device() {
        let handler = MknodHandler {
            path: FdOrPath::Path(0),
            mode: 1,
        };
        let sc = make_syscall(
            "mknod",
            vec![buf_expr(b"/tmp/dev"), named_symbol("S_IFBLK")],
            0,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(
            actions,
            vec![
                ProgramAction::MknodSpecial,
                ProgramAction::Create("/tmp/dev".into())
            ]
        );
    }

    #[test]
    fn mknod_handler_char_device() {
        let handler = MknodHandler {
            path: FdOrPath::Path(0),
            mode: 1,
        };
        let sc = make_syscall(
            "mknod",
            vec![buf_expr(b"/tmp/dev"), named_symbol("S_IFCHR")],
            0,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(
            actions,
            vec![
                ProgramAction::MknodSpecial,
                ProgramAction::Create("/tmp/dev".into())
            ]
        );
    }

    #[test]
    fn mmap_handler_exec_only_prot() {
        let handler = MmapHandler {
            prot: 0,
            flags: None,
            fd: None,
        };
        let sc = make_syscall(
            "mmap",
            vec![named_symbol("PROT_EXEC"), int_literal(0), int_literal(4096)],
            0,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert!(actions.is_empty());
    }

    #[test]
    fn mmap_handler_exec_write_prot() {
        let handler = MmapHandler {
            prot: 0,
            flags: None,
            fd: None,
        };
        let sc = make_syscall(
            "mmap",
            vec![
                binary_or_flags(&["PROT_EXEC", "PROT_WRITE"]),
                int_literal(0),
                int_literal(4096),
            ],
            0,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(actions, vec![ProgramAction::WriteExecuteMemoryMapping]);
    }

    #[test]
    fn mmap_handler_hugetlb_flag() {
        let handler = MmapHandler {
            prot: 0,
            flags: Some(3),
            fd: None,
        };
        let sc = make_syscall(
            "mmap",
            vec![
                named_symbol("PROT_READ"),
                int_literal(0),
                int_literal(4096),
                binary_or_flags(&["MAP_HUGETLB"]),
            ],
            0,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(actions, vec![ProgramAction::HugePageMemoryMapping]);
    }

    #[test]
    fn mmap_handler_exec_hugetlb_flag() {
        let handler = MmapHandler {
            prot: 0,
            flags: Some(3),
            fd: None,
        };
        let sc = make_syscall(
            "mmap",
            vec![
                binary_or_flags(&["PROT_EXEC", "PROT_WRITE"]),
                int_literal(0),
                int_literal(4096),
                binary_or_flags(&["MAP_HUGETLB"]),
            ],
            0,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(
            actions,
            vec![
                ProgramAction::HugePageMemoryMapping,
                ProgramAction::WriteExecuteMemoryMapping
            ]
        );
    }

    #[test]
    fn mmap_handler_locked_flag() {
        let handler = MmapHandler {
            prot: 0,
            flags: Some(3),
            fd: None,
        };
        let sc = make_syscall(
            "mmap",
            vec![
                named_symbol("PROT_READ"),
                int_literal(0),
                int_literal(4096),
                binary_or_flags(&["MAP_LOCKED"]),
            ],
            0,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(actions, vec![ProgramAction::LockMemoryMapping]);
    }

    #[test]
    fn mmap_handler_wrong_prot_index() {
        let handler = MmapHandler {
            prot: 5, // Wrong index
            flags: None,
            fd: None,
        };
        let sc = make_syscall(
            "mmap",
            vec![int_literal(0), int_literal(4096), named_symbol("PROT_READ")],
            0,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(matches!(
            result,
            Err(HandlerError::ArgIndexOutOfBounds { .. })
        ));
        assert!(actions.is_empty());
    }

    #[test]
    fn mmap_handler_wrong_flags_type() {
        let handler = MmapHandler {
            prot: 0,
            flags: Some(3),
            fd: None,
        };
        let sc = make_syscall(
            "mmap",
            vec![
                named_symbol("PROT_READ"),
                int_literal(0),
                int_literal(4096),
                buf_expr(b"invalid"),
            ],
            0,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(matches!(result, Err(HandlerError::ArgTypeMismatch { .. })));
        assert!(actions.is_empty());
    }

    #[test]
    fn mprotect_handler_write() {
        let handler = MmapHandler {
            prot: 0,
            flags: None,
            fd: None,
        };
        let sc = make_syscall(
            "mprotect",
            vec![
                binary_or_flags(&["PROT_WRITE"]),
                int_literal(0x1000),
                int_literal(4096),
            ],
            0,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert!(actions.is_empty());
    }

    #[test]
    fn mprotect_handler_exec_write() {
        let handler = MmapHandler {
            prot: 0,
            flags: None,
            fd: None,
        };
        let sc = make_syscall(
            "mprotect",
            vec![
                binary_or_flags(&["PROT_EXEC", "PROT_WRITE"]),
                int_literal(0x1000),
                int_literal(4096),
            ],
            0,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(actions, vec![ProgramAction::WriteExecuteMemoryMapping]);
    }

    #[test]
    fn mount_handler_ms_shared() {
        let handler = MountHandler { flags: 3 };
        let sc = make_syscall(
            "mount",
            vec![
                buf_expr(b"source"),
                buf_expr(b"/mnt"),
                buf_expr(b"tmpfs"),
                named_symbol("MS_SHARED"),
            ],
            0,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(actions, vec![ProgramAction::MountToHost]);
    }

    #[test]
    fn mount_handler_no_shared() {
        let handler = MountHandler { flags: 3 };
        let sc = make_syscall(
            "mount",
            vec![
                buf_expr(b"source"),
                buf_expr(b"/mnt"),
                buf_expr(b"tmpfs"),
                binary_or_flags(&["MS_NODEV", "MS_NOEXEC"]),
            ],
            0,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert!(actions.is_empty());
    }

    #[test]
    fn mount_handler_wrong_flags_type() {
        let handler = MountHandler { flags: 3 };
        let sc = make_syscall(
            "mount",
            vec![
                buf_expr(b"source"),
                buf_expr(b"/mnt"),
                buf_expr(b"tmpfs"),
                buf_expr(b"invalid"),
            ],
            0,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(matches!(result, Err(HandlerError::ArgTypeMismatch { .. })));
        assert!(actions.is_empty());
    }

    #[test]
    fn sched_setscheduler_handler_fifo() {
        let handler = SetSchedulerHandler { policy: 1 };
        let sc = make_syscall(
            "sched_setscheduler",
            vec![int_literal(0), named_symbol("SCHED_FIFO")],
            0,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(actions, vec![ProgramAction::SetRealtimeScheduler]);
    }

    #[test]
    fn sched_setscheduler_handler_rr() {
        let handler = SetSchedulerHandler { policy: 1 };
        let sc = make_syscall(
            "sched_setscheduler",
            vec![int_literal(0), named_symbol("SCHED_RR")],
            0,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(actions, vec![ProgramAction::SetRealtimeScheduler]);
    }

    #[test]
    fn sched_setscheduler_handler_other() {
        let handler = SetSchedulerHandler { policy: 1 };
        let sc = make_syscall(
            "sched_setscheduler",
            vec![int_literal(0), named_symbol("SCHED_OTHER")],
            0,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert!(actions.is_empty());
    }

    #[test]
    fn sched_setscheduler_handler_wrong_type() {
        let handler = SetSchedulerHandler { policy: 1 };
        let sc = make_syscall(
            "sched_setscheduler",
            vec![int_literal(0), buf_expr(b"invalid")],
            0,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(matches!(result, Err(HandlerError::ArgTypeMismatch { .. })));
        assert!(actions.is_empty());
    }

    #[test]
    fn shmctl_handler_shm_lock() {
        let handler = ShmCtlHandler { op: 1 };
        let sc = make_syscall("shmctl", vec![int_literal(1), named_symbol("SHM_LOCK")], 0);
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(actions, vec![ProgramAction::LockMemoryMapping]);
    }

    #[test]
    fn shmctl_handler_shm_unlock() {
        let handler = ShmCtlHandler { op: 1 };
        let sc = make_syscall(
            "shmctl",
            vec![int_literal(1), named_symbol("SHM_UNLOCK")],
            0,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(actions, vec![ProgramAction::LockMemoryMapping]);
    }

    #[test]
    fn shmctl_handler_no_lock() {
        let handler = ShmCtlHandler { op: 1 };
        let sc = make_syscall("shmctl", vec![int_literal(1), named_symbol("SHM_STAT")], 0);
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert!(actions.is_empty());
    }

    #[test]
    fn shmctl_handler_wrong_type() {
        let handler = ShmCtlHandler { op: 1 };
        let sc = make_syscall("shmctl", vec![int_literal(1), buf_expr(b"invalid")], 0);
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(matches!(result, Err(HandlerError::ArgTypeMismatch { .. })));
        assert!(actions.is_empty());
    }

    #[test]
    fn socket_handler_tcp() {
        let handler = SocketHandler { af: 0, flags: 1 };
        let sc = make_syscall(
            "socket",
            vec![
                named_symbol("AF_INET"),
                binary_or_flags(&["SOCK_STREAM", "SOCK_CLOEXEC"]),
            ],
            3,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(
            state.known_sockets_proto.get(&(1000, 3)),
            Some(SocketProtocol::Tcp).as_ref()
        );
        assert_eq!(
            actions,
            vec![ProgramAction::NetworkActivity(
                NetworkActivity {
                    af: SetSpecifier::One(SocketFamily::Ipv4),
                    proto: SetSpecifier::One(SocketProtocol::Tcp),
                    kind: SetSpecifier::One(NetworkActivityKind::SocketCreation),
                    local_port: SetSpecifier::All,
                    address: SetSpecifier::All
                }
                .into()
            )]
        );
    }

    #[test]
    fn socket_handler_udp() {
        let handler = SocketHandler { af: 0, flags: 1 };
        let sc = make_syscall(
            "socket",
            vec![
                named_symbol("AF_INET6"),
                binary_or_flags(&["SOCK_DGRAM", "SOCK_CLOEXEC"]),
            ],
            5,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(
            state.known_sockets_proto.get(&(1000, 5)),
            Some(SocketProtocol::Udp).as_ref()
        );
        assert_eq!(
            actions,
            vec![ProgramAction::NetworkActivity(
                NetworkActivity {
                    af: SetSpecifier::One(SocketFamily::Ipv6),
                    proto: SetSpecifier::One(SocketProtocol::Udp),
                    kind: SetSpecifier::One(NetworkActivityKind::SocketCreation),
                    local_port: SetSpecifier::All,
                    address: SetSpecifier::All
                }
                .into()
            )]
        );
    }

    #[test]
    fn socket_handler_bad_af() {
        let handler = SocketHandler { af: 0, flags: 1 };
        let sc = make_syscall(
            "socket",
            vec![int_literal(999), binary_or_flags(&["SOCK_STREAM"])],
            -1,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(matches!(result, Err(HandlerError::ArgTypeMismatch { .. })));
        assert!(state.known_sockets_proto.is_empty());
        assert!(actions.is_empty());
    }

    #[test]
    fn socket_handler_bad_flags() {
        let handler = SocketHandler { af: 0, flags: 1 };
        let sc = make_syscall(
            "socket",
            vec![named_symbol("AF_INET"), buf_expr(b"invalid")],
            -1,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(matches!(result, Err(HandlerError::ArgTypeMismatch { .. })));
        assert!(state.known_sockets_proto.is_empty());
        assert!(actions.is_empty());
    }

    #[test]
    fn socket_handler_no_sock_flag() {
        let handler = SocketHandler { af: 0, flags: 1 };
        let sc = make_syscall("socket", vec![named_symbol("AF_INET"), int_literal(0)], -1);
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(matches!(result, Err(HandlerError::ParsingFailed { .. })));
        assert!(state.known_sockets_proto.is_empty());
        assert!(actions.is_empty());
    }

    #[test]
    fn socket_handler_bad_proto() {
        let handler = SocketHandler { af: 0, flags: 1 };
        let sc = make_syscall("socket", vec![named_symbol("AF_INET"), int_literal(123)], 3);
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(matches!(result, Err(HandlerError::ParsingFailed { .. })));
        assert!(state.known_sockets_proto.is_empty());
        assert!(actions.is_empty());
    }

    #[test]
    fn stat_fd_handler() {
        let handler = StatFdHandler { fd: 0 };
        let sc = Syscall {
            pid: 1000,
            rel_ts: 0.0,
            name: "fstat".into(),
            args: vec![Expression::Integer(IntegerExpression {
                value: IntegerExpressionValue::Literal(3),
                metadata: Some(b"/etc/passwd".to_vec()),
            })],
            ret_val: Some(IntegerExpression {
                value: IntegerExpressionValue::Literal(0),
                metadata: None,
            }),
        };
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(actions, vec![ProgramAction::Read("/etc/passwd".into())]);
    }

    #[test]
    fn stat_fd_handler_no_metadata() {
        let handler = StatFdHandler { fd: 0 };
        let sc = make_syscall("fstat", vec![int_literal(3)], 0);
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert!(actions.is_empty());
    }

    #[test]
    fn stat_path_handler() {
        let handler = StatPathHandler {
            relfd: None,
            path: 0,
        };
        let sc = make_syscall("stat", vec![buf_expr(b"/etc/passwd")], 0);
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(actions, vec![ProgramAction::Read("/etc/passwd".into())]);
    }

    #[test]
    fn statat_handler() {
        let handler = StatPathHandler {
            relfd: Some(0),
            path: 1,
        };
        let sc = make_syscall("statat", vec![int_literal(3), buf_expr(b"file")], 0);
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(actions, vec![ProgramAction::Read("/file".into())]);
    }

    #[test]
    fn stat_path_handler_wrong_type() {
        let handler = StatPathHandler {
            relfd: None,
            path: 0,
        };
        let sc = make_syscall("stat", vec![int_literal(42)], 0);
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(matches!(result, Err(HandlerError::ArgTypeMismatch { .. })));
        assert!(actions.is_empty());
    }

    #[test]
    fn timer_create_handler_monotonic() {
        let handler = TimerCreateHandler { clockid: 0 };
        let sc = make_syscall(
            "timer_create",
            vec![named_symbol("CLOCK_MONOTONIC"), int_literal(0)],
            0,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert!(actions.is_empty());
    }

    #[test]
    fn timer_create_handler_realtime() {
        let handler = TimerCreateHandler { clockid: 0 };
        let sc = make_syscall(
            "timer_create",
            vec![named_symbol("CLOCK_REALTIME"), int_literal(0)],
            0,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert!(actions.is_empty());
    }

    #[test]
    fn timer_create_handler_realtime_alarm() {
        let handler = TimerCreateHandler { clockid: 0 };
        let sc = make_syscall(
            "timer_create",
            vec![named_symbol("CLOCK_REALTIME_ALARM"), int_literal(0)],
            0,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(actions, vec![ProgramAction::SetAlarm]);
    }

    #[test]
    fn timer_create_handler_boottime_alarm() {
        let handler = TimerCreateHandler { clockid: 0 };
        let sc = make_syscall(
            "timer_create",
            vec![named_symbol("CLOCK_BOOTTIME_ALARM"), int_literal(0)],
            0,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(actions, vec![ProgramAction::SetAlarm]);
    }

    #[test]
    fn rename_handler_normal() {
        let handler = RenameHandler {
            relfd_src: None,
            path_src: 0,
            relfd_dst: None,
            path_dst: 1,
            flags: None,
        };
        let sc = make_syscall(
            "rename",
            vec![buf_expr(b"/tmp/old"), buf_expr(b"/tmp/new")],
            0,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(
            actions,
            vec![
                ProgramAction::Read("/tmp/old".into()),
                ProgramAction::Write("/tmp/old".into()),
                ProgramAction::Create("/tmp/new".into()),
                ProgramAction::Write("/tmp/new".into())
            ]
        );
    }

    #[test]
    fn renameat_handler() {
        let handler = RenameHandler {
            relfd_src: Some(0),
            path_src: 1,
            relfd_dst: Some(2),
            path_dst: 3,
            flags: None,
        };
        let sc = make_syscall(
            "renameat",
            vec![
                int_literal(3),
                buf_expr(b"old"),
                int_literal(4),
                buf_expr(b"new"),
            ],
            0,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(
            actions,
            vec![
                ProgramAction::Read("/old".into()),
                ProgramAction::Write("/old".into()),
                ProgramAction::Create("/new".into()),
                ProgramAction::Write("/new".into())
            ]
        );
    }

    #[test]
    fn rename_handler_exchange_flag() {
        let handler = RenameHandler {
            relfd_src: None,
            path_src: 0,
            relfd_dst: None,
            path_dst: 1,
            flags: Some(2),
        };
        let sc = make_syscall(
            "renameat2",
            vec![
                buf_expr(b"/tmp/a"),
                buf_expr(b"/tmp/b"),
                named_symbol("RENAME_EXCHANGE"),
            ],
            0,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(
            actions,
            vec![
                ProgramAction::Read("/tmp/a".into()),
                ProgramAction::Write("/tmp/a".into()),
                ProgramAction::Read("/tmp/b".into()),
                ProgramAction::Write("/tmp/b".into())
            ]
        );
    }

    #[test]
    fn kill_handler_wrong_pid_type() {
        let handler = KillHandler { pid: 0, sig: 1 };
        let sc = make_syscall(
            "kill",
            vec![buf_expr(b"invalid"), named_symbol("SIGTERM")],
            0,
        );
        let mut actions = vec![];
        let mut state = ProgramState::new("/");

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(matches!(result, Err(HandlerError::ArgTypeMismatch { .. })));
        assert!(actions.is_empty());
    }

    #[test]
    fn extract_arg_missing_usize() {
        let sc = make_syscall("test", vec![], 0);
        let idx: usize = 0;
        let result: Result<&Expression, _> = idx.extract(&sc);
        assert!(matches!(
            result,
            Err(HandlerError::ArgIndexOutOfBounds { .. })
        ));
    }

    #[test]
    fn extract_arg_option_usize_none() {
        let sc = make_syscall("test", vec![int_literal(42)], 0);
        let idx: Option<usize> = None;
        let result: Result<Option<&Expression>, _> = idx.extract(&sc);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn extract_arg_option_usize_some() {
        let sc = make_syscall("test", vec![int_literal(42)], 0);
        let idx: Option<usize> = Some(0);
        let result: Result<Option<&Expression>, _> = idx.extract(&sc);
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn extract_arg_fd_or_path_fd() {
        let sc = make_syscall("test", vec![int_literal(42)], 0);
        let fd_or_path: FdOrPath<usize> = FdOrPath::Fd(0);
        let result: Result<FdOrPath<&Expression>, _> = fd_or_path.extract(&sc);
        assert_eq!(result.unwrap(), FdOrPath::Fd(&int_literal(42)));
    }

    #[test]
    fn extract_arg_fd_or_path_path() {
        let sc = make_syscall("test", vec![buf_expr(b"/tmp")], 0);
        let fd_or_path: FdOrPath<usize> = FdOrPath::Path(0);
        let result: Result<FdOrPath<&Expression>, _> = fd_or_path.extract(&sc);
        assert_eq!(result.unwrap(), FdOrPath::Path(&buf_expr(b"/tmp")));
    }

    // chdir("/tmp")
    #[test]
    fn resolve_chdir_absolute() {
        let path = FdOrPath::Path(&buf_expr(b"/tmp"));
        assert_eq!(
            path.resolve(&"chdir".into(), Path::new("/")).unwrap(),
            Some(PathBuf::from("/tmp"))
        );
    }

    // chdir("subdir")
    #[test]
    fn resolve_chdir_relative() {
        let path = FdOrPath::Path(&buf_expr(b"subdir"));
        assert_eq!(
            path.resolve(&"chdir".into(), Path::new("/home/user"))
                .unwrap(),
            Some(PathBuf::from("/home/user/subdir"))
        );
    }

    // fchdir(3) with fd metadata pointing to /var/log
    #[test]
    fn resolve_fchdir() {
        let fd = Expression::Integer(IntegerExpression {
            value: IntegerExpressionValue::Literal(3),
            metadata: Some(b"/var/log".to_vec()),
        });
        let path = FdOrPath::Fd(&fd);
        assert_eq!(
            path.resolve(&"fchdir".into(), Path::new("/")).unwrap(),
            Some(PathBuf::from("/var/log"))
        );
    }

    // mknod("/dev/null", ...)
    #[test]
    fn resolve_mknod_absolute() {
        let path = FdOrPath::Path(&buf_expr(b"/dev/null"));
        assert_eq!(
            path.resolve(&"mknod".into(), Path::new("/")).unwrap(),
            Some(PathBuf::from("/dev/null"))
        );
    }

    // mknodat(AT_FDCWD</tmp>, "mydev", ...)
    #[test]
    fn resolve_mknodat_relative() {
        let fd = Expression::Integer(IntegerExpression {
            value: IntegerExpressionValue::NamedSymbol("AT_FDCWD".to_owned()),
            metadata: Some(b"/tmp".to_vec()),
        });
        let path = FdOrPath::Fd(&fd);
        assert_eq!(
            path.resolve(&"mknodat".into(), Path::new("/")).unwrap(),
            Some(PathBuf::from("/tmp"))
        );
    }

    // Pseudo path (eg pipe:[12345]) returns None
    #[test]
    fn resolve_pseudo_path() {
        let path = FdOrPath::Path(&buf_expr(b"pipe:[12345]"));
        assert_eq!(path.resolve(&"mknod".into(), Path::new("/")).unwrap(), None);
    }

    // Fd with pipe pseudo metadata returns None
    #[test]
    fn resolve_fd_pseudo_metadata() {
        let fd = Expression::Integer(IntegerExpression {
            value: IntegerExpressionValue::Literal(3),
            metadata: Some(b"pipe:[12345]".to_vec()),
        });
        let path = FdOrPath::Fd(&fd);
        assert_eq!(
            path.resolve(&"fchdir".into(), Path::new("/")).unwrap(),
            None
        );
    }

    // Wrong expression type for Path variant returns error
    #[test]
    fn resolve_path_type_mismatch() {
        let expr = int_literal(42);
        let path = FdOrPath::Path(&expr);
        assert!(path.resolve(&"chdir".into(), Path::new("/")).is_err());
    }
}
