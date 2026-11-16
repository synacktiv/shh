//! Syscall handlers, producing summary

use std::{
    any::{type_name, type_name_of_val},
    collections::HashMap,
    ffi::OsStr,
    os::{fd::RawFd, unix::ffi::OsStrExt as _},
    path::{Path, PathBuf},
};

use nix::libc::pid_t;

use super::{ProgramState, action::ProgramAction};
use crate::strace::{BufferExpression, BufferType, Expression, Syscall};

#[derive(thiserror::Error, Debug)]
pub(crate) enum HandlerError {
    #[error("Missing argument at index {index}")]
    SyscalllArgIndexOutOfBounds { index: usize },
    #[error("Unexpected argument type: {arg:?}")]
    ExpressionTypeMismatch { arg: Expression },
    #[error("Failed to interpret value {src:?} ({type_src}) as {type_dst}")]
    ValueInterpretationFailed {
        src: String,
        type_src: &'static str,
        type_dst: &'static str,
    },
    #[error("Missing member {member:?} in struct {struct_:?}")]
    MissingStructMember {
        member: &'static str,
        struct_: HashMap<String, Expression>,
    },
}

macro_rules! err_expr_type {
    ($arg:expr $(,)?) => {
        HandlerError::ExpressionTypeMismatch {
            arg: ($arg).to_owned(),
        }
    };
}

macro_rules! err_value {
    ($src:expr, $type_src:ty => $type_dst:ty $(,)?) => {
        HandlerError::ValueInterpretationFailed {
            src: format!("{:?}", $src),
            type_src: type_name::<$type_src>(),
            type_dst: type_name::<$type_dst>(),
        }
    };
    ($src:expr, $type_dst:ty $(,)?) => {
        HandlerError::ValueInterpretationFailed {
            src: format!("{:?}", $src),
            type_src: type_name_of_val(&($src)),
            type_dst: type_name::<$type_dst>(),
        }
    };
}

macro_rules! unpack_expr {
    ($expr:expr, $pat:pat => $result:expr $(,)?) => {
        match $expr {
            $pat => $result,
            other => return Err(err_expr_type!(other)),
        }
    };
}

macro_rules! unpack_struct_member {
    ($members:expr, $member:literal $(,)?) => {
        $members
            .get($member)
            .ok_or_else(|| HandlerError::MissingStructMember {
                member: $member,
                struct_: $members.to_owned(),
            })?
    };
}

// Declared after the macros, which are only in scope below their definition
mod dir_entry;
mod fd_fs;
mod memory;
mod open;
mod path;
mod process;
mod sockaddr;
mod socket;
mod timer;
mod walk;

pub(crate) use dir_entry::{LinkHandler, RemoveHandler, RenameHandler};
pub(crate) use fd_fs::{FdWriteHandler, IoctlHandler, StatFdHandler};
pub(crate) use memory::{MemfdCreateHandler, MmapHandler, ShmAtHandler, ShmCtlHandler};
pub(crate) use open::{MknodHandler, OpenHandler};
pub(crate) use path::{
    AccessHandler, FanotifyMarkHandler, FollowSymlink, MountHandler, PathHandler,
};
pub(crate) use process::{
    ChdirHandler, Clone3Handler, ExecHandler, ForkHandler, KillHandler, PidfdSendSignalHandler,
    SetSchedulerHandler, UnshareHandler,
};
pub(crate) use sockaddr::{NetworkHandler, SockaddrArg};
pub(crate) use socket::{DupHandler, DupQualifier, SetsockoptHandler, SocketHandler};
pub(crate) use timer::{EpollCtlHandler, TimerHandler};
use walk::resolve_path;
pub(crate) use walk::{PathWalk, traverse_path_within};

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
            .ok_or(HandlerError::SyscalllArgIndexOutOfBounds { index: *self })
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

#[derive(Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub(crate) enum FdOrPath<T> {
    Fd(T),
    Path(T),
}

impl FdOrPath<&Expression> {
    /// Resolve an fd-or-path reference to an optional absolute path
    fn resolve(self, cur_dir: &Path) -> Result<Option<PathBuf>, HandlerError> {
        match self {
            FdOrPath::Fd(fd) => Ok(resolve_path(Path::new(""), Some(fd), cur_dir)),
            FdOrPath::Path(path) => Ok(resolve_path(path_arg(path)?, None, cur_dir)),
        }
    }
}

/// Get the number of a descriptor argument
fn fd_number(fd: &Expression) -> Result<RawFd, HandlerError> {
    let fd = unpack_expr!(fd, Expression::Integer(fd) => fd);
    let value = fd.value().ok_or_else(|| err_value!(fd, RawFd))?;
    RawFd::try_from(value).map_err(|_| err_value!(value, i64 => RawFd))
}

/// Get the process a pidfd argument designates, if the tracer sees it
fn pidfd_pid(pidfd: &Expression) -> Result<Option<pid_t>, HandlerError> {
    // strace shows the path of a pidfd whose process is outside its PID namespace
    let Some(pid) = pidfd.metadata().and_then(|m| m.strip_prefix(b"pid:")) else {
        return Ok(None);
    };
    str::from_utf8(pid)
        .ok()
        .and_then(|pid| pid.parse().ok())
        .map(Some)
        .ok_or_else(|| err_value!(pid, pid_t))
}

/// Get the path of a path argument
fn path_arg(path: &Expression) -> Result<&Path, HandlerError> {
    Ok(unpack_expr!(
        path,
        Expression::Buffer(BufferExpression {
            value: b,
            type_: BufferType::Unknown,
        }) => Path::new(OsStr::from_bytes(b))
    ))
}

/// Get the label of descriptor metadata, its part before any bracketed details
fn fd_label(metadata: &[u8]) -> &[u8] {
    metadata
        .windows(2)
        .position(|w| w == b":[")
        .map_or(metadata, |i| metadata.split_at(i).0)
}

#[cfg(test)]
pub(crate) mod tests {
    use nix::libc::pid_t;

    use super::*;
    use crate::{
        strace::{IntegerExpression, IntegerExpressionValue, NamedSymbol, SyscallItem},
        summarize::{program_state, summarize},
    };

    // Helper to create a basic Syscall
    pub(crate) fn make_syscall(name: &str, args: Vec<Expression>, ret_val: i64) -> Syscall {
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

    pub(crate) fn make_failed_syscall(name: &str, args: Vec<Expression>, errno: &str) -> Syscall {
        let mut sc = make_syscall(name, args, -1);
        sc.ret_val.as_mut().unwrap().metadata =
            Some(format!("{errno} (Error message)").into_bytes());
        sc
    }

    // Helper to create a buffer expression
    pub(crate) fn buf_expr(content: &[u8]) -> Expression {
        Expression::Buffer(BufferExpression {
            value: content.to_vec(),
            type_: BufferType::Unknown,
        })
    }

    // Helper to create an integer expression from a literal
    pub(crate) fn int_literal(val: i64) -> Expression {
        Expression::Integer(IntegerExpression {
            value: IntegerExpressionValue::Literal(val),
            metadata: None,
        })
    }

    // Helper to create a descriptor expression with metadata
    pub(crate) fn fd_expr(fd: i64, metadata: impl AsRef<OsStr>) -> Expression {
        Expression::Integer(IntegerExpression {
            value: IntegerExpressionValue::Literal(fd),
            metadata: Some(metadata.as_ref().as_bytes().to_vec()),
        })
    }

    // Helper to create a named symbol integer expression
    pub(crate) fn named_symbol(name: &str) -> Expression {
        Expression::Integer(IntegerExpression {
            value: IntegerExpressionValue::NamedSymbol(NamedSymbol::Unambiguous(name.to_owned())),
            metadata: None,
        })
    }

    // Helper to create a BinaryOr flag expression
    pub(crate) fn binary_or_flags(flags: &[&str]) -> Expression {
        Expression::Integer(IntegerExpression {
            value: IntegerExpressionValue::BinaryOr(
                flags
                    .iter()
                    .map(|f| {
                        IntegerExpressionValue::NamedSymbol(NamedSymbol::Unambiguous(f.to_string()))
                    })
                    .collect(),
            ),
            metadata: None,
        })
    }

    // Helper to create an AF_INET bind syscall for a given pid, fd, and port
    pub(crate) fn make_bind_inet(pid: pid_t, fd: i64, port: i64) -> Syscall {
        let mut sc = make_syscall(
            "bind",
            vec![
                int_literal(fd),
                Expression::Struct(HashMap::from([
                    ("sa_family".to_owned(), named_symbol("AF_INET")),
                    ("sin_family".to_owned(), named_symbol("AF_INET")),
                    (
                        "sin_port".to_owned(),
                        Expression::Integer(IntegerExpression {
                            value: IntegerExpressionValue::Macro {
                                name: "htons".to_owned(),
                                args: vec![int_literal(port)],
                            },
                            metadata: None,
                        }),
                    ),
                    ("sin_addr".to_owned(), named_symbol("INADDR_ANY")),
                ])),
            ],
            0,
        );
        sc.pid = pid;
        sc
    }

    // Helper to create a socket syscall for a given pid, returning ret_fd
    pub(crate) fn make_socket_inet(pid: pid_t, sock_type: &str, ret_fd: i64) -> Syscall {
        let mut sc = make_syscall(
            "socket",
            vec![
                named_symbol("AF_INET"),
                binary_or_flags(&[sock_type, "SOCK_CLOEXEC"]),
            ],
            ret_fd,
        );
        sc.pid = pid;
        sc
    }

    pub(crate) fn syscall(name: &str, args: Vec<Expression>) -> SyscallItem {
        SyscallItem::Complete(Box::new(make_syscall(name, args, 0)))
    }

    pub(crate) fn summarize_syscall(sc: Syscall) -> Vec<ProgramAction> {
        let item = SyscallItem::Complete(Box::new(sc));
        summarize([Ok(item)], &[], program_state()).unwrap()
    }

    #[test]
    fn extract_arg_missing_usize() {
        let sc = make_syscall("test", vec![], 0);
        let idx: usize = 0;
        let result: Result<&Expression, _> = idx.extract(&sc);
        assert!(matches!(
            result,
            Err(HandlerError::SyscalllArgIndexOutOfBounds { .. })
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
            path.resolve(Path::new("/")).unwrap(),
            Some(PathBuf::from("/tmp"))
        );
    }

    // chdir("subdir")
    #[test]
    fn resolve_chdir_relative() {
        let path = FdOrPath::Path(&buf_expr(b"subdir"));
        assert_eq!(
            path.resolve(Path::new("/home/user")).unwrap(),
            Some(PathBuf::from("/home/user/subdir"))
        );
    }

    // fchdir(3) with fd metadata pointing to /var/log
    #[test]
    fn resolve_fchdir() {
        let fd = fd_expr(3, "/var/log");
        let path = FdOrPath::Fd(&fd);
        assert_eq!(
            path.resolve(Path::new("/")).unwrap(),
            Some(PathBuf::from("/var/log"))
        );
    }

    // A pathname shaped like a pseudo file (eg pipe:[12345]) is a relative path
    #[test]
    fn resolve_pseudo_file_name() {
        let path = FdOrPath::Path(&buf_expr(b"pipe:[12345]"));
        assert_eq!(
            path.resolve(Path::new("/")).unwrap(),
            Some(PathBuf::from("/pipe:[12345]"))
        );
    }

    // Fd with pipe pseudo metadata returns None
    #[test]
    fn resolve_fd_pseudo_metadata() {
        let fd = fd_expr(3, "pipe:[12345]");
        let path = FdOrPath::Fd(&fd);
        assert_eq!(path.resolve(Path::new("/")).unwrap(), None);
    }

    // Wrong expression type for Path variant returns error
    #[test]
    fn resolve_path_type_mismatch() {
        let expr = int_literal(42);
        let path = FdOrPath::Path(&expr);
        assert!(path.resolve(Path::new("/")).is_err());
    }
}
