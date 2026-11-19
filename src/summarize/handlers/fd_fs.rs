//! Syscall handlers acting on the filesystem entry a descriptor refers to

use std::{
    ffi::OsStr,
    os::unix::ffi::OsStrExt as _,
    path::{Path, PathBuf},
};

use super::{
    ExtractArg as _, HandlerError, SyscallHandler,
    walk::{is_fd_pseudo_path, resolve_path, traverse_path},
};
use crate::{
    strace::{Expression, IntegerExpression, Syscall},
    summarize::{ProgramState, action::ProgramAction},
};

/// Push the actions to reach the path of a file descriptor, and return that path
pub(super) fn fd_path(
    fd: &Expression,
    actions: &mut Vec<ProgramAction>,
    cur_dir: &Path,
) -> Option<PathBuf> {
    let metadata = fd.metadata().filter(|m| !is_fd_pseudo_path(m))?;
    let mut path = resolve_path(Path::new(OsStr::from_bytes(metadata)), None, cur_dir)?;
    traverse_path(&mut path, true, actions);
    Some(path)
}

/// Handler for stat-like syscalls operating on file descriptors
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
        if let Some(path) = fd_path(self.fd.extract(sc)?, actions, &state.cur_dir) {
            actions.push(ProgramAction::Read(path));
        }
        Ok(())
    }
}

/// Handler for syscalls changing the attributes of the file of a descriptor
pub(crate) struct FdWriteHandler {
    pub fd: usize,
}

impl SyscallHandler for FdWriteHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        if let Some(path) = fd_path(self.fd.extract(sc)?, actions, &state.cur_dir) {
            actions.push(ProgramAction::Write(path));
        }
        Ok(())
    }
}

/// Handler for `ioctl` syscall
pub(crate) struct IoctlHandler {
    pub fd: usize,
    pub request: usize,
}

impl SyscallHandler for IoctlHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        /// Requests changing the attributes of the file of the descriptor
        const ATTR_WRITE_REQUESTS: [&str; 7] = [
            "FS_IOC32_SETFLAGS",
            "FS_IOC32_SETVERSION",
            "FS_IOC_ENABLE_VERITY",
            "FS_IOC_FSSETXATTR",
            "FS_IOC_SETFLAGS",
            "FS_IOC_SETVERSION",
            "FS_IOC_SET_ENCRYPTION_POLICY",
        ];
        /// Requests setting the time or parameters of a hardware clock
        const HARDWARE_CLOCK_SET_REQUESTS: [&str; 4] = [
            "RTC_EPOCH_SET",
            "RTC_PARAM_SET",
            "RTC_PLL_SET",
            "RTC_SET_TIME",
        ];
        let request = unpack_expr!(
            self.request.extract(sc)?,
            Expression::Integer(IntegerExpression { value, .. }) => value
        );
        let matches_request = |names: &[&str]| names.iter().any(|name| request.is_flag_set(name));
        if matches_request(&HARDWARE_CLOCK_SET_REQUESTS) {
            actions.push(ProgramAction::SetHardwareClock);
        }
        if request.is_flag_set("KDSIGACCEPT") {
            actions.push(ProgramAction::AcceptKeyboardSignal);
        }
        if matches_request(&ATTR_WRITE_REQUESTS)
            && let Some(path) = fd_path(self.fd.extract(sc)?, actions, &state.cur_dir)
        {
            actions.push(ProgramAction::Write(path));
        }
        Ok(())
    }
}

#[expect(clippy::unreadable_literal)]
#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::{
        strace::{IntegerExpressionValue, NamedSymbol, SyscallItem},
        summarize::{
            handlers::tests::{
                binary_or_flags, buf_expr, fd_expr, int_literal, make_failed_syscall, make_syscall,
                named_symbol, summarize_syscall,
            },
            program_state, summarize,
        },
    };

    #[test]
    fn stat_fd_handler() {
        let handler = StatFdHandler { fd: 0 };
        let sc = Syscall {
            pid: 1000,
            rel_ts: 0.0,
            name: "fstat".into(),
            args: vec![fd_expr(3, "/etc/passwd")],
            ret_val: Some(IntegerExpression {
                value: IntegerExpressionValue::Literal(0),
                metadata: None,
            }),
        };
        let mut actions = vec![];
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(actions, vec![ProgramAction::Read("/etc/passwd".into())]);
    }

    #[test]
    fn stat_fd_handler_no_path() {
        let handler = StatFdHandler { fd: 0 };
        for fd in [
            int_literal(3),
            fd_expr(3, "UDP:[4951101]"),
            fd_expr(3, "TCP:[127.0.0.1:41022->127.0.0.2:54817]"),
            fd_expr(
                3,
                r#"UNIX-STREAM:[4913849->4913848,"\x2f\x74\x6d\x70\x2f\x73"]"#,
            ),
            fd_expr(3, "L2TP/IP:[4951101]"),
        ] {
            let sc = make_syscall("fstat", vec![fd], 0);
            let mut actions = vec![];
            let mut state = program_state();

            let result = handler.handle(&sc, &mut actions, &mut state);
            assert!(result.is_ok());
            assert!(actions.is_empty());
        }
    }

    #[test]
    fn fstat_unknown() {
        let _ = simple_logger::SimpleLogger::new().init();

        let state = program_state();

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
                                    IntegerExpressionValue::NamedSymbol(NamedSymbol::Unambiguous(
                                        "S_IFREG".to_owned(),
                                    )),
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

    #[test]
    fn fd_writes_write_fd_path() {
        let _ = simple_logger::SimpleLogger::new().init();

        // Descriptor of a file opened read-only
        let fd = fd_expr(3, "/var/lib/test");
        let ioctl =
            |request, arg| make_syscall("ioctl", vec![fd.clone(), named_symbol(request), arg], 0);
        for sc in [
            make_syscall("fchmod", vec![fd.clone(), int_literal(0o640)], 0),
            make_syscall(
                "fchown",
                vec![fd.clone(), int_literal(0), int_literal(0)],
                0,
            ),
            make_syscall(
                "fchown32",
                vec![fd.clone(), int_literal(0), int_literal(0)],
                0,
            ),
            make_syscall(
                "fsetxattr",
                vec![
                    fd.clone(),
                    buf_expr(b"user.test"),
                    buf_expr(b"x"),
                    int_literal(1),
                    int_literal(0),
                ],
                0,
            ),
            // Failing with ENODATA on an absent attribute, after the mount write check
            make_failed_syscall(
                "fremovexattr",
                vec![fd.clone(), buf_expr(b"user.absent")],
                "ENODATA",
            ),
            ioctl(
                "FS_IOC_SETFLAGS",
                Expression::Collection {
                    complement: false,
                    values: vec![(None, int_literal(0))],
                    truncated: false,
                },
            ),
            ioctl(
                "FS_IOC_FSSETXATTR",
                Expression::Struct(HashMap::from([("fsx_xflags".to_owned(), int_literal(0))])),
            ),
            ioctl(
                "FS_IOC_SETVERSION",
                buf_expr(b"\x00\x00\x00\x00\x00\x00\x00\x00"),
            ),
            ioctl(
                "FS_IOC32_SETFLAGS",
                Expression::Collection {
                    complement: false,
                    values: vec![(None, int_literal(0))],
                    truncated: false,
                },
            ),
            ioctl("FS_IOC32_SETVERSION", buf_expr(b"\x00\x00\x00\x00")),
            ioctl("FS_IOC_ENABLE_VERITY", int_literal(0x7ffd_0e48_4cc0)),
            ioctl(
                "FS_IOC_SET_ENCRYPTION_POLICY",
                int_literal(0x7ffd_0e48_4cc0),
            ),
        ] {
            let name = sc.name.clone();
            assert_eq!(
                summarize_syscall(sc),
                vec![
                    ProgramAction::Write("/var/lib/test".into()),
                    ProgramAction::Syscalls([name].into()),
                ]
            );
        }
    }

    #[test]
    fn fd_reads_read_fd_path() {
        let _ = simple_logger::SimpleLogger::new().init();

        let fd = fd_expr(3, "/var/lib/test");
        for name in ["fstat", "fstat64", "getdents", "oldfstat", "readdir"] {
            let sc = make_syscall(
                name,
                vec![fd.clone(), Expression::Struct(HashMap::new())],
                0,
            );
            assert_eq!(
                summarize_syscall(sc),
                vec![
                    ProgramAction::Read("/var/lib/test".into()),
                    ProgramAction::Syscalls([name.into()].into()),
                ]
            );
        }
    }

    #[test]
    fn pseudo_fd_paths_ignored() {
        let _ = simple_logger::SimpleLogger::new().init();

        let memfd = fd_expr(4, "/memfd:review");
        for sc in [
            make_syscall(
                "fchmod",
                vec![fd_expr(3, "pipe:[123]"), int_literal(0o600)],
                0,
            ),
            make_syscall("fchmod", vec![memfd.clone(), int_literal(0o600)], 0),
            make_syscall(
                "mmap",
                vec![
                    named_symbol("NULL"),
                    int_literal(4096),
                    binary_or_flags(&["PROT_READ", "PROT_EXEC"]),
                    named_symbol("MAP_SHARED"),
                    memfd,
                    int_literal(0),
                ],
                0x7f00_0000_0000,
            ),
        ] {
            let name = sc.name.clone();
            assert_eq!(
                summarize_syscall(sc),
                vec![ProgramAction::Syscalls([name].into())]
            );
        }
    }

    #[test]
    fn ioctl_requests() {
        let _ = simple_logger::SimpleLogger::new().init();

        for (device, request, mut expected) in [
            (
                "/dev/rtc0",
                "RTC_SET_TIME",
                vec![ProgramAction::SetHardwareClock],
            ),
            (
                "/dev/rtc0",
                "RTC_EPOCH_SET",
                vec![ProgramAction::SetHardwareClock],
            ),
            (
                "/dev/rtc0",
                "RTC_PARAM_SET",
                vec![ProgramAction::SetHardwareClock],
            ),
            (
                "/dev/rtc0",
                "RTC_PLL_SET",
                vec![ProgramAction::SetHardwareClock],
            ),
            ("/dev/rtc0", "RTC_ALM_SET", vec![]),
            ("/dev/rtc0", "RTC_WKALM_SET", vec![]),
            (
                "/dev/tty0",
                "KDSIGACCEPT",
                vec![ProgramAction::AcceptKeyboardSignal],
            ),
            ("/dev/pts/0", "TCGETS", vec![]),
        ] {
            let args = vec![fd_expr(3, device), named_symbol(request), int_literal(0)];
            expected.push(ProgramAction::Syscalls(["ioctl".into()].into()));
            assert_eq!(summarize_syscall(make_syscall("ioctl", args, 0)), expected);
        }
    }
}
