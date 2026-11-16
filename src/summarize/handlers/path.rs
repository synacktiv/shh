//! Path syscall handlers

use std::{os::unix::ffi::OsStrExt as _, path::PathBuf};

use super::{
    ExtractArg as _, HandlerError, SyscallHandler, path_arg,
    walk::{resolve_path, traverse_path},
};
use crate::{
    strace::{Expression, IntegerExpression, IntegerExpressionValue, NamedSymbol, Syscall},
    summarize::{ProgramState, action::ProgramAction},
};

/// Whether a path syscall acts on the target of the path's last component when it is a symlink
pub(crate) enum FollowSymlink {
    Always,
    /// Only when the path ends with a slash
    OnTrailingSlash,
    /// Unless the no-follow flag is set in the flags argument, and the path does not end with a slash
    UnlessNoFollowFlag {
        /// Index of the flags argument
        flags: usize,
        no_follow_flag: &'static str,
    },
    /// When `AT_SYMLINK_FOLLOW` is set in the flags argument at this index, or the path ends with a slash
    IfFollowFlag(usize),
    Never,
}

/// Handler for syscalls acting on a path possibly relative to a file descriptor
pub(crate) struct PathHandler {
    pub relfd: Option<usize>,
    pub path: usize,
    pub follow: FollowSymlink,
    pub action: fn(PathBuf) -> ProgramAction,
}

impl PathHandler {
    /// Push the actions the syscall takes on its path, and return that path
    pub(super) fn handle_path(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        state: &ProgramState,
    ) -> Result<Option<PathBuf>, HandlerError> {
        let relfd = self.relfd.extract(sc)?;
        let path = self.path.extract(sc)?;

        let path = match path {
            // A NULL path designates the relative file descriptor itself, like an empty one
            Expression::Integer(IntegerExpression {
                value: IntegerExpressionValue::NamedSymbol(NamedSymbol::Unambiguous(s)),
                ..
            }) if s == "NULL" => {
                // Without a descriptor path, the call fails or changes nothing
                if relfd.and_then(Expression::metadata).is_none() {
                    return Ok(None);
                }
                PathBuf::new()
            }
            other => path_arg(other)?.to_owned(),
        };
        let path_bytes = path.as_os_str().as_bytes();
        let trailing_slash = path_bytes.ends_with(b"/");
        let follow = match self.follow {
            FollowSymlink::Always => true,
            FollowSymlink::OnTrailingSlash => trailing_slash,
            FollowSymlink::UnlessNoFollowFlag {
                flags,
                no_follow_flag,
            } => {
                let flags = unpack_expr!(
                    flags.extract(sc)?,
                    Expression::Integer(IntegerExpression { value, .. }) => value
                );
                trailing_slash || !flags.is_flag_set(no_follow_flag)
            }
            FollowSymlink::IfFollowFlag(flags) => {
                let flags = unpack_expr!(
                    flags.extract(sc)?,
                    Expression::Integer(IntegerExpression { value, .. }) => value
                );
                trailing_slash || flags.is_flag_set("AT_SYMLINK_FOLLOW")
            }
            FollowSymlink::Never => false,
        };
        // A trailing `.` component makes the kernel follow the component before it
        let follow = follow || path_bytes.ends_with(b"/.");
        // A descriptor path is already resolved, and may designate a symlink itself
        let traverse = !path_bytes.is_empty();

        let Some(mut path) = resolve_path(&path, relfd, state.cur_dir.as_ref()) else {
            return Ok(None);
        };
        if traverse {
            traverse_path(&mut path, follow, actions);
        }
        if matches!(self.follow, FollowSymlink::Never) && !sc.is_successful() {
            // A removal of an absent entry still writes to its directory
            if sc.errno() == Some("ENOENT") {
                if let Some(dir) = path.parent() {
                    actions.push(ProgramAction::Write(dir.to_owned()));
                }
                return Ok(Some(path));
            }
            // A call failing on an existing entry, like a creation with EEXIST, depends on it, and acts on it in a
            // run where it is absent
            actions.push(ProgramAction::Read(path.clone()));
        }
        actions.push((self.action)(path.clone()));
        Ok(Some(path))
    }
}

impl SyscallHandler for PathHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        self.handle_path(sc, actions, state).map(|_| ())
    }
}

/// Handler for file access check syscalls
pub(crate) struct AccessHandler {
    pub path: PathHandler,
    pub mode: usize,
}

impl SyscallHandler for AccessHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        let mode = unpack_expr!(
            self.mode.extract(sc)?,
            Expression::Integer(IntegerExpression { value, .. }) => value
        );
        if let Some(path) = self.path.handle_path(sc, actions, state)? {
            let file_type = path.symlink_metadata().ok().map(|m| m.file_type());
            // A device, FIFO or socket stays writable on a read-only mount
            if mode.is_flag_set("W_OK")
                && file_type.is_none_or(|t| t.is_file() || t.is_dir() || t.is_symlink())
            {
                actions.push(ProgramAction::Write(path.clone()));
            }
            // Only a regular file can be executed
            if mode.is_flag_set("X_OK") && file_type.is_none_or(|t| t.is_file()) {
                actions.push(ProgramAction::Exec(path));
            }
        }
        Ok(())
    }
}

/// Handler for `fanotify_mark` syscall
pub(crate) struct FanotifyMarkHandler {
    pub path: PathHandler,
    pub flags: usize,
}

impl SyscallHandler for FanotifyMarkHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        let flags = unpack_expr!(
            self.flags.extract(sc)?,
            Expression::Integer(IntegerExpression { value, .. }) => value
        );
        // A flush removes marks without looking up the path
        if flags.is_flag_set("FAN_MARK_FLUSH") {
            return Ok(());
        }
        // A mount mark watches the copy of the mount in the caller's namespace; older strace versions print
        // FAN_MARK_MNTNS, which is not one, as FAN_MARK_MOUNT|FAN_MARK_FILESYSTEM
        if flags.is_flag_set("FAN_MARK_MOUNT") && !flags.is_flag_set("FAN_MARK_FILESYSTEM") {
            actions.push(ProgramAction::HostMountNamespace);
        }
        self.path.handle(sc, actions, state)
    }
}

/// Handler for mount syscall
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

        let mount_flags = unpack_expr!(
            flags,
            Expression::Integer(IntegerExpression {
                value: mount_flags,
                ..
            }) => mount_flags
        );
        if mount_flags.is_flag_set("MS_SHARED") {
            actions.push(ProgramAction::HostMountNamespace);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        fs::{self, File},
        os::unix,
    };

    use super::*;
    use crate::summarize::{
        handlers::tests::{
            binary_or_flags, buf_expr, fd_expr, int_literal, make_failed_syscall, make_syscall,
            named_symbol, summarize_syscall, syscall,
        },
        program_state, summarize,
    };

    #[test]
    fn mkdir_handler() {
        let handler = PathHandler {
            relfd: None,
            path: 0,
            follow: FollowSymlink::Never,
            action: ProgramAction::Create,
        };
        let sc = make_syscall("mkdir", vec![buf_expr(b"/tmp/newdir")], 0);
        let mut actions = vec![];
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(actions, vec![ProgramAction::Create("/tmp/newdir".into())]);
    }

    #[test]
    fn mkdirat_handler() {
        let handler = PathHandler {
            relfd: Some(0),
            path: 1,
            follow: FollowSymlink::Never,
            action: ProgramAction::Create,
        };
        let sc = make_syscall("mkdirat", vec![int_literal(3), buf_expr(b"subdir")], 0);
        let mut actions = vec![];
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(actions, vec![ProgramAction::Create("/subdir".into())]);
    }

    #[test]
    fn mkdir_handler_wrong_path_type() {
        let handler = PathHandler {
            relfd: None,
            path: 0,
            follow: FollowSymlink::Never,
            action: ProgramAction::Create,
        };
        let sc = make_syscall("mkdir", vec![int_literal(42)], 0);
        let mut actions = vec![];
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(matches!(
            result,
            Err(HandlerError::ExpressionTypeMismatch { .. })
        ));
        assert!(actions.is_empty());
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
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(actions, vec![ProgramAction::HostMountNamespace]);
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
        let mut state = program_state();

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
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(matches!(
            result,
            Err(HandlerError::ExpressionTypeMismatch { .. })
        ));
        assert!(actions.is_empty());
    }

    #[test]
    fn stat_path_handler() {
        let handler = PathHandler {
            relfd: None,
            path: 0,
            follow: FollowSymlink::Always,
            action: ProgramAction::Read,
        };
        let sc = make_syscall("stat", vec![buf_expr(b"/etc/passwd")], 0);
        let mut actions = vec![];
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(actions, vec![ProgramAction::Read("/etc/passwd".into())]);
    }

    #[test]
    fn statat_handler() {
        let handler = PathHandler {
            relfd: Some(0),
            path: 1,
            follow: FollowSymlink::Always,
            action: ProgramAction::Read,
        };
        let sc = make_syscall("statat", vec![int_literal(3), buf_expr(b"file")], 0);
        let mut actions = vec![];
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(actions, vec![ProgramAction::Read("/file".into())]);
    }

    #[test]
    fn stat_path_handler_wrong_type() {
        let handler = PathHandler {
            relfd: None,
            path: 0,
            follow: FollowSymlink::Always,
            action: ProgramAction::Read,
        };
        let sc = make_syscall("stat", vec![int_literal(42)], 0);
        let mut actions = vec![];
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(matches!(
            result,
            Err(HandlerError::ExpressionTypeMismatch { .. })
        ));
        assert!(actions.is_empty());
    }

    #[test]
    fn utimensat_null_path_writes_fd_path() {
        let _ = simple_logger::SimpleLogger::new().init();

        // glibc's futimens(fd, times)
        let fd = fd_expr(3, "/var/lib/test");
        for name in ["utimensat", "utimensat_time64"] {
            let syscalls = [Ok(syscall(
                name,
                vec![
                    fd.clone(),
                    named_symbol("NULL"),
                    named_symbol("NULL"),
                    int_literal(0),
                ],
            ))];
            assert_eq!(
                summarize(syscalls, &[], program_state()).unwrap(),
                vec![
                    ProgramAction::Write("/var/lib/test".into()),
                    ProgramAction::Syscalls([name.into()].into()),
                ]
            );
        }
    }

    #[test]
    fn write_symlink_follow() {
        let _ = simple_logger::SimpleLogger::new().init();

        let state = program_state();

        let temp_dir = tempfile::tempdir().unwrap();
        let target = temp_dir.path().join("target");
        let link = temp_dir.path().join("link");
        File::create(&target).unwrap();
        unix::fs::symlink(&target, &link).unwrap();
        let target_dir = temp_dir.path().join("target_dir");
        let link_dir = temp_dir.path().join("link_dir");
        fs::create_dir(&target_dir).unwrap();
        unix::fs::symlink(&target_dir, &link_dir).unwrap();
        let link_str = link.to_str().unwrap();
        let syscalls = [
            Ok(syscall(
                "utimensat",
                vec![
                    named_symbol("AT_FDCWD"),
                    buf_expr(link_str.as_bytes()),
                    named_symbol("NULL"),
                    named_symbol("AT_SYMLINK_NOFOLLOW"),
                ],
            )),
            Ok(syscall(
                "chmod",
                vec![buf_expr(link_str.as_bytes()), int_literal(0o644)],
            )),
            Ok(syscall(
                "chown32",
                vec![
                    buf_expr(link_str.as_bytes()),
                    int_literal(0),
                    int_literal(0),
                ],
            )),
            Ok(syscall(
                "truncate64",
                vec![buf_expr(link_str.as_bytes()), int_literal(0)],
            )),
            Ok(syscall("unlink", vec![buf_expr(link_str.as_bytes())])),
            // A trailing slash follows the symlink despite AT_SYMLINK_NOFOLLOW
            Ok(syscall(
                "utimensat",
                vec![
                    named_symbol("AT_FDCWD"),
                    buf_expr(format!("{}/", link_dir.to_str().unwrap()).as_bytes()),
                    named_symbol("NULL"),
                    named_symbol("AT_SYMLINK_NOFOLLOW"),
                ],
            )),
            Ok(syscall(
                "unlink",
                vec![buf_expr(link_dir.join("file").as_os_str().as_bytes())],
            )),
        ];
        assert_eq!(
            summarize(syscalls, &[], state).unwrap(),
            vec![
                ProgramAction::Write(link.clone()),
                ProgramAction::Read(link.clone()),
                ProgramAction::Write(target.clone()),
                ProgramAction::Read(link.clone()),
                ProgramAction::Write(target.clone()),
                ProgramAction::Read(link.clone()),
                ProgramAction::Write(target),
                ProgramAction::Remove(link.clone()),
                ProgramAction::RequireSameMount(link, temp_dir.path().to_owned()),
                ProgramAction::Read(link_dir.clone()),
                ProgramAction::Write(target_dir.clone()),
                ProgramAction::Read(link_dir),
                ProgramAction::Remove(target_dir.join("file")),
                ProgramAction::RequireSameMount(target_dir.join("file"), target_dir.clone()),
                ProgramAction::Syscalls(
                    [
                        "chmod".into(),
                        "chown32".into(),
                        "truncate64".into(),
                        "unlink".into(),
                        "utimensat".into()
                    ]
                    .into()
                ),
            ]
        );
    }

    #[test]
    fn write_fd_symlink_no_follow() {
        let _ = simple_logger::SimpleLogger::new().init();

        let state = program_state();

        let temp_dir = tempfile::tempdir().unwrap();
        let target = temp_dir.path().join("target");
        let link = temp_dir.path().join("link");
        File::create(&target).unwrap();
        unix::fs::symlink(&target, &link).unwrap();
        // O_PATH|O_NOFOLLOW descriptor of the symlink
        let fd = fd_expr(3, &link);
        let syscalls = [Ok(syscall(
            "fchownat",
            vec![
                fd,
                buf_expr(b""),
                int_literal(0),
                int_literal(0),
                named_symbol("AT_EMPTY_PATH"),
            ],
        ))];
        assert_eq!(
            summarize(syscalls, &[], state).unwrap(),
            vec![
                ProgramAction::Write(link),
                ProgramAction::Syscalls(["fchownat".into()].into()),
            ]
        );
    }

    #[test]
    fn write_at_symlink_no_follow_flag() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let target = temp_dir.path().join("target");
        let link = temp_dir.path().join("link");
        File::create(&target).unwrap();
        unix::fs::symlink(&target, &link).unwrap();
        let dir_fd = fd_expr(3, temp_dir.path());
        for (flags, path_actions) in [
            (
                named_symbol("AT_SYMLINK_NOFOLLOW"),
                vec![ProgramAction::Write(link.clone())],
            ),
            (
                int_literal(0),
                vec![
                    ProgramAction::Read(link.clone()),
                    ProgramAction::Write(target.clone()),
                ],
            ),
        ] {
            for (name, args) in [
                (
                    "fchmodat2",
                    vec![
                        dir_fd.clone(),
                        buf_expr(b"link"),
                        int_literal(0o644),
                        flags.clone(),
                    ],
                ),
                (
                    "fchownat",
                    vec![
                        dir_fd.clone(),
                        buf_expr(b"link"),
                        int_literal(0),
                        int_literal(0),
                        flags.clone(),
                    ],
                ),
                (
                    "file_setattr",
                    vec![
                        dir_fd.clone(),
                        buf_expr(b"link"),
                        Expression::Struct(HashMap::from([(
                            "fa_xflags".to_owned(),
                            int_literal(0),
                        )])),
                        int_literal(24),
                        flags.clone(),
                    ],
                ),
                (
                    "removexattrat",
                    vec![
                        dir_fd.clone(),
                        buf_expr(b"link"),
                        flags.clone(),
                        buf_expr(b"user.test"),
                    ],
                ),
                (
                    "setxattrat",
                    vec![
                        dir_fd.clone(),
                        buf_expr(b"link"),
                        flags.clone(),
                        buf_expr(b"user.test"),
                        Expression::Struct(HashMap::from([
                            ("value".to_owned(), buf_expr(b"value")),
                            ("size".to_owned(), int_literal(5)),
                            ("flags".to_owned(), int_literal(0)),
                        ])),
                        int_literal(16),
                    ],
                ),
                (
                    "utimensat",
                    vec![
                        dir_fd.clone(),
                        buf_expr(b"link"),
                        named_symbol("NULL"),
                        flags.clone(),
                    ],
                ),
            ] {
                assert_eq!(
                    summarize([Ok(syscall(name, args))], &[], program_state()).unwrap(),
                    [
                        path_actions.clone(),
                        vec![ProgramAction::Syscalls([name.into()].into())]
                    ]
                    .concat()
                );
            }
        }
    }

    #[test]
    fn utimensat_null_path_closed_fd() {
        let _ = simple_logger::SimpleLogger::new().init();

        let state = program_state();

        let syscalls = [Ok(syscall(
            "utimensat",
            vec![
                int_literal(3),
                named_symbol("NULL"),
                named_symbol("NULL"),
                int_literal(0),
            ],
        ))];
        assert_eq!(
            summarize(syscalls, &[], state).unwrap(),
            vec![ProgramAction::Syscalls(["utimensat".into()].into())]
        );
    }

    #[test]
    fn create_symlink_no_follow() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let link = temp_dir.path().join("link");
        unix::fs::symlink(temp_dir.path().join("missing"), &link).unwrap();
        let dir_fd = fd_expr(3, temp_dir.path());
        // The entry a successful call creates is a symlink when handled if the call made one, or if one
        // replaced it since
        for (name, args) in [
            (
                "mkdir",
                vec![buf_expr(link.as_os_str().as_bytes()), int_literal(0o755)],
            ),
            (
                "symlink",
                vec![buf_expr(b"/src"), buf_expr(link.as_os_str().as_bytes())],
            ),
            (
                "symlinkat",
                vec![buf_expr(b"/src"), dir_fd.clone(), buf_expr(b"link")],
            ),
            (
                "link",
                vec![buf_expr(b"/src"), buf_expr(link.as_os_str().as_bytes())],
            ),
            (
                "linkat",
                vec![
                    named_symbol("AT_FDCWD"),
                    buf_expr(b"/src"),
                    dir_fd.clone(),
                    buf_expr(b"link"),
                    int_literal(0),
                ],
            ),
            // A trailing slash does not make the kernel follow the entry a call creates
            (
                "mkdirat",
                vec![dir_fd.clone(), buf_expr(b"link/"), int_literal(0o755)],
            ),
        ] {
            // A hard link also reads its source, and needs it on the mount of the new entry's directory
            let hard_link = matches!(name, "link" | "linkat");
            let old = hard_link.then(|| ProgramAction::Read("/src".into()));
            let same_mount = hard_link.then(|| {
                ProgramAction::RequireSameMount("/src".into(), temp_dir.path().to_owned())
            });
            assert_eq!(
                summarize([Ok(syscall(name, args))], &[], program_state()).unwrap(),
                old.into_iter()
                    .chain([ProgramAction::Create(link.clone())])
                    .chain(same_mount)
                    .chain([ProgramAction::Syscalls([name.into()].into())])
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn create_existing_path_reads() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let dir = temp_dir.path().join("dir");
        fs::create_dir(&dir).unwrap();
        let link = temp_dir.path().join("link");
        unix::fs::symlink(temp_dir.path().join("missing"), &link).unwrap();
        for path in [dir, link] {
            // Failing with EEXIST, which the parser keeps
            let mkdir = make_syscall(
                "mkdir",
                vec![buf_expr(path.as_os_str().as_bytes()), int_literal(0o755)],
                -1,
            );
            assert_eq!(
                summarize_syscall(mkdir),
                vec![
                    ProgramAction::Read(path.clone()),
                    ProgramAction::Create(path),
                    ProgramAction::Syscalls(["mkdir".into()].into()),
                ]
            );
        }
    }

    #[test]
    fn create_through_dotdot() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let link_dir = temp_dir.path().join("links");
        let target_dir = temp_dir.path().join("target");
        let inner_dir = target_dir.join("inner");
        fs::create_dir(&link_dir).unwrap();
        fs::create_dir_all(&inner_dir).unwrap();
        fs::create_dir(target_dir.join("x")).unwrap();
        let link = link_dir.join("link");
        unix::fs::symlink(&inner_dir, &link).unwrap();
        let link_dotdot = link_dir.join("dotdot");
        unix::fs::symlink("link/../x", &link_dotdot).unwrap();
        // The directory `..` leaves is read, and when reached through a symlink, `..` leaves its target
        for (path, reads, created) in [
            (
                inner_dir.join("../x/new"),
                vec![inner_dir.clone()],
                target_dir.join("x/new"),
            ),
            (
                link.join("../new"),
                vec![link.clone(), inner_dir.clone()],
                target_dir.join("new"),
            ),
            (
                link_dotdot.join("new"),
                vec![link_dotdot.clone(), link.clone(), inner_dir.clone()],
                target_dir.join("x/new"),
            ),
        ] {
            let args = vec![
                buf_expr(b"/dev/null"),
                buf_expr(path.as_os_str().as_bytes()),
            ];
            assert_eq!(
                summarize([Ok(syscall("symlink", args))], &[], program_state()).unwrap(),
                [
                    reads.into_iter().map(ProgramAction::Read).collect(),
                    vec![
                        ProgramAction::Create(created),
                        ProgramAction::Syscalls(["symlink".into()].into()),
                    ],
                ]
                .concat()
            );
        }
    }

    #[test]
    fn create_through_nested_symlink_target() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let link_dir = temp_dir.path().join("www");
        let cache_dir = temp_dir.path().join("cache");
        fs::create_dir(&link_dir).unwrap();
        fs::create_dir_all(cache_dir.join("subdir")).unwrap();
        let public = link_dir.join("public");
        let bridge = link_dir.join("bridge");
        unix::fs::symlink("bridge/subdir", &public).unwrap();
        unix::fs::symlink(&cache_dir, &bridge).unwrap();
        let args = vec![
            buf_expr(public.join("new").as_os_str().as_bytes()),
            int_literal(0o755),
        ];
        assert_eq!(
            summarize([Ok(syscall("mkdir", args))], &[], program_state()).unwrap(),
            vec![
                ProgramAction::Read(public),
                ProgramAction::Read(bridge),
                ProgramAction::Create(cache_dir.join("subdir/new")),
                ProgramAction::Syscalls(["mkdir".into()].into()),
            ]
        );
    }

    #[test]
    fn lsetxattr_failed_symlink_writes() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let link = temp_dir.path().join("link");
        unix::fs::symlink(temp_dir.path().join("missing"), &link).unwrap();
        // Failing with EEXIST on an existing attribute, after the mount write check
        let lsetxattr = make_syscall(
            "lsetxattr",
            vec![
                buf_expr(link.as_os_str().as_bytes()),
                buf_expr(b"trusted.test"),
                buf_expr(b""),
                int_literal(0),
                named_symbol("XATTR_CREATE"),
            ],
            -1,
        );
        assert_eq!(
            summarize_syscall(lsetxattr),
            vec![
                ProgramAction::Write(link),
                ProgramAction::Syscalls(["lsetxattr".into()].into()),
            ]
        );
    }

    #[test]
    fn lchown_trailing_slash_follows() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let target = temp_dir.path().join("target");
        let link = temp_dir.path().join("link");
        fs::create_dir(&target).unwrap();
        unix::fs::symlink(&target, &link).unwrap();
        let link_bytes = link.as_os_str().as_bytes();
        for name in ["lchown", "lchown32"] {
            let lchown =
                |path: &[u8]| syscall(name, vec![buf_expr(path), int_literal(0), int_literal(0)]);
            assert_eq!(
                summarize([Ok(lchown(link_bytes))], &[], program_state()).unwrap(),
                vec![
                    ProgramAction::Write(link.clone()),
                    ProgramAction::Syscalls([name.into()].into()),
                ]
            );
            for suffix in [&b"/"[..], b"/."] {
                assert_eq!(
                    summarize(
                        [Ok(lchown(&[link_bytes, suffix].concat()))],
                        &[],
                        program_state()
                    )
                    .unwrap(),
                    vec![
                        ProgramAction::Read(link.clone()),
                        ProgramAction::Write(target.clone()),
                        ProgramAction::Syscalls([name.into()].into()),
                    ]
                );
            }
        }
    }

    #[test]
    fn read_path_follows_symlink() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let target = temp_dir.path().join("target");
        let link = temp_dir.path().join("link");
        File::create(&target).unwrap();
        unix::fs::symlink(&target, &link).unwrap();
        let link_bytes = link.as_os_str().as_bytes();
        let stat_buf = Expression::Struct(HashMap::from([("st_size".to_owned(), int_literal(0))]));
        let statfs_buf = Expression::Struct(HashMap::from([(
            "f_type".to_owned(),
            named_symbol("TMPFS_MAGIC"),
        )]));
        for (name, args) in [
            ("access", vec![buf_expr(link_bytes), named_symbol("R_OK")]),
            (
                "faccessat",
                vec![
                    fd_expr(3, temp_dir.path()),
                    buf_expr(b"link"),
                    named_symbol("R_OK"),
                ],
            ),
            (
                "getxattr",
                vec![
                    buf_expr(link_bytes),
                    buf_expr(b"user.test"),
                    buf_expr(b"value"),
                    int_literal(4096),
                ],
            ),
            (
                "listxattr",
                vec![buf_expr(link_bytes), buf_expr(b""), int_literal(4096)],
            ),
            (
                "fstatat64",
                vec![
                    fd_expr(3, temp_dir.path()),
                    buf_expr(b"link"),
                    stat_buf.clone(),
                    int_literal(0),
                ],
            ),
            ("lstat64", vec![buf_expr(link_bytes), stat_buf.clone()]),
            ("oldlstat", vec![buf_expr(link_bytes), stat_buf.clone()]),
            ("oldstat", vec![buf_expr(link_bytes), stat_buf.clone()]),
            ("stat64", vec![buf_expr(link_bytes), stat_buf.clone()]),
            ("statfs", vec![buf_expr(link_bytes), statfs_buf.clone()]),
            (
                "statfs64",
                vec![buf_expr(link_bytes), int_literal(84), statfs_buf.clone()],
            ),
        ] {
            assert_eq!(
                summarize([Ok(syscall(name, args))], &[], program_state()).unwrap(),
                vec![
                    ProgramAction::Read(link.clone()),
                    ProgramAction::Read(target.clone()),
                    ProgramAction::Syscalls([name.into()].into()),
                ]
            );
        }
    }

    #[test]
    fn read_symlink_no_follow() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let target = temp_dir.path().join("target");
        let link = temp_dir.path().join("link");
        fs::create_dir(&target).unwrap();
        unix::fs::symlink(&target, &link).unwrap();
        // A trailing slash follows the link
        for (suffix, path_actions) in [
            (&b""[..], vec![ProgramAction::Read(link.clone())]),
            (
                b"/",
                vec![
                    ProgramAction::Read(link.clone()),
                    ProgramAction::Read(target.clone()),
                ],
            ),
        ] {
            let link_bytes = [link.as_os_str().as_bytes(), suffix].concat();
            for (name, args) in [
                (
                    "lgetxattr",
                    vec![
                        buf_expr(&link_bytes),
                        buf_expr(b"trusted.test"),
                        buf_expr(b"value"),
                        int_literal(4096),
                    ],
                ),
                (
                    "llistxattr",
                    vec![buf_expr(&link_bytes), buf_expr(b""), int_literal(4096)],
                ),
                (
                    "readlink",
                    vec![
                        buf_expr(&link_bytes),
                        buf_expr(b"target"),
                        int_literal(4096),
                    ],
                ),
                (
                    "readlinkat",
                    vec![
                        fd_expr(3, temp_dir.path()),
                        buf_expr(&[&b"link"[..], suffix].concat()),
                        buf_expr(b"target"),
                        int_literal(4096),
                    ],
                ),
            ] {
                // Reading the directory as a symlink fails
                let sc = if suffix.is_empty() || !name.starts_with("readlink") {
                    make_syscall(name, args, 0)
                } else {
                    make_failed_syscall(name, args, "EINVAL")
                };
                assert_eq!(
                    summarize_syscall(sc),
                    [
                        path_actions.clone(),
                        vec![ProgramAction::Syscalls([name.into()].into())]
                    ]
                    .concat()
                );
            }
        }
    }

    #[test]
    fn read_symlink_follow_flags() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let target = temp_dir.path().join("target");
        let link = temp_dir.path().join("link");
        File::create(&target).unwrap();
        unix::fs::symlink(&target, &link).unwrap();
        let dir_fd = fd_expr(3, temp_dir.path());
        for (follow, path_actions) in [
            (false, vec![ProgramAction::Read(link.clone())]),
            (
                true,
                vec![
                    ProgramAction::Read(link.clone()),
                    ProgramAction::Read(target.clone()),
                ],
            ),
        ] {
            // Flags with the given flag added when enabled
            let flags_with = |base: &[&str], flag: &str, enabled: bool| {
                let mut flags = base.to_vec();
                flags.extend(enabled.then_some(flag));
                match flags.as_slice() {
                    [] => int_literal(0),
                    [single] => named_symbol(single),
                    _ => binary_or_flags(&flags),
                }
            };
            for (name, args) in [
                (
                    "faccessat2",
                    vec![
                        dir_fd.clone(),
                        buf_expr(b"link"),
                        named_symbol("R_OK"),
                        flags_with(&["AT_EACCESS"], "AT_SYMLINK_NOFOLLOW", !follow),
                    ],
                ),
                (
                    "fanotify_mark",
                    vec![
                        fd_expr(4, "anon_inode:[fanotify]"),
                        flags_with(&["FAN_MARK_ADD"], "FAN_MARK_DONT_FOLLOW", !follow),
                        named_symbol("FAN_MODIFY"),
                        dir_fd.clone(),
                        buf_expr(b"link"),
                    ],
                ),
                (
                    "file_getattr",
                    vec![
                        dir_fd.clone(),
                        buf_expr(b"link"),
                        Expression::Struct(HashMap::from([(
                            "fa_xflags".to_owned(),
                            int_literal(0),
                        )])),
                        int_literal(24),
                        flags_with(&[], "AT_SYMLINK_NOFOLLOW", !follow),
                    ],
                ),
                (
                    "getxattrat",
                    vec![
                        dir_fd.clone(),
                        buf_expr(b"link"),
                        flags_with(&[], "AT_SYMLINK_NOFOLLOW", !follow),
                        buf_expr(b"user.test"),
                        Expression::Struct(HashMap::from([
                            ("value".to_owned(), buf_expr(b"value")),
                            ("size".to_owned(), int_literal(4096)),
                            ("flags".to_owned(), int_literal(0)),
                        ])),
                        int_literal(16),
                    ],
                ),
                (
                    "inotify_add_watch",
                    vec![
                        fd_expr(4, "anon_inode:inotify"),
                        buf_expr(link.as_os_str().as_bytes()),
                        flags_with(&["IN_MODIFY"], "IN_DONT_FOLLOW", !follow),
                    ],
                ),
                (
                    "listxattrat",
                    vec![
                        dir_fd.clone(),
                        buf_expr(b"link"),
                        flags_with(&[], "AT_SYMLINK_NOFOLLOW", !follow),
                        buf_expr(b""),
                        int_literal(4096),
                    ],
                ),
                (
                    "name_to_handle_at",
                    vec![
                        dir_fd.clone(),
                        buf_expr(b"link"),
                        Expression::Struct(HashMap::from([(
                            "handle_type".to_owned(),
                            int_literal(1),
                        )])),
                        Expression::Collection {
                            complement: false,
                            values: vec![(None, int_literal(42))],
                            truncated: false,
                        },
                        flags_with(&["AT_HANDLE_FID"], "AT_SYMLINK_FOLLOW", follow),
                    ],
                ),
                (
                    "statx",
                    vec![
                        dir_fd.clone(),
                        buf_expr(b"link"),
                        flags_with(&["AT_STATX_SYNC_AS_STAT"], "AT_SYMLINK_NOFOLLOW", !follow),
                        named_symbol("STATX_ALL"),
                        Expression::Struct(HashMap::from([(
                            "stx_mask".to_owned(),
                            named_symbol("STATX_ALL"),
                        )])),
                    ],
                ),
            ] {
                assert_eq!(
                    summarize([Ok(syscall(name, args))], &[], program_state()).unwrap(),
                    [
                        path_actions.clone(),
                        vec![ProgramAction::Syscalls([name.into()].into())]
                    ]
                    .concat()
                );
            }
        }
    }

    #[test]
    fn readlink_non_symlink_reads() {
        let _ = simple_logger::SimpleLogger::new().init();

        // Failing with EINVAL on an entry that is not a symlink, which the parser keeps
        let sc = make_failed_syscall(
            "readlink",
            vec![
                buf_expr(b"/var/lib/file"),
                named_symbol("NULL"),
                int_literal(4096),
            ],
            "EINVAL",
        );
        assert_eq!(
            summarize_syscall(sc),
            vec![
                ProgramAction::Read("/var/lib/file".into()),
                ProgramAction::Syscalls(["readlink".into()].into()),
            ]
        );
    }

    #[test]
    fn access_check_modes() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let dir = temp_dir.path().to_owned();
        let file = dir.join("file");
        File::create(&file).unwrap();
        let dev_null = PathBuf::from("/dev/null");
        for (path, mode, path_actions) in [
            (
                &file,
                named_symbol("F_OK"),
                vec![ProgramAction::Read(file.clone())],
            ),
            (
                &file,
                named_symbol("W_OK"),
                vec![
                    ProgramAction::Read(file.clone()),
                    ProgramAction::Write(file.clone()),
                ],
            ),
            (
                &file,
                named_symbol("X_OK"),
                vec![
                    ProgramAction::Read(file.clone()),
                    ProgramAction::Exec(file.clone()),
                ],
            ),
            // Execution of a directory checks its search permission only
            (
                &dir,
                binary_or_flags(&["R_OK", "W_OK", "X_OK"]),
                vec![
                    ProgramAction::Read(dir.clone()),
                    ProgramAction::Write(dir.clone()),
                ],
            ),
            // A device stays writable on a read-only mount, and can not be executed
            (
                &dev_null,
                binary_or_flags(&["R_OK", "W_OK", "X_OK"]),
                vec![ProgramAction::Read(dev_null.clone())],
            ),
        ] {
            let path = buf_expr(path.as_os_str().as_bytes());
            for (name, args) in [
                ("access", vec![path.clone(), mode.clone()]),
                (
                    "faccessat",
                    vec![named_symbol("AT_FDCWD"), path.clone(), mode.clone()],
                ),
                (
                    "faccessat2",
                    vec![
                        named_symbol("AT_FDCWD"),
                        path.clone(),
                        mode.clone(),
                        int_literal(0),
                    ],
                ),
            ] {
                assert_eq!(
                    summarize([Ok(syscall(name, args))], &[], program_state()).unwrap(),
                    [
                        path_actions.clone(),
                        vec![ProgramAction::Syscalls([name.into()].into())]
                    ]
                    .concat()
                );
            }
        }

        // The link itself, not its target, when not followed
        let link = dir.join("link");
        unix::fs::symlink(&file, &link).unwrap();
        assert_eq!(
            summarize_syscall(make_syscall(
                "faccessat2",
                vec![
                    named_symbol("AT_FDCWD"),
                    buf_expr(link.as_os_str().as_bytes()),
                    named_symbol("X_OK"),
                    named_symbol("AT_SYMLINK_NOFOLLOW"),
                ],
                0,
            )),
            vec![
                ProgramAction::Read(link),
                ProgramAction::Syscalls(["faccessat2".into()].into()),
            ]
        );
    }

    #[test]
    fn fanotify_mark_flush_ignores_path() {
        let _ = simple_logger::SimpleLogger::new().init();

        // An unreadable path is printed as its address
        for path in [buf_expr(b"/etc"), int_literal(0x1234)] {
            assert_eq!(
                summarize_syscall(make_syscall(
                    "fanotify_mark",
                    vec![
                        fd_expr(3, "anon_inode:[fanotify]"),
                        named_symbol("FAN_MARK_FLUSH"),
                        int_literal(0),
                        named_symbol("AT_FDCWD"),
                        path,
                    ],
                    0,
                )),
                vec![ProgramAction::Syscalls(["fanotify_mark".into()].into())]
            );
        }
    }

    #[test]
    fn fanotify_mark_mount_acts_on_host_mount_namespace() {
        let _ = simple_logger::SimpleLogger::new().init();

        for (flags, mut expected) in [
            (
                &["FAN_MARK_ADD", "FAN_MARK_MOUNT"][..],
                vec![ProgramAction::HostMountNamespace],
            ),
            // FAN_MARK_MNTNS, as printed by strace 6.13
            (
                &["FAN_MARK_ADD", "FAN_MARK_MOUNT", "FAN_MARK_FILESYSTEM"],
                vec![],
            ),
            (&["FAN_MARK_ADD", "FAN_MARK_MNTNS"], vec![]),
        ] {
            expected.extend([
                ProgramAction::Read("/etc".into()),
                ProgramAction::Syscalls(["fanotify_mark".into()].into()),
            ]);
            assert_eq!(
                summarize_syscall(make_syscall(
                    "fanotify_mark",
                    vec![
                        fd_expr(3, "anon_inode:[fanotify]"),
                        binary_or_flags(flags),
                        named_symbol("FAN_MODIFY"),
                        named_symbol("AT_FDCWD"),
                        buf_expr(b"/etc"),
                    ],
                    0,
                )),
                expected
            );
        }
    }
}
