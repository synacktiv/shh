//! Directory entry rename, removal and link syscall handlers

use std::path::Path;

use super::{
    ExtractArg as _, HandlerError, SyscallHandler,
    path::PathHandler,
    path_arg,
    walk::{resolve_path, traverse_path},
};
use crate::{
    strace::{Expression, IntegerExpression, Syscall},
    summarize::{ProgramState, action::ProgramAction},
};

/// Handler for rename-like syscalls
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

        let path_src = path_arg(path_src_expr)?;
        let path_dst = path_arg(path_dst_expr)?;

        let (Some(mut path_src), Some(mut path_dst)) = (
            resolve_path(path_src, relfd_src, state.cur_dir.as_ref()),
            resolve_path(path_dst, relfd_dst, state.cur_dir.as_ref()),
        ) else {
            return Ok(());
        };

        let exchange = match flags {
            Some(other) => {
                let value = unpack_expr!(
                    other,
                    Expression::Integer(IntegerExpression { value, .. }) => value
                );
                value.is_flag_set("RENAME_EXCHANGE")
            }
            None => false,
        };

        // A rename acts on the entries themselves, never following their final component
        traverse_path(&mut path_src, false, actions);
        traverse_path(&mut path_dst, false, actions);
        let dir_src = path_src.parent().map(Path::to_path_buf);
        let dir_dst = path_dst.parent().map(Path::to_path_buf);
        // Different directories need the same mount
        if let (Some(dir_src), Some(dir_dst)) = (&dir_src, &dir_dst)
            && dir_src != dir_dst
        {
            actions.push(ProgramAction::RequireSameMount(
                dir_src.clone(),
                dir_dst.clone(),
            ));
        }
        // A rename of an absent entry still writes to both directories
        if sc.errno() == Some("ENOENT") {
            if let (Some(dir_src), Some(dir_dst)) = (dir_src, dir_dst) {
                actions.push(ProgramAction::Write(dir_src));
                actions.push(ProgramAction::Write(dir_dst));
            }
            return Ok(());
        }
        actions.push(ProgramAction::Read(path_src.clone()));
        actions.push(ProgramAction::Remove(path_src.clone()));
        // An exchanged destination, or one a rename fails on, like with RENAME_NOREPLACE, exists before the call
        if exchange || !sc.is_successful() {
            actions.push(ProgramAction::Read(path_dst.clone()));
        }
        // An exchange replaces each entry by the other one
        actions.push(if exchange {
            ProgramAction::Remove(path_dst.clone())
        } else {
            ProgramAction::Create(path_dst.clone())
        });
        // A moved entry must not be a mount point, and carries the mounts below it, so none may sit there
        if dir_src.is_some() {
            actions.push(ProgramAction::RequireNoMountWithin(path_src));
        }
        if let Some(dir_dst) = dir_dst {
            actions.push(if exchange {
                ProgramAction::RequireNoMountWithin(path_dst)
            } else {
                // A replaced entry must not be a mount point, so it must share the mount of its directory
                ProgramAction::RequireSameMount(path_dst, dir_dst)
            });
        }
        Ok(())
    }
}

/// Handler for entry removal syscalls
pub(crate) struct RemoveHandler {
    pub path: PathHandler,
}

impl SyscallHandler for RemoveHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        let path = self.path.handle_path(sc, actions, state)?;
        // Unless absent, the entry must not be a mount point, so it must share the mount of its directory
        if sc.errno() != Some("ENOENT")
            && let Some(path) = path
            && let Some(dir) = path.parent()
        {
            let dir = dir.to_owned();
            actions.push(ProgramAction::RequireSameMount(path, dir));
        }
        Ok(())
    }
}

/// Handler for hard link creation syscalls
pub(crate) struct LinkHandler {
    pub old: PathHandler,
    pub new: PathHandler,
}

impl SyscallHandler for LinkHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        let old = self.old.handle_path(sc, actions, state)?;
        let new = self.new.handle_path(sc, actions, state)?;
        // A link, even one failing on an existing new path, needs its old path on the mount of the new path's
        // directory
        if let (Some(old), Some(new_dir)) = (old, new.as_deref().and_then(Path::parent)) {
            actions.push(ProgramAction::RequireSameMount(old, new_dir.to_owned()));
        }
        Ok(())
    }
}

#[expect(clippy::unreadable_literal)]
#[cfg(test)]
mod tests {
    use std::{
        fs::{self, File},
        os::unix::{self, ffi::OsStrExt as _},
        path::PathBuf,
    };

    use super::*;
    use crate::{
        strace::{BufferExpression, BufferType, IntegerExpressionValue, NamedSymbol, SyscallItem},
        summarize::{
            handlers::tests::{
                buf_expr, fd_expr, int_literal, make_failed_syscall, make_syscall, named_symbol,
                summarize_syscall, syscall,
            },
            program_state, summarize,
        },
    };

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
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(
            actions,
            vec![
                ProgramAction::Read("/tmp/old".into()),
                ProgramAction::Remove("/tmp/old".into()),
                ProgramAction::Create("/tmp/new".into()),
                ProgramAction::RequireNoMountWithin("/tmp/old".into()),
                ProgramAction::RequireSameMount("/tmp/new".into(), "/tmp".into())
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
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(
            actions,
            vec![
                ProgramAction::Read("/old".into()),
                ProgramAction::Remove("/old".into()),
                ProgramAction::Create("/new".into()),
                ProgramAction::RequireNoMountWithin("/old".into()),
                ProgramAction::RequireSameMount("/new".into(), "/".into())
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
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(
            actions,
            vec![
                ProgramAction::Read("/tmp/a".into()),
                ProgramAction::Remove("/tmp/a".into()),
                ProgramAction::Read("/tmp/b".into()),
                ProgramAction::Remove("/tmp/b".into()),
                ProgramAction::RequireNoMountWithin("/tmp/a".into()),
                ProgramAction::RequireNoMountWithin("/tmp/b".into())
            ]
        );
    }

    #[test]
    fn relative_rename() {
        let _ = simple_logger::SimpleLogger::new().init();

        let env_paths = [
            PathBuf::from("/path/from/env/1"),
            PathBuf::from("/path/from/env/2"),
        ];
        let state = program_state();

        let temp_dir_src = tempfile::tempdir().unwrap();
        let temp_dir_dst = tempfile::tempdir().unwrap();
        let syscalls = [Ok(SyscallItem::Complete(Box::new(Syscall {
            pid: 1068781,
            rel_ts: 0.000083,
            name: "renameat".into(),
            args: vec![
                Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::NamedSymbol(NamedSymbol::Unambiguous(
                        "AT_FDCWD".to_owned(),
                    )),
                    metadata: Some(temp_dir_src.path().as_os_str().as_bytes().to_vec()),
                }),
                Expression::Buffer(BufferExpression {
                    value: "a".as_bytes().to_vec(),
                    type_: BufferType::Unknown,
                }),
                Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::NamedSymbol(NamedSymbol::Unambiguous(
                        "AT_FDCWD".to_owned(),
                    )),
                    metadata: Some(temp_dir_dst.path().as_os_str().as_bytes().to_vec()),
                }),
                Expression::Buffer(BufferExpression {
                    value: "b".as_bytes().to_vec(),
                    type_: BufferType::Unknown,
                }),
                Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::NamedSymbol(NamedSymbol::Unambiguous(
                        "RENAME_NOREPLACE".to_owned(),
                    )),
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
                ProgramAction::RequireSameMount(
                    temp_dir_src.path().to_owned(),
                    temp_dir_dst.path().to_owned()
                ),
                ProgramAction::Read(temp_dir_src.path().join("a")),
                ProgramAction::Remove(temp_dir_src.path().join("a")),
                ProgramAction::Create(temp_dir_dst.path().join("b")),
                ProgramAction::RequireNoMountWithin(temp_dir_src.path().join("a")),
                ProgramAction::RequireSameMount(
                    temp_dir_dst.path().join("b"),
                    temp_dir_dst.path().to_owned()
                ),
                ProgramAction::Syscalls(["renameat".into()].into()),
                ProgramAction::Read("/path/from/env/1".into()),
                ProgramAction::Read("/path/from/env/2".into()),
            ]
        );
    }

    #[test]
    fn rename_absent_entry_writes_dirs() {
        let _ = simple_logger::SimpleLogger::new().init();

        // Failing with ENOENT, which the parser keeps for renames
        let sc = make_failed_syscall(
            "rename",
            vec![
                buf_expr(b"/var/lib/apt/absent"),
                buf_expr(b"/var/lib/misc/new"),
            ],
            "ENOENT",
        );
        assert_eq!(
            summarize_syscall(sc),
            vec![
                ProgramAction::RequireSameMount("/var/lib/apt".into(), "/var/lib/misc".into()),
                ProgramAction::Write("/var/lib/apt".into()),
                ProgramAction::Write("/var/lib/misc".into()),
                ProgramAction::Syscalls(["rename".into()].into()),
            ]
        );
    }

    #[test]
    fn rename_requires_same_mount() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let src_dir = temp_dir.path().join("src_dir");
        let src_dir_link = temp_dir.path().join("src_dir_link");
        let other_dir = temp_dir.path().join("other_dir");
        fs::create_dir(&src_dir).unwrap();
        fs::create_dir(&other_dir).unwrap();
        unix::fs::symlink(&src_dir, &src_dir_link).unwrap();
        unix::fs::symlink(other_dir.join("target"), src_dir.join("old")).unwrap();
        let new = temp_dir.path().join("new");
        let args = vec![
            named_symbol("AT_FDCWD"),
            buf_expr(src_dir_link.join("old").as_os_str().as_bytes()),
            named_symbol("AT_FDCWD"),
            buf_expr(new.as_os_str().as_bytes()),
        ];
        assert_eq!(
            summarize([Ok(syscall("renameat", args))], &[], program_state()).unwrap(),
            vec![
                ProgramAction::Read(src_dir_link.clone()),
                ProgramAction::RequireSameMount(src_dir.clone(), temp_dir.path().to_path_buf()),
                ProgramAction::Read(src_dir.join("old")),
                ProgramAction::Remove(src_dir.join("old")),
                ProgramAction::Create(new.clone()),
                ProgramAction::RequireNoMountWithin(src_dir.join("old")),
                ProgramAction::RequireSameMount(new, temp_dir.path().to_path_buf()),
                ProgramAction::Syscalls(["renameat".into()].into()),
            ]
        );
    }

    #[test]
    fn rename_removes_source() {
        let _ = simple_logger::SimpleLogger::new().init();

        // State after renaming a symlink over another: the source is gone, the destination is the moved symlink
        let temp_dir = tempfile::tempdir().unwrap();
        let src = temp_dir.path().join("new");
        let dst = temp_dir.path().join("cur");
        let target = temp_dir.path().join("target");
        File::create(&target).unwrap();
        unix::fs::symlink(&target, &dst).unwrap();
        let args = vec![
            named_symbol("AT_FDCWD"),
            buf_expr(src.as_os_str().as_bytes()),
            named_symbol("AT_FDCWD"),
            buf_expr(dst.as_os_str().as_bytes()),
        ];
        assert_eq!(
            summarize([Ok(syscall("renameat", args))], &[], program_state()).unwrap(),
            vec![
                ProgramAction::Read(src.clone()),
                ProgramAction::Remove(src.clone()),
                ProgramAction::Create(dst.clone()),
                ProgramAction::RequireNoMountWithin(src),
                ProgramAction::RequireSameMount(dst, temp_dir.path().to_owned()),
                ProgramAction::Syscalls(["renameat".into()].into()),
            ]
        );
    }

    #[test]
    fn rename_noreplace_existing_reads() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let existing = temp_dir.path().join("existing");
        File::create(&existing).unwrap();
        // Failing with EEXIST, which the parser keeps
        let sc = make_syscall(
            "renameat2",
            vec![
                named_symbol("AT_FDCWD"),
                buf_expr(b"/src/file"),
                named_symbol("AT_FDCWD"),
                buf_expr(existing.as_os_str().as_bytes()),
                named_symbol("RENAME_NOREPLACE"),
            ],
            -1,
        );
        assert_eq!(
            summarize_syscall(sc),
            vec![
                ProgramAction::RequireSameMount("/src".into(), temp_dir.path().to_owned()),
                ProgramAction::Read("/src/file".into()),
                ProgramAction::Remove("/src/file".into()),
                ProgramAction::Read(existing.clone()),
                ProgramAction::Create(existing.clone()),
                ProgramAction::RequireNoMountWithin("/src/file".into()),
                ProgramAction::RequireSameMount(existing, temp_dir.path().to_owned()),
                ProgramAction::Syscalls(["renameat2".into()].into()),
            ]
        );
    }

    #[test]
    fn rename_through_nested_symlink_target() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let src_dir = temp_dir.path().join("src");
        let dst_dir = temp_dir.path().join("dst");
        fs::create_dir_all(src_dir.join("sub")).unwrap();
        fs::create_dir(&dst_dir).unwrap();
        let alias = dst_dir.join("alias");
        let bridge = dst_dir.join("bridge");
        unix::fs::symlink(bridge.join("sub"), &alias).unwrap();
        unix::fs::symlink(&src_dir, &bridge).unwrap();
        let old = src_dir.join("sub/file");
        let new = dst_dir.join("new");
        let args = vec![
            named_symbol("AT_FDCWD"),
            buf_expr(alias.join("file").as_os_str().as_bytes()),
            named_symbol("AT_FDCWD"),
            buf_expr(new.as_os_str().as_bytes()),
        ];
        assert_eq!(
            summarize([Ok(syscall("renameat", args))], &[], program_state()).unwrap(),
            vec![
                ProgramAction::Read(alias),
                ProgramAction::Read(bridge),
                ProgramAction::RequireSameMount(src_dir.join("sub"), dst_dir.clone()),
                ProgramAction::Read(old.clone()),
                ProgramAction::Remove(old.clone()),
                ProgramAction::Create(new.clone()),
                ProgramAction::RequireNoMountWithin(old),
                ProgramAction::RequireSameMount(new, dst_dir),
                ProgramAction::Syscalls(["renameat".into()].into()),
            ]
        );
    }

    #[test]
    fn remove_requires_same_mount() {
        let _ = simple_logger::SimpleLogger::new().init();

        for (name, args) in [
            ("unlink", vec![buf_expr(b"/var/lib/test")]),
            (
                "unlinkat",
                vec![
                    named_symbol("AT_FDCWD"),
                    buf_expr(b"/var/lib/test"),
                    named_symbol("AT_REMOVEDIR"),
                ],
            ),
            ("rmdir", vec![buf_expr(b"/var/lib/test")]),
        ] {
            assert_eq!(
                summarize([Ok(syscall(name, args))], &[], program_state()).unwrap(),
                vec![
                    ProgramAction::Remove("/var/lib/test".into()),
                    ProgramAction::RequireSameMount("/var/lib/test".into(), "/var/lib".into()),
                    ProgramAction::Syscalls([name.into()].into()),
                ]
            );
        }
    }

    #[test]
    fn unlink_absent_entry_writes_dir() {
        let _ = simple_logger::SimpleLogger::new().init();

        // Failing with ENOENT, which the parser keeps for removals
        let sc = make_failed_syscall("unlink", vec![buf_expr(b"/var/lib/absent")], "ENOENT");
        assert_eq!(
            summarize_syscall(sc),
            vec![
                ProgramAction::Write("/var/lib".into()),
                ProgramAction::Syscalls(["unlink".into()].into()),
            ]
        );
    }

    #[test]
    fn rmdir_non_empty_requires_same_mount() {
        let _ = simple_logger::SimpleLogger::new().init();

        // Failing with ENOTEMPTY, which the parser keeps
        let sc = make_failed_syscall("rmdir", vec![buf_expr(b"/var/lib/full")], "ENOTEMPTY");
        assert_eq!(
            summarize_syscall(sc),
            vec![
                ProgramAction::Read("/var/lib/full".into()),
                ProgramAction::Remove("/var/lib/full".into()),
                ProgramAction::RequireSameMount("/var/lib/full".into(), "/var/lib".into()),
                ProgramAction::Syscalls(["rmdir".into()].into()),
            ]
        );
    }

    #[test]
    fn link_creates_path() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let target_dir = temp_dir.path().join("target_dir");
        let link_dir = temp_dir.path().join("link_dir");
        fs::create_dir(&target_dir).unwrap();
        unix::fs::symlink(&target_dir, &link_dir).unwrap();
        let dir_fd = fd_expr(3, temp_dir.path());
        let new = link_dir.join("new");
        let new_bytes = new.as_os_str().as_bytes();
        for (name, args) in [
            ("link", vec![buf_expr(b"/src"), buf_expr(new_bytes)]),
            (
                "linkat",
                vec![
                    named_symbol("AT_FDCWD"),
                    buf_expr(b"/src"),
                    dir_fd.clone(),
                    buf_expr(b"link_dir/new"),
                    int_literal(0),
                ],
            ),
            ("symlink", vec![buf_expr(b"/src"), buf_expr(new_bytes)]),
            (
                "symlinkat",
                vec![buf_expr(b"/src"), dir_fd.clone(), buf_expr(b"link_dir/new")],
            ),
        ] {
            // A hard link also reads its source, and needs it on the mount of the new entry's directory
            let hard_link = matches!(name, "link" | "linkat");
            let old = hard_link.then(|| ProgramAction::Read("/src".into()));
            let same_mount = hard_link
                .then(|| ProgramAction::RequireSameMount("/src".into(), target_dir.clone()));
            assert_eq!(
                summarize([Ok(syscall(name, args))], &[], program_state()).unwrap(),
                old.into_iter()
                    .chain([
                        ProgramAction::Read(link_dir.clone()),
                        ProgramAction::Create(target_dir.join("new")),
                    ])
                    .chain(same_mount)
                    .chain([ProgramAction::Syscalls([name.into()].into())])
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn link_reads_old_path() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let target = temp_dir.path().join("target");
        let link = temp_dir.path().join("link");
        File::create(&target).unwrap();
        unix::fs::symlink(&target, &link).unwrap();
        let dir_fd = fd_expr(3, temp_dir.path());
        let target_fd = fd_expr(4, &target);
        let new = temp_dir.path().join("new");
        let linkat = |old_fd: &Expression, old: &[u8], flags| {
            vec![
                old_fd.clone(),
                buf_expr(old),
                named_symbol("AT_FDCWD"),
                buf_expr(new.as_os_str().as_bytes()),
                flags,
            ]
        };
        for (name, args, old_actions, old) in [
            (
                "link",
                vec![
                    buf_expr(link.as_os_str().as_bytes()),
                    buf_expr(new.as_os_str().as_bytes()),
                ],
                vec![ProgramAction::Read(link.clone())],
                &link,
            ),
            (
                "linkat",
                linkat(&dir_fd, b"link", int_literal(0)),
                vec![ProgramAction::Read(link.clone())],
                &link,
            ),
            (
                "linkat",
                linkat(&dir_fd, b"link", named_symbol("AT_SYMLINK_FOLLOW")),
                vec![
                    ProgramAction::Read(link.clone()),
                    ProgramAction::Read(target.clone()),
                ],
                &target,
            ),
            (
                "linkat",
                linkat(&target_fd, b"", named_symbol("AT_EMPTY_PATH")),
                vec![ProgramAction::Read(target.clone())],
                &target,
            ),
        ] {
            let mut expected = old_actions;
            expected.extend([
                ProgramAction::Create(new.clone()),
                ProgramAction::RequireSameMount(old.clone(), temp_dir.path().to_owned()),
                ProgramAction::Syscalls([name.into()].into()),
            ]);
            assert_eq!(
                summarize([Ok(syscall(name, args))], &[], program_state()).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn link_trailing_slash_follows_old_path() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let target_dir = temp_dir.path().join("target_dir");
        let link_dir = temp_dir.path().join("link_dir");
        let existing = temp_dir.path().join("existing");
        fs::create_dir(&target_dir).unwrap();
        unix::fs::symlink(&target_dir, &link_dir).unwrap();
        unix::fs::symlink(temp_dir.path().join("missing"), &existing).unwrap();
        let dir_fd = fd_expr(3, temp_dir.path());
        // Failing with EEXIST, which the parser keeps, as hard linking a directory never succeeds
        for (name, args) in [
            (
                "link",
                vec![
                    buf_expr(&[link_dir.as_os_str().as_bytes(), b"/"].concat()),
                    buf_expr(existing.as_os_str().as_bytes()),
                ],
            ),
            (
                "linkat",
                vec![
                    dir_fd.clone(),
                    buf_expr(b"link_dir/"),
                    dir_fd,
                    buf_expr(b"existing"),
                    int_literal(0),
                ],
            ),
        ] {
            let sc = make_syscall(name, args, -1);
            assert_eq!(
                summarize_syscall(sc),
                vec![
                    ProgramAction::Read(link_dir.clone()),
                    ProgramAction::Read(target_dir.clone()),
                    ProgramAction::Read(existing.clone()),
                    ProgramAction::Create(existing.clone()),
                    ProgramAction::RequireSameMount(target_dir.clone(), temp_dir.path().to_owned()),
                    ProgramAction::Syscalls([name.into()].into()),
                ]
            );
        }
    }

    #[test]
    fn link_existing_requires_same_mount() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let existing = temp_dir.path().join("existing");
        File::create(&existing).unwrap();
        // Failing with EEXIST, which the parser keeps
        let link = make_syscall(
            "link",
            vec![buf_expr(b"/src"), buf_expr(existing.as_os_str().as_bytes())],
            -1,
        );
        assert_eq!(
            summarize_syscall(link),
            vec![
                ProgramAction::Read("/src".into()),
                ProgramAction::Read(existing.clone()),
                ProgramAction::Create(existing),
                ProgramAction::RequireSameMount("/src".into(), temp_dir.path().to_owned()),
                ProgramAction::Syscalls(["link".into()].into()),
            ]
        );
    }
}
