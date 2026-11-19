//! File opening and creation syscall handlers

use std::{
    ffi::OsStr,
    os::unix::{ffi::OsStrExt as _, fs::FileTypeExt as _},
    path::{Path, PathBuf},
};

use super::{
    ExtractArg as _, HandlerError, SyscallHandler,
    path::PathHandler,
    path_arg,
    walk::{PathWalk, is_pseudo_path, lookup_dir, resolve_path, traverse_path_within},
};
use crate::{
    strace::{Expression, IntegerExpression, Syscall},
    summarize::{ProgramState, action::ProgramAction},
};

/// Handler for open-like syscalls
pub(crate) struct OpenHandler {
    pub relfd: Option<usize>,
    pub path: usize,
    /// Index of the flags argument, or of the `open_how` struct argument for `openat2`, absent for `creat`
    pub flags: Option<usize>,
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

        let mut path = path_arg(path_expr)?.to_owned();

        // Resolve flags of openat2
        let mut resolve = None;
        let mut nofollow = false;
        let (create, exclusive, write, read) = if let Some(flags) = flags {
            let flags = if sc.name == "openat2" {
                let members = unpack_expr!(flags, Expression::Struct(members) => members);
                resolve = Some(unpack_expr!(
                    unpack_struct_member!(members, "resolve"),
                    Expression::Integer(IntegerExpression { value, .. }) => value
                ));
                unpack_struct_member!(members, "flags")
            } else {
                flags
            };
            let flags_val = unpack_expr!(flags, Expression::Integer(flags) => &flags.value);
            nofollow = flags_val.is_flag_set("O_NOFOLLOW");
            if flags_val.is_flag_set("O_PATH") {
                // Lookup only
                (false, false, false, true)
            } else if flags_val.is_flag_set("O_TMPFILE") {
                // Unnamed file in the opened directory, the returned fd path names a placeholder entry there
                (true, false, false, false)
            } else {
                let create = flags_val.is_flag_set("O_CREAT");
                (
                    create,
                    create && flags_val.is_flag_set("O_EXCL"),
                    flags_val.is_any_flag_set(&["O_WRONLY", "O_RDWR", "O_TRUNC"]),
                    flags_val.is_flag_set("O_RDONLY") || !flags_val.is_flag_set("O_WRONLY"),
                )
            }
        } else {
            // creat, same as O_CREAT|O_WRONLY|O_TRUNC
            (true, false, true, false)
        };

        // A final symlink is not followed by an exclusive creation, which fails on it, nor with O_NOFOLLOW, unless a
        // trailing slash or `.` component makes the kernel walk through it
        let path_bytes = path.as_os_str().as_bytes();
        let follow_last =
            !exclusive && (!nofollow || path_bytes.ends_with(b"/") || path_bytes.ends_with(b"/."));

        let in_root = resolve.is_some_and(|r| r.is_flag_set("RESOLVE_IN_ROOT"));
        // With RESOLVE_IN_ROOT, an absolute path is walked from the directory, like a relative one
        if in_root && path.is_absolute() {
            path = path.components().skip(1).collect();
        }
        let start = if path.is_absolute() {
            Some(PathBuf::from("/"))
        } else {
            lookup_dir(relfd, state.cur_dir.as_ref())
        };
        let (Some(start), Some(mut path)) =
            (start, resolve_path(&path, relfd, state.cur_dir.as_ref()))
        else {
            return Ok(());
        };
        let walk = PathWalk {
            start: &start,
            root: if in_root { &start } else { Path::new("/") },
            same_mount: resolve.is_some_and(|r| r.is_flag_set("RESOLVE_NO_XDEV")),
        };

        // Add actions for the path walk
        traverse_path_within(&mut path, &walk, follow_last, actions);

        if sc.is_successful()
            && let Some(metadata) = sc.ret_val.as_ref().and_then(|rv| rv.metadata.as_deref())
        {
            // Returned fd has normalized path, use it if we can
            path = PathBuf::from(OsStr::from_bytes(metadata));
        }

        // A creation failing on an existing entry, like with O_EXCL, depends on it
        let existing = create && !sc.is_successful();
        if !is_pseudo_path(&path) {
            let char_device = path
                .metadata()
                .is_ok_and(|m| m.file_type().is_char_device());
            if char_device && sc.is_successful() {
                // A char device is never created by the open that returns it
                actions.push(ProgramAction::Read(path));
            } else {
                // Set actions from flags
                if existing {
                    actions.push(ProgramAction::Read(path.clone()));
                }
                if create {
                    actions.push(ProgramAction::Create(path.clone()));
                }
                // Character devices remain writable on a read-only filesystem
                if write && !char_device {
                    actions.push(ProgramAction::Write(path.clone()));
                }
                if read && !existing {
                    assert!(!path.to_str().is_some_and(|p| p.starts_with("net:")));
                    actions.push(ProgramAction::Read(path.clone()));
                }
            }
        }

        Ok(())
    }
}

/// Handler for mknod-like syscalls
pub(crate) struct MknodHandler {
    pub path: PathHandler,
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
        let mode = unpack_expr!(mode, Expression::Integer(mode) => mode);

        if mode.value.is_any_flag_set(&PRIVILEGED_ST_MODES) {
            actions.push(ProgramAction::MknodSpecial);
        }
        self.path.handle(sc, actions, state)
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
    use crate::{
        strace::{IntegerExpressionValue, SyscallItem},
        summarize::{
            handlers::{
                FollowSymlink,
                tests::{
                    binary_or_flags, buf_expr, fd_expr, int_literal, make_syscall, named_symbol,
                    summarize_syscall, syscall,
                },
            },
            program_state, summarize,
        },
    };

    #[test]
    fn creat_creates_path() {
        let _ = simple_logger::SimpleLogger::new().init();

        let syscalls = [Ok(syscall(
            "creat",
            vec![buf_expr(b"/var/lib/test"), int_literal(0o644)],
        ))];
        assert_eq!(
            summarize(syscalls, &[], program_state()).unwrap(),
            vec![
                ProgramAction::Create("/var/lib/test".into()),
                ProgramAction::Write("/var/lib/test".into()),
                ProgramAction::Syscalls(["creat".into()].into()),
            ]
        );
    }

    #[test]
    fn creat_creates_pseudo_file_name() {
        let _ = simple_logger::SimpleLogger::new().init();

        let syscalls = [Ok(syscall(
            "creat",
            vec![buf_expr(b"backup:[20261115]"), int_literal(0o644)],
        ))];
        assert_eq!(
            summarize(syscalls, &[], program_state()).unwrap(),
            vec![
                ProgramAction::Create("/backup:[20261115]".into()),
                ProgramAction::Write("/backup:[20261115]".into()),
                ProgramAction::Syscalls(["creat".into()].into()),
            ]
        );
    }

    #[test]
    fn openat2_actions_follow_flags() {
        let _ = simple_logger::SimpleLogger::new().init();

        for (flags, actions) in [
            (
                &["O_RDWR", "O_CREAT", "O_CLOEXEC"][..],
                vec![
                    ProgramAction::Create("/var/lib/test".into()),
                    ProgramAction::Write("/var/lib/test".into()),
                    ProgramAction::Read("/var/lib/test".into()),
                ],
            ),
            (
                &["O_RDONLY"],
                vec![ProgramAction::Read("/var/lib/test".into())],
            ),
            (
                &["O_WRONLY"],
                vec![ProgramAction::Write("/var/lib/test".into())],
            ),
            (
                &["O_RDONLY", "O_TRUNC"],
                vec![
                    ProgramAction::Write("/var/lib/test".into()),
                    ProgramAction::Read("/var/lib/test".into()),
                ],
            ),
        ] {
            let syscalls = [Ok(openat2_resolve(
                fd_expr(3, "/var/lib"),
                "test",
                flags,
                &[],
            ))];
            assert_eq!(
                summarize(syscalls, &[], program_state()).unwrap(),
                [
                    actions,
                    vec![ProgramAction::Syscalls(["openat2".into()].into())]
                ]
                .concat()
            );
        }
    }

    /// Build an `openat2` call with open and resolve flags
    fn openat2_resolve(
        dirfd: Expression,
        path: &str,
        flags: &[&str],
        resolve: &[&str],
    ) -> SyscallItem {
        syscall(
            "openat2",
            vec![
                dirfd,
                buf_expr(path.as_bytes()),
                Expression::Struct(HashMap::from([
                    ("flags".to_owned(), binary_or_flags(flags)),
                    ("resolve".to_owned(), binary_or_flags(resolve)),
                ])),
                int_literal(24),
            ],
        )
    }

    #[test]
    fn openat2_in_root_symlink() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let root = temp_dir.path();
        fs::create_dir_all(root.join("usr/lib")).unwrap();
        File::create(root.join("usr/lib/file")).unwrap();
        unix::fs::symlink("usr/lib", root.join("lib")).unwrap();
        unix::fs::symlink("/lib/file", root.join("abs")).unwrap();
        // The root as a directory descriptor or as the working directory
        for (dirfd, cur_dir) in [
            (fd_expr(3, root), Path::new("/")),
            (named_symbol("AT_FDCWD"), root),
        ] {
            for (path, links) in [
                ("/lib/file", &["lib"][..]),
                // `..` stops at the root
                ("../../lib/file", &["lib"]),
                ("abs", &["abs", "lib"]),
            ] {
                let syscalls = [Ok(openat2_resolve(
                    dirfd.clone(),
                    path,
                    &["O_RDONLY"],
                    &["RESOLVE_IN_ROOT"],
                ))];
                assert_eq!(
                    summarize(syscalls, &[], ProgramState::new(cur_dir, false)).unwrap(),
                    links
                        .iter()
                        .map(|l| ProgramAction::Read(root.join(l)))
                        .chain([
                            ProgramAction::Read(root.join("usr/lib/file")),
                            ProgramAction::Syscalls(["openat2".into()].into()),
                        ])
                        .collect::<Vec<_>>()
                );
            }
        }
    }

    #[test]
    fn openat2_no_xdev_same_mount() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let dir = temp_dir.path();
        let sub = dir.join("sub");
        fs::create_dir(&sub).unwrap();
        unix::fs::symlink("sub", dir.join("link")).unwrap();
        let abs_path = sub.join("file");
        unix::fs::symlink(&abs_path, dir.join("abs")).unwrap();
        // Walk of the absolute path from a start directory
        let abs_walk = |start: &Path| {
            let mut actions: Vec<_> = abs_path
                .ancestors()
                .filter(|p| *p != start)
                .map(|p| ProgramAction::RequireSameMount(start.to_owned(), p.to_owned()))
                .collect();
            actions.reverse();
            actions.push(ProgramAction::Read(abs_path.clone()));
            actions
        };
        for (dirfd, path, resolve, mut actions) in [
            // An absolute path is walked from the root directory
            (
                named_symbol("AT_FDCWD"),
                abs_path.to_str().unwrap(),
                &["RESOLVE_NO_XDEV"][..],
                abs_walk(Path::new("/")),
            ),
            (
                fd_expr(3, dir),
                "sub/file",
                &["RESOLVE_NO_XDEV"],
                vec![
                    ProgramAction::RequireSameMount(dir.to_owned(), sub.clone()),
                    ProgramAction::RequireSameMount(dir.to_owned(), sub.join("file")),
                    ProgramAction::Read(sub.join("file")),
                ],
            ),
            (
                fd_expr(3, &sub),
                "../file",
                &["RESOLVE_NO_XDEV"],
                vec![
                    ProgramAction::Read(sub.clone()),
                    ProgramAction::RequireSameMount(sub.clone(), dir.to_owned()),
                    ProgramAction::RequireSameMount(sub.clone(), dir.join("file")),
                    ProgramAction::Read(dir.join("file")),
                ],
            ),
            (
                fd_expr(3, dir),
                "link/file",
                &["RESOLVE_NO_XDEV"],
                vec![
                    ProgramAction::Read(dir.join("link")),
                    ProgramAction::RequireSameMount(dir.to_owned(), sub.clone()),
                    ProgramAction::RequireSameMount(dir.to_owned(), sub.join("file")),
                    ProgramAction::Read(sub.join("file")),
                ],
            ),
            // An absolute symlink target is walked from the root directory
            (
                fd_expr(3, dir),
                "abs",
                &["RESOLVE_NO_XDEV"],
                [vec![ProgramAction::Read(dir.join("abs"))], abs_walk(dir)].concat(),
            ),
            // An absolute path is walked from the directory with RESOLVE_IN_ROOT
            (
                fd_expr(3, dir),
                "/sub/file",
                &["RESOLVE_IN_ROOT", "RESOLVE_NO_XDEV"],
                vec![
                    ProgramAction::RequireSameMount(dir.to_owned(), sub.clone()),
                    ProgramAction::RequireSameMount(dir.to_owned(), sub.join("file")),
                    ProgramAction::Read(sub.join("file")),
                ],
            ),
        ] {
            let syscalls = [Ok(openat2_resolve(dirfd, path, &["O_RDONLY"], resolve))];
            actions.push(ProgramAction::Syscalls(["openat2".into()].into()));
            assert_eq!(summarize(syscalls, &[], program_state()).unwrap(), actions);
        }
    }

    #[test]
    fn openat2_no_xdev_no_follow() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let dir = temp_dir.path();
        let sub = dir.join("sub");
        let link = dir.join("link");
        fs::create_dir(&sub).unwrap();
        unix::fs::symlink("sub", &link).unwrap();
        let followed = vec![
            ProgramAction::Read(link.clone()),
            ProgramAction::RequireSameMount(dir.to_owned(), sub.clone()),
            ProgramAction::Read(sub.clone()),
        ];
        for (path, mut actions) in [
            (
                "link",
                vec![
                    ProgramAction::RequireSameMount(dir.to_owned(), link.clone()),
                    ProgramAction::Read(link.clone()),
                ],
            ),
            // A trailing slash or `.` component walks through the symlink
            ("link/", followed.clone()),
            ("link/.", followed),
        ] {
            let syscalls = [Ok(openat2_resolve(
                fd_expr(3, dir),
                path,
                &["O_NOFOLLOW", "O_PATH"],
                &["RESOLVE_NO_XDEV"],
            ))];
            actions.push(ProgramAction::Syscalls(["openat2".into()].into()));
            assert_eq!(summarize(syscalls, &[], program_state()).unwrap(), actions);
        }
    }

    #[test]
    fn open_tmpfile_creates_in_dir() {
        let _ = simple_logger::SimpleLogger::new().init();

        // glibc's tmpfile()
        let syscalls = [Ok(SyscallItem::Complete(Box::new(Syscall {
            ret_val: Some(IntegerExpression {
                value: IntegerExpressionValue::Literal(3),
                metadata: Some(b"/tmp/#80".to_vec()),
            }),
            ..make_syscall(
                "openat",
                vec![
                    named_symbol("AT_FDCWD"),
                    buf_expr(b"/tmp"),
                    binary_or_flags(&["O_RDWR", "O_CLOEXEC", "O_TMPFILE"]),
                    int_literal(0o600),
                ],
                3,
            )
        })))];
        assert_eq!(
            summarize(syscalls, &[], program_state()).unwrap(),
            vec![
                ProgramAction::Create("/tmp/#80".into()),
                ProgramAction::Syscalls(["openat".into()].into()),
            ]
        );
    }

    #[test]
    fn open_path_ignores_tmpfile() {
        let _ = simple_logger::SimpleLogger::new().init();

        let syscalls = [Ok(syscall(
            "openat",
            vec![
                named_symbol("AT_FDCWD"),
                buf_expr(b"/tmp/cache"),
                binary_or_flags(&["O_RDWR", "O_CLOEXEC", "O_PATH", "O_TMPFILE"]),
                int_literal(0o777),
            ],
        ))];
        assert_eq!(
            summarize(syscalls, &[], program_state()).unwrap(),
            vec![
                ProgramAction::Read("/tmp/cache".into()),
                ProgramAction::Syscalls(["openat".into()].into()),
            ]
        );
    }

    #[test]
    fn open_excl_existing_reads() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let existing = temp_dir.path().join("existing");
        File::create(&existing).unwrap();
        let existing_bytes = existing.as_os_str().as_bytes();
        let flags = ["O_RDWR", "O_CREAT", "O_EXCL"];
        // Failing with EEXIST, which the parser keeps
        for (name, args) in [
            (
                "open",
                vec![
                    buf_expr(existing_bytes),
                    binary_or_flags(&flags),
                    int_literal(0o644),
                ],
            ),
            (
                "openat",
                vec![
                    named_symbol("AT_FDCWD"),
                    buf_expr(existing_bytes),
                    binary_or_flags(&flags),
                    int_literal(0o644),
                ],
            ),
            (
                "openat2",
                vec![
                    named_symbol("AT_FDCWD"),
                    buf_expr(existing_bytes),
                    Expression::Struct(HashMap::from([
                        ("flags".to_owned(), binary_or_flags(&flags)),
                        ("mode".to_owned(), int_literal(0o644)),
                        ("resolve".to_owned(), int_literal(0)),
                    ])),
                    int_literal(24),
                ],
            ),
        ] {
            let sc = make_syscall(name, args, -1);
            assert_eq!(
                summarize_syscall(sc),
                vec![
                    ProgramAction::Read(existing.clone()),
                    ProgramAction::Create(existing.clone()),
                    ProgramAction::Write(existing.clone()),
                    ProgramAction::Syscalls([name.into()].into()),
                ]
            );
        }
    }

    #[test]
    fn open_char_device_reads() {
        let _ = simple_logger::SimpleLogger::new().init();

        for flags in [
            &["O_WRONLY"][..],
            &["O_WRONLY", "O_CREAT", "O_TRUNC"],
            &["O_RDWR"],
        ] {
            let sc = make_syscall(
                "openat",
                vec![
                    named_symbol("AT_FDCWD"),
                    buf_expr(b"/dev/null"),
                    binary_or_flags(flags),
                    int_literal(0o666),
                ],
                3,
            );
            assert_eq!(
                summarize_syscall(sc),
                vec![
                    ProgramAction::Read("/dev/null".into()),
                    ProgramAction::Syscalls(["openat".into()].into()),
                ]
            );
        }

        // Failing with EEXIST, which the parser keeps, on a symlink the exclusive creation does not follow
        let temp_dir = tempfile::tempdir().unwrap();
        let link = temp_dir.path().join("link");
        unix::fs::symlink("/dev/null", &link).unwrap();
        let sc = make_syscall(
            "openat",
            vec![
                named_symbol("AT_FDCWD"),
                buf_expr(link.as_os_str().as_bytes()),
                binary_or_flags(&["O_WRONLY", "O_CREAT", "O_EXCL"]),
                int_literal(0o666),
            ],
            -1,
        );
        assert_eq!(
            summarize_syscall(sc),
            vec![
                ProgramAction::Read(link.clone()),
                ProgramAction::Create(link),
                ProgramAction::Syscalls(["openat".into()].into()),
            ]
        );
    }

    #[test]
    fn open_excl_existing_symlink_no_follow() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let parent = temp_dir.path().join("parent");
        fs::create_dir(&parent).unwrap();
        let alias = temp_dir.path().join("alias");
        unix::fs::symlink(&parent, &alias).unwrap();
        let target = temp_dir.path().join("target");
        let link = parent.join("link");
        File::create(&target).unwrap();
        unix::fs::symlink(&target, &link).unwrap();
        // Failing with EEXIST, which the parser keeps
        let sc = make_syscall(
            "openat",
            vec![
                named_symbol("AT_FDCWD"),
                buf_expr(alias.join("link").as_os_str().as_bytes()),
                binary_or_flags(&["O_WRONLY", "O_CREAT", "O_EXCL"]),
                int_literal(0o644),
            ],
            -1,
        );
        assert_eq!(
            summarize_syscall(sc),
            vec![
                ProgramAction::Read(alias),
                ProgramAction::Read(link.clone()),
                ProgramAction::Create(link.clone()),
                ProgramAction::Write(link),
                ProgramAction::Syscalls(["openat".into()].into()),
            ]
        );
    }

    #[test]
    fn mknod_handler_regular_file() {
        let handler = MknodHandler {
            path: PathHandler {
                relfd: None,
                path: 0,
                follow: FollowSymlink::Never,
                action: ProgramAction::Create,
            },
            mode: 1,
        };
        let sc = make_syscall(
            "mknod",
            vec![buf_expr(b"/tmp/file"), int_literal(0o100_644)],
            0,
        );
        let mut actions = vec![];
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(actions, vec![ProgramAction::Create("/tmp/file".into())]);
    }

    #[test]
    fn mknod_handler_special_device() {
        let handler = MknodHandler {
            path: PathHandler {
                relfd: None,
                path: 0,
                follow: FollowSymlink::Never,
                action: ProgramAction::Create,
            },
            mode: 1,
        };
        for mode in ["S_IFBLK", "S_IFCHR"] {
            let sc = make_syscall("mknod", vec![buf_expr(b"/tmp/dev"), named_symbol(mode)], 0);
            let mut actions = vec![];
            let mut state = program_state();

            handler.handle(&sc, &mut actions, &mut state).unwrap();
            assert_eq!(
                actions,
                vec![
                    ProgramAction::MknodSpecial,
                    ProgramAction::Create("/tmp/dev".into())
                ]
            );
        }
    }

    #[test]
    fn mknod_existing_reads() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        // A dangling symlink, which the creation does not follow
        let existing = temp_dir.path().join("existing");
        unix::fs::symlink(temp_dir.path().join("missing"), &existing).unwrap();
        let existing_bytes = existing.as_os_str().as_bytes();
        for (name, args) in [
            (
                "mknod",
                vec![
                    buf_expr(existing_bytes),
                    binary_or_flags(&["S_IFIFO"]),
                    int_literal(0),
                ],
            ),
            (
                "mknodat",
                vec![
                    named_symbol("AT_FDCWD"),
                    buf_expr(existing_bytes),
                    binary_or_flags(&["S_IFIFO"]),
                    int_literal(0),
                ],
            ),
        ] {
            // Failing with EEXIST, which the parser keeps
            assert_eq!(
                summarize_syscall(make_syscall(name, args, -1)),
                vec![
                    ProgramAction::Read(existing.clone()),
                    ProgramAction::Create(existing.clone()),
                    ProgramAction::Syscalls([name.into()].into()),
                ]
            );
        }
    }

    #[test]
    fn mknodat_creates_path() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let fifo = temp_dir.path().join("fifo");
        for (dir_fd, path) in [
            (fd_expr(3, temp_dir.path()), buf_expr(b"fifo")),
            (
                named_symbol("AT_FDCWD"),
                buf_expr(fifo.as_os_str().as_bytes()),
            ),
        ] {
            let args = vec![dir_fd, path, binary_or_flags(&["S_IFIFO"])];
            assert_eq!(
                summarize([Ok(syscall("mknodat", args))], &[], program_state()).unwrap(),
                vec![
                    ProgramAction::Create(fifo.clone()),
                    ProgramAction::Syscalls(["mknodat".into()].into()),
                ]
            );
        }
    }

    #[test]
    fn mknod_through_symlink() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let target_dir = temp_dir.path().join("target_dir");
        let link_dir = temp_dir.path().join("link_dir");
        fs::create_dir(&target_dir).unwrap();
        unix::fs::symlink(&target_dir, &link_dir).unwrap();
        let fifo = link_dir.join("fifo");
        let fifo_bytes = fifo.as_os_str().as_bytes();
        for (name, args) in [
            (
                "mknod",
                vec![buf_expr(fifo_bytes), binary_or_flags(&["S_IFIFO"])],
            ),
            (
                "mknodat",
                vec![
                    named_symbol("AT_FDCWD"),
                    buf_expr(fifo_bytes),
                    binary_or_flags(&["S_IFIFO"]),
                ],
            ),
        ] {
            assert_eq!(
                summarize([Ok(syscall(name, args))], &[], program_state()).unwrap(),
                vec![
                    ProgramAction::Read(link_dir.clone()),
                    ProgramAction::Create(target_dir.join("fifo")),
                    ProgramAction::Syscalls([name.into()].into()),
                ]
            );
        }
    }
}
