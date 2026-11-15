//! Path resolution and walks

use std::{
    ffi::OsStr,
    os::unix::ffi::OsStrExt as _,
    path::{Component, Path, PathBuf},
    sync::LazyLock,
};

use path_clean::PathClean as _;

use crate::{strace::Expression, summarize::action::ProgramAction};

/// Get the directory a relative path is looked up from, unless it is a pseudo file
pub(super) fn lookup_dir(relfd: Option<&Expression>, cur_dir: &Path) -> Option<PathBuf> {
    match relfd.and_then(|a| a.metadata()) {
        Some(metadata) if is_fd_pseudo_path(metadata) => None,
        Some(metadata) => Some(PathBuf::from(OsStr::from_bytes(metadata))),
        None => Some(cur_dir.to_owned()),
    }
}

/// Make a path absolute if possible, normalizing its separators and `.` components but not its `..` components
pub(super) fn resolve_path(
    path: &Path,
    relfd: Option<&Expression>,
    cur_dir: &Path,
) -> Option<PathBuf> {
    let path = if path.is_relative() {
        lookup_dir(relfd, cur_dir)?.join(path)
    } else {
        path.to_path_buf()
    };
    Some(path.components().collect())
}

/// Bounds of a path walk
pub(crate) struct PathWalk<'a> {
    /// Absolute starting directory and required prefix of the walked path
    pub start: &'a Path,
    /// Directory absolute symlink targets restart from, and `..` stops at
    pub root: &'a Path,
    /// Whether every entered path must be on the mount of the start directory
    pub same_mount: bool,
}

/// Resolve the path, following its final symlink only if `follow_last`, and record reads of followed symlinks
/// and directories exited through `..`
pub(super) fn traverse_path(
    in_path: &mut PathBuf,
    follow_last: bool,
    actions: &mut Vec<ProgramAction>,
) {
    let root = Path::new("/");
    let walk = PathWalk {
        start: root,
        root,
        same_mount: false,
    };
    traverse_path_within(in_path, &walk, follow_last, actions);
}

/// Resolve the path within the bounds of a walk, following its final symlink only if `follow_last`, and record
/// reads of followed symlinks and directories exited through `..`, and the mount requirements of the walk
pub(crate) fn traverse_path_within(
    in_path: &mut PathBuf,
    walk: &PathWalk<'_>,
    follow_last: bool,
    actions: &mut Vec<ProgramAction>,
) {
    /// Max number of symlinks followed in a path walk, like the kernel
    const MAX_LINK_COUNT: usize = 40;

    debug_assert!(walk.start.is_absolute() && in_path.starts_with(walk.start));
    let mut walk_actions = Vec::new();
    let mut link_count = 0;
    let mut resolved = walk.start.to_owned();
    let mut remaining = in_path.clone();
    let mut components = remaining.components();
    // The walk starts past the start directory
    for _ in walk.start.components() {
        components.next();
    }
    while let Some(component) = components.next() {
        match component {
            Component::RootDir => walk.root.clone_into(&mut resolved),
            Component::ParentDir if resolved != walk.root => {
                walk_actions.push(ProgramAction::Read(resolved.clone()));
                resolved.pop();
            }
            Component::ParentDir | Component::CurDir | Component::Prefix(_) => continue,
            Component::Normal(name) => {
                let path = resolved.join(name);
                let follow = follow_last || !components.as_path().as_os_str().is_empty();
                if follow && let Ok(target) = path.read_link() {
                    if link_count >= MAX_LINK_COUNT {
                        // A symlink loop fails the lookup
                        *in_path = in_path.clean();
                        return;
                    }
                    link_count += 1;
                    walk_actions.push(ProgramAction::Read(path.clone()));
                    // A pseudo file, ie the target of /proc/[PID]/ns/net, has no path to walk
                    if !is_pseudo_path(&target) {
                        // The target is walked in place of the symlink, from the symlink directory if relative
                        remaining = target.join(components.as_path());
                        components = remaining.components();
                        continue;
                    }
                }
                resolved = path;
            }
        }
        if walk.same_mount && resolved != walk.start {
            walk_actions.push(ProgramAction::RequireSameMount(
                walk.start.to_owned(),
                resolved.clone(),
            ));
        }
    }
    *in_path = resolved;
    actions.extend(walk_actions);
}

/// Tell whether fd metadata names no file of the filesystem tree
pub(super) fn is_fd_pseudo_path(metadata: &[u8]) -> bool {
    #[expect(clippy::unwrap_used)]
    static SOCKET_DETAILS_REGEX_BYTES: LazyLock<regex::bytes::Regex> = LazyLock::new(|| {
        regex::bytes::Regex::new(r"(?s-u)^[0-9A-Za-z][0-9A-Za-z/-]*:\[.*\]$").unwrap()
    });
    is_pseudo_path(Path::new(OsStr::from_bytes(metadata)))
        || SOCKET_DETAILS_REGEX_BYTES.is_match(metadata)
}

/// Tell whether a path is the kernel's name for a file outside the filesystem tree
pub(super) fn is_pseudo_path(path: &Path) -> bool {
    #[expect(clippy::unwrap_used)]
    static PSEUDO_PATH_REGEX_BYTES: LazyLock<regex::bytes::Regex> = LazyLock::new(|| {
        regex::bytes::Regex::new(r"^(?:[a-z]+:\[[0-9a-z]+\]/?$|/memfd:)").unwrap()
    });
    PSEUDO_PATH_REGEX_BYTES.is_match(path.as_os_str().as_bytes())
}

#[cfg(test)]
mod tests {
    use std::{fs, fs::File, os::unix, process};

    use super::*;

    #[test]
    fn is_socket_or_pipe_pseudo_path() {
        assert!(!is_fd_pseudo_path("plop".as_bytes()));
        assert!(is_fd_pseudo_path("pipe:[12334]".as_bytes()));
        assert!(is_fd_pseudo_path("socket:[1234]/".as_bytes()));
        assert!(!is_fd_pseudo_path("/srv/data:[1234]".as_bytes()));
    }

    #[test]
    fn traverse_path_lib() {
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
        let mut actions = Vec::new();
        traverse_path(&mut in_path, true, &mut actions);
        assert_eq!(
            actions,
            vec![
                ProgramAction::Read(tmp_dir.path().join("lib")),
                ProgramAction::Read(
                    tmp_dir
                        .path()
                        .join("usr/lib/x86_64-linux-gnu/libselinux.so")
                )
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
    fn traverse_path_parent() {
        let tmp_dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp_dir.path().join("a/b")).unwrap();
        fs::create_dir_all(tmp_dir.path().join("d/e")).unwrap();
        unix::fs::symlink("../../d", tmp_dir.path().join("a/b/c")).unwrap();

        let mut in_path = tmp_dir.path().join("a/b/c/e");
        let mut actions = Vec::new();
        traverse_path(&mut in_path, true, &mut actions);
        assert_eq!(
            actions,
            vec![
                ProgramAction::Read(tmp_dir.path().join("a/b/c")),
                ProgramAction::Read(tmp_dir.path().join("a/b")),
                ProgramAction::Read(tmp_dir.path().join("a"))
            ]
        );
        assert_eq!(in_path, tmp_dir.path().join("d/e"));
    }

    #[test]
    fn traverse_path_loop() {
        let tmp_dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp_dir.path().join("a/b")).unwrap();
        // Walking the target reaches the symlink itself again
        unix::fs::symlink(
            tmp_dir.path().join("a/b/c/../.."),
            tmp_dir.path().join("a/b/c"),
        )
        .unwrap();

        let mut in_path = tmp_dir.path().join("a/b/c/e");
        let mut actions = Vec::new();
        traverse_path(&mut in_path, true, &mut actions);
        assert!(actions.is_empty());
        assert_eq!(in_path, tmp_dir.path().join("a/b/c/e"));
    }

    /// Create a chain of `count` symlinks in `dir`, the last one pointing to `target`, and get their paths in walk
    /// order
    fn symlink_chain(dir: &Path, count: usize, target: &Path) -> Vec<PathBuf> {
        let links: Vec<_> = (0..count).map(|i| dir.join(format!("link{i}"))).collect();
        for (i, link) in links.iter().enumerate() {
            unix::fs::symlink(links.get(i + 1).map_or(target, PathBuf::as_path), link).unwrap();
        }
        links
    }

    #[test]
    fn traverse_path_link_limit() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let dir = tmp_dir.path().join("dir");
        fs::create_dir(&dir).unwrap();
        let mut links = symlink_chain(tmp_dir.path(), 20, &dir);
        links.extend(symlink_chain(&dir, 20, &dir.join("file")));

        let mut in_path = tmp_dir.path().join("link0/link0");
        let mut actions = Vec::new();
        traverse_path(&mut in_path, true, &mut actions);
        assert_eq!(
            actions,
            links
                .into_iter()
                .map(ProgramAction::Read)
                .collect::<Vec<_>>()
        );
        assert_eq!(in_path, dir.join("file"));
    }

    #[test]
    fn traverse_path_link_limit_exceeded() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let dir = tmp_dir.path().join("dir");
        fs::create_dir(&dir).unwrap();
        symlink_chain(tmp_dir.path(), 21, &dir);
        symlink_chain(&dir, 20, &dir.join("file"));

        let mut in_path = tmp_dir.path().join("link0/link0");
        let mut actions = Vec::new();
        traverse_path(&mut in_path, true, &mut actions);
        assert!(actions.is_empty());
        assert_eq!(in_path, tmp_dir.path().join("link0/link0"));
    }

    #[test]
    fn traverse_path_pseudo_target() {
        let ns_path = PathBuf::from(format!("/proc/{pid}/ns/net", pid = process::id()));
        let mut in_path = PathBuf::from("/proc/self/ns/net");
        let mut actions = Vec::new();
        traverse_path(&mut in_path, true, &mut actions);
        assert_eq!(
            actions,
            vec![
                ProgramAction::Read("/proc/self".into()),
                ProgramAction::Read(ns_path.clone())
            ]
        );
        assert_eq!(in_path, ns_path);
    }
}
