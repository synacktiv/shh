//! Syscall handlers by syscall name

use super::{
    action::ProgramAction,
    handlers::{
        AccessHandler, ChdirHandler, Clone3Handler, DupHandler, DupQualifier, EpollCtlHandler,
        ExecHandler, FanotifyMarkHandler, FdOrPath, FdWriteHandler, FollowSymlink, ForkHandler,
        IoctlHandler, KillHandler, LinkHandler, MemfdCreateHandler, MknodHandler, MmapHandler,
        MountHandler, NetworkHandler, OpenHandler, PathHandler, RemoveHandler, RenameHandler,
        SetSchedulerHandler, SetsockoptHandler, ShmAtHandler, ShmCtlHandler, SockaddrArg,
        SocketHandler, StatFdHandler, SyscallHandler, TimerHandler, UnshareHandler,
    },
};

//
// For some reference on syscalls, see:
// - https://man7.org/linux/man-pages/man2/syscalls.2.html
// - https://filippo.io/linux-syscall-table/
// - https://linasm.sourceforge.net/docs/syscalls/filesystem.php
//
// 32-bit ABI names share the entry of their 64-bit call, the only exception to the alphabetical order of keys
//
pub(super) static SYSCALL_MAP: phf::Map<&'static str, &'static dyn SyscallHandler> = phf::phf_map! {
    "accept" => &NetworkHandler { fd: 0, sockaddr: SockaddrArg::Sockaddr(1) },
    "accept4" => &NetworkHandler { fd: 0, sockaddr: SockaddrArg::Sockaddr(1) },
    "access" => &AccessHandler {
        path: PathHandler {
            relfd: None,
            path: 0,
            follow: FollowSymlink::Always,
            action: ProgramAction::Read,
        },
        mode: 1,
    },
    "bind" => &NetworkHandler { fd: 0, sockaddr: SockaddrArg::Sockaddr(1) },
    "chdir" => &ChdirHandler {
        path: FdOrPath::Path(0),
    },
    "chmod" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::Always,
        action: ProgramAction::Write,
    },
    "chown" | "chown32" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::Always,
        action: ProgramAction::Write,
    },
    "clock_nanosleep" | "clock_nanosleep_time64" => &TimerHandler { clockid: 0 },
    // Note: strace decodes clone's arguments as a struct, like clone3
    "clone" => &Clone3Handler { args: 0 },
    "clone3" => &Clone3Handler { args: 0 },
    "connect" => &NetworkHandler { fd: 0, sockaddr: SockaddrArg::Sockaddr(1) },
    "creat" => &OpenHandler {
        relfd: None,
        path: 0,
        flags: None,
    },
    "dup" => &DupHandler { fd: 0, qualifier: None },
    "dup2" => &DupHandler { fd: 0, qualifier: None },
    "dup3" => &DupHandler { fd: 0, qualifier: None },
    "epoll_ctl" => &EpollCtlHandler { op: 1, event: 3 },
    "execve" => &ExecHandler {
        relfd: None,
        path: 0,
    },
    "execveat" => &ExecHandler {
        relfd: Some(0),
        path: 1,
    },
    "faccessat" => &AccessHandler {
        path: PathHandler {
            relfd: Some(0),
            path: 1,
            follow: FollowSymlink::Always,
            action: ProgramAction::Read,
        },
        mode: 2,
    },
    "faccessat2" => &AccessHandler {
        path: PathHandler {
            relfd: Some(0),
            path: 1,
            follow: FollowSymlink::UnlessNoFollowFlag {
                flags: 3,
                no_follow_flag: "AT_SYMLINK_NOFOLLOW",
            },
            action: ProgramAction::Read,
        },
        mode: 2,
    },
    "fanotify_mark" => &FanotifyMarkHandler {
        path: PathHandler {
            relfd: Some(3),
            path: 4,
            follow: FollowSymlink::UnlessNoFollowFlag {
                flags: 1,
                no_follow_flag: "FAN_MARK_DONT_FOLLOW",
            },
            action: ProgramAction::Read,
        },
        flags: 1,
    },
    "fchdir" => &ChdirHandler {
        path: FdOrPath::Fd(0),
    },
    "fchmod" => &FdWriteHandler { fd: 0 },
    "fchmodat" => &PathHandler {
        relfd: Some(0),
        path: 1,
        follow: FollowSymlink::Always,
        action: ProgramAction::Write,
    },
    "fchmodat2" => &PathHandler {
        relfd: Some(0),
        path: 1,
        follow: FollowSymlink::UnlessNoFollowFlag {
            flags: 3,
            no_follow_flag: "AT_SYMLINK_NOFOLLOW",
        },
        action: ProgramAction::Write,
    },
    "fchown" | "fchown32" => &FdWriteHandler { fd: 0 },
    "fchownat" => &PathHandler {
        relfd: Some(0),
        path: 1,
        follow: FollowSymlink::UnlessNoFollowFlag {
            flags: 4,
            no_follow_flag: "AT_SYMLINK_NOFOLLOW",
        },
        action: ProgramAction::Write,
    },
    "fcntl" | "fcntl64" => &DupHandler { fd: 0, qualifier: Some(DupQualifier::FcntlCmd(1)) },
    "file_getattr" => &PathHandler {
        relfd: Some(0),
        path: 1,
        follow: FollowSymlink::UnlessNoFollowFlag {
            flags: 4,
            no_follow_flag: "AT_SYMLINK_NOFOLLOW",
        },
        action: ProgramAction::Read,
    },
    "file_setattr" => &PathHandler {
        relfd: Some(0),
        path: 1,
        follow: FollowSymlink::UnlessNoFollowFlag {
            flags: 4,
            no_follow_flag: "AT_SYMLINK_NOFOLLOW",
        },
        action: ProgramAction::Write,
    },
    "fork" => &ForkHandler,
    "fremovexattr" => &FdWriteHandler { fd: 0 },
    "fsetxattr" => &FdWriteHandler { fd: 0 },
    "fstat" | "fstat64" | "oldfstat" => &StatFdHandler { fd: 0 },
    "futimesat" => &PathHandler {
        relfd: Some(0),
        path: 1,
        follow: FollowSymlink::Always,
        action: ProgramAction::Write,
    },
    "getdents" | "readdir" => &StatFdHandler { fd: 0 },
    "getxattr" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::Always,
        action: ProgramAction::Read,
    },
    "getxattrat" => &PathHandler {
        relfd: Some(0),
        path: 1,
        follow: FollowSymlink::UnlessNoFollowFlag {
            flags: 2,
            no_follow_flag: "AT_SYMLINK_NOFOLLOW",
        },
        action: ProgramAction::Read,
    },
    "inotify_add_watch" => &PathHandler {
        relfd: None,
        path: 1,
        follow: FollowSymlink::UnlessNoFollowFlag {
            flags: 2,
            no_follow_flag: "IN_DONT_FOLLOW",
        },
        action: ProgramAction::Read,
    },
    "ioctl" => &IoctlHandler { fd: 0, request: 1 },
    "kill" => &KillHandler { pid: 0, sig: 1 },
    "lchown" | "lchown32" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::OnTrailingSlash,
        action: ProgramAction::Write,
    },
    "lgetxattr" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::OnTrailingSlash,
        action: ProgramAction::Read,
    },
    "link" => &LinkHandler {
        old: PathHandler {
            relfd: None,
            path: 0,
            follow: FollowSymlink::OnTrailingSlash,
            action: ProgramAction::Read,
        },
        new: PathHandler {
            relfd: None,
            path: 1,
            follow: FollowSymlink::Never,
            action: ProgramAction::Create,
        },
    },
    "linkat" => &LinkHandler {
        old: PathHandler {
            relfd: Some(0),
            path: 1,
            follow: FollowSymlink::IfFollowFlag(4),
            action: ProgramAction::Read,
        },
        new: PathHandler {
            relfd: Some(2),
            path: 3,
            follow: FollowSymlink::Never,
            action: ProgramAction::Create,
        },
    },
    "listxattr" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::Always,
        action: ProgramAction::Read,
    },
    "listxattrat" => &PathHandler {
        relfd: Some(0),
        path: 1,
        follow: FollowSymlink::UnlessNoFollowFlag {
            flags: 2,
            no_follow_flag: "AT_SYMLINK_NOFOLLOW",
        },
        action: ProgramAction::Read,
    },
    "llistxattr" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::OnTrailingSlash,
        action: ProgramAction::Read,
    },
    "lremovexattr" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::OnTrailingSlash,
        action: ProgramAction::Write,
    },
    "lsetxattr" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::OnTrailingSlash,
        action: ProgramAction::Write,
    },
    "lstat" | "lstat64" | "oldlstat" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::Always,
        action: ProgramAction::Read,
    },
    "memfd_create" => &MemfdCreateHandler { flags: 1 },
    "mkdir" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::Never,
        action: ProgramAction::Create,
    },
    "mkdirat" => &PathHandler {
        relfd: Some(0),
        path: 1,
        follow: FollowSymlink::Never,
        action: ProgramAction::Create,
    },
    "mknod" => &MknodHandler {
        path: PathHandler {
            relfd: None,
            path: 0,
            follow: FollowSymlink::Never,
            action: ProgramAction::Create,
        },
        mode: 1,
    },
    "mknodat" => &MknodHandler {
        path: PathHandler {
            relfd: Some(0),
            path: 1,
            follow: FollowSymlink::Never,
            action: ProgramAction::Create,
        },
        mode: 2,
    },
    "mmap" | "mmap2" => &MmapHandler {
        prot: 2,
        flags: Some(3),
        fd: Some(4),
    },
    "mount" => &MountHandler { flags: 3 },
    "mprotect" => &MmapHandler {
        prot: 2,
        flags: None,
        fd: None,
    },
    "name_to_handle_at" => &PathHandler {
        relfd: Some(0),
        path: 1,
        follow: FollowSymlink::IfFollowFlag(4),
        action: ProgramAction::Read,
    },
    "newfstatat" | "fstatat64" => &PathHandler {
        relfd: Some(0),
        path: 1,
        follow: FollowSymlink::Always,
        action: ProgramAction::Read,
    },
    "open" => &OpenHandler {
        relfd: None,
        path: 0,
        flags: Some(1),
    },
    "openat" => &OpenHandler {
        relfd: Some(0),
        path: 1,
        flags: Some(2),
    },
    "openat2" => &OpenHandler {
        relfd: Some(0),
        path: 1,
        flags: Some(2),
    },
    "pidfd_getfd" => &DupHandler { fd: 1, qualifier: Some(DupQualifier::Pidfd(0)) },
    "pkey_mprotect" => &MmapHandler {
        prot: 2,
        flags: None,
        fd: None,
    },
    "preadv2" => &NetworkHandler { fd: 0, sockaddr: SockaddrArg::None },
    "read" => &NetworkHandler { fd: 0, sockaddr: SockaddrArg::None },
    "readlink" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::OnTrailingSlash,
        action: ProgramAction::Read,
    },
    "readlinkat" => &PathHandler {
        relfd: Some(0),
        path: 1,
        follow: FollowSymlink::OnTrailingSlash,
        action: ProgramAction::Read,
    },
    "readv" => &NetworkHandler { fd: 0, sockaddr: SockaddrArg::None },
    "recv" => &NetworkHandler { fd: 0, sockaddr: SockaddrArg::None },
    "recvfrom" => &NetworkHandler { fd: 0, sockaddr: SockaddrArg::Sockaddr(4) },
    "recvmmsg" | "recvmmsg_time64" => &NetworkHandler { fd: 0, sockaddr: SockaddrArg::MmsgHdrs(1) },
    "recvmsg" => &NetworkHandler { fd: 0, sockaddr: SockaddrArg::MsgHdr(1) },
    "removexattr" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::Always,
        action: ProgramAction::Write,
    },
    "removexattrat" => &PathHandler {
        relfd: Some(0),
        path: 1,
        follow: FollowSymlink::UnlessNoFollowFlag {
            flags: 2,
            no_follow_flag: "AT_SYMLINK_NOFOLLOW",
        },
        action: ProgramAction::Write,
    },
    "rename" => &RenameHandler {
        relfd_src: None,
        path_src: 0,
        relfd_dst: None,
        path_dst: 1,
        flags: None,
    },
    "renameat" => &RenameHandler {
        relfd_src: Some(0),
        path_src: 1,
        relfd_dst: Some(2),
        path_dst: 3,
        flags: None,
    },
    "renameat2" => &RenameHandler {
        relfd_src: Some(0),
        path_src: 1,
        relfd_dst: Some(2),
        path_dst: 3,
        flags: Some(4),
    },
    "rmdir" => &RemoveHandler {
        path: PathHandler {
            relfd: None,
            path: 0,
            follow: FollowSymlink::Never,
            action: ProgramAction::Remove,
        },
    },
    "sched_setscheduler" => &SetSchedulerHandler { policy: 1 },
    "sendfile" | "sendfile64" => &NetworkHandler { fd: 1, sockaddr: SockaddrArg::None },
    "sendmmsg" => &NetworkHandler { fd: 0, sockaddr: SockaddrArg::MmsgHdrs(1) },
    "sendmsg" => &NetworkHandler { fd: 0, sockaddr: SockaddrArg::MsgHdr(1) },
    "sendto" => &NetworkHandler { fd: 0, sockaddr: SockaddrArg::Sockaddr(4) },
    "setsockopt" => &SetsockoptHandler {
        fd: 0,
        level: 1,
        optname: 2,
        optval: 3,
    },
    "setxattr" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::Always,
        action: ProgramAction::Write,
    },
    "setxattrat" => &PathHandler {
        relfd: Some(0),
        path: 1,
        follow: FollowSymlink::UnlessNoFollowFlag {
            flags: 2,
            no_follow_flag: "AT_SYMLINK_NOFOLLOW",
        },
        action: ProgramAction::Write,
    },
    "shmat" => &ShmAtHandler { flags: 2 },
    "shmctl" => &ShmCtlHandler { op: 1 },
    "socket" => &SocketHandler { af: 0, flags: 1 },
    "splice" => &NetworkHandler { fd: 0, sockaddr: SockaddrArg::None },
    "stat" | "stat64" | "oldstat" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::Always,
        action: ProgramAction::Read,
    },
    "statfs" | "statfs64" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::Always,
        action: ProgramAction::Read,
    },
    "statx" => &PathHandler {
        relfd: Some(0),
        path: 1,
        follow: FollowSymlink::UnlessNoFollowFlag {
            flags: 2,
            no_follow_flag: "AT_SYMLINK_NOFOLLOW",
        },
        action: ProgramAction::Read,
    },
    "symlink" => &PathHandler {
        relfd: None,
        path: 1,
        follow: FollowSymlink::Never,
        action: ProgramAction::Create,
    },
    "symlinkat" => &PathHandler {
        relfd: Some(1),
        path: 2,
        follow: FollowSymlink::Never,
        action: ProgramAction::Create,
    },
    "timer_create" | "timerfd_create" => &TimerHandler { clockid: 0 },
    "truncate" | "truncate64" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::Always,
        action: ProgramAction::Write,
    },
    "unlink" => &RemoveHandler {
        path: PathHandler {
            relfd: None,
            path: 0,
            follow: FollowSymlink::Never,
            action: ProgramAction::Remove,
        },
    },
    "unlinkat" => &RemoveHandler {
        path: PathHandler {
            relfd: Some(0),
            path: 1,
            follow: FollowSymlink::Never,
            action: ProgramAction::Remove,
        },
    },
    "unshare" => &UnshareHandler { flags: 0 },
    "utime" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::Always,
        action: ProgramAction::Write,
    },
    "utimensat" | "utimensat_time64" => &PathHandler {
        relfd: Some(0),
        path: 1,
        follow: FollowSymlink::UnlessNoFollowFlag {
            flags: 3,
            no_follow_flag: "AT_SYMLINK_NOFOLLOW",
        },
        action: ProgramAction::Write,
    },
    "utimes" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::Always,
        action: ProgramAction::Write,
    },
    "vfork" => &ForkHandler,
};
