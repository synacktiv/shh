//! Systemd option model

// Last updated for systemd v257

use std::{
    borrow::ToOwned,
    collections::{HashMap, HashSet},
    fmt, iter,
    num::NonZeroUsize,
    os::unix::ffi::OsStrExt as _,
    path::{Path, PathBuf},
    str::FromStr,
    sync::LazyLock,
};

use itertools::Itertools as _;
use strum::IntoEnumIterator as _;

use crate::{
    cl::{HardeningMode, HardeningOptions},
    summarize::{
        CountableSetSpecifier, NetworkActivity, NetworkActivityKind, ProgramAction, SetSpecifier,
    },
    systemd::{KernelVersion, SystemdVersion},
};

/// Callbacks to dynamically update an option to make it compatible with an action
#[derive(Debug)]
pub(crate) struct OptionUpdater {
    /// Generate a new option effect compatible with the previously incompatible action
    pub effect:
        fn(&OptionValueEffect, &ProgramAction, &HardeningOptions) -> Option<OptionValueEffect>,
    /// Generate new options from the new effect
    pub options: fn(&OptionValueEffect, &HardeningOptions) -> Vec<OptionWithValue<&'static str>>,
}

/// Systemd option with its possibles values, and their effect
#[derive(Debug)]
pub(crate) struct OptionDescription {
    pub name: &'static str,
    pub possible_values: Vec<OptionValueDescription>,
    pub updater: Option<OptionUpdater>,
}

impl fmt::Display for OptionDescription {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.name.fmt(f)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListMode {
    WhiteList,
    BlackList,
}

/// Systemd option value
#[derive(Debug, Clone)]
pub(crate) enum OptionValue {
    Boolean(bool), // In most case we only model the 'true' value, because false is no-op and the default
    String(String), // enum-like, or free string
    List(ListOptionValue),
}

#[derive(Debug, Clone)]
pub(crate) struct ListOptionValue {
    pub values: Vec<String>,
    pub value_if_empty: Option<&'static str>,
    pub option_prefix: &'static str,
    pub elem_prefix: &'static str,
    pub repeat_option: bool,
    pub mode: ListMode,
    pub mergeable_paths: bool,
}

impl FromStr for OptionValue {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "true" => Ok(OptionValue::Boolean(true)),
            "false" => Ok(OptionValue::Boolean(false)),
            _ => Ok(OptionValue::String(s.to_owned())),
        }
    }
}

/// A systemd option value and its effects
#[derive(Debug)]
pub(crate) struct OptionValueDescription {
    pub value: OptionValue,
    pub desc: OptionEffect,
}

/// The effects a systemd option has if enabled
#[derive(Debug, Clone)]
pub(crate) enum OptionEffect {
    /// Option has no modeled effect (it will be unconditionally enabled)
    None,
    /// Option has several mutually exclusive possible values
    Simple(OptionValueEffect),
    /// Option has several possible values, that can be combined to stack effects
    Cumulative(Vec<OptionValueEffect>),
}

#[derive(Debug, Clone)]
pub(crate) enum PathDescription {
    Base {
        base: PathBuf,
        exceptions: Vec<PathBuf>,
    },
    Pattern(regex::bytes::Regex),
}

impl PathDescription {
    pub(crate) fn base(base: &'static str) -> Self {
        Self::Base {
            base: base.into(),
            exceptions: vec![],
        }
    }

    pub(crate) fn pattern(pattern: &'static str) -> Self {
        #[expect(clippy::unwrap_used)]
        Self::Pattern(regex::bytes::Regex::new(pattern).unwrap())
    }

    pub(crate) fn matches(&self, path: &Path) -> bool {
        assert!(path.is_absolute(), "{path:?}");
        match self {
            PathDescription::Base { base, exceptions } => {
                path.starts_with(base) && !exceptions.iter().any(|e| path.starts_with(e))
            }
            PathDescription::Pattern(r) => r.is_match(path.as_os_str().as_bytes()),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum OptionValueEffect {
    /// Deny an action
    DenyAction(ProgramAction),
    /// Mount path as read only
    DenyWrite(PathDescription),
    /// Mount path as noexec
    DenyExec(PathDescription),
    /// Mount an empty tmpfs under given directory
    Hide(PathDescription),
    /// Deny syscall(s)
    DenySyscalls(DenySyscalls),
    /// Union of multiple effects
    Multiple(Vec<OptionValueEffect>),
}

impl OptionValueEffect {
    /// Merge current effect with another, while avoiding creating nested `Multiple`
    pub(crate) fn merge(&mut self, other: &OptionValueEffect) {
        match self {
            OptionValueEffect::Multiple(effs) => match other {
                OptionValueEffect::Multiple(oeffs) => {
                    effs.extend(oeffs.iter().cloned());
                }
                oeff => {
                    effs.push(oeff.clone());
                }
            },
            eff => match other {
                OptionValueEffect::Multiple(oeffs) => {
                    let mut new_effs = Vec::with_capacity(oeffs.len() + 1);
                    new_effs.push(eff.to_owned());
                    new_effs.extend(oeffs.iter().cloned());
                    *eff = OptionValueEffect::Multiple(new_effs);
                }
                oeff => {
                    *eff = OptionValueEffect::Multiple(vec![eff.to_owned(), oeff.to_owned()]);
                }
            },
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum DenySyscalls {
    /// See <https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L306>
    /// for the content of each class
    Class(&'static str),
    Single(&'static str),
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    strum::EnumIter,
    strum::Display,
    serde::Serialize,
    serde::Deserialize,
)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum SocketFamily {
    Ipv4,
    Ipv6,
    Other(String),
}

impl FromStr for SocketFamily {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "AF_INET" => Ok(Self::Ipv4),
            "AF_INET6" => Ok(Self::Ipv6),
            _ => Ok(Self::Other(s.to_owned())),
        }
    }
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    strum::EnumIter,
    strum::Display,
    serde::Serialize,
    serde::Deserialize,
)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum SocketProtocol {
    Tcp,
    Udp,
    Other(String),
}

impl FromStr for SocketProtocol {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "SOCK_STREAM" => Ok(Self::Tcp),
            "SOCK_DGRAM" => Ok(Self::Udp),
            _ => Ok(Self::Other(s.to_owned())),
        }
    }
}

impl DenySyscalls {
    /// Get denied syscall names
    pub(crate) fn syscalls(&self) -> HashSet<&'static str> {
        match self {
            Self::Class(class) => {
                #[expect(clippy::unwrap_used)]
                let mut content = SYSCALL_CLASSES.get(class).unwrap().clone();
                while content.iter().any(|e| e.starts_with('@')) {
                    content = content
                        .iter()
                        .filter_map(|c| {
                            #[expect(clippy::unwrap_used)]
                            c.strip_prefix('@')
                                .map(|cn| SYSCALL_CLASSES.get(cn).unwrap())
                        })
                        .flatten()
                        .chain(content.iter().filter(|e| !e.starts_with('@')))
                        .copied()
                        .collect();
                }
                content
            }
            Self::Single(sc) => HashSet::from([sc.to_owned()]),
        }
    }
}

/// A systemd option with a value, as would be present in a config file
#[derive(Debug, Clone)]
pub(crate) struct OptionWithValue<T> {
    pub name: T,
    pub value: OptionValue,
}

impl<T: PartialEq> OptionWithValue<T> {
    /// Merge current option with another if we can, return true if we succeeded
    pub(crate) fn merge(&mut self, other: &Self) -> bool {
        if self.name == other.name {
            match (&mut self.value, &other.value) {
                (
                    OptionValue::List(ListOptionValue {
                        values,
                        value_if_empty,
                        option_prefix,
                        elem_prefix,
                        repeat_option,
                        mode,
                        mergeable_paths,
                    }),
                    OptionValue::List(ListOptionValue {
                        values: ovalues,
                        value_if_empty: ovalue_if_empty,
                        option_prefix: ooption_prefix,
                        elem_prefix: oelem_prefix,
                        repeat_option: orepeat_option,
                        mode: omode,
                        mergeable_paths: omergeable_paths,
                    }),
                ) if value_if_empty == ovalue_if_empty
                    && option_prefix == ooption_prefix
                    && elem_prefix == oelem_prefix
                    && repeat_option == orepeat_option
                    && mode == omode
                    && mergeable_paths == omergeable_paths =>
                {
                    values.extend(ovalues.iter().cloned());
                    values.sort_unstable();
                    true
                }
                _ => false,
            }
        } else {
            false
        }
    }
}

impl FromStr for OptionWithValue<String> {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (name, value) = s
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("Missing '=' char in {s:?}"))?;

        Ok(Self {
            name: name.to_owned(),
            #[expect(clippy::unwrap_used)] // never fails
            value: value.parse().unwrap(),
        })
    }
}

impl<T: fmt::Display> fmt::Display for OptionWithValue<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.value {
            OptionValue::Boolean(value) => {
                write!(f, "{}={}", self.name, if *value { "true" } else { "false" })
            }
            OptionValue::String(value) => write!(f, "{}={}", self.name, value),
            OptionValue::List(ListOptionValue {
                values,
                value_if_empty,
                option_prefix,
                elem_prefix,
                repeat_option,
                ..
            }) => {
                if values.is_empty() {
                    write!(f, "{}=", self.name)?;
                    if let Some(value_if_empty) = value_if_empty {
                        write!(f, "{value_if_empty}")
                    } else {
                        unreachable!()
                    }
                } else if *repeat_option {
                    for (i, value) in values.iter().enumerate() {
                        write!(f, "{}={}{}{}", self.name, option_prefix, elem_prefix, value)?;
                        if i < values.len() - 1 {
                            writeln!(f)?;
                        }
                    }
                    Ok(())
                } else {
                    write!(
                        f,
                        "{}={}{}",
                        self.name,
                        option_prefix,
                        values
                            .iter()
                            .map(|v| format!("{elem_prefix}{v}"))
                            .collect::<Vec<_>>()
                            .join(" ")
                    )
                }
            }
        }
    }
}

static SYSCALL_CLASSES: LazyLock<HashMap<&'static str, HashSet<&'static str>>> =
    LazyLock::new(|| {
        HashMap::from([
            (
                // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L374
                "aio",
                HashSet::from([
                    "io_cancel",
                    "io_destroy",
                    "io_getevents",
                    "io_pgetevents",
                    "io_pgetevents_time64",
                    "io_setup",
                    "io_submit",
                    "io_uring_enter",
                    "io_uring_register",
                    "io_uring_setup",
                ]),
            ),
            (
                // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L389
                "basic-io",
                HashSet::from([
                    "_llseek",
                    "close",
                    "close_range",
                    "dup",
                    "dup2",
                    "dup3",
                    "lseek",
                    "pread64",
                    "preadv",
                    "preadv2",
                    "pwrite64",
                    "pwritev",
                    "pwritev2",
                    "read",
                    "readv",
                    "write",
                    "writev",
                ]),
            ),
            (
                // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L411
                "chown",
                HashSet::from([
                    "chown", "chown32", "fchown", "fchown32", "fchownat", "lchown", "lchown32",
                ]),
            ),
            (
                // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L423
                "clock",
                HashSet::from([
                    "adjtimex",
                    "clock_adjtime",
                    "clock_adjtime64",
                    "clock_settime",
                    "clock_settime64",
                    "settimeofday",
                ]),
            ),
            (
                // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L434
                "cpu-emulation",
                HashSet::from([
                    "modify_ldt",
                    "subpage_prot",
                    "switch_endian",
                    "vm86",
                    "vm86old",
                ]),
            ),
            (
                // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L444
                "debug",
                HashSet::from([
                    "lookup_dcookie",
                    "perf_event_open",
                    "pidfd_getfd",
                    "ptrace",
                    "rtas",
                    "s390_runtime_instr",
                    "sys_debug_setcontext",
                ]),
            ),
            (
                // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L456
                "file-system",
                HashSet::from([
                    "access",
                    "chdir",
                    "chmod",
                    "close",
                    "creat",
                    "faccessat",
                    "faccessat2",
                    "fallocate",
                    "fchdir",
                    "fchmod",
                    "fchmodat",
                    "fcntl",
                    "fcntl64",
                    "fgetxattr",
                    "flistxattr",
                    "fremovexattr",
                    "fsetxattr",
                    "fstat",
                    "fstat64",
                    "fstatat64",
                    "fstatfs",
                    "fstatfs64",
                    "ftruncate",
                    "ftruncate64",
                    "futimesat",
                    "getcwd",
                    "getdents",
                    "getdents64",
                    "getxattr",
                    "inotify_add_watch",
                    "inotify_init",
                    "inotify_init1",
                    "inotify_rm_watch",
                    "lgetxattr",
                    "link",
                    "linkat",
                    "listxattr",
                    "llistxattr",
                    "lremovexattr",
                    "lsetxattr",
                    "lstat",
                    "lstat64",
                    "mkdir",
                    "mkdirat",
                    "mknod",
                    "mknodat",
                    "newfstatat",
                    "oldfstat",
                    "oldlstat",
                    "oldstat",
                    "open",
                    "openat",
                    "openat2",
                    "readlink",
                    "readlinkat",
                    "removexattr",
                    "rename",
                    "renameat",
                    "renameat2",
                    "rmdir",
                    "setxattr",
                    "stat",
                    "stat64",
                    "statfs",
                    "statfs64",
                    "statx",
                    "symlink",
                    "symlinkat",
                    "truncate",
                    "truncate64",
                    "unlink",
                    "unlinkat",
                    "utime",
                    "utimensat",
                    "utimensat_time64",
                    "utimes",
                ]),
            ),
            (
                // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L537
                "io-event",
                HashSet::from([
                    "_newselect",
                    "epoll_create",
                    "epoll_create1",
                    "epoll_ctl",
                    "epoll_ctl_old",
                    "epoll_pwait",
                    "epoll_pwait2",
                    "epoll_wait",
                    "epoll_wait_old",
                    "eventfd",
                    "eventfd2",
                    "poll",
                    "ppoll",
                    "ppoll_time64",
                    "pselect6",
                    "pselect6_time64",
                    "select",
                ]),
            ),
            (
                // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L559
                "ipc",
                HashSet::from([
                    "ipc",
                    "memfd_create",
                    "mq_getsetattr",
                    "mq_notify",
                    "mq_open",
                    "mq_timedreceive",
                    "mq_timedreceive_time64",
                    "mq_timedsend",
                    "mq_timedsend_time64",
                    "mq_unlink",
                    "msgctl",
                    "msgget",
                    "msgrcv",
                    "msgsnd",
                    "pipe",
                    "pipe2",
                    "process_madvise",
                    "process_vm_readv",
                    "process_vm_writev",
                    "semctl",
                    "semget",
                    "semop",
                    "semtimedop",
                    "semtimedop_time64",
                    "shmat",
                    "shmctl",
                    "shmdt",
                    "shmget",
                ]),
            ),
            (
                // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L592
                "keyring",
                HashSet::from(["add_key", "keyctl", "request_key"]),
            ),
            (
                // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L600
                "memlock",
                HashSet::from(["mlock", "mlock2", "mlockall", "munlock", "munlockall"]),
            ),
            (
                // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L610
                "module",
                HashSet::from(["delete_module", "finit_module", "init_module"]),
            ),
            (
                // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L618
                "mount",
                HashSet::from([
                    "chroot",
                    "fsconfig",
                    "fsmount",
                    "fsopen",
                    "fspick",
                    "mount",
                    "mount_setattr",
                    "move_mount",
                    "open_tree",
                    "pivot_root",
                    "umount",
                    "umount2",
                ]),
            ),
            (
                // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L635
                "network-io",
                HashSet::from([
                    "accept",
                    "accept4",
                    "bind",
                    "connect",
                    "getpeername",
                    "getsockname",
                    "getsockopt",
                    "listen",
                    "recv",
                    "recvfrom",
                    "recvmmsg",
                    "recvmmsg_time64",
                    "recvmsg",
                    "send",
                    "sendmmsg",
                    "sendmsg",
                    "sendto",
                    "setsockopt",
                    "shutdown",
                    "socket",
                    "socketcall",
                    "socketpair",
                ]),
            ),
            (
                // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L662
                "obsolete",
                HashSet::from([
                    "_sysctl",
                    "afs_syscall",
                    "bdflush",
                    "break",
                    "create_module",
                    "ftime",
                    "get_kernel_syms",
                    "getpmsg",
                    "gtty",
                    "idle",
                    "lock",
                    "mpx",
                    "prof",
                    "profil",
                    "putpmsg",
                    "query_module",
                    "security",
                    "sgetmask",
                    "ssetmask",
                    "stime",
                    "stty",
                    "sysfs",
                    "tuxcall",
                    "ulimit",
                    "uselib",
                    "ustat",
                    "vserver",
                ]),
            ),
            (
                // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L695
                "pkey",
                HashSet::from(["pkey_alloc", "pkey_free", "pkey_mprotect"]),
            ),
            (
                // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L703
                "privileged",
                HashSet::from([
                    "@chown",
                    "@clock",
                    "@module",
                    "@raw-io",
                    "@reboot",
                    "@swap",
                    "_sysctl",
                    "acct",
                    "bpf",
                    "capset",
                    "chroot",
                    "fanotify_init",
                    "fanotify_mark",
                    "nfsservctl",
                    "open_by_handle_at",
                    "pivot_root",
                    "quotactl",
                    "quotactl_fd",
                    "setdomainname",
                    "setfsuid",
                    "setfsuid32",
                    "setgroups",
                    "setgroups32",
                    "sethostname",
                    "setresuid",
                    "setresuid32",
                    "setreuid",
                    "setreuid32",
                    "setuid",
                    "setuid32",
                    "vhangup",
                ]),
            ),
            (
                // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L739
                "process",
                HashSet::from([
                    "capget",
                    "clone",
                    "clone3",
                    "execveat",
                    "fork",
                    "getrusage",
                    "kill",
                    "pidfd_open",
                    "pidfd_send_signal",
                    "prctl",
                    "rt_sigqueueinfo",
                    "rt_tgsigqueueinfo",
                    "setns",
                    "swapcontext",
                    "tgkill",
                    "times",
                    "tkill",
                    "unshare",
                    "vfork",
                    "wait4",
                    "waitid",
                    "waitpid",
                ]),
            ),
            (
                // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L769
                "raw-io",
                HashSet::from([
                    "ioperm",
                    "iopl",
                    "pciconfig_iobase",
                    "pciconfig_read",
                    "pciconfig_write",
                    "s390_pci_mmio_read",
                    "s390_pci_mmio_write",
                ]),
            ),
            (
                // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L781
                "reboot",
                HashSet::from(["kexec_file_load", "kexec_load", "reboot"]),
            ),
            (
                // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L789
                "resources",
                HashSet::from([
                    "ioprio_set",
                    "mbind",
                    "migrate_pages",
                    "move_pages",
                    "nice",
                    "sched_setaffinity",
                    "sched_setattr",
                    "sched_setparam",
                    "sched_setscheduler",
                    "set_mempolicy",
                    "set_mempolicy_home_node",
                    "setpriority",
                    "setrlimit",
                ]),
            ),
            (
                // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L807
                "sandbox",
                HashSet::from([
                    "landlock_add_rule",
                    "landlock_create_ruleset",
                    "landlock_restrict_self",
                    "seccomp",
                ]),
            ),
            (
                // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L816
                "setuid",
                HashSet::from([
                    "setgid",
                    "setgid32",
                    "setgroups",
                    "setgroups32",
                    "setregid",
                    "setregid32",
                    "setresgid",
                    "setresgid32",
                    "setresuid",
                    "setresuid32",
                    "setreuid",
                    "setreuid32",
                    "setuid",
                    "setuid32",
                ]),
            ),
            (
                // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L835
                "signal",
                HashSet::from([
                    "rt_sigaction",
                    "rt_sigpending",
                    "rt_sigprocmask",
                    "rt_sigsuspend",
                    "rt_sigtimedwait",
                    "rt_sigtimedwait_time64",
                    "sigaction",
                    "sigaltstack",
                    "signal",
                    "signalfd",
                    "signalfd4",
                    "sigpending",
                    "sigprocmask",
                    "sigsuspend",
                ]),
            ),
            (
                // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L854
                "swap",
                HashSet::from(["swapoff", "swapon"]),
            ),
            (
                // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L861
                "sync",
                HashSet::from([
                    "fdatasync",
                    "fsync",
                    "msync",
                    "sync",
                    "sync_file_range",
                    "sync_file_range2",
                    "syncfs",
                ]),
            ),
            (
                // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L939
                "timer",
                HashSet::from([
                    "alarm",
                    "getitimer",
                    "setitimer",
                    "timer_create",
                    "timer_delete",
                    "timer_getoverrun",
                    "timer_gettime",
                    "timer_gettime64",
                    "timer_settime",
                    "timer_settime64",
                    "timerfd_create",
                    "timerfd_gettime",
                    "timerfd_gettime64",
                    "timerfd_settime",
                    "timerfd_settime64",
                    "times",
                ]),
            ),
        ])
    });

pub(crate) fn merge_similar_paths(paths: &[PathBuf], threshold: NonZeroUsize) -> Vec<PathBuf> {
    if paths.len() <= threshold.get() {
        paths.to_vec()
    } else {
        let mut children: HashMap<PathBuf, HashSet<PathBuf>> = HashMap::new();
        for path in paths {
            let ancestors: Vec<_> = path.ancestors().map(Path::to_path_buf).collect();
            let mut parent: Option<PathBuf> = None;
            for dir in ancestors.into_iter().rev() {
                if let Some(parent) = parent.as_ref() {
                    children
                        .entry(parent.to_owned())
                        .or_default()
                        .insert(dir.clone());
                }
                parent = Some(dir);
            }
        }
        let initial_candidates = vec![PathBuf::from("/")];
        let mut candidates = initial_candidates.clone();
        loop {
            let mut advancing = false;
            let mut new_candidates = Vec::with_capacity(candidates.len());
            for candidate in &candidates {
                match children.get(candidate) {
                    Some(candidate_children) if !paths.contains(candidate) => {
                        new_candidates.extend(candidate_children.iter().cloned());
                        advancing |= !candidate_children.is_empty();
                    }
                    _ => {
                        new_candidates.push(candidate.to_owned());
                    }
                }
            }
            // Bail out if:
            // not progressing anymore (paths don't have children)
            if !advancing
                // previous candidate count were lower, and new one is above threshold
                || ((new_candidates.len() > threshold.get())
                    && (candidates.len() < new_candidates.len())
                    && (candidates != initial_candidates))
                // not less path than initial input
                || (new_candidates.len() >= paths.len())
            {
                break;
            }
            candidates = new_candidates;
        }
        if candidates == initial_candidates {
            paths.to_vec()
        } else {
            candidates.sort_unstable();
            candidates
        }
    }
}

#[expect(clippy::too_many_lines, clippy::unnecessary_wraps)]
pub(crate) fn build_options(
    systemd_version: &SystemdVersion,
    kernel_version: &KernelVersion,
    hardening_opts: &HardeningOptions,
) -> anyhow::Result<Vec<OptionDescription>> {
    let mut options = Vec::new();

    //
    // Warning: options values must be ordered from less to most restrictive
    //

    // Options model does not aim to accurately define the option's effects, it is often an oversimplification.
    // However the model should always tend to make options *more* (or equally as) restrictive than what they really are,
    // as to avoid suggesting options that might break execution.

    // TODO APPROXIMATION
    // Some options implicitly force NoNewPrivileges=true which has some effects in itself,
    // which we need to model

    // https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectSystem=
    let protect_system_yes_nowrite: Vec<_> = [
        "/usr/", "/boot/", "/efi/", "/lib/", "/lib64/", "/bin/", "/sbin/",
    ]
    .iter()
    .map(|p| OptionValueEffect::DenyWrite(PathDescription::base(p)))
    .collect();
    let mut protect_system_full_nowrite = protect_system_yes_nowrite.clone();
    protect_system_full_nowrite.push(OptionValueEffect::DenyWrite(PathDescription::base("/etc/")));
    options.push(OptionDescription {
        name: "ProtectSystem",
        possible_values: vec![
            OptionValueDescription {
                value: OptionValue::Boolean(true),
                desc: OptionEffect::Simple(OptionValueEffect::Multiple(protect_system_yes_nowrite)),
            },
            OptionValueDescription {
                value: OptionValue::String("full".to_owned()),
                desc: OptionEffect::Simple(OptionValueEffect::Multiple(
                    protect_system_full_nowrite,
                )),
            },
            OptionValueDescription {
                value: OptionValue::String("strict".to_owned()),
                desc: OptionEffect::Simple(OptionValueEffect::DenyWrite(PathDescription::Base {
                    base: "/".into(),
                    exceptions: vec!["/dev/".into(), "/proc/".into(), "/sys/".into()],
                })),
            },
        ],
        updater: None,
    });

    // https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectHome=
    let home_paths = ["/home/", "/root/", "/run/user/"];
    options.push(OptionDescription {
        name: "ProtectHome",
        possible_values: vec![
            OptionValueDescription {
                value: OptionValue::String("read-only".to_owned()),
                desc: OptionEffect::Simple(OptionValueEffect::Multiple(
                    home_paths
                        .iter()
                        .map(|p| OptionValueEffect::DenyWrite(PathDescription::base(p)))
                        .collect(),
                )),
            },
            OptionValueDescription {
                value: OptionValue::Boolean(true),
                desc: OptionEffect::Simple(OptionValueEffect::Multiple(
                    home_paths
                        .iter()
                        .map(|p| OptionValueEffect::Hide(PathDescription::base(p)))
                        .collect(),
                )),
            },
            OptionValueDescription {
                value: OptionValue::String("tmpfs".to_owned()),
                desc: OptionEffect::Simple(OptionValueEffect::Multiple(
                    home_paths
                        .iter()
                        .map(|p| OptionValueEffect::Hide(PathDescription::base(p)))
                        .chain(
                            home_paths
                                .iter()
                                .map(|p| OptionValueEffect::DenyWrite(PathDescription::base(p))),
                        )
                        .collect(),
                )),
            },
        ],
        updater: None,
    });

    // https://www.freedesktop.org/software/systemd/man/systemd.exec.html#PrivateTmp=
    options.push(OptionDescription {
        name: "PrivateTmp",
        possible_values: vec![OptionValueDescription {
            value: if *systemd_version >= SystemdVersion::new(257, 0) {
                OptionValue::String("disconnected".into())
            } else {
                OptionValue::Boolean(true)
            },
            desc: OptionEffect::Simple(OptionValueEffect::Multiple(vec![
                OptionValueEffect::Hide(PathDescription::base("/tmp")),
                OptionValueEffect::Hide(PathDescription::base("/var/tmp")),
            ])),
        }],
        updater: None,
    });

    // https://www.freedesktop.org/software/systemd/man/systemd.exec.html#PrivateDevices=
    options.push(OptionDescription {
        name: "PrivateDevices",
        possible_values: vec![OptionValueDescription {
            value: OptionValue::Boolean(true),
            desc: OptionEffect::Simple(OptionValueEffect::Multiple(vec![
                OptionValueEffect::Hide(PathDescription::Base {
                    base: "/dev/".into(),
                    // https://github.com/systemd/systemd/blob/v254/src/core/namespace.c#L912
                    exceptions: [
                        "null",
                        "zero",
                        "full",
                        "random",
                        "urandom",
                        "tty",
                        "pts/",
                        "ptmx",
                        "shm/",
                        "mqueue/",
                        "hugepages/",
                        "log",
                    ]
                    .iter()
                    .map(|p| PathBuf::from("/dev/").join(p))
                    .collect(),
                }),
                OptionValueEffect::DenySyscalls(DenySyscalls::Class("raw-io")),
                OptionValueEffect::DenyAction(ProgramAction::MknodSpecial),
                OptionValueEffect::DenyExec(PathDescription::base("/dev")),
            ])),
        }],
        updater: None,
    });

    // https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectKernelTunables=
    options.push(OptionDescription {
        name: "ProtectKernelTunables",
        possible_values: vec![OptionValueDescription {
            value: OptionValue::Boolean(true),
            desc: OptionEffect::Simple(OptionValueEffect::Multiple(
                // https://github.com/systemd/systemd/blob/v254/src/core/namespace.c#L113
                [
                    "acpi/",
                    "apm",
                    "asound/",
                    "bus/",
                    "fs/",
                    "irq/",
                    "latency_stats",
                    "mttr",
                    "scsi/",
                    "sys/",
                    "sysrq-trigger",
                    "timer_stats",
                ]
                .iter()
                .map(|p| {
                    OptionValueEffect::DenyWrite(PathDescription::Base {
                        base: PathBuf::from("/proc/").join(p),
                        exceptions: vec![],
                    })
                })
                .chain(["kallsyms", "kcore"].iter().map(|p| {
                    OptionValueEffect::Hide(PathDescription::Base {
                        base: PathBuf::from("/proc/").join(p),
                        exceptions: vec![],
                    })
                }))
                .chain(
                    // https://github.com/systemd/systemd/blob/v254/src/core/namespace.c#L130
                    iter::once(OptionValueEffect::DenyWrite(PathDescription::base("/sys"))),
                )
                .collect(),
            )),
        }],
        updater: None,
    });

    // https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectKernelModules=
    options.push(OptionDescription {
        name: "ProtectKernelModules",
        possible_values: vec![OptionValueDescription {
            value: OptionValue::Boolean(true),
            desc: OptionEffect::Simple(OptionValueEffect::Multiple(vec![
                // https://github.com/systemd/systemd/blob/v254/src/core/namespace.c#L140
                OptionValueEffect::Hide(PathDescription::base("/lib/modules/")),
                OptionValueEffect::Hide(PathDescription::base("/usr/lib/modules/")),
                OptionValueEffect::DenySyscalls(DenySyscalls::Class("module")),
            ])),
        }],
        updater: None,
    });

    // https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectKernelLogs=
    options.push(OptionDescription {
        name: "ProtectKernelLogs",
        possible_values: vec![OptionValueDescription {
            value: OptionValue::Boolean(true),
            desc: OptionEffect::Simple(OptionValueEffect::Multiple(vec![
                // https://github.com/systemd/systemd/blob/v254/src/core/namespace.c#L148
                OptionValueEffect::Hide(PathDescription::base("/proc/kmsg")),
                OptionValueEffect::Hide(PathDescription::base("/dev/kmsg")),
                OptionValueEffect::DenySyscalls(DenySyscalls::Single("syslog")),
            ])),
        }],
        updater: None,
    });

    // https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectControlGroups=
    // TODO private/strip
    options.push(OptionDescription {
        name: "ProtectControlGroups",
        possible_values: vec![OptionValueDescription {
            value: OptionValue::Boolean(true),
            desc: OptionEffect::Simple(OptionValueEffect::DenyWrite(PathDescription::base(
                "/sys/fs/cgroup/",
            ))),
        }],
        updater: None,
    });

    // https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectProc=
    // https://github.com/systemd/systemd/blob/v247/NEWS#L342
    // https://github.com/systemd/systemd/commit/4e39995371738b04d98d27b0d34ea8fe09ec9fab
    // https://docs.kernel.org/filesystems/proc.html#mount-options
    if (systemd_version >= &SystemdVersion::new(247, 0))
        && (kernel_version >= &KernelVersion::new(5, 8, 0))
    {
        options.push(OptionDescription {
            name: "ProtectProc",
            // Since we have no easy & reliable (race free) way to know which process belongs to
            // which user, only support the most restrictive option
            possible_values: vec![OptionValueDescription {
                value: OptionValue::String("ptraceable".to_owned()),
                desc: OptionEffect::Simple(OptionValueEffect::Hide(PathDescription::pattern(
                    "^/proc/[0-9]+(/|$)",
                ))),
            }],
            updater: None,
        });
    }

    // https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#ReadWritePaths=
    if hardening_opts.filesystem_whitelisting {
        options.push(OptionDescription {
            name: "ReadOnlyPaths",
            possible_values: vec![OptionValueDescription {
                value: OptionValue::List(ListOptionValue {
                    values: vec!["/".to_owned()],
                    value_if_empty: None,
                    option_prefix: "",
                    elem_prefix: "-",
                    repeat_option: false,
                    mode: ListMode::BlackList,
                    mergeable_paths: true,
                }),
                desc: OptionEffect::Simple(OptionValueEffect::DenyWrite(PathDescription::base(
                    "/",
                ))),
            }],
            updater: Some(OptionUpdater {
                effect: |effect, action, _| match effect {
                    OptionValueEffect::DenyWrite(PathDescription::Base { base, exceptions }) => {
                        let new_exception = match action {
                            ProgramAction::Write(action_path) => Some(action_path.to_owned()),
                            ProgramAction::Create(action_path) => {
                                action_path.parent().map(Path::to_path_buf)
                            }
                            _ => None,
                        };
                        new_exception.map(|new_exception_path| {
                            let mut new_exceptions = Vec::with_capacity(exceptions.len() + 1);
                            new_exceptions.extend(exceptions.iter().cloned());
                            new_exceptions.push(new_exception_path);
                            OptionValueEffect::DenyWrite(PathDescription::Base {
                                base: base.to_owned(),
                                exceptions: new_exceptions,
                            })
                        })
                    }
                    OptionValueEffect::DenyWrite(PathDescription::Pattern(_)) => {
                        unimplemented!()
                    }
                    _ => None,
                },
                options: |effect, hopts| match effect {
                    OptionValueEffect::DenyWrite(PathDescription::Base { base, exceptions }) => {
                        vec![
                            OptionWithValue {
                                name: "ReadOnlyPaths",
                                value: OptionValue::List(ListOptionValue {
                                    #[expect(clippy::unwrap_used)] // path is from our option, so unicode safe
                                    values: vec![base.to_str().unwrap().to_owned()],
                                    value_if_empty: None,
                                    option_prefix: "",
                    elem_prefix: "-",
                                    repeat_option: false,
                                    mode: ListMode::BlackList,
                                    mergeable_paths: true,
                                }),
                            },
                            OptionWithValue {
                                name: "ReadWritePaths",
                                value: OptionValue::List(ListOptionValue {
                                    values: merge_similar_paths(
                                        exceptions,
                                        hopts.merge_paths_threshold,
                                    )
                                    .iter()
                                    .filter_map(|p| p.to_str().map(ToOwned::to_owned))
                                    .collect(),
                                    value_if_empty: None,
                                    option_prefix: "",
                                    elem_prefix: "-",
                                    repeat_option: false,
                                    mode: ListMode::WhiteList,
                                    mergeable_paths: true,
                                }),
                            },
                        ]
                    }
                    OptionValueEffect::DenyWrite(PathDescription::Pattern(_)) => {
                        unimplemented!()
                    }
                    _ => unreachable!(),
                },
            }),
        });

        options.push(OptionDescription {
            name: "InaccessiblePaths",
            possible_values: vec![OptionValueDescription {
                value: OptionValue::List(ListOptionValue {
                    values: vec!["/".to_owned()],
                    value_if_empty: None,
                    option_prefix: "",
                    elem_prefix: "-",
                    repeat_option: false,
                    mode: ListMode::BlackList,
                    mergeable_paths: true,
                }),
                desc: OptionEffect::Simple(OptionValueEffect::Hide(PathDescription::base("/"))),
            }],
            updater: Some(OptionUpdater {
                effect: |effect, action, _| {
                    let action_path = match action {
                        ProgramAction::Read(action_path)
                        | ProgramAction::Write(action_path)
                        | ProgramAction::Exec(action_path) => action_path.to_owned(),
                        ProgramAction::Create(action_path) => {
                            action_path.parent().map(Path::to_path_buf)?
                        }
                        _ => return None,
                    };
                    match effect {
                        OptionValueEffect::Hide(PathDescription::Base { base, exceptions }) => {
                            let mut new_exceptions = Vec::with_capacity(exceptions.len() + 1);
                            new_exceptions.extend(exceptions.iter().cloned());
                            new_exceptions.push(action_path);
                            Some(OptionValueEffect::Hide(PathDescription::Base {
                                base: base.to_owned(),
                                exceptions: new_exceptions,
                            }))
                        }
                        OptionValueEffect::Hide(PathDescription::Pattern(_)) => {
                            unimplemented!()
                        }
                        _ => None,
                    }
                },
                options: |effect, hopts| match effect {
                    OptionValueEffect::Hide(PathDescription::Base { base, exceptions }) => {
                        vec![
                            OptionWithValue {
                                name: "TemporaryFileSystem",
                                value: OptionValue::List(ListOptionValue {
                                    #[expect(clippy::unwrap_used)] // path is from our option, so unicode safe
                                    values: vec![base.to_str().unwrap().to_owned()], // TODO ro?
                                    value_if_empty: None,
                                    option_prefix: "",
                                    elem_prefix: "",
                                    repeat_option: false,
                                    mode: ListMode::BlackList,
                                    mergeable_paths: true,
                                }),
                            },
                            OptionWithValue {
                                name: "BindPaths",
                                value: OptionValue::List(ListOptionValue {
                                    values: merge_similar_paths(
                                        exceptions,
                                        hopts.merge_paths_threshold,
                                    )
                                    .iter()
                                    .filter_map(|p| p.to_str().map(ToOwned::to_owned))
                                    .collect(),
                                    value_if_empty: None,
                                    option_prefix: "",
                                    elem_prefix: "-",
                                    repeat_option: false,
                                    mode: ListMode::WhiteList,
                                    mergeable_paths: true,
                                }),
                            },
                        ]
                    }
                    OptionValueEffect::DenyWrite(PathDescription::Pattern(_)) => {
                        unimplemented!()
                    }
                    _ => unreachable!(),
                },
            }),
        });

        options.push(OptionDescription {
            name: "NoExecPaths",
            possible_values: vec![OptionValueDescription {
                value: OptionValue::List(ListOptionValue {
                    values: vec!["/".to_owned()],
                    value_if_empty: None,
                    option_prefix: "",
                    elem_prefix: "-",
                    repeat_option: false,
                    mode: ListMode::BlackList,
                    mergeable_paths: true,
                }),
                desc: OptionEffect::Simple(OptionValueEffect::DenyExec(PathDescription::base("/"))),
            }],
            updater: Some(OptionUpdater {
                effect: |effect, action, _| match effect {
                    OptionValueEffect::DenyExec(PathDescription::Base { base, exceptions }) => {
                        let ProgramAction::Exec(new_exception) = action else {
                            return None;
                        };
                        let mut new_exceptions = Vec::with_capacity(exceptions.len() + 1);
                        new_exceptions.extend(exceptions.iter().cloned());
                        new_exceptions.push(new_exception.to_owned());
                        Some(OptionValueEffect::DenyExec(PathDescription::Base {
                            base: base.to_owned(),
                            exceptions: new_exceptions,
                        }))
                    }
                    _ => None,
                },
                options: |effect, hopts| match effect {
                    OptionValueEffect::DenyExec(PathDescription::Base { base, exceptions }) => {
                        vec![
                            OptionWithValue {
                                name: "NoExecPaths",
                                value: OptionValue::List(ListOptionValue {
                                    #[expect(clippy::unwrap_used)] // path is from our option, so unicode safe
                                    values: vec![base.to_str().unwrap().to_owned()],
                                    value_if_empty: None,
                                    option_prefix: "",
                                    elem_prefix: "-",
                                    repeat_option: false,
                                    mode: ListMode::BlackList,
                                    mergeable_paths: true,
                                }),
                            },
                            OptionWithValue {
                                name: "ExecPaths",
                                value: OptionValue::List(ListOptionValue {
                                    values: merge_similar_paths(
                                        exceptions,
                                        hopts.merge_paths_threshold,
                                    )
                                    .iter()
                                    .filter_map(|p| p.to_str().map(ToOwned::to_owned))
                                    .collect(),
                                    value_if_empty: None,
                                    option_prefix: "",
                                    elem_prefix: "-",
                                    repeat_option: false,
                                    mode: ListMode::WhiteList,
                                    mergeable_paths: true,
                                }),
                            },
                        ]
                    }
                    _ => unreachable!(),
                },
            }),
        });
    }

    // https://www.freedesktop.org/software/systemd/man/systemd.exec.html#MemoryDenyWriteExecute=
    // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L1721
    options.push(OptionDescription {
        name: "MemoryDenyWriteExecute",
        possible_values: vec![OptionValueDescription {
            value: OptionValue::Boolean(true),
            desc: OptionEffect::Simple(OptionValueEffect::DenyAction(
                ProgramAction::WriteExecuteMemoryMapping,
            )),
        }],
        updater: None,
    });

    // https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictAddressFamilies=
    // https://man7.org/linux/man-pages/man7/address_families.7.html
    // curl https://man7.org/linux/man-pages/man7/address_families.7.html | grep -o 'AF_[A-Za-z0-9]*' | sort -u | xargs -I'{}' echo \"'{}'\",
    let afs = [
        "AF_ALG",
        "AF_APPLETALK",
        "AF_ATMPVC",
        "AF_ATMSVC",
        "AF_AX25",
        "AF_BLUETOOTH",
        "AF_BRIDGE",
        "AF_CAIF",
        "AF_CAN",
        "AF_DECnet",
        "AF_ECONET",
        "AF_IB",
        "AF_IEEE802154",
        "AF_INET",
        "AF_INET6",
        "AF_IPX",
        "AF_IRDA",
        "AF_ISDN",
        "AF_IUCV",
        "AF_KCM",
        "AF_KEY",
        "AF_LLC",
        "AF_LOCAL",
        "AF_MPLS",
        "AF_NETBEUI",
        "AF_NETLINK",
        "AF_NETROM",
        "AF_PACKET",
        "AF_PHONET",
        "AF_PPPOX",
        "AF_QIPCRTR",
        "AF_RDS",
        "AF_ROSE",
        "AF_RXRPC",
        "AF_SECURITY",
        "AF_SMC",
        "AF_TIPC",
        "AF_UNIX",
        "AF_VSOCK",
        "AF_WANPIPE",
        "AF_X25",
        "AF_XDP",
    ];
    options.push(OptionDescription {
        name: "RestrictAddressFamilies",
        possible_values: vec![OptionValueDescription {
            value: OptionValue::List(ListOptionValue {
                values: afs.iter().map(|s| (*s).to_owned()).collect(),
                value_if_empty: Some("none"),
                option_prefix: "",
                elem_prefix: "",
                repeat_option: false,
                mode: ListMode::WhiteList,
                mergeable_paths: false,
            }),
            desc: OptionEffect::Cumulative(
                afs.into_iter()
                    .map(|af| {
                        OptionValueEffect::DenyAction(ProgramAction::NetworkActivity(
                            NetworkActivity {
                                #[expect(clippy::unwrap_used)]
                                af: SetSpecifier::One(af.parse().unwrap()),
                                proto: SetSpecifier::All,
                                kind: SetSpecifier::All,
                                local_port: CountableSetSpecifier::All,
                            },
                        ))
                    })
                    .collect(),
            ),
        }],
        updater: None,
    });

    if let HardeningMode::Aggressive = hardening_opts.mode {
        // https://www.freedesktop.org/software/systemd/man/systemd.exec.html#PrivateNetwork=
        //
        // For now we enable this option if no sockets are used at all, in theory this could break if
        // a socket file descriptor is passed to it from another process.
        // Although this is probably a very rare/niche case, it is possible, so we consider it only in aggressive mode
        options.push(OptionDescription {
            name: "PrivateNetwork",
            possible_values: vec![OptionValueDescription {
                value: OptionValue::Boolean(true),
                desc: OptionEffect::Simple(OptionValueEffect::DenyAction(
                    ProgramAction::NetworkActivity(NetworkActivity {
                        af: SetSpecifier::All,
                        proto: SetSpecifier::All,
                        kind: SetSpecifier::All,
                        local_port: CountableSetSpecifier::All,
                    }),
                )),
            }],
            updater: None,
        });
    }

    // https://www.freedesktop.org/software/systemd/man/systemd.resource-control.html#SocketBindAllow=bind-rule
    //
    // We don't go as far as allowing/denying individual ports, as that would easily break for example if a port is changed
    // in a server configuration
    let deny_binds: Vec<_> = SocketFamily::iter()
        .take(2)
        .cartesian_product(SocketProtocol::iter().take(2))
        .collect();
    options.push(OptionDescription {
        name: "SocketBindDeny",
        possible_values: vec![OptionValueDescription {
            value: OptionValue::List(ListOptionValue {
                values: deny_binds
                    .iter()
                    .map(|(af, proto)| format!("{af}:{proto}"))
                    .collect(),
                value_if_empty: None,
                option_prefix: "",
                elem_prefix: "",
                repeat_option: true,
                mode: ListMode::BlackList,
                mergeable_paths: false,
            }),
            desc: OptionEffect::Cumulative(
                deny_binds
                    .into_iter()
                    .map(|(af, proto)| {
                        OptionValueEffect::DenyAction(ProgramAction::NetworkActivity(
                            NetworkActivity {
                                af: SetSpecifier::One(af),
                                proto: SetSpecifier::One(proto),
                                kind: SetSpecifier::One(NetworkActivityKind::Bind),
                                local_port: CountableSetSpecifier::All,
                            },
                        ))
                    })
                    .collect(),
            ),
        }],
        updater: hardening_opts.network_firewalling.then_some(OptionUpdater {
            effect: |e, a, _| {
                let OptionValueEffect::DenyAction(ProgramAction::NetworkActivity(effect_na)) = e
                else {
                    unreachable!();
                };
                let ProgramAction::NetworkActivity(NetworkActivity {
                    local_port: CountableSetSpecifier::One(local_port),
                    ..
                }) = a
                else {
                    unreachable!();
                };
                let mut new_eff_local_port = effect_na.local_port.clone();
                new_eff_local_port.remove(local_port);
                Some(OptionValueEffect::DenyAction(
                    ProgramAction::NetworkActivity(NetworkActivity {
                        af: effect_na.af.clone(),
                        proto: effect_na.proto.clone(),
                        kind: effect_na.kind.clone(),
                        local_port: new_eff_local_port,
                    }),
                ))
            },
            options: |e, _| {
                let OptionValueEffect::DenyAction(ProgramAction::NetworkActivity(denied_na)) = e
                else {
                    unreachable!();
                };
                vec![OptionWithValue {
                    name: "SocketBindDeny",
                    value: OptionValue::List(ListOptionValue {
                        values: denied_na
                            .af
                            .elements()
                            .iter()
                            .cartesian_product(denied_na.proto.elements())
                            .cartesian_product(denied_na.local_port.ranges())
                            .map(|((af, proto), port_range)| {
                                format!(
                                    "{}:{}:{}-{}",
                                    af,
                                    proto,
                                    port_range.start(),
                                    port_range.end()
                                )
                            })
                            .collect(),
                        value_if_empty: None,
                        option_prefix: "",
                        elem_prefix: "",
                        repeat_option: true,
                        mode: ListMode::BlackList,
                        mergeable_paths: false,
                    }),
                }]
            },
        }),
    });

    // https://www.freedesktop.org/software/systemd/man/systemd.exec.html#LockPersonality=
    options.push(OptionDescription {
        name: "LockPersonality",
        possible_values: vec![OptionValueDescription {
            value: OptionValue::Boolean(true),
            // In practice, the option allows the call if the default personality is set, but we don't
            // need to model that level of precision.
            // The "deny" model prevents false positives
            desc: OptionEffect::Simple(OptionValueEffect::DenySyscalls(DenySyscalls::Single(
                "personality",
            ))),
        }],
        updater: None,
    });

    // https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictRealtime=
    options.push(OptionDescription {
        name: "RestrictRealtime",
        possible_values: vec![OptionValueDescription {
            value: OptionValue::Boolean(true),
            desc: OptionEffect::Simple(OptionValueEffect::DenyAction(
                ProgramAction::SetRealtimeScheduler,
            )),
        }],
        updater: None,
    });

    // https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectClock=
    options.push(OptionDescription {
        name: "ProtectClock",
        possible_values: vec![OptionValueDescription {
            value: OptionValue::Boolean(true),
            // This option essentially does the same thing as deny @clock
            desc: OptionEffect::Simple(OptionValueEffect::DenySyscalls(DenySyscalls::Class(
                "clock",
            ))),
        }],
        updater: None,
    });

    // https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#CapabilityBoundingSet=
    // Note: we don't want to duplicate the kernel permission checking logic here, which would be
    // a maintenance nightmare, so in most case we over (never under!) simplify the capability's effect
    // or we don't implement it at all if too complex because the risk of breakage is too high
    let cap_effects = [
        // CAP_AUDIT_CONTROL, CAP_AUDIT_READ, CAP_AUDIT_WRITE: requires netlink socket message handling
        (
            "CAP_BLOCK_SUSPEND",
            OptionValueEffect::Multiple(vec![
                OptionValueEffect::DenyWrite(PathDescription::base("/proc/sys/wake_lock")),
                OptionValueEffect::DenyAction(ProgramAction::Wakeup),
            ]),
        ),
        (
            "CAP_BPF",
            OptionValueEffect::DenySyscalls(DenySyscalls::Single("bpf")),
        ),
        // CAP_CHECKPOINT_RESTORE: too complex?
        (
            "CAP_CHOWN",
            OptionValueEffect::DenySyscalls(DenySyscalls::Class("chown")),
        ),
        // CAP_DAC_OVERRIDE: too complex?
        // CAP_DAC_READ_SEARCH: too complex?
        // CAP_FOWNER: too complex?
        // CAP_FSETID: too complex?
        // TODO CAP_IPC_LOCK
        // CAP_IPC_OWNER: too complex?
        // TODO CAP_KILL
        // TODO CAP_LEASE
        // TODO CAP_LINUX_IMMUTABLE
        // CAP_MAC_ADMIN: too complex?
        // CAP_MAC_OVERRIDE: too complex?
        (
            "CAP_MKNOD",
            OptionValueEffect::DenyAction(ProgramAction::MknodSpecial),
        ),
        // CAP_NET_ADMIN: too complex?
        // CAP_NET_BIND_SERVICE would be too complex/unreliable to handle:
        // - for IPv4 sockets, either PROT_SOCK or net.ipv4.ip_unprivileged_port_start sysctl control the provileged port threshold
        // - for other socket families, rules are different
        // CAP_NET_BROADCAST: unused
        (
            "CAP_NET_RAW",
            OptionValueEffect::Multiple(
                iter::once(OptionValueEffect::DenyAction(
                    ProgramAction::NetworkActivity(NetworkActivity {
                        af: SetSpecifier::One(SocketFamily::Other("AF_PACKET".into())),
                        proto: SetSpecifier::All,
                        kind: SetSpecifier::All,
                        local_port: CountableSetSpecifier::All,
                    }),
                ))
                .chain(
                    // AF_NETLINK sockets use SOCK_RAW, but does not require CAP_NET_RAW
                    afs.iter().filter(|af| **af != "AF_NETLINK").map(|af| {
                        OptionValueEffect::DenyAction(ProgramAction::NetworkActivity(
                            NetworkActivity {
                                #[expect(clippy::unwrap_used)]
                                af: SetSpecifier::One(af.parse().unwrap()),
                                proto: SetSpecifier::One(SocketProtocol::Other("SOCK_RAW".into())),
                                kind: SetSpecifier::All,
                                local_port: CountableSetSpecifier::All,
                            },
                        ))
                    }),
                )
                .collect(),
                // TODO non local bind
            ),
        ),
        (
            "CAP_PERFMON",
            OptionValueEffect::Multiple(vec![
                OptionValueEffect::DenySyscalls(DenySyscalls::Single("perf_event_open")),
                OptionValueEffect::DenySyscalls(DenySyscalls::Single("bpf")),
            ]),
        ),
        // CAP_SETFCAP: too complex?
        // TODO CAP_SETGID
        // TODO CAP_SETPCAP
        // TODO CAP_SETUID
        // CAP_SYS_ADMIN: definitely too complex
        (
            "CAP_SYS_BOOT",
            OptionValueEffect::DenySyscalls(DenySyscalls::Class("reboot")),
        ),
        (
            "CAP_SYS_CHROOT",
            OptionValueEffect::Multiple(vec![
                OptionValueEffect::DenySyscalls(DenySyscalls::Single("chroot")),
                OptionValueEffect::DenySyscalls(DenySyscalls::Single("setns")),
            ]),
        ),
        (
            "CAP_SYS_MODULE",
            OptionValueEffect::DenySyscalls(DenySyscalls::Class("module")),
        ),
        (
            "CAP_SYS_NICE",
            OptionValueEffect::DenySyscalls(DenySyscalls::Class("resources")),
        ),
        (
            "CAP_SYS_PACCT",
            OptionValueEffect::DenySyscalls(DenySyscalls::Single("acct")),
        ),
        (
            "CAP_SYS_PTRACE",
            OptionValueEffect::Multiple(vec![
                // TODO distinguish other processes
                OptionValueEffect::DenySyscalls(DenySyscalls::Single("ptrace)")),
                OptionValueEffect::DenySyscalls(DenySyscalls::Single("get_robust_list")),
                OptionValueEffect::DenySyscalls(DenySyscalls::Single("process_vm_readv")),
                OptionValueEffect::DenySyscalls(DenySyscalls::Single("process_vm_writev")),
                OptionValueEffect::DenySyscalls(DenySyscalls::Single("kcmp")),
            ]),
        ),
        // CAP_SYS_RAWIO: too complex?
        // CAP_SYS_RESOURCE: too complex?
        (
            "CAP_SYS_TIME",
            OptionValueEffect::Multiple(vec![
                OptionValueEffect::DenySyscalls(DenySyscalls::Class("clock")),
                OptionValueEffect::DenySyscalls(DenySyscalls::Single("stime")),
            ]),
        ),
        (
            "CAP_SYS_TTY_CONFIG",
            OptionValueEffect::Multiple(vec![
                OptionValueEffect::DenySyscalls(DenySyscalls::Single("vhangup")),
                OptionValueEffect::DenySyscalls(DenySyscalls::Single("ioctl")), // TODO only consider tty related ioctl?
            ]),
        ),
        (
            "CAP_SYSLOG",
            OptionValueEffect::Multiple(vec![
                OptionValueEffect::DenySyscalls(DenySyscalls::Single("syslog")),
                OptionValueEffect::DenyAction(ProgramAction::Read("/dev/kmsg".into())),
            ]),
        ),
        (
            "CAP_WAKE_ALARM",
            OptionValueEffect::DenyAction(ProgramAction::SetAlarm),
        ),
    ];
    options.push(OptionDescription {
        name: "CapabilityBoundingSet",
        possible_values: vec![OptionValueDescription {
            value: OptionValue::List(ListOptionValue {
                values: cap_effects.iter().map(|(c, _e)| (*c).to_owned()).collect(),
                value_if_empty: None,
                option_prefix: "~",
                elem_prefix: "",
                repeat_option: false,
                mode: ListMode::BlackList,
                mergeable_paths: false,
            }),
            desc: OptionEffect::Cumulative(cap_effects.into_iter().map(|(_c, e)| e).collect()),
        }],
        updater: None,
    });

    // https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallFilter=
    //
    // Also change the default behavior when calling a denied syscall to return EPERM instead of killing
    // the program.
    // Rationale:
    // Some programs call chown as non root even though it always fails, and ignore the error. Since the call
    // fails, we don't monitor it, but if we deny the chown syscall, the program gets killed with SIGSYS
    // signal when it makes the call, so change the default to just return EPERM.
    // Real world example: https://github.com/tjko/jpegoptim/blob/v1.5.5/jpegoptim.c#L1097-L1099
    //
    let mut syscall_classes: Vec<_> = SYSCALL_CLASSES.keys().copied().collect();
    syscall_classes.sort_unstable();
    options.push(OptionDescription {
        name: "SystemCallFilter",
        possible_values: vec![OptionValueDescription {
            value: OptionValue::List(ListOptionValue {
                values: syscall_classes
                    .iter()
                    .map(|c| format!("@{c}:EPERM"))
                    .collect(),
                value_if_empty: None,
                option_prefix: "~",
                elem_prefix: "",
                repeat_option: false,
                mode: ListMode::BlackList,
                mergeable_paths: false,
            }),
            desc: OptionEffect::Cumulative(
                syscall_classes
                    .into_iter()
                    .map(|class| OptionValueEffect::DenySyscalls(DenySyscalls::Class(class)))
                    .collect(),
            ),
        }],
        updater: None,
    });

    if let HardeningMode::Aggressive = hardening_opts.mode {
        // https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallArchitectures=
        //
        // This is actually very safe to enable, but since we don't currently support checking for its
        // compatibility during profiling, only enable it in aggressive mode
        options.push(OptionDescription {
            name: "SystemCallArchitectures",
            possible_values: vec![OptionValueDescription {
                value: OptionValue::String("native".to_owned()),
                desc: OptionEffect::None,
            }],
            updater: None,
        });
    }

    log::debug!("{options:#?}");
    Ok(options)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merge_similar_paths() {
        assert_eq!(
            merge_similar_paths(
                &[
                    PathBuf::from("/a/ab/ab1"),
                    PathBuf::from("/a/ab/ab2"),
                    PathBuf::from("/a/ab/ab3"),
                    PathBuf::from("/a/ab/ab4/abc")
                ],
                NonZeroUsize::new(2).unwrap()
            ),
            vec![PathBuf::from("/a/ab")]
        );
        assert_eq!(
            merge_similar_paths(
                &[
                    PathBuf::from("/a1/ab/ab1"),
                    PathBuf::from("/a2/ab/ab2"),
                    PathBuf::from("/a3/ab/ab3")
                ],
                NonZeroUsize::new(2).unwrap()
            ),
            vec![
                PathBuf::from("/a1/ab/ab1"),
                PathBuf::from("/a2/ab/ab2"),
                PathBuf::from("/a3/ab/ab3")
            ]
        );
        assert_eq!(
            merge_similar_paths(
                &[
                    PathBuf::from("/a/aa/ab1"),
                    PathBuf::from("/a/ab/ab2"),
                    PathBuf::from("/a/ac/ab3")
                ],
                NonZeroUsize::new(2).unwrap()
            ),
            vec![PathBuf::from("/a")]
        );
        assert_eq!(
            merge_similar_paths(
                &[
                    PathBuf::from("/a/aa/ab1"),
                    PathBuf::from("/a/aa/ab2"),
                    PathBuf::from("/a/ab/ab3")
                ],
                NonZeroUsize::new(2).unwrap()
            ),
            vec![PathBuf::from("/a/aa"), PathBuf::from("/a/ab")]
        );
    }
}
