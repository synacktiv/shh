//! Systemd option model

use std::{
    collections::{HashMap, HashSet},
    fmt, iter,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    str::FromStr,
    sync::LazyLock,
};

use itertools::Itertools;
use strum::IntoEnumIterator;

use crate::{
    cl::HardeningMode,
    summarize::{NetworkActivity, NetworkActivityKind, ProgramAction, SetSpecifier},
    systemd::{KernelVersion, SystemdVersion},
};

/// Systemd option with its possibles values, and their effect
#[derive(Debug)]
pub struct OptionDescription {
    pub name: &'static str,
    pub possible_values: Vec<OptionValueDescription>,
}

impl fmt::Display for OptionDescription {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.name.fmt(f)
    }
}

#[derive(Debug, Clone)]
pub enum ListMode {
    WhiteList,
    BlackList,
}

/// Systemd option value
#[derive(Debug, Clone)]
pub enum OptionValue {
    Boolean(bool), // In most case we only model the 'true' value, because false is no-op and the default
    String(String), // enum-like, or free string
    List {
        values: Vec<String>,
        value_if_empty: Option<String>,
        negation_prefix: bool,
        repeat_option: bool,
        mode: ListMode,
    },
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
pub struct OptionValueDescription {
    pub value: OptionValue,
    pub desc: OptionEffect,
}

/// The effects a systemd option has if enabled
#[derive(Debug, Clone)]
pub enum OptionEffect {
    /// Option has no modeled effect (it will be unconditionally enabled)
    None,
    /// Option has several mutually exclusive possible values
    Simple(OptionValueEffect),
    /// Option has several possible values, that can be combined to stack effects
    Cumulative(Vec<OptionValueEffect>),
}

#[derive(Debug, Clone)]
pub enum PathDescription {
    Base {
        base: PathBuf,
        exceptions: Vec<PathBuf>,
    },
    Pattern(regex::bytes::Regex),
}

impl PathDescription {
    pub fn matches(&self, path: &Path) -> bool {
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
pub enum OptionValueEffect {
    /// Deny an action
    DenyAction(ProgramAction),
    /// Mount path as read only
    DenyWrite(PathDescription),
    /// Mount an empty tmpfs under given directory
    Hide(PathDescription),
    /// Deny syscall(s)
    DenySyscalls(DenySyscalls),
    /// Union of multiple effects
    Multiple(Vec<OptionValueEffect>),
}

#[derive(Debug, Clone)]
pub enum DenySyscalls {
    /// See https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L306
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
pub enum SocketFamily {
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
pub enum SocketProtocol {
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
    pub fn syscalls(&self) -> HashSet<&'static str> {
        match self {
            Self::Class(class) => {
                let mut content = SYSCALL_CLASSES.get(class).unwrap().clone();
                while content.iter().any(|e| e.starts_with('@')) {
                    content = content
                        .iter()
                        .flat_map(|c| {
                            c.strip_prefix('@')
                                .map(|class| SYSCALL_CLASSES.get(class).unwrap())
                        })
                        .flatten()
                        .chain(content.iter().filter(|e| !e.starts_with('@')))
                        .cloned()
                        .collect();
                }
                content
            }
            Self::Single(sc) => HashSet::from([sc.to_owned()]),
        }
    }
}

/// A systemd option with a value, as would be present in a config file
pub struct OptionWithValue {
    pub name: String,
    pub value: OptionValue,
}

impl FromStr for OptionWithValue {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (name, value) = s
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("Missing '=' char in {s:?}"))?;

        Ok(Self {
            name: name.to_owned(),
            value: value.parse().unwrap(), // never fails
        })
    }
}

impl fmt::Display for OptionWithValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.value {
            OptionValue::Boolean(value) => {
                write!(f, "{}={}", self.name, if *value { "true" } else { "false" })
            }
            OptionValue::String(value) => write!(f, "{}={}", self.name, value),
            OptionValue::List {
                values,
                value_if_empty,
                negation_prefix,
                repeat_option,
                ..
            } => {
                if values.is_empty() {
                    write!(f, "{}=", self.name)?;
                    if let Some(value_if_empty) = value_if_empty {
                        write!(f, "{value_if_empty}")
                    } else {
                        unreachable!()
                    }
                } else if *repeat_option {
                    for (i, value) in values.iter().enumerate() {
                        write!(f, "{}=", self.name)?;
                        if *negation_prefix {
                            write!(f, "~")?;
                        }
                        write!(f, "{value}")?;
                        if i < values.len() - 1 {
                            writeln!(f)?;
                        }
                    }
                    Ok(())
                } else {
                    write!(f, "{}=", self.name)?;
                    if *negation_prefix {
                        write!(f, "~")?;
                    }
                    write!(
                        f,
                        "{}",
                        values
                            .iter()
                            .map(|v| v.to_owned())
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

#[allow(clippy::vec_init_then_push)]
pub fn build_options(
    systemd_version: &SystemdVersion,
    kernel_version: &KernelVersion,
    mode: &HardeningMode,
) -> Vec<OptionDescription> {
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
    .map(|p| {
        OptionValueEffect::DenyWrite(PathDescription::Base {
            base: p.into(),
            exceptions: vec![],
        })
    })
    .collect();
    let mut protect_system_full_nowrite = protect_system_yes_nowrite.clone();
    protect_system_full_nowrite.push(OptionValueEffect::DenyWrite(PathDescription::Base {
        base: "/etc/".into(),
        exceptions: vec![],
    }));
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
                        .map(|p| {
                            OptionValueEffect::DenyWrite(PathDescription::Base {
                                base: p.into(),
                                exceptions: vec![],
                            })
                        })
                        .collect(),
                )),
            },
            OptionValueDescription {
                value: OptionValue::Boolean(true),
                desc: OptionEffect::Simple(OptionValueEffect::Multiple(
                    home_paths
                        .iter()
                        .map(|p| {
                            OptionValueEffect::Hide(PathDescription::Base {
                                base: p.into(),
                                exceptions: vec![],
                            })
                        })
                        .collect(),
                )),
            },
            OptionValueDescription {
                value: OptionValue::String("tmpfs".to_owned()),
                desc: OptionEffect::Simple(OptionValueEffect::Multiple(
                    home_paths
                        .iter()
                        .map(|p| {
                            OptionValueEffect::Hide(PathDescription::Base {
                                base: p.into(),
                                exceptions: vec![],
                            })
                        })
                        .chain(home_paths.iter().map(|p| {
                            OptionValueEffect::DenyWrite(PathDescription::Base {
                                base: p.into(),
                                exceptions: vec![],
                            })
                        }))
                        .collect(),
                )),
            },
        ],
    });

    // https://www.freedesktop.org/software/systemd/man/systemd.exec.html#PrivateTmp=
    options.push(OptionDescription {
        name: "PrivateTmp",
        possible_values: vec![OptionValueDescription {
            value: OptionValue::Boolean(true),
            desc: OptionEffect::Simple(OptionValueEffect::Multiple(vec![
                OptionValueEffect::Hide(PathDescription::Base {
                    base: "/tmp/".into(),
                    exceptions: vec![],
                }),
                OptionValueEffect::Hide(PathDescription::Base {
                    base: "/var/tmp/".into(),
                    exceptions: vec![],
                }),
            ])),
        }],
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
            ])),
        }],
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
                    iter::once(OptionValueEffect::DenyWrite(PathDescription::Base {
                        base: "/sys/".into(),
                        exceptions: vec![],
                    })),
                )
                .collect(),
            )),
        }],
    });

    // https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectKernelModules=
    options.push(OptionDescription {
        name: "ProtectKernelModules",
        possible_values: vec![OptionValueDescription {
            value: OptionValue::Boolean(true),
            desc: OptionEffect::Simple(OptionValueEffect::Multiple(vec![
                // https://github.com/systemd/systemd/blob/v254/src/core/namespace.c#L140
                OptionValueEffect::Hide(PathDescription::Base {
                    base: "/lib/modules/".into(),
                    exceptions: vec![],
                }),
                OptionValueEffect::Hide(PathDescription::Base {
                    base: "/usr/lib/modules/".into(),
                    exceptions: vec![],
                }),
                OptionValueEffect::DenySyscalls(DenySyscalls::Class("module")),
            ])),
        }],
    });

    // https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectKernelLogs=
    options.push(OptionDescription {
        name: "ProtectKernelLogs",
        possible_values: vec![OptionValueDescription {
            value: OptionValue::Boolean(true),
            desc: OptionEffect::Simple(OptionValueEffect::Multiple(vec![
                // https://github.com/systemd/systemd/blob/v254/src/core/namespace.c#L140
                OptionValueEffect::Hide(PathDescription::Base {
                    base: "/proc/kmsg".into(),
                    exceptions: vec![],
                }),
                OptionValueEffect::Hide(PathDescription::Base {
                    base: "/dev/kmsg".into(),
                    exceptions: vec![],
                }),
            ])),
        }],
    });

    // https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectControlGroups=
    options.push(OptionDescription {
        name: "ProtectControlGroups",
        possible_values: vec![OptionValueDescription {
            value: OptionValue::Boolean(true),
            desc: OptionEffect::Simple(OptionValueEffect::DenyWrite(PathDescription::Base {
                base: "/sys/fs/cgroup/".into(),
                exceptions: vec![],
            })),
        }],
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
                desc: OptionEffect::Simple(OptionValueEffect::Hide(PathDescription::Pattern(
                    regex::bytes::Regex::new("^/proc/[0-9]+(/|$)").unwrap(),
                ))),
            }],
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
            value: OptionValue::List {
                values: afs.iter().map(|s| s.to_string()).collect(),
                value_if_empty: Some("none".to_owned()),
                negation_prefix: false,
                repeat_option: false,
                mode: ListMode::WhiteList,
            },
            desc: OptionEffect::Cumulative(
                afs.into_iter()
                    .map(|af| {
                        OptionValueEffect::DenyAction(ProgramAction::NetworkActivity(
                            NetworkActivity {
                                af: SetSpecifier::One(af.parse().unwrap()),
                                proto: SetSpecifier::All,
                                kind: SetSpecifier::All,
                            },
                        ))
                    })
                    .collect(),
            ),
        }],
    });

    if let HardeningMode::Aggressive = mode {
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
                    }),
                )),
            }],
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
            value: OptionValue::List {
                values: deny_binds
                    .iter()
                    .map(|(af, proto)| format!("{af}:{proto}"))
                    .collect(),
                value_if_empty: None,
                negation_prefix: false,
                repeat_option: true,
                mode: ListMode::BlackList,
            },
            desc: OptionEffect::Cumulative(
                deny_binds
                    .into_iter()
                    .map(|(af, proto)| {
                        OptionValueEffect::DenyAction(ProgramAction::NetworkActivity(
                            NetworkActivity {
                                af: SetSpecifier::One(af),
                                proto: SetSpecifier::One(proto),
                                kind: SetSpecifier::One(NetworkActivityKind::Bind),
                            },
                        ))
                    })
                    .collect(),
            ),
        }],
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
    });

    // https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#CapabilityBoundingSet=
    let cap_effects = [
        // CAP_AUDIT_CONTROL, CAP_AUDIT_READ, CAP_AUDIT_WRITE: requires netlink socket message handling
        (
            "CAP_BLOCK_SUSPEND",
            OptionValueEffect::Multiple(vec![
                OptionValueEffect::DenyWrite(PathDescription::Base {
                    base: "/proc/sys/wake_lock".into(),
                    exceptions: vec![],
                }),
                OptionValueEffect::DenyAction(ProgramAction::Wakeup),
            ]),
        ),
        // TODO CAP_BPF
        // TODO CAP_CHECKPOINT_RESTORE
        (
            "CAP_CHOWN",
            OptionValueEffect::DenySyscalls(DenySyscalls::Class("chown")),
        ),
        // TODO CAP_DAC_OVER
        // TODO CAP_DAC_OVERRIDE
        // TODO CAP_DAC_READ_SEARCH
        // TODO CAP_FOWNER
        // TODO CAP_FSETID
        // TODO CAP_INIT_EFF_SET
        // TODO CAP_IPC_LOCK
        // TODO CAP_IPC_OWNER
        // TODO CAP_KILL
        // TODO CAP_LAST_CAP
        // TODO CAP_LEASE
        // TODO CAP_LINUX_IMMUTABLE
        // TODO CAP_MAC_ADMIN
        // TODO CAP_MAC_OVERRIDE
        // TODO CAP_MKNOD
        // TODO CAP_NET_ADMIN
        // CAP_NET_BIND_SERVICE would be too complex/unreliable to handle:
        // - for IPv4 sockets, either PROT_SOCK or net.ipv4.ip_unprivileged_port_start sysctl control the provileged port threshold
        // - for other socket families, rules are different
        // TODO CAP_NET_BROADCAST
        // TODO CAP_NET_RAW
        // TODO CAP_PERFMON
        // TODO CAP_SETFCAP
        // TODO CAP_SETGID
        // TODO CAP_SETPCAP
        // TODO CAP_SETUID
        // TODO CAP_SYS_ADMIN
        (
            "CAP_SYS_BOOT",
            OptionValueEffect::DenySyscalls(DenySyscalls::Class("reboot")),
        ),
        // TODO CAP_SYS_CHROOT
        // TODO CAP_SYSLOG
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
        // TODO CAP_SYS_PTRACE
        // TODO CAP_SYS_RAWIO
        // TODO CAP_SYS_RESOURCE
        // TODO CAP_SYS_TIME
        // TODO CAP_SYS_TTY_CONFIG
        // TODO CAP_WAKE_ALARM
    ];
    options.push(OptionDescription {
        name: "CapabilityBoundingSet",
        possible_values: vec![OptionValueDescription {
            value: OptionValue::List {
                values: cap_effects.iter().map(|(c, _e)| c.to_string()).collect(),
                value_if_empty: None,
                negation_prefix: true,
                repeat_option: false,
                mode: ListMode::BlackList,
            },
            desc: OptionEffect::Cumulative(cap_effects.into_iter().map(|(_c, e)| e).collect()),
        }],
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
    let mut syscall_classes: Vec<_> = SYSCALL_CLASSES.keys().cloned().collect();
    syscall_classes.sort();
    options.push(OptionDescription {
        name: "SystemCallFilter",
        possible_values: vec![OptionValueDescription {
            value: OptionValue::List {
                values: syscall_classes
                    .iter()
                    .map(|c| format!("@{c}:EPERM"))
                    .collect(),
                value_if_empty: None,
                negation_prefix: true,
                repeat_option: false,
                mode: ListMode::BlackList,
            },
            desc: OptionEffect::Cumulative(
                syscall_classes
                    .into_iter()
                    .map(|class| OptionValueEffect::DenySyscalls(DenySyscalls::Class(class)))
                    .collect(),
            ),
        }],
    });

    if let HardeningMode::Aggressive = mode {
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
        });
    }

    log::debug!("{options:#?}");
    options
}
