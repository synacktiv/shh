//! Systemd option model

use std::{
    collections::{HashMap, HashSet},
    fmt, iter,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    str::FromStr,
};

use itertools::Itertools;
use lazy_static::lazy_static;
use strum::IntoEnumIterator;

use crate::{
    cl::HardeningMode,
    systemd::{KernelVersion, SystemdVersion},
};

/// Systemd option with its possibles values, and their effect
#[derive(Debug)]
pub struct OptionDescription {
    pub name: String,
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
    /// Mount path as read only
    DenyWrite(PathDescription),
    /// Mount an empty tmpfs under given directory
    Hide(PathDescription),
    /// Deny syscall(s)
    DenySyscalls(DenySyscalls),
    /// Deny a socket family
    DenySocketFamily(String),
    /// Deny a write execute memory mapping
    DenyWriteExecuteMemoryMapping,
    /// Deny real time scheduling
    DenyRealtimeScheduler,
    /// Deny a socket family and protocol socket bind
    DenySocketBind {
        af: SocketFamily,
        proto: SocketProtocol,
    },
    /// Union of multiple effects
    Multiple(Vec<OptionValueEffect>),
}

#[derive(Debug, Clone)]
pub enum DenySyscalls {
    /// See https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L306
    /// for the content of each class
    Class(String),
    Single(String),
}

// Not a complete enumeration, only used with SocketBindDeny
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
}

impl SocketFamily {
    pub fn from_syscall_arg(s: &str) -> Option<Self> {
        match s {
            "AF_INET" => Some(Self::Ipv4),
            "AF_INET6" => Some(Self::Ipv6),
            _ => None,
        }
    }
}

// Not a complete enumeration, only used with SocketBindDeny
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
}

impl SocketProtocol {
    pub fn from_syscall_arg(s: &str) -> Option<Self> {
        // Only makes sense for IP addresses
        match s {
            "SOCK_STREAM" => Some(Self::Tcp),
            "SOCK_DGRAM" => Some(Self::Udp),
            _ => None,
        }
    }
}

impl DenySyscalls {
    /// Get denied syscall names
    pub fn syscalls(&self) -> HashSet<String> {
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
            Self::Single(sc) => HashSet::from([sc.clone()]),
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

lazy_static! {
    static ref SYSCALL_CLASSES: HashMap<String, HashSet<String>> = HashMap::from([
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L374
            "aio".to_owned(),
             HashSet::from([
                "io_cancel".to_owned(),
                "io_destroy".to_owned(),
                "io_getevents".to_owned(),
                "io_pgetevents".to_owned(),
                "io_pgetevents_time64".to_owned(),
                "io_setup".to_owned(),
                "io_submit".to_owned(),
                "io_uring_enter".to_owned(),
                "io_uring_register".to_owned(),
                "io_uring_setup".to_owned(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L389
            "basic-io".to_owned(),
             HashSet::from([
                "_llseek".to_owned(),
                "close".to_owned(),
                "close_range".to_owned(),
                "dup".to_owned(),
                "dup2".to_owned(),
                "dup3".to_owned(),
                "lseek".to_owned(),
                "pread64".to_owned(),
                "preadv".to_owned(),
                "preadv2".to_owned(),
                "pwrite64".to_owned(),
                "pwritev".to_owned(),
                "pwritev2".to_owned(),
                "read".to_owned(),
                "readv".to_owned(),
                "write".to_owned(),
                "writev".to_owned(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L411
            "chown".to_owned(),
             HashSet::from([
                "chown".to_owned(),
                "chown32".to_owned(),
                "fchown".to_owned(),
                "fchown32".to_owned(),
                "fchownat".to_owned(),
                "lchown".to_owned(),
                "lchown32".to_owned(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L423
            "clock".to_owned(),
             HashSet::from([
                "adjtimex".to_owned(),
                "clock_adjtime".to_owned(),
                "clock_adjtime64".to_owned(),
                "clock_settime".to_owned(),
                "clock_settime64".to_owned(),
                "settimeofday".to_owned(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L434
            "cpu-emulation".to_owned(),
             HashSet::from([
                "modify_ldt".to_owned(),
                "subpage_prot".to_owned(),
                "switch_endian".to_owned(),
                "vm86".to_owned(),
                "vm86old".to_owned(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L444
            "debug".to_owned(),
             HashSet::from([
                "lookup_dcookie".to_owned(),
                "perf_event_open".to_owned(),
                "pidfd_getfd".to_owned(),
                "ptrace".to_owned(),
                "rtas".to_owned(),
                "s390_runtime_instr".to_owned(),
                "sys_debug_setcontext".to_owned(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L456
            "file-system".to_owned(),
             HashSet::from([
                "access".to_owned(),
                "chdir".to_owned(),
                "chmod".to_owned(),
                "close".to_owned(),
                "creat".to_owned(),
                "faccessat".to_owned(),
                "faccessat2".to_owned(),
                "fallocate".to_owned(),
                "fchdir".to_owned(),
                "fchmod".to_owned(),
                "fchmodat".to_owned(),
                "fcntl".to_owned(),
                "fcntl64".to_owned(),
                "fgetxattr".to_owned(),
                "flistxattr".to_owned(),
                "fremovexattr".to_owned(),
                "fsetxattr".to_owned(),
                "fstat".to_owned(),
                "fstat64".to_owned(),
                "fstatat64".to_owned(),
                "fstatfs".to_owned(),
                "fstatfs64".to_owned(),
                "ftruncate".to_owned(),
                "ftruncate64".to_owned(),
                "futimesat".to_owned(),
                "getcwd".to_owned(),
                "getdents".to_owned(),
                "getdents64".to_owned(),
                "getxattr".to_owned(),
                "inotify_add_watch".to_owned(),
                "inotify_init".to_owned(),
                "inotify_init1".to_owned(),
                "inotify_rm_watch".to_owned(),
                "lgetxattr".to_owned(),
                "link".to_owned(),
                "linkat".to_owned(),
                "listxattr".to_owned(),
                "llistxattr".to_owned(),
                "lremovexattr".to_owned(),
                "lsetxattr".to_owned(),
                "lstat".to_owned(),
                "lstat64".to_owned(),
                "mkdir".to_owned(),
                "mkdirat".to_owned(),
                "mknod".to_owned(),
                "mknodat".to_owned(),
                "newfstatat".to_owned(),
                "oldfstat".to_owned(),
                "oldlstat".to_owned(),
                "oldstat".to_owned(),
                "open".to_owned(),
                "openat".to_owned(),
                "openat2".to_owned(),
                "readlink".to_owned(),
                "readlinkat".to_owned(),
                "removexattr".to_owned(),
                "rename".to_owned(),
                "renameat".to_owned(),
                "renameat2".to_owned(),
                "rmdir".to_owned(),
                "setxattr".to_owned(),
                "stat".to_owned(),
                "stat64".to_owned(),
                "statfs".to_owned(),
                "statfs64".to_owned(),
                "statx".to_owned(),
                "symlink".to_owned(),
                "symlinkat".to_owned(),
                "truncate".to_owned(),
                "truncate64".to_owned(),
                "unlink".to_owned(),
                "unlinkat".to_owned(),
                "utime".to_owned(),
                "utimensat".to_owned(),
                "utimensat_time64".to_owned(),
                "utimes".to_owned(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L537
            "io-event".to_owned(),
             HashSet::from([
                "_newselect".to_owned(),
                "epoll_create".to_owned(),
                "epoll_create1".to_owned(),
                "epoll_ctl".to_owned(),
                "epoll_ctl_old".to_owned(),
                "epoll_pwait".to_owned(),
                "epoll_pwait2".to_owned(),
                "epoll_wait".to_owned(),
                "epoll_wait_old".to_owned(),
                "eventfd".to_owned(),
                "eventfd2".to_owned(),
                "poll".to_owned(),
                "ppoll".to_owned(),
                "ppoll_time64".to_owned(),
                "pselect6".to_owned(),
                "pselect6_time64".to_owned(),
                "select".to_owned(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L559
            "ipc".to_owned(),
             HashSet::from([
                "ipc".to_owned(),
                "memfd_create".to_owned(),
                "mq_getsetattr".to_owned(),
                "mq_notify".to_owned(),
                "mq_open".to_owned(),
                "mq_timedreceive".to_owned(),
                "mq_timedreceive_time64".to_owned(),
                "mq_timedsend".to_owned(),
                "mq_timedsend_time64".to_owned(),
                "mq_unlink".to_owned(),
                "msgctl".to_owned(),
                "msgget".to_owned(),
                "msgrcv".to_owned(),
                "msgsnd".to_owned(),
                "pipe".to_owned(),
                "pipe2".to_owned(),
                "process_madvise".to_owned(),
                "process_vm_readv".to_owned(),
                "process_vm_writev".to_owned(),
                "semctl".to_owned(),
                "semget".to_owned(),
                "semop".to_owned(),
                "semtimedop".to_owned(),
                "semtimedop_time64".to_owned(),
                "shmat".to_owned(),
                "shmctl".to_owned(),
                "shmdt".to_owned(),
                "shmget".to_owned(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L592
            "keyring".to_owned(),
             HashSet::from([
                "add_key".to_owned(),
                "keyctl".to_owned(),
                "request_key".to_owned(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L600
            "memlock".to_owned(),
             HashSet::from([
                "mlock".to_owned(),
                "mlock2".to_owned(),
                "mlockall".to_owned(),
                "munlock".to_owned(),
                "munlockall".to_owned(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L610
            "module".to_owned(),
             HashSet::from([
                "delete_module".to_owned(),
                "finit_module".to_owned(),
                "init_module".to_owned(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L618
            "mount".to_owned(),
             HashSet::from([
                "chroot".to_owned(),
                "fsconfig".to_owned(),
                "fsmount".to_owned(),
                "fsopen".to_owned(),
                "fspick".to_owned(),
                "mount".to_owned(),
                "mount_setattr".to_owned(),
                "move_mount".to_owned(),
                "open_tree".to_owned(),
                "pivot_root".to_owned(),
                "umount".to_owned(),
                "umount2".to_owned(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L635
            "network-io".to_owned(),
             HashSet::from([
                "accept".to_owned(),
                "accept4".to_owned(),
                "bind".to_owned(),
                "connect".to_owned(),
                "getpeername".to_owned(),
                "getsockname".to_owned(),
                "getsockopt".to_owned(),
                "listen".to_owned(),
                "recv".to_owned(),
                "recvfrom".to_owned(),
                "recvmmsg".to_owned(),
                "recvmmsg_time64".to_owned(),
                "recvmsg".to_owned(),
                "send".to_owned(),
                "sendmmsg".to_owned(),
                "sendmsg".to_owned(),
                "sendto".to_owned(),
                "setsockopt".to_owned(),
                "shutdown".to_owned(),
                "socket".to_owned(),
                "socketcall".to_owned(),
                "socketpair".to_owned(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L662
            "obsolete".to_owned(),
             HashSet::from([
                "_sysctl".to_owned(),
                "afs_syscall".to_owned(),
                "bdflush".to_owned(),
                "break".to_owned(),
                "create_module".to_owned(),
                "ftime".to_owned(),
                "get_kernel_syms".to_owned(),
                "getpmsg".to_owned(),
                "gtty".to_owned(),
                "idle".to_owned(),
                "lock".to_owned(),
                "mpx".to_owned(),
                "prof".to_owned(),
                "profil".to_owned(),
                "putpmsg".to_owned(),
                "query_module".to_owned(),
                "security".to_owned(),
                "sgetmask".to_owned(),
                "ssetmask".to_owned(),
                "stime".to_owned(),
                "stty".to_owned(),
                "sysfs".to_owned(),
                "tuxcall".to_owned(),
                "ulimit".to_owned(),
                "uselib".to_owned(),
                "ustat".to_owned(),
                "vserver".to_owned(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L695
            "pkey".to_owned(),
             HashSet::from([
                "pkey_alloc".to_owned(),
                "pkey_free".to_owned(),
                "pkey_mprotect".to_owned(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L703
            "privileged".to_owned(),
             HashSet::from([
                "@chown".to_owned(),
                "@clock".to_owned(),
                "@module".to_owned(),
                "@raw-io".to_owned(),
                "@reboot".to_owned(),
                "@swap".to_owned(),
                "_sysctl".to_owned(),
                "acct".to_owned(),
                "bpf".to_owned(),
                "capset".to_owned(),
                "chroot".to_owned(),
                "fanotify_init".to_owned(),
                "fanotify_mark".to_owned(),
                "nfsservctl".to_owned(),
                "open_by_handle_at".to_owned(),
                "pivot_root".to_owned(),
                "quotactl".to_owned(),
                "quotactl_fd".to_owned(),
                "setdomainname".to_owned(),
                "setfsuid".to_owned(),
                "setfsuid32".to_owned(),
                "setgroups".to_owned(),
                "setgroups32".to_owned(),
                "sethostname".to_owned(),
                "setresuid".to_owned(),
                "setresuid32".to_owned(),
                "setreuid".to_owned(),
                "setreuid32".to_owned(),
                "setuid".to_owned(),
                "setuid32".to_owned(),
                "vhangup".to_owned(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L739
            "process".to_owned(),
             HashSet::from([
                "capget".to_owned(),
                "clone".to_owned(),
                "clone3".to_owned(),
                "execveat".to_owned(),
                "fork".to_owned(),
                "getrusage".to_owned(),
                "kill".to_owned(),
                "pidfd_open".to_owned(),
                "pidfd_send_signal".to_owned(),
                "prctl".to_owned(),
                "rt_sigqueueinfo".to_owned(),
                "rt_tgsigqueueinfo".to_owned(),
                "setns".to_owned(),
                "swapcontext".to_owned(),
                "tgkill".to_owned(),
                "times".to_owned(),
                "tkill".to_owned(),
                "unshare".to_owned(),
                "vfork".to_owned(),
                "wait4".to_owned(),
                "waitid".to_owned(),
                "waitpid".to_owned(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L769
            "raw-io".to_owned(),
             HashSet::from([
                "ioperm".to_owned(),
                "iopl".to_owned(),
                "pciconfig_iobase".to_owned(),
                "pciconfig_read".to_owned(),
                "pciconfig_write".to_owned(),
                "s390_pci_mmio_read".to_owned(),
                "s390_pci_mmio_write".to_owned(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L781
            "reboot".to_owned(),
             HashSet::from([
                "kexec_file_load".to_owned(),
                "kexec_load".to_owned(),
                "reboot".to_owned(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L789
            "resources".to_owned(),
             HashSet::from([
                "ioprio_set".to_owned(),
                "mbind".to_owned(),
                "migrate_pages".to_owned(),
                "move_pages".to_owned(),
                "nice".to_owned(),
                "sched_setaffinity".to_owned(),
                "sched_setattr".to_owned(),
                "sched_setparam".to_owned(),
                "sched_setscheduler".to_owned(),
                "set_mempolicy".to_owned(),
                "set_mempolicy_home_node".to_owned(),
                "setpriority".to_owned(),
                "setrlimit".to_owned(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L807
            "sandbox".to_owned(),
             HashSet::from([
                "landlock_add_rule".to_owned(),
                "landlock_create_ruleset".to_owned(),
                "landlock_restrict_self".to_owned(),
                "seccomp".to_owned(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L816
            "setuid".to_owned(),
             HashSet::from([
                "setgid".to_owned(),
                "setgid32".to_owned(),
                "setgroups".to_owned(),
                "setgroups32".to_owned(),
                "setregid".to_owned(),
                "setregid32".to_owned(),
                "setresgid".to_owned(),
                "setresgid32".to_owned(),
                "setresuid".to_owned(),
                "setresuid32".to_owned(),
                "setreuid".to_owned(),
                "setreuid32".to_owned(),
                "setuid".to_owned(),
                "setuid32".to_owned(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L835
            "signal".to_owned(),
             HashSet::from([
                "rt_sigaction".to_owned(),
                "rt_sigpending".to_owned(),
                "rt_sigprocmask".to_owned(),
                "rt_sigsuspend".to_owned(),
                "rt_sigtimedwait".to_owned(),
                "rt_sigtimedwait_time64".to_owned(),
                "sigaction".to_owned(),
                "sigaltstack".to_owned(),
                "signal".to_owned(),
                "signalfd".to_owned(),
                "signalfd4".to_owned(),
                "sigpending".to_owned(),
                "sigprocmask".to_owned(),
                "sigsuspend".to_owned(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L854
            "swap".to_owned(),
             HashSet::from([
                "swapoff".to_owned(),
                "swapon".to_owned(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L861
            "sync".to_owned(),
             HashSet::from([
                "fdatasync".to_owned(),
                "fsync".to_owned(),
                "msync".to_owned(),
                "sync".to_owned(),
                "sync_file_range".to_owned(),
                "sync_file_range2".to_owned(),
                "syncfs".to_owned(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L939
            "timer".to_owned(),
             HashSet::from([
                "alarm".to_owned(),
                "getitimer".to_owned(),
                "setitimer".to_owned(),
                "timer_create".to_owned(),
                "timer_delete".to_owned(),
                "timer_getoverrun".to_owned(),
                "timer_gettime".to_owned(),
                "timer_gettime64".to_owned(),
                "timer_settime".to_owned(),
                "timer_settime64".to_owned(),
                "timerfd_create".to_owned(),
                "timerfd_gettime".to_owned(),
                "timerfd_gettime64".to_owned(),
                "timerfd_settime".to_owned(),
                "timerfd_settime64".to_owned(),
                "times".to_owned(),
            ])
        ),
    ]);
}

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
        name: "ProtectSystem".to_owned(),
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
        name: "ProtectHome".to_owned(),
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
        name: "PrivateTmp".to_owned(),
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
        name: "PrivateDevices".to_owned(),
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
                OptionValueEffect::DenySyscalls(DenySyscalls::Class("raw-io".to_owned())),
            ])),
        }],
    });

    // https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectKernelTunables=
    options.push(OptionDescription {
        name: "ProtectKernelTunables".to_owned(),
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
        name: "ProtectKernelModules".to_owned(),
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
                OptionValueEffect::DenySyscalls(DenySyscalls::Class("module".to_owned())),
            ])),
        }],
    });

    // https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectKernelLogs=
    options.push(OptionDescription {
        name: "ProtectKernelLogs".to_owned(),
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
        name: "ProtectControlGroups".to_owned(),
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
            name: "ProtectProc".to_owned(),
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
        name: "MemoryDenyWriteExecute".to_owned(),
        possible_values: vec![OptionValueDescription {
            value: OptionValue::Boolean(true),
            desc: OptionEffect::Simple(OptionValueEffect::DenyWriteExecuteMemoryMapping),
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
        name: "RestrictAddressFamilies".to_owned(),
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
                    .map(|af| OptionValueEffect::DenySocketFamily(af.to_owned()))
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
            name: "PrivateNetwork".to_owned(),
            possible_values: vec![OptionValueDescription {
                value: OptionValue::Boolean(true),
                desc: OptionEffect::Simple(OptionValueEffect::Multiple(
                    afs.into_iter()
                        .map(|af| OptionValueEffect::DenySocketFamily(af.to_owned()))
                        .collect(),
                )),
            }],
        });
    }

    // https://www.freedesktop.org/software/systemd/man/systemd.resource-control.html#SocketBindAllow=bind-rule
    //
    // We don't go as far as allowing/denying individual ports, as that would easily break for example if a port is changed
    // in a server configuration
    let deny_binds: Vec<_> = SocketFamily::iter()
        .cartesian_product(SocketProtocol::iter())
        .collect();
    options.push(OptionDescription {
        name: "SocketBindDeny".to_owned(),
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
                    .map(|(af, proto)| OptionValueEffect::DenySocketBind { af, proto })
                    .collect(),
            ),
        }],
    });

    // https://www.freedesktop.org/software/systemd/man/systemd.exec.html#LockPersonality=
    options.push(OptionDescription {
        name: "LockPersonality".to_owned(),
        possible_values: vec![OptionValueDescription {
            value: OptionValue::Boolean(true),
            // In practice, the option allows the call if the default personality is set, but we don't
            // need to model that level of precision.
            // The "deny" model prevents false positives
            desc: OptionEffect::Simple(OptionValueEffect::DenySyscalls(DenySyscalls::Single(
                "personality".to_owned(),
            ))),
        }],
    });

    // https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictRealtime=
    options.push(OptionDescription {
        name: "RestrictRealtime".to_owned(),
        possible_values: vec![OptionValueDescription {
            value: OptionValue::Boolean(true),
            desc: OptionEffect::Simple(OptionValueEffect::DenyRealtimeScheduler),
        }],
    });

    // https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectClock=
    options.push(OptionDescription {
        name: "ProtectClock".to_owned(),
        possible_values: vec![OptionValueDescription {
            value: OptionValue::Boolean(true),
            // This option essentially does the same thing as deny @clock
            desc: OptionEffect::Simple(OptionValueEffect::DenySyscalls(DenySyscalls::Class(
                "clock".to_owned(),
            ))),
        }],
    });

    // https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallFilter=
    //
    // Also change the default behavior when calling a denied syscall to return EPERM instead og killing
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
        name: "SystemCallFilter".to_owned(),
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
            name: "SystemCallArchitectures".to_owned(),
            possible_values: vec![OptionValueDescription {
                value: OptionValue::String("native".to_owned()),
                desc: OptionEffect::None,
            }],
        });
    }

    log::debug!("{options:#?}");
    options
}
