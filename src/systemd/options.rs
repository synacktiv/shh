//! Systemd option modeling

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::iter;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use itertools::Itertools;
use lazy_static::lazy_static;
use strum::IntoEnumIterator;

use crate::cl::HardeningMode;
use crate::systemd::{KernelVersion, SystemdVersion};

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
            _ => Ok(OptionValue::String(s.to_string())),
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
#[derive(Debug, Clone, Eq, PartialEq, strum::EnumIter, strum::Display)]
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
#[derive(Debug, Clone, Eq, PartialEq, strum::EnumIter, strum::Display)]
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
            name: name.to_string(),
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
                            .map(|v| v.to_string())
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
            "aio".to_string(),
             HashSet::from([
                "io_cancel".to_string(),
                "io_destroy".to_string(),
                "io_getevents".to_string(),
                "io_pgetevents".to_string(),
                "io_pgetevents_time64".to_string(),
                "io_setup".to_string(),
                "io_submit".to_string(),
                "io_uring_enter".to_string(),
                "io_uring_register".to_string(),
                "io_uring_setup".to_string(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L389
            "basic-io".to_string(),
             HashSet::from([
                "_llseek".to_string(),
                "close".to_string(),
                "close_range".to_string(),
                "dup".to_string(),
                "dup2".to_string(),
                "dup3".to_string(),
                "lseek".to_string(),
                "pread64".to_string(),
                "preadv".to_string(),
                "preadv2".to_string(),
                "pwrite64".to_string(),
                "pwritev".to_string(),
                "pwritev2".to_string(),
                "read".to_string(),
                "readv".to_string(),
                "write".to_string(),
                "writev".to_string(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L411
            "chown".to_string(),
             HashSet::from([
                "chown".to_string(),
                "chown32".to_string(),
                "fchown".to_string(),
                "fchown32".to_string(),
                "fchownat".to_string(),
                "lchown".to_string(),
                "lchown32".to_string(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L423
            "clock".to_string(),
             HashSet::from([
                "adjtimex".to_string(),
                "clock_adjtime".to_string(),
                "clock_adjtime64".to_string(),
                "clock_settime".to_string(),
                "clock_settime64".to_string(),
                "settimeofday".to_string(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L434
            "cpu-emulation".to_string(),
             HashSet::from([
                "modify_ldt".to_string(),
                "subpage_prot".to_string(),
                "switch_endian".to_string(),
                "vm86".to_string(),
                "vm86old".to_string(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L444
            "debug".to_string(),
             HashSet::from([
                "lookup_dcookie".to_string(),
                "perf_event_open".to_string(),
                "pidfd_getfd".to_string(),
                "ptrace".to_string(),
                "rtas".to_string(),
                "s390_runtime_instr".to_string(),
                "sys_debug_setcontext".to_string(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L456
            "file-system".to_string(),
             HashSet::from([
                "access".to_string(),
                "chdir".to_string(),
                "chmod".to_string(),
                "close".to_string(),
                "creat".to_string(),
                "faccessat".to_string(),
                "faccessat2".to_string(),
                "fallocate".to_string(),
                "fchdir".to_string(),
                "fchmod".to_string(),
                "fchmodat".to_string(),
                "fcntl".to_string(),
                "fcntl64".to_string(),
                "fgetxattr".to_string(),
                "flistxattr".to_string(),
                "fremovexattr".to_string(),
                "fsetxattr".to_string(),
                "fstat".to_string(),
                "fstat64".to_string(),
                "fstatat64".to_string(),
                "fstatfs".to_string(),
                "fstatfs64".to_string(),
                "ftruncate".to_string(),
                "ftruncate64".to_string(),
                "futimesat".to_string(),
                "getcwd".to_string(),
                "getdents".to_string(),
                "getdents64".to_string(),
                "getxattr".to_string(),
                "inotify_add_watch".to_string(),
                "inotify_init".to_string(),
                "inotify_init1".to_string(),
                "inotify_rm_watch".to_string(),
                "lgetxattr".to_string(),
                "link".to_string(),
                "linkat".to_string(),
                "listxattr".to_string(),
                "llistxattr".to_string(),
                "lremovexattr".to_string(),
                "lsetxattr".to_string(),
                "lstat".to_string(),
                "lstat64".to_string(),
                "mkdir".to_string(),
                "mkdirat".to_string(),
                "mknod".to_string(),
                "mknodat".to_string(),
                "newfstatat".to_string(),
                "oldfstat".to_string(),
                "oldlstat".to_string(),
                "oldstat".to_string(),
                "open".to_string(),
                "openat".to_string(),
                "openat2".to_string(),
                "readlink".to_string(),
                "readlinkat".to_string(),
                "removexattr".to_string(),
                "rename".to_string(),
                "renameat".to_string(),
                "renameat2".to_string(),
                "rmdir".to_string(),
                "setxattr".to_string(),
                "stat".to_string(),
                "stat64".to_string(),
                "statfs".to_string(),
                "statfs64".to_string(),
                "statx".to_string(),
                "symlink".to_string(),
                "symlinkat".to_string(),
                "truncate".to_string(),
                "truncate64".to_string(),
                "unlink".to_string(),
                "unlinkat".to_string(),
                "utime".to_string(),
                "utimensat".to_string(),
                "utimensat_time64".to_string(),
                "utimes".to_string(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L537
            "io-event".to_string(),
             HashSet::from([
                "_newselect".to_string(),
                "epoll_create".to_string(),
                "epoll_create1".to_string(),
                "epoll_ctl".to_string(),
                "epoll_ctl_old".to_string(),
                "epoll_pwait".to_string(),
                "epoll_pwait2".to_string(),
                "epoll_wait".to_string(),
                "epoll_wait_old".to_string(),
                "eventfd".to_string(),
                "eventfd2".to_string(),
                "poll".to_string(),
                "ppoll".to_string(),
                "ppoll_time64".to_string(),
                "pselect6".to_string(),
                "pselect6_time64".to_string(),
                "select".to_string(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L559
            "ipc".to_string(),
             HashSet::from([
                "ipc".to_string(),
                "memfd_create".to_string(),
                "mq_getsetattr".to_string(),
                "mq_notify".to_string(),
                "mq_open".to_string(),
                "mq_timedreceive".to_string(),
                "mq_timedreceive_time64".to_string(),
                "mq_timedsend".to_string(),
                "mq_timedsend_time64".to_string(),
                "mq_unlink".to_string(),
                "msgctl".to_string(),
                "msgget".to_string(),
                "msgrcv".to_string(),
                "msgsnd".to_string(),
                "pipe".to_string(),
                "pipe2".to_string(),
                "process_madvise".to_string(),
                "process_vm_readv".to_string(),
                "process_vm_writev".to_string(),
                "semctl".to_string(),
                "semget".to_string(),
                "semop".to_string(),
                "semtimedop".to_string(),
                "semtimedop_time64".to_string(),
                "shmat".to_string(),
                "shmctl".to_string(),
                "shmdt".to_string(),
                "shmget".to_string(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L592
            "keyring".to_string(),
             HashSet::from([
                "add_key".to_string(),
                "keyctl".to_string(),
                "request_key".to_string(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L600
            "memlock".to_string(),
             HashSet::from([
                "mlock".to_string(),
                "mlock2".to_string(),
                "mlockall".to_string(),
                "munlock".to_string(),
                "munlockall".to_string(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L610
            "module".to_string(),
             HashSet::from([
                "delete_module".to_string(),
                "finit_module".to_string(),
                "init_module".to_string(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L618
            "mount".to_string(),
             HashSet::from([
                "chroot".to_string(),
                "fsconfig".to_string(),
                "fsmount".to_string(),
                "fsopen".to_string(),
                "fspick".to_string(),
                "mount".to_string(),
                "mount_setattr".to_string(),
                "move_mount".to_string(),
                "open_tree".to_string(),
                "pivot_root".to_string(),
                "umount".to_string(),
                "umount2".to_string(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L635
            "network-io".to_string(),
             HashSet::from([
                "accept".to_string(),
                "accept4".to_string(),
                "bind".to_string(),
                "connect".to_string(),
                "getpeername".to_string(),
                "getsockname".to_string(),
                "getsockopt".to_string(),
                "listen".to_string(),
                "recv".to_string(),
                "recvfrom".to_string(),
                "recvmmsg".to_string(),
                "recvmmsg_time64".to_string(),
                "recvmsg".to_string(),
                "send".to_string(),
                "sendmmsg".to_string(),
                "sendmsg".to_string(),
                "sendto".to_string(),
                "setsockopt".to_string(),
                "shutdown".to_string(),
                "socket".to_string(),
                "socketcall".to_string(),
                "socketpair".to_string(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L662
            "obsolete".to_string(),
             HashSet::from([
                "_sysctl".to_string(),
                "afs_syscall".to_string(),
                "bdflush".to_string(),
                "break".to_string(),
                "create_module".to_string(),
                "ftime".to_string(),
                "get_kernel_syms".to_string(),
                "getpmsg".to_string(),
                "gtty".to_string(),
                "idle".to_string(),
                "lock".to_string(),
                "mpx".to_string(),
                "prof".to_string(),
                "profil".to_string(),
                "putpmsg".to_string(),
                "query_module".to_string(),
                "security".to_string(),
                "sgetmask".to_string(),
                "ssetmask".to_string(),
                "stime".to_string(),
                "stty".to_string(),
                "sysfs".to_string(),
                "tuxcall".to_string(),
                "ulimit".to_string(),
                "uselib".to_string(),
                "ustat".to_string(),
                "vserver".to_string(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L695
            "pkey".to_string(),
             HashSet::from([
                "pkey_alloc".to_string(),
                "pkey_free".to_string(),
                "pkey_mprotect".to_string(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L703
            "privileged".to_string(),
             HashSet::from([
                "@chown".to_string(),
                "@clock".to_string(),
                "@module".to_string(),
                "@raw-io".to_string(),
                "@reboot".to_string(),
                "@swap".to_string(),
                "_sysctl".to_string(),
                "acct".to_string(),
                "bpf".to_string(),
                "capset".to_string(),
                "chroot".to_string(),
                "fanotify_init".to_string(),
                "fanotify_mark".to_string(),
                "nfsservctl".to_string(),
                "open_by_handle_at".to_string(),
                "pivot_root".to_string(),
                "quotactl".to_string(),
                "quotactl_fd".to_string(),
                "setdomainname".to_string(),
                "setfsuid".to_string(),
                "setfsuid32".to_string(),
                "setgroups".to_string(),
                "setgroups32".to_string(),
                "sethostname".to_string(),
                "setresuid".to_string(),
                "setresuid32".to_string(),
                "setreuid".to_string(),
                "setreuid32".to_string(),
                "setuid".to_string(),
                "setuid32".to_string(),
                "vhangup".to_string(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L739
            "process".to_string(),
             HashSet::from([
                "capget".to_string(),
                "clone".to_string(),
                "clone3".to_string(),
                "execveat".to_string(),
                "fork".to_string(),
                "getrusage".to_string(),
                "kill".to_string(),
                "pidfd_open".to_string(),
                "pidfd_send_signal".to_string(),
                "prctl".to_string(),
                "rt_sigqueueinfo".to_string(),
                "rt_tgsigqueueinfo".to_string(),
                "setns".to_string(),
                "swapcontext".to_string(),
                "tgkill".to_string(),
                "times".to_string(),
                "tkill".to_string(),
                "unshare".to_string(),
                "vfork".to_string(),
                "wait4".to_string(),
                "waitid".to_string(),
                "waitpid".to_string(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L769
            "raw-io".to_string(),
             HashSet::from([
                "ioperm".to_string(),
                "iopl".to_string(),
                "pciconfig_iobase".to_string(),
                "pciconfig_read".to_string(),
                "pciconfig_write".to_string(),
                "s390_pci_mmio_read".to_string(),
                "s390_pci_mmio_write".to_string(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L781
            "reboot".to_string(),
             HashSet::from([
                "kexec_file_load".to_string(),
                "kexec_load".to_string(),
                "reboot".to_string(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L789
            "resources".to_string(),
             HashSet::from([
                "ioprio_set".to_string(),
                "mbind".to_string(),
                "migrate_pages".to_string(),
                "move_pages".to_string(),
                "nice".to_string(),
                "sched_setaffinity".to_string(),
                "sched_setattr".to_string(),
                "sched_setparam".to_string(),
                "sched_setscheduler".to_string(),
                "set_mempolicy".to_string(),
                "set_mempolicy_home_node".to_string(),
                "setpriority".to_string(),
                "setrlimit".to_string(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L807
            "sandbox".to_string(),
             HashSet::from([
                "landlock_add_rule".to_string(),
                "landlock_create_ruleset".to_string(),
                "landlock_restrict_self".to_string(),
                "seccomp".to_string(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L816
            "setuid".to_string(),
             HashSet::from([
                "setgid".to_string(),
                "setgid32".to_string(),
                "setgroups".to_string(),
                "setgroups32".to_string(),
                "setregid".to_string(),
                "setregid32".to_string(),
                "setresgid".to_string(),
                "setresgid32".to_string(),
                "setresuid".to_string(),
                "setresuid32".to_string(),
                "setreuid".to_string(),
                "setreuid32".to_string(),
                "setuid".to_string(),
                "setuid32".to_string(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L835
            "signal".to_string(),
             HashSet::from([
                "rt_sigaction".to_string(),
                "rt_sigpending".to_string(),
                "rt_sigprocmask".to_string(),
                "rt_sigsuspend".to_string(),
                "rt_sigtimedwait".to_string(),
                "rt_sigtimedwait_time64".to_string(),
                "sigaction".to_string(),
                "sigaltstack".to_string(),
                "signal".to_string(),
                "signalfd".to_string(),
                "signalfd4".to_string(),
                "sigpending".to_string(),
                "sigprocmask".to_string(),
                "sigsuspend".to_string(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L854
            "swap".to_string(),
             HashSet::from([
                "swapoff".to_string(),
                "swapon".to_string(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L861
            "sync".to_string(),
             HashSet::from([
                "fdatasync".to_string(),
                "fsync".to_string(),
                "msync".to_string(),
                "sync".to_string(),
                "sync_file_range".to_string(),
                "sync_file_range2".to_string(),
                "syncfs".to_string(),
            ])
        ),
        (
            // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L939
            "timer".to_string(),
             HashSet::from([
                "alarm".to_string(),
                "getitimer".to_string(),
                "setitimer".to_string(),
                "timer_create".to_string(),
                "timer_delete".to_string(),
                "timer_getoverrun".to_string(),
                "timer_gettime".to_string(),
                "timer_gettime64".to_string(),
                "timer_settime".to_string(),
                "timer_settime64".to_string(),
                "timerfd_create".to_string(),
                "timerfd_gettime".to_string(),
                "timerfd_gettime64".to_string(),
                "timerfd_settime".to_string(),
                "timerfd_settime64".to_string(),
                "times".to_string(),
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
        name: "ProtectSystem".to_string(),
        possible_values: vec![
            OptionValueDescription {
                value: OptionValue::Boolean(true),
                desc: OptionEffect::Simple(OptionValueEffect::Multiple(protect_system_yes_nowrite)),
            },
            OptionValueDescription {
                value: OptionValue::String("full".to_string()),
                desc: OptionEffect::Simple(OptionValueEffect::Multiple(
                    protect_system_full_nowrite,
                )),
            },
            OptionValueDescription {
                value: OptionValue::String("strict".to_string()),
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
        name: "ProtectHome".to_string(),
        possible_values: vec![
            OptionValueDescription {
                value: OptionValue::String("read-only".to_string()),
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
                value: OptionValue::String("tmpfs".to_string()),
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
        name: "PrivateTmp".to_string(),
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
        name: "PrivateDevices".to_string(),
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
                OptionValueEffect::DenySyscalls(DenySyscalls::Class("raw-io".to_string())),
            ])),
        }],
    });

    // https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectKernelTunables=
    options.push(OptionDescription {
        name: "ProtectKernelTunables".to_string(),
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
        name: "ProtectKernelModules".to_string(),
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
                OptionValueEffect::DenySyscalls(DenySyscalls::Class("module".to_string())),
            ])),
        }],
    });

    // https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectKernelLogs=
    options.push(OptionDescription {
        name: "ProtectKernelLogs".to_string(),
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
        name: "ProtectControlGroups".to_string(),
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
            name: "ProtectProc".to_string(),
            // Since we have no easy & reliable (race free) way to know which process belongs to
            // which user, only support the most restrictive option
            possible_values: vec![OptionValueDescription {
                value: OptionValue::String("ptraceable".to_string()),
                desc: OptionEffect::Simple(OptionValueEffect::Hide(PathDescription::Pattern(
                    regex::bytes::Regex::new("^/proc/[0-9]+(/|$)").unwrap(),
                ))),
            }],
        });
    }

    // https://www.freedesktop.org/software/systemd/man/systemd.exec.html#MemoryDenyWriteExecute=
    // https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L1721
    options.push(OptionDescription {
        name: "MemoryDenyWriteExecute".to_string(),
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
        name: "RestrictAddressFamilies".to_string(),
        possible_values: vec![OptionValueDescription {
            value: OptionValue::List {
                values: afs.iter().map(|s| s.to_string()).collect(),
                value_if_empty: Some("none".to_string()),
                negation_prefix: false,
                repeat_option: false,
                mode: ListMode::WhiteList,
            },
            desc: OptionEffect::Cumulative(
                afs.into_iter()
                    .map(|af| OptionValueEffect::DenySocketFamily(af.to_string()))
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
            name: "PrivateNetwork".to_string(),
            possible_values: vec![OptionValueDescription {
                value: OptionValue::Boolean(true),
                desc: OptionEffect::Simple(OptionValueEffect::Multiple(
                    afs.into_iter()
                        .map(|af| OptionValueEffect::DenySocketFamily(af.to_string()))
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
        name: "SocketBindDeny".to_string(),
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
        name: "LockPersonality".to_string(),
        possible_values: vec![OptionValueDescription {
            value: OptionValue::Boolean(true),
            // In practice, the option allows the call if the default personality is set, but we don't
            // need to model that level of precision.
            // The "deny" modeling prevents false positives
            desc: OptionEffect::Simple(OptionValueEffect::DenySyscalls(DenySyscalls::Single(
                "personality".to_string(),
            ))),
        }],
    });

    // https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictRealtime=
    options.push(OptionDescription {
        name: "RestrictRealtime".to_string(),
        possible_values: vec![OptionValueDescription {
            value: OptionValue::Boolean(true),
            desc: OptionEffect::Simple(OptionValueEffect::DenyRealtimeScheduler),
        }],
    });

    // https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectClock=
    options.push(OptionDescription {
        name: "ProtectClock".to_string(),
        possible_values: vec![OptionValueDescription {
            value: OptionValue::Boolean(true),
            // This option essentially does the same thing as deny @clock
            desc: OptionEffect::Simple(OptionValueEffect::DenySyscalls(DenySyscalls::Class(
                "clock".to_string(),
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
        name: "SystemCallFilter".to_string(),
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
            name: "SystemCallArchitectures".to_string(),
            possible_values: vec![OptionValueDescription {
                value: OptionValue::String("native".to_string()),
                desc: OptionEffect::None,
            }],
        });
    }

    log::debug!("{options:#?}");
    options
}
