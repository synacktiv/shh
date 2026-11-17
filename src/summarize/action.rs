//! Program actions summarized from syscalls

use std::{
    collections::HashSet,
    fmt::{self, Display},
    net::{IpAddr, Ipv4Addr},
    num::NonZeroU16,
    path::PathBuf,
};

use crate::{
    strace::SyscallName,
    systemd::{SocketFamily, SocketProtocol},
};

/// A high level program runtime action
/// This does *not* map 1-1 with a syscall, and does *not* necessarily respect chronology
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) enum ProgramAction {
    /// Create a path, or an unnamed file in the directory it names
    Create(PathBuf),
    /// Exec a path
    Exec(PathBuf),
    /// Act on the host's mount namespace
    HostMountNamespace,
    /// Memory mapping with huge pages
    HugePageMemoryMapping,
    /// Send signal to other process ("other" being defined as requiring `CAP_KILL`)
    KillOther,
    /// Lock memory mapping
    LockMemoryMapping,
    /// Create special files
    MknodSpecial,
    /// Network (socket) activity
    NetworkActivity(Box<NetworkActivity>),
    /// Access a path (open, stat, read...)
    Read(PathBuf),
    /// Remove a path
    Remove(PathBuf),
    /// Path requiring no mount at or below it
    RequireNoMountWithin(PathBuf),
    /// Paths required to share a mount
    RequireSameMount(PathBuf, PathBuf),
    /// Set privileged timer alarm
    SetAlarm,
    /// Set the time or parameters of a hardware clock
    SetHardwareClock,
    /// Set scheduler to a real time one
    SetRealtimeScheduler,
    /// Names of the syscalls made by the program
    Syscalls(HashSet<SyscallName>),
    /// Inhibit suspend
    Wakeup,
    /// Modify a path on its filesystem (content, metadata...)
    Write(PathBuf),
    /// Executable mapping of writable memory, or execute permission set on an existing mapping
    WriteExecuteMemoryMapping,
}

/// Network (socket) activity
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct NetworkActivity {
    pub af: SetSpecifier<SocketFamily>,
    pub proto: SetSpecifier<SocketProtocol>,
    pub kind: SetSpecifier<NetworkActivityKind>,
    pub local_port: SetSpecifier<NetworkPort>,
    // Note: this account for source and destination addresses
    pub address: SetSpecifier<NetworkAddress>,
}

/// Quantify something that is done or denied
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) enum SetSpecifier<T> {
    None,
    One(T),
    Some(Vec<T>),
    AllExcept(Vec<T>),
    All,
}

impl<T: Eq + Clone> SetSpecifier<T> {
    fn contains_one(&self, needle: &T) -> bool {
        match self {
            Self::None => false,
            Self::One(e) => e == needle,
            Self::Some(es) => es.contains(needle),
            Self::AllExcept(es) => !es.contains(needle),
            Self::All => true,
        }
    }

    pub(crate) fn intersects(&self, other: &Self) -> bool {
        match self {
            Self::None => false,
            Self::One(e) => other.contains_one(e),
            Self::Some(es) => es.iter().any(|e| other.contains_one(e)),
            Self::AllExcept(excs) => match other {
                Self::None => false,
                Self::One(e) => !excs.contains(e),
                Self::Some(es) => es.iter().any(|e| !excs.contains(e)),
                Self::AllExcept(other_excs) => excs != other_excs,
                Self::All => true, // this is incorrect, but unless excs has the whole address/port space, we should be good
            },
            Self::All => !matches!(other, Self::None),
        }
    }

    pub(crate) fn excluded_elements(&self) -> Vec<T> {
        match self {
            Self::AllExcept(vec) => vec.to_owned(),
            _ => unimplemented!(),
        }
    }

    /// Remove a single element from the set
    /// The element to remove **must** be in the set, otherwise may panic
    #[expect(clippy::unwrap_used, clippy::panic)]
    pub(crate) fn remove(&mut self, to_rm: &T) {
        debug_assert!(self.contains_one(to_rm));
        match self {
            Self::None => panic!(),
            Self::One(_) => {
                *self = Self::None;
            }
            Self::Some(es) => {
                let idx = es.iter().position(|e| e == to_rm).unwrap();
                es.remove(idx);
            }
            Self::AllExcept(excs) => {
                debug_assert!(!excs.contains(to_rm));
                excs.push(to_rm.to_owned());
            }
            Self::All => {
                *self = Self::AllExcept(vec![to_rm.to_owned()]);
            }
        }
    }
}

/// Socket activity
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) enum NetworkActivityKind {
    SocketCreation,
    Bind,
    Connect,
    Accept,
    SendRecv,
}

impl NetworkActivityKind {
    /// All kinds that are linked with one or more addresses
    pub(crate) const ADDRESSED: [Self; 4] = [
        NetworkActivityKind::Bind,
        NetworkActivityKind::Connect,
        NetworkActivityKind::Accept,
        NetworkActivityKind::SendRecv,
    ];

    /// Get kind from syscall name, panic if it fails
    pub(super) fn from_sc_name(sc: &str) -> Self {
        match sc {
            "socket" => NetworkActivityKind::SocketCreation,
            "bind" => NetworkActivityKind::Bind,
            "connect" => NetworkActivityKind::Connect,
            "accept" | "accept4" => NetworkActivityKind::Accept,
            "sendto" | "recvfrom" | "sendmsg" | "recvmsg" | "sendmmsg" | "recvmmsg"
            | "recvmmsg_time64" | "read" | "readv" | "preadv2" | "recv" | "splice" | "sendfile"
            | "sendfile64" => NetworkActivityKind::SendRecv,
            _ => unreachable!("{:?}", sc),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct NetworkPort(NonZeroU16);

impl From<NonZeroU16> for NetworkPort {
    fn from(value: NonZeroU16) -> Self {
        Self(value)
    }
}

impl Display for NetworkPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct NetworkAddress(IpAddr);

impl NetworkAddress {
    /// Check if this address is the unspecified address (`::` or `0.0.0.0`).
    pub(crate) fn is_unspecified(&self) -> bool {
        self.0.is_unspecified()
    }

    /// Return the IPv4 equivalent of this address on a dual-stack socket, if any.
    /// `::` -> `0.0.0.0`, `::ffff:A.B.C.D` -> `A.B.C.D`, everything else -> None.
    pub(crate) fn ipv4_equivalent(&self) -> Option<Self> {
        match self.0 {
            IpAddr::V6(v6) if v6.is_unspecified() => Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED).into()),
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(|v4| IpAddr::V4(v4).into()),
            IpAddr::V4(_) => None,
        }
    }
}

impl From<IpAddr> for NetworkAddress {
    fn from(value: IpAddr) -> Self {
        Self(value)
    }
}

impl Display for NetworkAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
