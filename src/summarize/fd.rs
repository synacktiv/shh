//! Tracked sockets and the process file descriptors designating them

use std::{collections::HashMap, os::fd::RawFd};

use nix::libc::pid_t;

use crate::systemd::{SocketFamily, SocketProtocol};

/// Address family info for a socket
#[derive(Debug, Clone)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub(crate) enum SocketAfInfo {
    Ipv4,
    Ipv6 { v6only: Option<bool> },
    Other(String),
}

impl SocketAfInfo {
    pub(crate) fn is_dual_stack(&self, bindv6only_default: bool) -> bool {
        matches!(self, Self::Ipv6 { v6only } if !v6only.unwrap_or(bindv6only_default))
    }

    pub(crate) fn family(&self) -> SocketFamily {
        match self {
            Self::Ipv4 => SocketFamily::Ipv4,
            Self::Ipv6 { .. } => SocketFamily::Ipv6,
            Self::Other(s) => SocketFamily::Other(s.clone()),
        }
    }
}

impl From<SocketFamily> for SocketAfInfo {
    fn from(af: SocketFamily) -> Self {
        match af {
            SocketFamily::Ipv4 => Self::Ipv4,
            SocketFamily::Ipv6 => Self::Ipv6 { v6only: None },
            SocketFamily::Other(s) => Self::Other(s),
        }
    }
}

/// Tracked socket information
#[derive(Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub(crate) struct SocketInfo {
    pub proto: SocketProtocol,
    pub af: SocketAfInfo,
    pub connected: bool,
    /// Label of the socket's descriptor metadata
    pub label: Option<Vec<u8>>,
}

/// Synthetic fd-table identifier, used to group pids that share an fd table
type FdTableId = usize;

/// Index of a tracked socket
type SocketId = usize;

/// Process fd-table topology and shared socket state
///
/// Descriptor closures are not tracked
#[derive(Debug, Default)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub(crate) struct ProcessFdTracker {
    /// Tracked socket IDs keyed by fd-table ID and descriptor
    socket_ids: HashMap<(FdTableId, RawFd), SocketId>,
    /// Tracked sockets, shared by the descriptors designating them
    sockets: Vec<SocketInfo>,
    /// Which fd table each pid currently uses.
    pid_table: HashMap<pid_t, FdTableId>,
    /// Counter for allocating synthetic fd-table ids.
    next_table_id: FdTableId,
}

impl ProcessFdTracker {
    /// Register socket info for a PID and socket file descriptor
    pub(crate) fn add_sock_info(&mut self, pid: pid_t, fd: RawFd, info: SocketInfo) {
        let table_id = self.table_id_for_pid_mut(pid);
        self.socket_ids.insert((table_id, fd), self.sockets.len());
        self.sockets.push(info);
    }

    /// Get socket info for a PID and socket file descriptor
    pub(crate) fn get_sock_info(&self, pid: pid_t, fd: RawFd) -> Option<&SocketInfo> {
        let table_id = self.pid_table.get(&pid)?;
        self.sockets.get(*self.socket_ids.get(&(*table_id, fd))?)
    }

    /// Get mutable socket info for a PID and socket file descriptor
    pub(crate) fn get_sock_info_mut(&mut self, pid: pid_t, fd: RawFd) -> Option<&mut SocketInfo> {
        let table_id = self.pid_table.get(&pid)?;
        self.sockets
            .get_mut(*self.socket_ids.get(&(*table_id, fd))?)
    }

    /// Make a descriptor designate the same tracked socket as another, or none
    pub(crate) fn dup_fd(&mut self, pid: pid_t, old_fd: RawFd, new_fd: RawFd) {
        let Some(&table_id) = self.pid_table.get(&pid) else {
            return;
        };
        if let Some(&socket_id) = self.socket_ids.get(&(table_id, old_fd)) {
            self.socket_ids.insert((table_id, new_fd), socket_id);
        } else {
            self.socket_ids.remove(&(table_id, new_fd));
        }
    }

    /// Register a child process, and wether or it shares its parent fds
    pub(crate) fn add_child_proc(
        &mut self,
        parent_pid: pid_t,
        child_pid: pid_t,
        share_fd_table: bool,
    ) {
        let parent_table_id = self.table_id_for_pid_mut(parent_pid);
        if share_fd_table {
            self.pid_table.insert(child_pid, parent_table_id);
        } else {
            let child_table_id = self.alloc_table_id();
            self.copy_socket_ids(parent_table_id, child_table_id);
            self.pid_table.insert(child_pid, child_table_id);
        }
    }

    /// Ensure a process has its own private fd table
    pub(crate) fn split_fd_table(&mut self, pid: pid_t) {
        let old_table_id = self.table_id_for_pid_mut(pid);
        let new_table_id = self.alloc_table_id();
        self.copy_socket_ids(old_table_id, new_table_id);
        self.pid_table.insert(pid, new_table_id);
    }

    fn alloc_table_id(&mut self) -> FdTableId {
        let id = self.next_table_id;
        self.next_table_id += 1;
        id
    }

    /// Get existing or new table id for a PID
    fn table_id_for_pid_mut(&mut self, pid: pid_t) -> FdTableId {
        let next = &mut self.next_table_id;
        *self.pid_table.entry(pid).or_insert_with(|| {
            let id = *next;
            *next += 1;
            id
        })
    }

    fn copy_socket_ids(&mut self, src_table: FdTableId, dst_table: FdTableId) {
        let ids_to_copy = self
            .socket_ids
            .iter()
            .filter_map(|((table_id, fd), socket_id)| {
                (*table_id == src_table).then_some(((dst_table, *fd), *socket_id))
            })
            .collect::<Vec<_>>();
        self.socket_ids.extend(ids_to_copy);
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;

    use super::*;
    use crate::{
        strace::{Expression, Syscall, SyscallItem},
        summarize::{
            NetworkActivity, NetworkActivityKind, ProgramAction, SetSpecifier,
            handlers::{
                Clone3Handler, ForkHandler, NetworkHandler, SockaddrArg, SocketHandler,
                SyscallHandler as _, UnshareHandler,
                tests::{
                    binary_or_flags, make_bind_inet, make_socket_inet, make_syscall, named_symbol,
                },
            },
            program_state, summarize,
        },
    };

    // Helper to create a clone/clone3 syscall
    fn make_clone(parent_pid: pid_t, child_pid: pid_t, clone_files: bool) -> Syscall {
        let flags = if clone_files {
            binary_or_flags(&["CLONE_FILES", "SIGCHLD"])
        } else {
            named_symbol("SIGCHLD")
        };
        let mut sc = make_syscall(
            "clone3",
            vec![Expression::Struct(HashMap::from([(
                "flags".to_owned(),
                flags,
            )]))],
            i64::from(child_pid),
        );
        sc.pid = parent_pid;
        sc
    }

    // Helper to create a fork/vfork syscall
    fn make_fork(parent_pid: pid_t, child_pid: pid_t) -> Syscall {
        let mut sc = make_syscall("vfork", vec![], i64::from(child_pid));
        sc.pid = parent_pid;
        sc
    }

    // Helper to create an unshare(CLONE_FILES) syscall
    fn make_unshare_files(pid: pid_t) -> Syscall {
        let mut sc = make_syscall("unshare", vec![named_symbol("CLONE_FILES")], 0);
        sc.pid = pid;
        sc
    }

    // A child sees its parent's sockets, whatever syscall created it
    #[test]
    fn child_inherits_parent_sockets() {
        for name in ["clone", "clone3", "fork", "vfork"] {
            let mut child = if name.starts_with("clone") {
                make_clone(1000, 2000, true)
            } else {
                make_fork(1000, 2000)
            };
            child.name = name.into();
            // Parent opens a TCP socket on fd 3, then child binds fd 3 => should resolve to TCP
            let syscalls = [
                make_socket_inet(1000, "SOCK_STREAM", 3),
                child,
                make_bind_inet(2000, 3, 80),
            ]
            .map(|sc| Ok(SyscallItem::Complete(Box::new(sc))));
            assert_eq!(
                summarize(syscalls, &[], program_state()).unwrap(),
                vec![
                    ProgramAction::NetworkActivity(
                        NetworkActivity {
                            af: SetSpecifier::One(SocketFamily::Ipv4),
                            proto: SetSpecifier::One(SocketProtocol::Tcp),
                            kind: SetSpecifier::One(NetworkActivityKind::SocketCreation),
                            local_port: SetSpecifier::All,
                            address: SetSpecifier::All
                        }
                        .into()
                    ),
                    ProgramAction::NetworkActivity(
                        NetworkActivity {
                            af: SetSpecifier::One(SocketFamily::Ipv4),
                            proto: SetSpecifier::One(SocketProtocol::Tcp),
                            kind: SetSpecifier::One(NetworkActivityKind::Bind),
                            local_port: SetSpecifier::One(NonZeroU16::new(80).unwrap().into()),
                            address: SetSpecifier::None
                        }
                        .into()
                    ),
                    ProgramAction::Syscalls(
                        ["socket", name, "bind"]
                            .into_iter()
                            .map(Into::into)
                            .collect()
                    ),
                ]
            );
        }
    }

    #[test]
    fn bind_handler_socket_protocol_isolated_between_processes() {
        let socket_handler = SocketHandler { af: 0, flags: 1 };
        let network_handler = NetworkHandler {
            fd: 0,
            sockaddr: SockaddrArg::Sockaddr(1),
        };

        let socket_pid_1000 = make_socket_inet(1000, "SOCK_STREAM", 3);
        let socket_pid_3000 = make_socket_inet(3000, "SOCK_DGRAM", 3);
        let bind_sc = make_bind_inet(1000, 3, 80);

        let mut actions = vec![];
        let mut state = program_state();

        socket_handler
            .handle(&socket_pid_1000, &mut actions, &mut state)
            .unwrap();
        socket_handler
            .handle(&socket_pid_3000, &mut actions, &mut state)
            .unwrap();
        network_handler
            .handle(&bind_sc, &mut actions, &mut state)
            .unwrap();

        assert_eq!(
            actions.last(),
            Some(&ProgramAction::NetworkActivity(
                NetworkActivity {
                    af: SetSpecifier::One(SocketFamily::Ipv4),
                    proto: SetSpecifier::One(SocketProtocol::Tcp),
                    kind: SetSpecifier::One(NetworkActivityKind::Bind),
                    local_port: SetSpecifier::One(NonZeroU16::new(80).unwrap().into()),
                    address: SetSpecifier::None
                }
                .into()
            ))
        );
    }

    // fork creates independent copy: new socket in child doesn't affect parent
    #[test]
    fn fork_independent_tables() {
        let socket_handler = SocketHandler { af: 0, flags: 1 };
        let fork_handler = ForkHandler;
        let network_handler = NetworkHandler {
            fd: 0,
            sockaddr: SockaddrArg::Sockaddr(1),
        };

        let mut actions = vec![];
        let mut state = program_state();

        // Parent opens a TCP socket on fd 3
        socket_handler
            .handle(
                &make_socket_inet(1000, "SOCK_STREAM", 3),
                &mut actions,
                &mut state,
            )
            .unwrap();

        // fork => child 2000 gets a copy
        fork_handler
            .handle(&make_fork(1000, 2000), &mut actions, &mut state)
            .unwrap();

        // Child opens a UDP socket reusing fd 3 (after closing it)
        socket_handler
            .handle(
                &make_socket_inet(2000, "SOCK_DGRAM", 3),
                &mut actions,
                &mut state,
            )
            .unwrap();

        // Parent binds fd 3 => should still be TCP (child's change didn't affect parent)
        network_handler
            .handle(&make_bind_inet(1000, 3, 80), &mut actions, &mut state)
            .unwrap();

        let bind_action = actions.last().unwrap();
        assert_eq!(
            bind_action,
            &ProgramAction::NetworkActivity(
                NetworkActivity {
                    af: SetSpecifier::One(SocketFamily::Ipv4),
                    proto: SetSpecifier::One(SocketProtocol::Tcp),
                    kind: SetSpecifier::One(NetworkActivityKind::Bind),
                    local_port: SetSpecifier::One(NonZeroU16::new(80).unwrap().into()),
                    address: SetSpecifier::None
                }
                .into()
            )
        );

        // Child binds fd 3 => should be UDP
        network_handler
            .handle(&make_bind_inet(2000, 3, 8080), &mut actions, &mut state)
            .unwrap();

        let child_bind = actions.last().unwrap();
        assert_eq!(
            child_bind,
            &ProgramAction::NetworkActivity(
                NetworkActivity {
                    af: SetSpecifier::One(SocketFamily::Ipv4),
                    proto: SetSpecifier::One(SocketProtocol::Udp),
                    kind: SetSpecifier::One(NetworkActivityKind::Bind),
                    local_port: SetSpecifier::One(NonZeroU16::new(8080).unwrap().into()),
                    address: SetSpecifier::None
                }
                .into()
            )
        );
    }

    // clone3 with CLONE_FILES shares the fd table: new socket visible to both
    #[test]
    fn clone_files_shares_fd_table() {
        let socket_handler = SocketHandler { af: 0, flags: 1 };
        let clone_handler = Clone3Handler { args: 0 };
        let network_handler = NetworkHandler {
            fd: 0,
            sockaddr: SockaddrArg::Sockaddr(1),
        };

        let mut actions = vec![];
        let mut state = program_state();

        // Parent opens TCP on fd 3
        socket_handler
            .handle(
                &make_socket_inet(1000, "SOCK_STREAM", 3),
                &mut actions,
                &mut state,
            )
            .unwrap();

        // clone3 with CLONE_FILES => shared fd table
        clone_handler
            .handle(&make_clone(1000, 2000, true), &mut actions, &mut state)
            .unwrap();

        // Child opens UDP on fd 5 => parent should also see it
        socket_handler
            .handle(
                &make_socket_inet(2000, "SOCK_DGRAM", 5),
                &mut actions,
                &mut state,
            )
            .unwrap();

        // Parent binds fd 5 => should resolve to UDP (shared table)
        network_handler
            .handle(&make_bind_inet(1000, 5, 443), &mut actions, &mut state)
            .unwrap();

        let bind_action = actions.last().unwrap();
        assert_eq!(
            bind_action,
            &ProgramAction::NetworkActivity(
                NetworkActivity {
                    af: SetSpecifier::One(SocketFamily::Ipv4),
                    proto: SetSpecifier::One(SocketProtocol::Udp),
                    kind: SetSpecifier::One(NetworkActivityKind::Bind),
                    local_port: SetSpecifier::One(NonZeroU16::new(443).unwrap().into()),
                    address: SetSpecifier::None
                }
                .into()
            )
        );
    }

    // clone3 without CLONE_FILES copies the fd table (like fork)
    #[test]
    fn clone_without_clone_files_copies_fd_table() {
        let socket_handler = SocketHandler { af: 0, flags: 1 };
        let clone_handler = Clone3Handler { args: 0 };
        let network_handler = NetworkHandler {
            fd: 0,
            sockaddr: SockaddrArg::Sockaddr(1),
        };

        let mut actions = vec![];
        let mut state = program_state();

        // Parent opens TCP on fd 3
        socket_handler
            .handle(
                &make_socket_inet(1000, "SOCK_STREAM", 3),
                &mut actions,
                &mut state,
            )
            .unwrap();

        // clone3 without CLONE_FILES => independent copy
        clone_handler
            .handle(&make_clone(1000, 2000, false), &mut actions, &mut state)
            .unwrap();

        // Child opens UDP on fd 3 (overwriting the copied TCP entry)
        socket_handler
            .handle(
                &make_socket_inet(2000, "SOCK_DGRAM", 3),
                &mut actions,
                &mut state,
            )
            .unwrap();

        // Parent binds fd 3 => still TCP (independent table)
        network_handler
            .handle(&make_bind_inet(1000, 3, 80), &mut actions, &mut state)
            .unwrap();

        let bind_action = actions.last().unwrap();
        assert_eq!(
            bind_action,
            &ProgramAction::NetworkActivity(
                NetworkActivity {
                    af: SetSpecifier::One(SocketFamily::Ipv4),
                    proto: SetSpecifier::One(SocketProtocol::Tcp),
                    kind: SetSpecifier::One(NetworkActivityKind::Bind),
                    local_port: SetSpecifier::One(NonZeroU16::new(80).unwrap().into()),
                    address: SetSpecifier::None
                }
                .into()
            )
        );
    }

    // unshare(CLONE_FILES) splits a previously shared fd table
    #[test]
    fn unshare_splits_shared_fd_table() {
        let socket_handler = SocketHandler { af: 0, flags: 1 };
        let clone_handler = Clone3Handler { args: 0 };
        let unshare_handler = UnshareHandler { flags: 0 };
        let network_handler = NetworkHandler {
            fd: 0,
            sockaddr: SockaddrArg::Sockaddr(1),
        };

        let mut actions = vec![];
        let mut state = program_state();

        // Parent opens TCP on fd 3
        socket_handler
            .handle(
                &make_socket_inet(1000, "SOCK_STREAM", 3),
                &mut actions,
                &mut state,
            )
            .unwrap();

        // clone3 with CLONE_FILES => shared fd table
        clone_handler
            .handle(&make_clone(1000, 2000, true), &mut actions, &mut state)
            .unwrap();

        // Child calls unshare(CLONE_FILES) => splits off its own table (copy of shared)
        unshare_handler
            .handle(&make_unshare_files(2000), &mut actions, &mut state)
            .unwrap();

        // Child opens UDP on fd 3 (in its now-private table)
        socket_handler
            .handle(
                &make_socket_inet(2000, "SOCK_DGRAM", 3),
                &mut actions,
                &mut state,
            )
            .unwrap();

        // Parent binds fd 3 => still TCP (unshare isolated the child)
        network_handler
            .handle(&make_bind_inet(1000, 3, 80), &mut actions, &mut state)
            .unwrap();

        let parent_bind = actions.last().unwrap();
        assert_eq!(
            parent_bind,
            &ProgramAction::NetworkActivity(
                NetworkActivity {
                    af: SetSpecifier::One(SocketFamily::Ipv4),
                    proto: SetSpecifier::One(SocketProtocol::Tcp),
                    kind: SetSpecifier::One(NetworkActivityKind::Bind),
                    local_port: SetSpecifier::One(NonZeroU16::new(80).unwrap().into()),
                    address: SetSpecifier::None
                }
                .into()
            )
        );

        // Child binds fd 3 => UDP (its own table)
        network_handler
            .handle(&make_bind_inet(2000, 3, 8080), &mut actions, &mut state)
            .unwrap();

        let child_bind = actions.last().unwrap();
        assert_eq!(
            child_bind,
            &ProgramAction::NetworkActivity(
                NetworkActivity {
                    af: SetSpecifier::One(SocketFamily::Ipv4),
                    proto: SetSpecifier::One(SocketProtocol::Udp),
                    kind: SetSpecifier::One(NetworkActivityKind::Bind),
                    local_port: SetSpecifier::One(NonZeroU16::new(8080).unwrap().into()),
                    address: SetSpecifier::None
                }
                .into()
            )
        );
    }

    // unshare preserves existing socket protos from the shared table
    #[test]
    fn unshare_preserves_existing_protos() {
        let socket_handler = SocketHandler { af: 0, flags: 1 };
        let clone_handler = Clone3Handler { args: 0 };
        let unshare_handler = UnshareHandler { flags: 0 };

        let mut actions = vec![];
        let mut state = program_state();

        // Parent opens TCP on fd 3
        socket_handler
            .handle(
                &make_socket_inet(1000, "SOCK_STREAM", 3),
                &mut actions,
                &mut state,
            )
            .unwrap();

        // clone3 with CLONE_FILES
        clone_handler
            .handle(&make_clone(1000, 2000, true), &mut actions, &mut state)
            .unwrap();

        // child unshares
        unshare_handler
            .handle(&make_unshare_files(2000), &mut actions, &mut state)
            .unwrap();

        // Child should still see fd 3 as TCP (copied during unshare)
        assert_eq!(
            state.proc_fd.get_sock_info(2000, 3),
            Some(&SocketInfo {
                proto: SocketProtocol::Tcp,
                af: SocketAfInfo::Ipv4,
                connected: false,
                label: None,
            })
        );
    }

    // Multiple children sharing same fd table via CLONE_FILES all see each other's sockets
    #[test]
    fn multiple_children_share_fd_table() {
        let socket_handler = SocketHandler { af: 0, flags: 1 };
        let clone_handler = Clone3Handler { args: 0 };
        let network_handler = NetworkHandler {
            fd: 0,
            sockaddr: SockaddrArg::Sockaddr(1),
        };

        let mut actions = vec![];
        let mut state = program_state();

        // Parent opens TCP on fd 3
        socket_handler
            .handle(
                &make_socket_inet(1000, "SOCK_STREAM", 3),
                &mut actions,
                &mut state,
            )
            .unwrap();

        // clone3 with CLONE_FILES => child 2000 shares fd table
        clone_handler
            .handle(&make_clone(1000, 2000, true), &mut actions, &mut state)
            .unwrap();

        // clone3 with CLONE_FILES => child 3000 also shares the same fd table
        clone_handler
            .handle(&make_clone(1000, 3000, true), &mut actions, &mut state)
            .unwrap();

        // Child 2000 opens UDP on fd 5
        socket_handler
            .handle(
                &make_socket_inet(2000, "SOCK_DGRAM", 5),
                &mut actions,
                &mut state,
            )
            .unwrap();

        // Child 3000 binds fd 5 => should resolve to UDP (shared table)
        network_handler
            .handle(&make_bind_inet(3000, 5, 53), &mut actions, &mut state)
            .unwrap();

        let bind_action = actions.last().unwrap();
        assert_eq!(
            bind_action,
            &ProgramAction::NetworkActivity(
                NetworkActivity {
                    af: SetSpecifier::One(SocketFamily::Ipv4),
                    proto: SetSpecifier::One(SocketProtocol::Udp),
                    kind: SetSpecifier::One(NetworkActivityKind::Bind),
                    local_port: SetSpecifier::One(NonZeroU16::new(53).unwrap().into()),
                    address: SetSpecifier::None
                }
                .into()
            )
        );
    }

    // Bind with unknown fd (no prior socket call) produces no network action
    #[test]
    fn bind_unknown_fd_no_action() {
        let network_handler = NetworkHandler {
            fd: 0,
            sockaddr: SockaddrArg::Sockaddr(1),
        };

        let mut actions = vec![];
        let mut state = program_state();

        // Bind fd 3 without any prior socket() => no protocol known
        network_handler
            .handle(&make_bind_inet(1000, 3, 80), &mut actions, &mut state)
            .unwrap();

        assert!(actions.is_empty());
    }

    // Grandchild inherits shared fd table through chain of clone(CLONE_FILES)
    #[test]
    fn grandchild_inherits_shared_table() {
        let socket_handler = SocketHandler { af: 0, flags: 1 };
        let clone_handler = Clone3Handler { args: 0 };
        let network_handler = NetworkHandler {
            fd: 0,
            sockaddr: SockaddrArg::Sockaddr(1),
        };

        let mut actions = vec![];
        let mut state = program_state();

        // Parent opens TCP on fd 3
        socket_handler
            .handle(
                &make_socket_inet(1000, "SOCK_STREAM", 3),
                &mut actions,
                &mut state,
            )
            .unwrap();

        // clone with CLONE_FILES => child 2000
        clone_handler
            .handle(&make_clone(1000, 2000, true), &mut actions, &mut state)
            .unwrap();

        // child 2000 clone with CLONE_FILES => grandchild 3000
        clone_handler
            .handle(&make_clone(2000, 3000, true), &mut actions, &mut state)
            .unwrap();

        // Grandchild binds fd 3 => should see TCP
        network_handler
            .handle(&make_bind_inet(3000, 3, 80), &mut actions, &mut state)
            .unwrap();

        let bind_action = actions.last().unwrap();
        assert_eq!(
            bind_action,
            &ProgramAction::NetworkActivity(
                NetworkActivity {
                    af: SetSpecifier::One(SocketFamily::Ipv4),
                    proto: SetSpecifier::One(SocketProtocol::Tcp),
                    kind: SetSpecifier::One(NetworkActivityKind::Bind),
                    local_port: SetSpecifier::One(NonZeroU16::new(80).unwrap().into()),
                    address: SetSpecifier::None
                }
                .into()
            )
        );
    }

    // fork then clone(CLONE_FILES): forked child has independent table,
    // cloned grandchild shares with its parent but not grandparent
    #[test]
    fn fork_then_clone_files_mixed_semantics() {
        let socket_handler = SocketHandler { af: 0, flags: 1 };
        let fork_handler = ForkHandler;
        let clone_handler = Clone3Handler { args: 0 };
        let network_handler = NetworkHandler {
            fd: 0,
            sockaddr: SockaddrArg::Sockaddr(1),
        };

        let mut actions = vec![];
        let mut state = program_state();

        // Parent opens TCP on fd 3
        socket_handler
            .handle(
                &make_socket_inet(1000, "SOCK_STREAM", 3),
                &mut actions,
                &mut state,
            )
            .unwrap();

        // fork => child 2000 (independent copy)
        fork_handler
            .handle(&make_fork(1000, 2000), &mut actions, &mut state)
            .unwrap();

        // child 2000 opens UDP on fd 4
        socket_handler
            .handle(
                &make_socket_inet(2000, "SOCK_DGRAM", 4),
                &mut actions,
                &mut state,
            )
            .unwrap();

        // child 2000 clones with CLONE_FILES => grandchild 3000 shares with 2000
        clone_handler
            .handle(&make_clone(2000, 3000, true), &mut actions, &mut state)
            .unwrap();

        // Grandchild binds fd 4 => should see UDP (shared with child 2000)
        network_handler
            .handle(&make_bind_inet(3000, 4, 53), &mut actions, &mut state)
            .unwrap();

        let gc_bind = actions.last().unwrap();
        assert_eq!(
            gc_bind,
            &ProgramAction::NetworkActivity(
                NetworkActivity {
                    af: SetSpecifier::One(SocketFamily::Ipv4),
                    proto: SetSpecifier::One(SocketProtocol::Udp),
                    kind: SetSpecifier::One(NetworkActivityKind::Bind),
                    local_port: SetSpecifier::One(NonZeroU16::new(53).unwrap().into()),
                    address: SetSpecifier::None
                }
                .into()
            )
        );

        // Parent should NOT see fd 4 (fork created independent table)
        assert!(state.proc_fd.get_sock_info(1000, 4).is_none());

        // Grandchild binds fd 3 => should see TCP (copied from parent at fork time)
        network_handler
            .handle(&make_bind_inet(3000, 3, 443), &mut actions, &mut state)
            .unwrap();

        let gc_bind2 = actions.last().unwrap();
        assert_eq!(
            gc_bind2,
            &ProgramAction::NetworkActivity(
                NetworkActivity {
                    af: SetSpecifier::One(SocketFamily::Ipv4),
                    proto: SetSpecifier::One(SocketProtocol::Tcp),
                    kind: SetSpecifier::One(NetworkActivityKind::Bind),
                    local_port: SetSpecifier::One(NonZeroU16::new(443).unwrap().into()),
                    address: SetSpecifier::None
                }
                .into()
            )
        );
    }

    // Same fd number reused by different unrelated processes resolves independently
    #[test]
    fn same_fd_different_unrelated_processes() {
        let socket_handler = SocketHandler { af: 0, flags: 1 };
        let network_handler = NetworkHandler {
            fd: 0,
            sockaddr: SockaddrArg::Sockaddr(1),
        };

        let mut actions = vec![];
        let mut state = program_state();

        // Process 1000 opens TCP on fd 3
        socket_handler
            .handle(
                &make_socket_inet(1000, "SOCK_STREAM", 3),
                &mut actions,
                &mut state,
            )
            .unwrap();

        // Process 5000 (unrelated, never cloned from 1000) opens UDP on fd 3
        socket_handler
            .handle(
                &make_socket_inet(5000, "SOCK_DGRAM", 3),
                &mut actions,
                &mut state,
            )
            .unwrap();

        // Process 1000 binds fd 3 => TCP
        network_handler
            .handle(&make_bind_inet(1000, 3, 80), &mut actions, &mut state)
            .unwrap();

        let bind1 = actions.last().unwrap();
        assert_eq!(
            bind1,
            &ProgramAction::NetworkActivity(
                NetworkActivity {
                    af: SetSpecifier::One(SocketFamily::Ipv4),
                    proto: SetSpecifier::One(SocketProtocol::Tcp),
                    kind: SetSpecifier::One(NetworkActivityKind::Bind),
                    local_port: SetSpecifier::One(NonZeroU16::new(80).unwrap().into()),
                    address: SetSpecifier::None
                }
                .into()
            )
        );

        // Process 5000 binds fd 3 => UDP
        network_handler
            .handle(&make_bind_inet(5000, 3, 8080), &mut actions, &mut state)
            .unwrap();

        let bind2 = actions.last().unwrap();
        assert_eq!(
            bind2,
            &ProgramAction::NetworkActivity(
                NetworkActivity {
                    af: SetSpecifier::One(SocketFamily::Ipv4),
                    proto: SetSpecifier::One(SocketProtocol::Udp),
                    kind: SetSpecifier::One(NetworkActivityKind::Bind),
                    local_port: SetSpecifier::One(NonZeroU16::new(8080).unwrap().into()),
                    address: SetSpecifier::None
                }
                .into()
            )
        );
    }

    #[test]
    fn dup_fd_replaces_tracked_socket() {
        let info = |connected| SocketInfo {
            proto: SocketProtocol::Udp,
            af: SocketAfInfo::Ipv4,
            connected,
            label: None,
        };
        let mut tracker = ProcessFdTracker::default();
        tracker.add_sock_info(1000, 3, info(false));
        tracker.add_sock_info(1000, 4, info(true));
        tracker.dup_fd(1000, 3, 4);
        assert_eq!(tracker.get_sock_info(1000, 4), Some(&info(false)));
    }
}
