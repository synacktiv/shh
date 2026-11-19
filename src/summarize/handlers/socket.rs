//! Socket descriptor and option syscall handlers

use std::{
    any::{type_name, type_name_of_val},
    os::fd::RawFd,
};

use super::{ExtractArg as _, HandlerError, SyscallHandler, fd_label, fd_number, pidfd_pid};
use crate::{
    strace::{Expression, IntegerExpression, IntegerExpressionValue, NamedSymbol, Syscall},
    summarize::{
        ProgramState,
        action::{NetworkActivity, NetworkActivityKind, ProgramAction, SetSpecifier},
        fd::{SocketAfInfo, SocketInfo},
    },
    systemd::{SocketFamily, SocketProtocol},
};

/// Handler for socket syscall
pub(crate) struct SocketHandler {
    pub af: usize,
    pub flags: usize,
}

impl SyscallHandler for SocketHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        let af_expr = self.af.extract(sc)?;
        let flags = self.flags.extract(sc)?;

        let af_name = unpack_expr!(
            af_expr,
            Expression::Integer(IntegerExpression {
                value: IntegerExpressionValue::NamedSymbol(NamedSymbol::Unambiguous(af_name)),
                ..
            }) => af_name
        );
        let af: SocketFamily = af_name
            .parse()
            .map_err(|()| err_value!(af_name, &str => SocketFamily))?;

        let flags =
            unpack_expr!(flags, Expression::Integer(IntegerExpression { value, .. }) => value)
                .flags();
        let proto_flag = flags
            .iter()
            .find(|f| f.starts_with("SOCK_"))
            .ok_or_else(|| err_value!(flags, SocketProtocol))?;
        let proto = proto_flag
            .parse::<SocketProtocol>()
            .map_err(|_e| err_value!(proto_flag, &str => SocketProtocol))?;
        let Some(ret_val) = &sc.ret_val else {
            return Ok(());
        };
        let ret_fd = ret_val.value().ok_or_else(|| err_value!(sc.ret_val, i64))?;

        if ret_fd != -1 {
            let fd =
                TryInto::<RawFd>::try_into(ret_fd).map_err(|_| err_value!(ret_fd, i64 => RawFd))?;
            let metadata = ret_val.metadata.as_deref();
            state.proc_fd.add_sock_info(
                sc.pid,
                fd,
                SocketInfo {
                    proto: proto.clone(),
                    af: af.clone().into(),
                    connected: false,
                    label: metadata.map(|m| fd_label(m).to_vec()),
                },
            );
            if let Some(metadata) = metadata {
                state.proc_fd.register_metadata(sc.pid, fd, metadata);
            }
        }

        actions.push(ProgramAction::NetworkActivity(
            NetworkActivity {
                af: SetSpecifier::One(af),
                proto: SetSpecifier::One(proto),
                kind: SetSpecifier::One(NetworkActivityKind::SocketCreation),
                local_port: SetSpecifier::All,
                address: SetSpecifier::All,
            }
            .into(),
        ));
        Ok(())
    }
}

/// Argument index qualifying a descriptor copy
pub(crate) enum DupQualifier {
    /// Index of the `fcntl` command argument
    FcntlCmd(usize),
    /// Index of the pidfd argument
    Pidfd(usize),
}

/// Handler for syscalls duplicating a descriptor
pub(crate) struct DupHandler {
    pub fd: usize,
    pub qualifier: Option<DupQualifier>,
}

impl SyscallHandler for DupHandler {
    fn handle(
        &self,
        sc: &Syscall,
        _actions: &mut Vec<ProgramAction>,
        state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        let new_fd = match sc.ret_val.as_ref().and_then(IntegerExpression::value) {
            Some(fd) if fd >= 0 => fd,
            _ => return Ok(()),
        };
        let old_pid = match &self.qualifier {
            Some(DupQualifier::FcntlCmd(cmd)) => {
                let cmd = unpack_expr!(
                    cmd.extract(sc)?,
                    Expression::Integer(IntegerExpression { value, .. }) => value
                );
                if !cmd.is_any_flag_set(&["F_DUPFD", "F_DUPFD_CLOEXEC"]) {
                    return Ok(());
                }
                Some(sc.pid)
            }
            Some(DupQualifier::Pidfd(pidfd)) => pidfd_pid(pidfd.extract(sc)?)?,
            None => Some(sc.pid),
        };
        let old_fd = fd_number(self.fd.extract(sc)?)?;
        let new_fd = RawFd::try_from(new_fd).map_err(|_| err_value!(new_fd, i64 => RawFd))?;
        state
            .proc_fd
            .dup_fd(old_pid.map(|pid| (pid, old_fd)), sc.pid, new_fd);
        Ok(())
    }
}

/// Handler for setsockopt syscalls to track `IPV6_V6ONLY` option
pub(crate) struct SetsockoptHandler {
    pub fd: usize,
    pub level: usize,
    pub optname: usize,
    pub optval: usize,
}

impl SyscallHandler for SetsockoptHandler {
    fn handle(
        &self,
        sc: &Syscall,
        _actions: &mut Vec<ProgramAction>,
        state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        if !sc.is_successful() {
            return Ok(());
        }

        let fd = self.fd.extract(sc)?;
        let level = self.level.extract(sc)?;
        let optname = self.optname.extract(sc)?;
        let optval = self.optval.extract(sc)?;

        // Only handle SOL_IPV6 + IPV6_V6ONLY
        let is_v6only = matches!(
            (level, optname),
            (
                Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::NamedSymbol(NamedSymbol::Unambiguous(l)),
                    ..
                }),
                Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::NamedSymbol(NamedSymbol::Unambiguous(o)),
                    ..
                }),
            ) if l == "SOL_IPV6" && o == "IPV6_V6ONLY"
        );
        if !is_v6only {
            return Ok(());
        }

        // Extract fd value
        let fd_raw = fd_number(fd)?;

        // Extract optval from collection like [0] or [1]
        let values = unpack_expr!(
            optval,
            Expression::Collection {
                complement: false,
                values,
                ..
            } => values
        );
        let val = if let Some(Expression::Integer(IntegerExpression { value, .. })) =
            values.first().map(|(_, e)| e)
        {
            value.value()
        } else {
            None
        };
        let Some(val) = val else {
            return Err(err_expr_type!(optval));
        };

        // Update socket info if known and IPv6
        if let Some(SocketInfo {
            af: SocketAfInfo::Ipv6 { v6only },
            label,
            ..
        }) = state.proc_fd.get_sock_info_mut(sc.pid, fd_raw)
            // Another socket may reuse the descriptor number of a closed one
            && label.as_deref() == fd.metadata().map(fd_label)
        {
            *v6only = Some(val != 0);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, net::IpAddr, num::NonZeroU16};

    use nix::libc::pid_t;

    use super::*;
    use crate::summarize::{
        fd::ProcessFdTracker,
        handlers::{
            NetworkHandler, SockaddrArg,
            tests::{
                binary_or_flags, buf_expr, fd_expr, int_literal, make_bind_inet, make_socket_inet,
                make_syscall, named_symbol,
            },
        },
        program_state,
    };

    #[test]
    fn socket_handler_tcp() {
        let handler = SocketHandler { af: 0, flags: 1 };
        let sc = make_syscall(
            "socket",
            vec![
                named_symbol("AF_INET"),
                binary_or_flags(&["SOCK_STREAM", "SOCK_CLOEXEC"]),
            ],
            3,
        );
        let mut actions = vec![];
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(
            state.proc_fd.get_sock_info(1000, 3),
            Some(SocketInfo {
                proto: SocketProtocol::Tcp,
                af: SocketAfInfo::Ipv4,
                connected: false,
                label: None,
            })
            .as_ref()
        );
        assert_eq!(
            actions,
            vec![ProgramAction::NetworkActivity(
                NetworkActivity {
                    af: SetSpecifier::One(SocketFamily::Ipv4),
                    proto: SetSpecifier::One(SocketProtocol::Tcp),
                    kind: SetSpecifier::One(NetworkActivityKind::SocketCreation),
                    local_port: SetSpecifier::All,
                    address: SetSpecifier::All
                }
                .into()
            )]
        );
    }

    #[test]
    fn socket_handler_udp() {
        let handler = SocketHandler { af: 0, flags: 1 };
        let sc = make_syscall(
            "socket",
            vec![
                named_symbol("AF_INET6"),
                binary_or_flags(&["SOCK_DGRAM", "SOCK_CLOEXEC"]),
            ],
            5,
        );
        let mut actions = vec![];
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(
            state.proc_fd.get_sock_info(1000, 5),
            Some(SocketInfo {
                proto: SocketProtocol::Udp,
                af: SocketAfInfo::Ipv6 { v6only: None },
                connected: false,
                label: None,
            })
            .as_ref()
        );
        assert_eq!(
            actions,
            vec![ProgramAction::NetworkActivity(
                NetworkActivity {
                    af: SetSpecifier::One(SocketFamily::Ipv6),
                    proto: SetSpecifier::One(SocketProtocol::Udp),
                    kind: SetSpecifier::One(NetworkActivityKind::SocketCreation),
                    local_port: SetSpecifier::All,
                    address: SetSpecifier::All
                }
                .into()
            )]
        );
    }

    #[test]
    fn socket_handler_bad_af() {
        let handler = SocketHandler { af: 0, flags: 1 };
        let sc = make_syscall(
            "socket",
            vec![int_literal(999), binary_or_flags(&["SOCK_STREAM"])],
            -1,
        );
        let mut actions = vec![];
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(matches!(
            result,
            Err(HandlerError::ExpressionTypeMismatch { .. })
        ));
        assert_eq!(state.proc_fd, ProcessFdTracker::default());
        assert!(actions.is_empty());
    }

    #[test]
    fn socket_handler_bad_flags() {
        let handler = SocketHandler { af: 0, flags: 1 };
        let sc = make_syscall(
            "socket",
            vec![named_symbol("AF_INET"), buf_expr(b"invalid")],
            -1,
        );
        let mut actions = vec![];
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(matches!(
            result,
            Err(HandlerError::ExpressionTypeMismatch { .. })
        ));
        assert_eq!(state.proc_fd, ProcessFdTracker::default());
        assert!(actions.is_empty());
    }

    #[test]
    fn socket_handler_no_sock_flag() {
        let handler = SocketHandler { af: 0, flags: 1 };
        let sc = make_syscall("socket", vec![named_symbol("AF_INET"), int_literal(0)], -1);
        let mut actions = vec![];
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(matches!(
            result,
            Err(HandlerError::ValueInterpretationFailed { .. })
        ));
        assert_eq!(state.proc_fd, ProcessFdTracker::default());
        assert!(actions.is_empty());
    }

    #[test]
    fn socket_handler_bad_proto() {
        let handler = SocketHandler { af: 0, flags: 1 };
        let sc = make_syscall("socket", vec![named_symbol("AF_INET"), int_literal(123)], 3);
        let mut actions = vec![];
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(matches!(
            result,
            Err(HandlerError::ValueInterpretationFailed { .. })
        ));
        assert_eq!(state.proc_fd, ProcessFdTracker::default());
        assert!(actions.is_empty());
    }

    // Helper to create an IPv6 TCP socket in state for a given fd
    fn setup_ipv6_socket(state: &mut ProgramState, fd: RawFd) {
        state.proc_fd.add_sock_info(
            1000,
            fd,
            SocketInfo {
                proto: SocketProtocol::Tcp,
                af: SocketAfInfo::Ipv6 { v6only: None },
                connected: false,
                label: None,
            },
        );
    }

    // Helper to create a setsockopt syscall
    fn make_setsockopt(fd: i64, level: &str, optname: &str, optval: i64) -> Syscall {
        make_syscall(
            "setsockopt",
            vec![
                int_literal(fd),
                named_symbol(level),
                named_symbol(optname),
                Expression::Collection {
                    complement: false,
                    values: vec![(None, int_literal(optval))],
                    truncated: false,
                },
                int_literal(4),
            ],
            0,
        )
    }

    #[test]
    fn setsockopt_v6only_set() {
        let handler = SetsockoptHandler {
            fd: 0,
            level: 1,
            optname: 2,
            optval: 3,
        };
        let mut state = program_state();
        setup_ipv6_socket(&mut state, 3);

        let sc = make_setsockopt(3, "SOL_IPV6", "IPV6_V6ONLY", 1);
        let mut actions = vec![];
        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(
            state.proc_fd.get_sock_info(1000, 3),
            Some(SocketInfo {
                proto: SocketProtocol::Tcp,
                af: SocketAfInfo::Ipv6 { v6only: Some(true) },
                connected: false,
                label: None,
            })
            .as_ref()
        );
        assert!(actions.is_empty());
    }

    #[test]
    fn setsockopt_v6only_clear() {
        let handler = SetsockoptHandler {
            fd: 0,
            level: 1,
            optname: 2,
            optval: 3,
        };
        let mut state = program_state();
        setup_ipv6_socket(&mut state, 3);

        let sc = make_setsockopt(3, "SOL_IPV6", "IPV6_V6ONLY", 0);
        let mut actions = vec![];
        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(
            state.proc_fd.get_sock_info(1000, 3),
            Some(SocketInfo {
                proto: SocketProtocol::Tcp,
                af: SocketAfInfo::Ipv6 {
                    v6only: Some(false)
                },
                connected: false,
                label: None,
            })
            .as_ref()
        );
        assert!(actions.is_empty());
    }

    #[test]
    fn setsockopt_non_ipv6_ignored() {
        let handler = SetsockoptHandler {
            fd: 0,
            level: 1,
            optname: 2,
            optval: 3,
        };
        let mut state = program_state();
        setup_ipv6_socket(&mut state, 3);

        let sc = make_setsockopt(3, "SOL_SOCKET", "SO_REUSEADDR", 1);
        let mut actions = vec![];
        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        // v6only should remain None (unchanged)
        assert_eq!(
            state.proc_fd.get_sock_info(1000, 3),
            Some(SocketInfo {
                proto: SocketProtocol::Tcp,
                af: SocketAfInfo::Ipv6 { v6only: None },
                connected: false,
                label: None,
            })
            .as_ref()
        );
        assert!(actions.is_empty());
    }

    #[test]
    fn setsockopt_v6only_other_socket() {
        // Another socket reusing the descriptor number of a tracked one
        let handler = SetsockoptHandler {
            fd: 0,
            level: 1,
            optname: 2,
            optval: 3,
        };
        let mut state = program_state();
        let info = || SocketInfo {
            proto: SocketProtocol::Tcp,
            af: SocketAfInfo::Ipv6 { v6only: None },
            connected: false,
            label: Some(b"TCPv6".to_vec()),
        };
        state.proc_fd.add_sock_info(1000, 3, info());

        let mut sc = make_setsockopt(3, "SOL_IPV6", "IPV6_V6ONLY", 1);
        sc.args[0] = fd_expr(3, "UNIX:[9]");
        let mut actions = vec![];
        handler.handle(&sc, &mut actions, &mut state).unwrap();
        assert_eq!(state.proc_fd.get_sock_info(1000, 3), Some(&info()));
        assert!(actions.is_empty());
    }

    // Helper to create an AF_INET6 socket syscall
    fn make_socket_inet6(pid: pid_t, sock_type: &str, ret_fd: i64) -> Syscall {
        let mut sc = make_syscall(
            "socket",
            vec![
                named_symbol("AF_INET6"),
                binary_or_flags(&[sock_type, "SOCK_CLOEXEC"]),
            ],
            ret_fd,
        );
        sc.pid = pid;
        sc
    }

    // Helper to create an AF_INET6 socket address
    fn inet6_sockaddr(port: i64, addr: &str) -> Expression {
        Expression::Struct(HashMap::from([
            ("sa_family".to_owned(), named_symbol("AF_INET6")),
            ("sin6_family".to_owned(), named_symbol("AF_INET6")),
            (
                "sin6_port".to_owned(),
                Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::Macro {
                        name: "htons".to_owned(),
                        args: vec![int_literal(port)],
                    },
                    metadata: None,
                }),
            ),
            (
                "sin6_addr".to_owned(),
                Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::Macro {
                        name: "inet_pton".to_owned(),
                        args: vec![named_symbol("AF_INET6"), buf_expr(addr.as_bytes())],
                    },
                    metadata: None,
                }),
            ),
        ]))
    }

    // Helper to create an AF_INET6 bind syscall with an IPv6 address
    fn make_bind_inet6(pid: pid_t, fd: i64, port: i64, addr: &str) -> Syscall {
        let mut sc = make_syscall("bind", vec![int_literal(fd), inet6_sockaddr(port, addr)], 0);
        sc.pid = pid;
        sc
    }

    // Helper to create an AF_INET6 connect syscall with an IPv6 address
    fn make_connect_inet6(pid: pid_t, fd: i64, addr: &str) -> Syscall {
        let mut sc = make_syscall(
            "connect",
            vec![int_literal(fd), inet6_sockaddr(443, addr)],
            0,
        );
        sc.pid = pid;
        sc
    }

    #[test]
    fn dual_stack_bind_unspecified() {
        let socket_handler = SocketHandler { af: 0, flags: 1 };
        let network_handler = NetworkHandler {
            fd: 0,
            sockaddr: SockaddrArg::Sockaddr(1),
        };

        let mut actions = vec![];
        let mut state = program_state();

        socket_handler
            .handle(
                &make_socket_inet6(1000, "SOCK_STREAM", 3),
                &mut actions,
                &mut state,
            )
            .unwrap();

        network_handler
            .handle(
                &make_bind_inet6(1000, 3, 80, "::"),
                &mut actions,
                &mut state,
            )
            .unwrap();

        // Should emit IPv4 action with 0.0.0.0, then IPv6 action with ::
        assert_eq!(
            actions[1..],
            vec![
                ProgramAction::NetworkActivity(
                    NetworkActivity {
                        af: SetSpecifier::One(SocketFamily::Ipv4),
                        proto: SetSpecifier::One(SocketProtocol::Tcp),
                        kind: SetSpecifier::One(NetworkActivityKind::Bind),
                        local_port: SetSpecifier::One(NonZeroU16::new(80).unwrap().into()),
                        address: SetSpecifier::One("0.0.0.0".parse::<IpAddr>().unwrap().into()),
                    }
                    .into()
                ),
                ProgramAction::NetworkActivity(
                    NetworkActivity {
                        af: SetSpecifier::One(SocketFamily::Ipv6),
                        proto: SetSpecifier::One(SocketProtocol::Tcp),
                        kind: SetSpecifier::One(NetworkActivityKind::Bind),
                        local_port: SetSpecifier::One(NonZeroU16::new(80).unwrap().into()),
                        address: SetSpecifier::One("::".parse::<IpAddr>().unwrap().into()),
                    }
                    .into()
                ),
            ]
        );
    }

    #[test]
    fn dual_stack_connect_v4mapped() {
        let socket_handler = SocketHandler { af: 0, flags: 1 };
        let network_handler = NetworkHandler {
            fd: 0,
            sockaddr: SockaddrArg::Sockaddr(1),
        };

        let mut actions = vec![];
        let mut state = program_state();

        socket_handler
            .handle(
                &make_socket_inet6(1000, "SOCK_STREAM", 3),
                &mut actions,
                &mut state,
            )
            .unwrap();

        network_handler
            .handle(
                &make_connect_inet6(1000, 3, "::ffff:192.168.1.1"),
                &mut actions,
                &mut state,
            )
            .unwrap();

        // Should emit IPv4 action with 192.168.1.1, then IPv6 action
        assert_eq!(
            actions[1..],
            vec![
                ProgramAction::NetworkActivity(
                    NetworkActivity {
                        af: SetSpecifier::One(SocketFamily::Ipv4),
                        proto: SetSpecifier::One(SocketProtocol::Tcp),
                        kind: SetSpecifier::One(NetworkActivityKind::Connect),
                        local_port: SetSpecifier::All,
                        address: SetSpecifier::One("192.168.1.1".parse::<IpAddr>().unwrap().into()),
                    }
                    .into()
                ),
                ProgramAction::NetworkActivity(
                    NetworkActivity {
                        af: SetSpecifier::One(SocketFamily::Ipv6),
                        proto: SetSpecifier::One(SocketProtocol::Tcp),
                        kind: SetSpecifier::One(NetworkActivityKind::Connect),
                        local_port: SetSpecifier::All,
                        address: SetSpecifier::One(
                            "::ffff:192.168.1.1".parse::<IpAddr>().unwrap().into()
                        ),
                    }
                    .into()
                ),
            ]
        );
    }

    #[test]
    fn v6only_bind_no_ipv4() {
        let socket_handler = SocketHandler { af: 0, flags: 1 };
        let setsockopt_handler = SetsockoptHandler {
            fd: 0,
            level: 1,
            optname: 2,
            optval: 3,
        };
        let network_handler = NetworkHandler {
            fd: 0,
            sockaddr: SockaddrArg::Sockaddr(1),
        };

        let mut actions = vec![];
        let mut state = program_state();

        socket_handler
            .handle(
                &make_socket_inet6(1000, "SOCK_STREAM", 3),
                &mut actions,
                &mut state,
            )
            .unwrap();

        setsockopt_handler
            .handle(
                &make_setsockopt(3, "SOL_IPV6", "IPV6_V6ONLY", 1),
                &mut actions,
                &mut state,
            )
            .unwrap();

        network_handler
            .handle(
                &make_bind_inet6(1000, 3, 80, "::"),
                &mut actions,
                &mut state,
            )
            .unwrap();

        // Should only emit IPv6 action, no IPv4
        assert_eq!(
            actions[1..],
            vec![ProgramAction::NetworkActivity(
                NetworkActivity {
                    af: SetSpecifier::One(SocketFamily::Ipv6),
                    proto: SetSpecifier::One(SocketProtocol::Tcp),
                    kind: SetSpecifier::One(NetworkActivityKind::Bind),
                    local_port: SetSpecifier::One(NonZeroU16::new(80).unwrap().into()),
                    address: SetSpecifier::One("::".parse::<IpAddr>().unwrap().into()),
                }
                .into()
            )]
        );
    }

    #[test]
    fn dual_stack_pure_ipv6_no_ipv4() {
        let socket_handler = SocketHandler { af: 0, flags: 1 };
        let network_handler = NetworkHandler {
            fd: 0,
            sockaddr: SockaddrArg::Sockaddr(1),
        };

        let mut actions = vec![];
        let mut state = program_state();

        socket_handler
            .handle(
                &make_socket_inet6(1000, "SOCK_STREAM", 3),
                &mut actions,
                &mut state,
            )
            .unwrap();

        network_handler
            .handle(
                &make_connect_inet6(1000, 3, "2001:db8::1"),
                &mut actions,
                &mut state,
            )
            .unwrap();

        // Pure IPv6 address has no IPv4 equivalent — only IPv6 action emitted
        assert_eq!(
            actions[1..],
            vec![ProgramAction::NetworkActivity(
                NetworkActivity {
                    af: SetSpecifier::One(SocketFamily::Ipv6),
                    proto: SetSpecifier::One(SocketProtocol::Tcp),
                    kind: SetSpecifier::One(NetworkActivityKind::Connect),
                    local_port: SetSpecifier::All,
                    address: SetSpecifier::One("2001:db8::1".parse::<IpAddr>().unwrap().into()),
                }
                .into()
            )]
        );
    }

    #[test]
    fn dual_stack_loopback_no_ipv4() {
        let socket_handler = SocketHandler { af: 0, flags: 1 };
        let network_handler = NetworkHandler {
            fd: 0,
            sockaddr: SockaddrArg::Sockaddr(1),
        };

        let mut actions = vec![];
        let mut state = program_state();

        socket_handler
            .handle(
                &make_socket_inet6(1000, "SOCK_STREAM", 3),
                &mut actions,
                &mut state,
            )
            .unwrap();

        network_handler
            .handle(
                &make_bind_inet6(1000, 3, 80, "::1"),
                &mut actions,
                &mut state,
            )
            .unwrap();

        // ::1 is IPv6-only loopback — no IPv4 action
        assert_eq!(
            actions[1..],
            vec![ProgramAction::NetworkActivity(
                NetworkActivity {
                    af: SetSpecifier::One(SocketFamily::Ipv6),
                    proto: SetSpecifier::One(SocketProtocol::Tcp),
                    kind: SetSpecifier::One(NetworkActivityKind::Bind),
                    local_port: SetSpecifier::One(NonZeroU16::new(80).unwrap().into()),
                    address: SetSpecifier::One("::1".parse::<IpAddr>().unwrap().into()),
                }
                .into()
            )]
        );
    }

    // 2. When bindv6only_default is true, IPv6 socket with v6only=None should not emit IPv4
    #[test]
    fn bindv6only_default_true_no_ipv4() {
        let socket_handler = SocketHandler { af: 0, flags: 1 };
        let network_handler = NetworkHandler {
            fd: 0,
            sockaddr: SockaddrArg::Sockaddr(1),
        };

        let mut actions = vec![];
        let mut state = ProgramState::new("/", true);

        socket_handler
            .handle(
                &make_socket_inet6(1000, "SOCK_STREAM", 3),
                &mut actions,
                &mut state,
            )
            .unwrap();

        network_handler
            .handle(
                &make_bind_inet6(1000, 3, 80, "::"),
                &mut actions,
                &mut state,
            )
            .unwrap();

        // With bindv6only_default=true and v6only=None, should be treated as v6-only
        assert_eq!(
            actions[1..],
            vec![ProgramAction::NetworkActivity(
                NetworkActivity {
                    af: SetSpecifier::One(SocketFamily::Ipv6),
                    proto: SetSpecifier::One(SocketProtocol::Tcp),
                    kind: SetSpecifier::One(NetworkActivityKind::Bind),
                    local_port: SetSpecifier::One(NonZeroU16::new(80).unwrap().into()),
                    address: SetSpecifier::One("::".parse::<IpAddr>().unwrap().into()),
                }
                .into()
            )]
        );
    }

    // Helper to create an AF_INET6 sendto syscall
    fn make_sendto_inet6(pid: pid_t, fd: i64, addr: &str) -> Syscall {
        let mut sc = make_syscall(
            "sendto",
            vec![
                int_literal(fd),
                buf_expr(b"data"),
                int_literal(4),
                int_literal(0),
                inet6_sockaddr(53, addr),
            ],
            4,
        );
        sc.pid = pid;
        sc
    }

    // 3. Dual-stack with sendto emits both IPv4 and IPv6 actions
    #[test]
    fn dual_stack_sendto() {
        let socket_handler = SocketHandler { af: 0, flags: 1 };
        let network_handler = NetworkHandler {
            fd: 0,
            sockaddr: SockaddrArg::Sockaddr(4),
        };

        let mut actions = vec![];
        let mut state = program_state();

        socket_handler
            .handle(
                &make_socket_inet6(1000, "SOCK_DGRAM", 3),
                &mut actions,
                &mut state,
            )
            .unwrap();

        network_handler
            .handle(
                &make_sendto_inet6(1000, 3, "::ffff:8.8.8.8"),
                &mut actions,
                &mut state,
            )
            .unwrap();

        // Should emit IPv4 action with 8.8.8.8, then IPv6 action
        assert_eq!(
            actions[1..],
            vec![
                ProgramAction::NetworkActivity(
                    NetworkActivity {
                        af: SetSpecifier::One(SocketFamily::Ipv4),
                        proto: SetSpecifier::One(SocketProtocol::Udp),
                        kind: SetSpecifier::One(NetworkActivityKind::SendRecv),
                        local_port: SetSpecifier::All,
                        address: SetSpecifier::One("8.8.8.8".parse::<IpAddr>().unwrap().into()),
                    }
                    .into()
                ),
                ProgramAction::NetworkActivity(
                    NetworkActivity {
                        af: SetSpecifier::One(SocketFamily::Ipv6),
                        proto: SetSpecifier::One(SocketProtocol::Udp),
                        kind: SetSpecifier::One(NetworkActivityKind::SendRecv),
                        local_port: SetSpecifier::All,
                        address: SetSpecifier::One(
                            "::ffff:8.8.8.8".parse::<IpAddr>().unwrap().into()
                        ),
                    }
                    .into()
                ),
            ]
        );
    }

    // 4. AF_INET socket never triggers dual-stack path
    #[test]
    fn ipv4_socket_no_dual_stack() {
        let socket_handler = SocketHandler { af: 0, flags: 1 };
        let network_handler = NetworkHandler {
            fd: 0,
            sockaddr: SockaddrArg::Sockaddr(1),
        };

        let mut actions = vec![];
        let mut state = program_state();

        socket_handler
            .handle(
                &make_socket_inet(1000, "SOCK_STREAM", 3),
                &mut actions,
                &mut state,
            )
            .unwrap();

        network_handler
            .handle(&make_bind_inet(1000, 3, 80), &mut actions, &mut state)
            .unwrap();

        // Only one bind action with IPv4, no dual-stack IPv6
        assert_eq!(
            actions[1..],
            vec![ProgramAction::NetworkActivity(
                NetworkActivity {
                    af: SetSpecifier::One(SocketFamily::Ipv4),
                    proto: SetSpecifier::One(SocketProtocol::Tcp),
                    kind: SetSpecifier::One(NetworkActivityKind::Bind),
                    local_port: SetSpecifier::One(NonZeroU16::new(80).unwrap().into()),
                    address: SetSpecifier::None,
                }
                .into()
            )]
        );
    }
}
