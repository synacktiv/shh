//! Socket address syscall handlers

use std::{
    any::type_name,
    ffi::OsStr,
    net::{IpAddr, SocketAddr},
    num::NonZeroU16,
    os::unix::ffi::OsStrExt as _,
    path::Path,
    str,
};

use super::{
    ExtractArg, HandlerError, SyscallHandler, fd_label, fd_number,
    walk::{resolve_path, traverse_path},
};
use crate::{
    strace::{
        BufferExpression, BufferType, Expression, IntegerExpression, IntegerExpressionValue,
        NamedSymbol, Syscall,
    },
    summarize::{
        ProgramState,
        action::{
            NetworkActivity, NetworkActivityKind, NetworkAddress, NetworkPort, ProgramAction,
            SetSpecifier,
        },
    },
    systemd::{SocketFamily, SocketProtocol},
};

/// Map an address specifier to its IPv4 dual-stack equivalent.
/// Returns `None` when the specifier contains an address with no IPv4 mapping
/// (e.g. `::1`, `2001:db8::1`).
fn ipv4_equivalent_specifier(
    spec: &SetSpecifier<NetworkAddress>,
) -> Option<SetSpecifier<NetworkAddress>> {
    match spec {
        SetSpecifier::All => Some(SetSpecifier::All),
        SetSpecifier::None => Some(SetSpecifier::None),
        SetSpecifier::One(addr) => addr.ipv4_equivalent().map(SetSpecifier::One),
        SetSpecifier::Some(addrs) => addrs
            .iter()
            .map(NetworkAddress::ipv4_equivalent)
            .collect::<Option<Vec<_>>>()
            .map(SetSpecifier::Some),
        SetSpecifier::AllExcept(addrs) => addrs
            .iter()
            .map(NetworkAddress::ipv4_equivalent)
            .collect::<Option<Vec<_>>>()
            .map(SetSpecifier::AllExcept),
    }
}

/// Argument holding the socket addresses of a network syscall
pub(crate) enum SockaddrArg {
    /// `sockaddr` struct
    Sockaddr(usize),
    /// `msghdr` struct, with the address in `msg_name`
    MsgHdr(usize),
    /// Array of `mmsghdr` structs, with an address per message
    MmsgHdrs(usize),
    /// No address argument
    None,
}

impl ExtractArg for SockaddrArg {
    /// The socket addresses, whether the call may carry messages from addresses not among them, and the
    /// descriptors passed in `SCM_RIGHTS` control messages
    type Output<'a> = (Vec<&'a Expression>, bool, Vec<&'a Expression>);

    fn extract<'a>(&self, sc: &'a Syscall) -> Result<Self::Output<'a>, HandlerError> {
        match self {
            Self::Sockaddr(i) => Ok((vec![i.extract(sc)?], false, vec![])),
            Self::MsgHdr(i) => {
                let (name, fds) = msg_parts(i.extract(sc)?)?;
                Ok((vec![name], false, fds))
            }
            Self::MmsgHdrs(i) => match i.extract(sc)? {
                Expression::Collection {
                    values, truncated, ..
                } => {
                    let mut names = Vec::with_capacity(values.len());
                    let mut fds = vec![];
                    for (_, msg) in values {
                        let members = unpack_expr!(msg, Expression::Struct(members) => members);
                        let msghdr = unpack_struct_member!(members, "msg_hdr");
                        let (name, msg_fds) = msg_parts(msghdr)?;
                        names.push(name);
                        fds.extend(msg_fds);
                    }
                    Ok((names, *truncated, fds))
                }
                // An empty batch
                Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::NamedSymbol(NamedSymbol::Unambiguous(s)),
                    ..
                }) if s == "NULL" => Ok((vec![], false, vec![])),
                other => Err(err_expr_type!(other)),
            },
            Self::None => Ok((vec![], true, vec![])),
        }
    }
}

/// Get the socket address of a `msghdr` struct, and the descriptors passed in its `SCM_RIGHTS` control messages
fn msg_parts(msghdr: &Expression) -> Result<(&Expression, Vec<&Expression>), HandlerError> {
    let members = unpack_expr!(msghdr, Expression::Struct(members) => members);
    let name = unpack_struct_member!(members, "msg_name");
    // Absent without control data, an address when unreadable
    let Some(Expression::Collection { values: cmsgs, .. }) = members.get("msg_control") else {
        return Ok((name, vec![]));
    };
    let mut fds = vec![];
    for (_, cmsg) in cmsgs {
        let cmsg = unpack_expr!(cmsg, Expression::Struct(fields) => fields);
        if matches!(
            unpack_struct_member!(cmsg, "cmsg_type"),
            Expression::Integer(IntegerExpression {
                value: IntegerExpressionValue::NamedSymbol(NamedSymbol::Unambiguous(t)),
                ..
            }) if t == "SCM_RIGHTS"
        )
            // Absent, or a buffer, for data shorter than a descriptor
            && let Some(Expression::Collection { values, .. }) = cmsg.get("cmsg_data")
        {
            fds.extend(values.iter().map(|(_, fd)| fd));
        }
    }
    Ok((name, fds))
}

/// Handle network syscalls
pub(crate) struct NetworkHandler {
    pub fd: usize,
    pub sockaddr: SockaddrArg,
}

impl SyscallHandler for NetworkHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        // Calls without an address argument read from their descriptor
        let receive = sc.name.starts_with("recv") || matches!(self.sockaddr, SockaddrArg::None);
        let accept = sc.name.starts_with("accept");
        // A failed call gets no incoming traffic, nor its address
        if (receive || accept) && !sc.is_successful() {
            return Ok(());
        }
        let fd = self.fd.extract(sc)?;
        // Incoming traffic without a decoded address, or past the printed addresses, comes from peers the arguments
        // do not name
        let (sockaddrs, mut unnamed, passed_fds) = self.sockaddr.extract(sc)?;
        for passed_fd in passed_fds {
            let number = fd_number(passed_fd)?;
            if receive {
                // The sender registers the socket under the metadata both processes show
                state
                    .proc_fd
                    .designate_by_metadata(sc.pid, number, passed_fd.metadata());
            } else if let Some(metadata) = passed_fd.metadata()
                && state
                    .proc_fd
                    .get_sock_info(sc.pid, number)
                    // Another socket may reuse the descriptor number of a closed one
                    .is_some_and(|info| info.label.as_deref() == Some(fd_label(metadata)))
            {
                state.proc_fd.register_metadata(sc.pid, number, metadata);
            }
        }
        for sockaddr in sockaddrs {
            unnamed |= !handle_sockaddr(sc, fd, sockaddr, actions, state)?;
        }
        if unnamed
            && (receive || accept)
            && let Some(info) = state.proc_fd.get_sock_info(sc.pid, fd_number(fd)?)
            // Another file may reuse the descriptor number of a closed socket
            && info.label.as_deref() == fd.metadata().map(fd_label)
        {
            if accept {
                // Record an accept from the peer named by the metadata of the accepted socket, or from any peer
                let address = sc
                    .ret_val
                    .as_ref()
                    .and_then(|ret_val| ret_val.metadata.as_deref())
                    .and_then(metadata_peer)
                    .map_or(SetSpecifier::All, |peer| SetSpecifier::One(peer.into()));
                push_socket_activity(sc, fd, SetSpecifier::All, address, actions, state)?;
            } else if info.proto != SocketProtocol::Tcp && !info.connected {
                // Stream and connected sockets receive only from their peer
                push_socket_activity(sc, fd, SetSpecifier::All, SetSpecifier::All, actions, state)?;
            }
        }
        Ok(())
    }
}

/// Handle a socket address of a network syscall, and return whether the trace decodes it
fn handle_sockaddr(
    sc: &Syscall,
    fd: &Expression,
    sockaddr: &Expression,
    actions: &mut Vec<ProgramAction>,
    state: &mut ProgramState,
) -> Result<bool, HandlerError> {
    let (af_str, addr_struct) = if let Expression::Struct(members) = sockaddr {
        let af_expr = unpack_struct_member!(members, "sa_family");
        let af = unpack_expr!(
            af_expr,
            Expression::Integer(IntegerExpression {
                value: IntegerExpressionValue::NamedSymbol(NamedSymbol::Unambiguous(af)),
                ..
            }) => af
        );
        (af.as_str(), members)
    } else {
        // No decoded socket address is available
        return Ok(false);
    };
    // A connect associates the socket with a peer, or dissolves the association for an AF_UNSPEC address
    if sc.name == "connect"
        && sc.is_successful()
        && let Some(info) = state.proc_fd.get_sock_info_mut(sc.pid, fd_number(fd)?)
        // Another socket may reuse the descriptor number of a closed one
        && info.label.as_deref() == fd.metadata().map(fd_label)
    {
        info.connected = af_str != "AF_UNSPEC";
    }
    if af_str == "AF_UNIX"
        // A peer address returned by other calls is not looked up
        && matches!(sc.name.as_str(), "bind" | "connect" | "sendto" | "sendmsg" | "sendmmsg")
        // Extract path for socket address structure if it's a non abstract one
        && let Some(Expression::Buffer(BufferExpression {
            value: b,
            type_: BufferType::Unknown,
        })) = addr_struct.get("sun_path")
        && let Some(mut path) =
            resolve_path(Path::new(OsStr::from_bytes(b)), None, &state.cur_dir)
    {
        // A bind creates its last component, other calls look up the socket it names
        let bind = sc.name == "bind";
        traverse_path(&mut path, !bind, actions);
        // Peers outside the service reach the socket through its path
        actions.push(ProgramAction::Read(path.clone()));
        if bind {
            actions.push(ProgramAction::Create(path));
        }
    }
    let ip_addr: SetSpecifier<NetworkAddress> = match addr_struct
        .iter()
        .find_map(|(k, v)| ["sin_addr", "sin6_addr"].contains(&k.as_str()).then_some(v))
    {
        Some(Expression::Integer(IntegerExpression {
            value:
                IntegerExpressionValue::Macro {
                    name: macro_name,
                    args,
                },
            ..
        })) if matches!(macro_name.as_str(), "inet_addr" | "inet_pton") => {
            let arg = if macro_name == "inet_addr" {
                args.first()
            } else {
                args.get(1)
            };
            match arg {
                Some(Expression::Buffer(BufferExpression { value, .. })) => {
                    let ip_str =
                        str::from_utf8(value).map_err(|_| err_value!(value, &[u8] => &str))?;
                    let ip = ip_str
                        .parse::<IpAddr>()
                        .map_err(|_| err_value!(ip_str, &str => IpAddr))?;
                    SetSpecifier::One(ip.into())
                }
                _ => unreachable!(),
            }
        }
        // An address buffer too short for the IP address
        None if matches!(af_str, "AF_INET" | "AF_INET6") => return Ok(false),
        _ => SetSpecifier::None,
    };

    let local_port = if sc.name == "bind" {
        match addr_struct
            .iter()
            .find_map(|(k, v)| k.ends_with("_port").then_some(v))
        {
            Some(Expression::Integer(IntegerExpression {
                value:
                    IntegerExpressionValue::Macro {
                        name: macro_name,
                        args,
                    },
                ..
            })) if macro_name == "htons" => match args.first() {
                Some(Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::Literal(port_val),
                    ..
                })) => {
                    if *port_val == 0 {
                        // 0 means bind random port, we don't know which one, but this is not
                        // denied by SocketBindDeny
                        SetSpecifier::None
                    } else {
                        SetSpecifier::One(NetworkPort::from(
                            TryInto::<u16>::try_into(*port_val)
                                .ok()
                                .and_then(NonZeroU16::new)
                                .ok_or_else(|| err_value!(*port_val, i64 => NetworkPort))?,
                        ))
                    }
                }
                _ => unreachable!(),
            },
            _ => SetSpecifier::None,
        }
    } else {
        SetSpecifier::All
    };

    push_socket_activity(sc, fd, local_port, ip_addr, actions, state)?;
    Ok(true)
}

/// Record the network activity of a syscall on a socket
fn push_socket_activity(
    sc: &Syscall,
    fd: &Expression,
    local_port: SetSpecifier<NetworkPort>,
    address: SetSpecifier<NetworkAddress>,
    actions: &mut Vec<ProgramAction>,
    state: &ProgramState,
) -> Result<(), HandlerError> {
    if let Some(info) = state.proc_fd.get_sock_info(sc.pid, fd_number(fd)?) {
        let activity = NetworkActivity {
            af: SetSpecifier::One(info.af.family()),
            proto: SetSpecifier::One(info.proto.clone()),
            kind: SetSpecifier::One(NetworkActivityKind::from_sc_name(&sc.name)),
            local_port,
            address,
        };

        // Dual-stack: emit an IPv4 action if this AF_INET6 socket can serve IPv4
        if info.af.is_dual_stack(state.bindv6only_default)
            && let Some(ipv4_addr) = ipv4_equivalent_specifier(&activity.address)
        {
            actions.push(ProgramAction::NetworkActivity(
                NetworkActivity {
                    af: SetSpecifier::One(SocketFamily::Ipv4),
                    address: ipv4_addr,
                    ..activity.clone()
                }
                .into(),
            ));
        }

        actions.push(ProgramAction::NetworkActivity(activity.into()));
    }

    Ok(())
}

/// Get the peer IP address of descriptor metadata
fn metadata_peer(metadata: &[u8]) -> Option<IpAddr> {
    let (_, peer) = str::from_utf8(metadata).ok()?.rsplit_once("->")?;
    peer.strip_suffix(']')?
        .parse::<SocketAddr>()
        .ok()
        .map(|peer| peer.ip())
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, fs, os::unix, path::PathBuf};

    use nix::libc::pid_t;

    use super::*;
    use crate::{
        strace::SyscallItem,
        summarize::{
            handlers::tests::{
                buf_expr, fd_expr, int_literal, make_bind_inet, make_failed_syscall, make_syscall,
                named_symbol, summarize_syscall, syscall,
            },
            program_state, summarize,
        },
    };

    #[test]
    fn connect_bind_uds() {
        let _ = simple_logger::SimpleLogger::new().init();

        let env_paths = [
            PathBuf::from("/path/from/env/1"),
            PathBuf::from("/path/from/env/2"),
        ];
        let read = ProgramAction::Read("/run/test/sock".into());
        let create = ProgramAction::Create("/run/test/sock".into());
        for (name, path_actions) in [
            ("connect", vec![read.clone()]),
            ("bind", vec![read, create]),
        ] {
            let syscalls = [Ok(syscall(
                name,
                vec![
                    int_literal(3),
                    Expression::Struct(HashMap::from([
                        ("sa_family".to_owned(), named_symbol("AF_UNIX")),
                        ("sun_path".to_owned(), buf_expr(b"/run/test/sock")),
                    ])),
                    int_literal(17),
                ],
            ))];
            let other_actions = vec![
                ProgramAction::Syscalls([name.into()].into()),
                ProgramAction::Read("/path/from/env/1".into()),
                ProgramAction::Read("/path/from/env/2".into()),
            ];
            assert_eq!(
                summarize(syscalls, &env_paths, program_state()).unwrap(),
                [path_actions, other_actions].concat()
            );
        }
    }

    #[test]
    fn bind_abstract_uds() {
        let _ = simple_logger::SimpleLogger::new().init();

        let syscalls = [Ok(syscall(
            "bind",
            vec![
                int_literal(3),
                Expression::Struct(HashMap::from([
                    ("sa_family".to_owned(), named_symbol("AF_UNIX")),
                    (
                        "sun_path".to_owned(),
                        Expression::Buffer(BufferExpression {
                            value: b"/run/test/sock".to_vec(),
                            type_: BufferType::AbstractPath,
                        }),
                    ),
                ])),
                int_literal(17),
            ],
        ))];
        assert_eq!(
            summarize(syscalls, &[], program_state()).unwrap(),
            vec![ProgramAction::Syscalls(["bind".into()].into())]
        );
    }

    /// Build a `msghdr` expression naming a socket address
    fn msghdr(name: Expression) -> Expression {
        Expression::Struct(HashMap::from([("msg_name".to_owned(), name)]))
    }

    /// Build an `mmsghdr` array expression with a message per socket address
    fn mmsghdrs(names: Vec<Expression>, truncated: bool) -> Expression {
        Expression::Collection {
            complement: false,
            values: names
                .into_iter()
                .map(|name| {
                    (
                        None,
                        Expression::Struct(HashMap::from([("msg_hdr".to_owned(), msghdr(name))])),
                    )
                })
                .collect(),
            truncated,
        }
    }

    /// Build an `AF_INET` socket address expression
    fn inet_sockaddr(addr: &str) -> Expression {
        Expression::Struct(HashMap::from([
            ("sa_family".to_owned(), named_symbol("AF_INET")),
            (
                "sin_addr".to_owned(),
                Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::Macro {
                        name: "inet_addr".to_owned(),
                        args: vec![buf_expr(addr.as_bytes())],
                    },
                    metadata: None,
                }),
            ),
        ]))
    }

    #[test]
    fn uds_through_symlink() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let target_dir = temp_dir.path().join("target_dir");
        let link_dir = temp_dir.path().join("link_dir");
        fs::create_dir(&target_dir).unwrap();
        unix::fs::symlink(&target_dir, &link_dir).unwrap();
        let sock = target_dir.join("sock");
        let sock_link = temp_dir.path().join("sock_link");
        unix::fs::symlink(&sock, &sock_link).unwrap();
        let inner_dir = target_dir.join("inner");
        let alias = temp_dir.path().join("alias");
        fs::create_dir(&inner_dir).unwrap();
        unix::fs::symlink(&inner_dir, &alias).unwrap();
        let sockaddr = |path: &Path| {
            Expression::Struct(HashMap::from([
                ("sa_family".to_owned(), named_symbol("AF_UNIX")),
                ("sun_path".to_owned(), buf_expr(path.as_os_str().as_bytes())),
            ]))
        };
        let lookup_actions = vec![
            ProgramAction::Read(sock_link.clone()),
            ProgramAction::Read(sock.clone()),
        ];
        for (name, args, mut path_actions) in [
            (
                "connect",
                vec![int_literal(3), sockaddr(&sock_link), int_literal(110)],
                lookup_actions.clone(),
            ),
            (
                "sendto",
                vec![
                    int_literal(3),
                    buf_expr(b"x"),
                    int_literal(1),
                    int_literal(0),
                    sockaddr(&sock_link),
                    int_literal(110),
                ],
                lookup_actions.clone(),
            ),
            (
                "sendmsg",
                vec![int_literal(3), msghdr(sockaddr(&sock_link)), int_literal(0)],
                lookup_actions.clone(),
            ),
            (
                "sendmmsg",
                vec![
                    int_literal(3),
                    mmsghdrs(vec![sockaddr(&sock_link)], false),
                    int_literal(1),
                    int_literal(0),
                ],
                lookup_actions,
            ),
            (
                "bind",
                vec![
                    int_literal(3),
                    sockaddr(&link_dir.join("new")),
                    int_literal(110),
                ],
                vec![
                    ProgramAction::Read(link_dir.clone()),
                    ProgramAction::Read(target_dir.join("new")),
                    ProgramAction::Create(target_dir.join("new")),
                ],
            ),
            // A `..` after a symlink leaves the symlink target
            (
                "bind",
                vec![
                    int_literal(3),
                    sockaddr(&alias.join("../new")),
                    int_literal(110),
                ],
                vec![
                    ProgramAction::Read(alias.clone()),
                    ProgramAction::Read(inner_dir.clone()),
                    ProgramAction::Read(target_dir.join("new")),
                    ProgramAction::Create(target_dir.join("new")),
                ],
            ),
            // A bind does not follow its last component
            (
                "bind",
                vec![int_literal(3), sockaddr(&sock_link), int_literal(110)],
                vec![
                    ProgramAction::Read(sock_link.clone()),
                    ProgramAction::Create(sock_link.clone()),
                ],
            ),
            // A returned peer address is not looked up
            (
                "accept",
                vec![int_literal(3), sockaddr(&sock_link), int_literal(110)],
                vec![],
            ),
            (
                "recvfrom",
                vec![
                    int_literal(3),
                    buf_expr(b"x"),
                    int_literal(1),
                    int_literal(0),
                    sockaddr(&sock_link),
                    int_literal(110),
                ],
                vec![],
            ),
            (
                "recvmsg",
                vec![int_literal(3), msghdr(sockaddr(&sock_link)), int_literal(0)],
                vec![],
            ),
            (
                "recvmmsg",
                vec![
                    int_literal(3),
                    mmsghdrs(vec![sockaddr(&sock_link)], false),
                    int_literal(1),
                    int_literal(0),
                    named_symbol("NULL"),
                ],
                vec![],
            ),
        ] {
            path_actions.push(ProgramAction::Syscalls([name.into()].into()));
            assert_eq!(summarize_syscall(make_syscall(name, args, 0)), path_actions);
        }
    }

    #[test]
    fn msg_peer_addresses() {
        let _ = simple_logger::SimpleLogger::new().init();

        let activity = |kind, address| inet_activity(SocketProtocol::Udp, kind, address);
        let peer = |addr: &str| SetSpecifier::One(addr.parse::<IpAddr>().unwrap().into());
        let timespec = Expression::Struct(HashMap::from([
            ("tv_sec".to_owned(), int_literal(0)),
            ("tv_nsec".to_owned(), int_literal(0)),
        ]));
        for (name, msgs, ret, peers) in [
            (
                "sendmsg",
                msghdr(inet_sockaddr("127.0.0.1")),
                1,
                vec![peer("127.0.0.1")],
            ),
            (
                "recvmsg",
                msghdr(inet_sockaddr("127.0.0.2")),
                1,
                vec![peer("127.0.0.2")],
            ),
            // A zero-length datagram
            (
                "recvmsg",
                msghdr(inet_sockaddr("127.0.0.2")),
                0,
                vec![peer("127.0.0.2")],
            ),
            // On a connected socket
            ("sendmsg", msghdr(named_symbol("NULL")), 1, vec![]),
            // From a peer without a decoded address
            (
                "recvmsg",
                msghdr(int_literal(0x7ffc_19ef_9970)),
                1,
                vec![SetSpecifier::All],
            ),
            // With control data other than descriptors
            (
                "recvmsg",
                cmsg_msghdr(
                    inet_sockaddr("127.0.0.2"),
                    "SCM_TIMESTAMPING_OLD",
                    vec![timespec; 3],
                ),
                1,
                vec![peer("127.0.0.2")],
            ),
            (
                "sendmmsg",
                mmsghdrs(
                    vec![inet_sockaddr("127.0.0.1"), inet_sockaddr("127.0.0.2")],
                    false,
                ),
                2,
                vec![peer("127.0.0.1"), peer("127.0.0.2")],
            ),
            // The first message to the connected peer
            (
                "sendmmsg",
                mmsghdrs(
                    vec![named_symbol("NULL"), inet_sockaddr("127.0.0.2")],
                    false,
                ),
                2,
                vec![peer("127.0.0.2")],
            ),
            (
                "recvmmsg",
                mmsghdrs(
                    vec![inet_sockaddr("127.0.0.1"), inet_sockaddr("127.0.0.2")],
                    false,
                ),
                2,
                vec![peer("127.0.0.1"), peer("127.0.0.2")],
            ),
            (
                "recvmmsg_time64",
                mmsghdrs(vec![inet_sockaddr("127.0.0.1")], false),
                1,
                vec![peer("127.0.0.1")],
            ),
            // The kernel sends no message past the printed ones
            (
                "sendmmsg",
                mmsghdrs(vec![inet_sockaddr("127.0.0.1")], true),
                1024,
                vec![peer("127.0.0.1")],
            ),
            // The messages past the printed ones come from unknown peers
            (
                "recvmmsg",
                mmsghdrs(vec![inet_sockaddr("127.0.0.1")], true),
                1025,
                vec![peer("127.0.0.1"), SetSpecifier::All],
            ),
            // Empty batches
            ("sendmmsg", named_symbol("NULL"), 0, vec![]),
            ("recvmmsg", named_symbol("NULL"), 0, vec![]),
        ] {
            let mut expected = vec![activity(
                NetworkActivityKind::SocketCreation,
                SetSpecifier::All,
            )];
            expected.extend(
                peers
                    .into_iter()
                    .map(|address| activity(NetworkActivityKind::SendRecv, address)),
            );
            assert_network_activities(
                vec![
                    make_syscall(
                        "socket",
                        vec![
                            named_symbol("AF_INET"),
                            named_symbol("SOCK_DGRAM"),
                            named_symbol("IPPROTO_IP"),
                        ],
                        3,
                    ),
                    make_syscall(name, vec![int_literal(3), msgs, int_literal(0)], ret),
                ],
                expected,
            );
        }
    }

    #[test]
    fn failed_msg_calls() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let sock = temp_dir.path().join("sock");
        for (name, msgs, mut actions) in [
            // A failed receive returns no address
            (
                "recvmsg",
                Expression::Struct(HashMap::from([("msg_namelen".to_owned(), int_literal(16))])),
                vec![],
            ),
            ("recvmmsg", int_literal(0x7ffc_e32a_da50), vec![]),
            // A send failing on a full peer queue has looked up its destination
            (
                "sendmsg",
                msghdr(Expression::Struct(HashMap::from([
                    ("sa_family".to_owned(), named_symbol("AF_UNIX")),
                    ("sun_path".to_owned(), buf_expr(sock.as_os_str().as_bytes())),
                ]))),
                vec![ProgramAction::Read(sock.clone())],
            ),
        ] {
            actions.push(ProgramAction::Syscalls([name.into()].into()));
            assert_eq!(
                summarize_syscall(make_failed_syscall(
                    name,
                    vec![int_literal(3), msgs, int_literal(1)],
                    "EAGAIN"
                )),
                actions
            );
        }
    }

    /// Build a `socket` call returning descriptor 3 for an `AF_INET` socket of a type, with its metadata
    fn inet_socket(type_: &str, metadata: &str) -> Syscall {
        let mut sc = make_syscall(
            "socket",
            vec![
                named_symbol("AF_INET"),
                named_symbol(type_),
                named_symbol("IPPROTO_IP"),
            ],
            3,
        );
        sc.ret_val.as_mut().unwrap().metadata = Some(metadata.as_bytes().to_vec());
        sc
    }

    /// Build descriptor 3 with metadata lacking decoded socket details
    fn sock() -> Expression {
        fd_expr(3, "socket:[7]")
    }

    /// Build a `recvfrom` call on `sock`, with a source address argument
    fn recvfrom(addr: Expression) -> Syscall {
        make_syscall(
            "recvfrom",
            vec![
                sock(),
                buf_expr(b"x"),
                int_literal(16),
                int_literal(0),
                addr,
                named_symbol("NULL"),
            ],
            1,
        )
    }

    /// Build a `recvmmsg` or `recvmmsg_time64` call on `sock`
    fn recvmmsg(name: &str, msgs: Expression, ret: i64) -> Syscall {
        make_syscall(
            name,
            vec![
                sock(),
                msgs,
                int_literal(1024),
                int_literal(0),
                named_symbol("NULL"),
            ],
            ret,
        )
    }

    /// Build a `read` call on a descriptor
    fn read(fd: Expression) -> Syscall {
        make_syscall("read", vec![fd, buf_expr(b"x"), int_literal(16)], 1)
    }

    /// Build a `sendto` call of a process to 127.0.0.5 through a descriptor
    fn sendto(pid: pid_t, fd: Expression) -> Syscall {
        let mut sc = make_syscall(
            "sendto",
            vec![
                fd,
                buf_expr(b"x"),
                int_literal(1),
                int_literal(0),
                inet_sockaddr("127.0.0.5"),
                int_literal(16),
            ],
            1,
        );
        sc.pid = pid;
        sc
    }

    /// Build the activity of a socket on any local port
    fn network_activity(
        af: SocketFamily,
        proto: SocketProtocol,
        kind: NetworkActivityKind,
        address: SetSpecifier<NetworkAddress>,
    ) -> ProgramAction {
        ProgramAction::NetworkActivity(
            NetworkActivity {
                af: SetSpecifier::One(af),
                proto: SetSpecifier::One(proto),
                kind: SetSpecifier::One(kind),
                local_port: SetSpecifier::All,
                address,
            }
            .into(),
        )
    }

    /// Build the activity of an `AF_INET` socket on any local port
    fn inet_activity(
        proto: SocketProtocol,
        kind: NetworkActivityKind,
        address: SetSpecifier<NetworkAddress>,
    ) -> ProgramAction {
        network_activity(SocketFamily::Ipv4, proto, kind, address)
    }

    /// Summarize calls, and check their actions are network activities followed by the names of the calls
    fn assert_network_activities(calls: Vec<Syscall>, activities: Vec<ProgramAction>) {
        let names = calls.iter().map(|sc| sc.name.clone()).collect();
        let syscalls = calls
            .into_iter()
            .map(|sc| Ok(SyscallItem::Complete(Box::new(sc))));
        assert_eq!(
            summarize(syscalls, &[], program_state()).unwrap(),
            [activities, vec![ProgramAction::Syscalls(names)]].concat()
        );
    }

    #[test]
    fn recv_unnamed_peer() {
        let _ = simple_logger::SimpleLogger::new().init();

        let null = || named_symbol("NULL");
        let other_fd = || fd_expr(4, "pipe:[5]");
        let splice = |fd_in, fd_out| {
            make_syscall(
                "splice",
                vec![
                    fd_in,
                    null(),
                    fd_out,
                    null(),
                    int_literal(16),
                    int_literal(0),
                ],
                1,
            )
        };
        let sendfile = |name, fd_out, fd_in| {
            make_syscall(name, vec![fd_out, fd_in, null(), int_literal(16)], 1)
        };
        for (call, received) in [
            (recvfrom(null()), true),
            // An address buffer of zero length
            (recvfrom(int_literal(0x7ffc_9a69_7f90)), true),
            // Address buffers too short for the IP address
            (
                recvfrom(Expression::Struct(HashMap::from([(
                    "sa_family".to_owned(),
                    named_symbol("AF_INET"),
                )]))),
                true,
            ),
            (
                recvfrom(Expression::Struct(HashMap::from([
                    ("sa_family".to_owned(), named_symbol("AF_INET6")),
                    ("sa_data".to_owned(), buf_expr(b"\xb2\x0c")),
                ]))),
                true,
            ),
            (
                make_syscall("recvmsg", vec![sock(), msghdr(null()), int_literal(0)], 1),
                true,
            ),
            (recvmmsg("recvmmsg", mmsghdrs(vec![null()], false), 1), true),
            (
                recvmmsg("recvmmsg_time64", mmsghdrs(vec![null()], false), 1),
                true,
            ),
            (read(sock()), true),
            (
                make_syscall("readv", vec![sock(), int_literal(0), int_literal(1)], 1),
                true,
            ),
            (
                make_syscall(
                    "preadv2",
                    vec![
                        sock(),
                        int_literal(0),
                        int_literal(1),
                        int_literal(-1),
                        int_literal(0),
                    ],
                    1,
                ),
                true,
            ),
            (
                make_syscall(
                    "recv",
                    vec![sock(), buf_expr(b"x"), int_literal(16), int_literal(0)],
                    1,
                ),
                true,
            ),
            (splice(sock(), other_fd()), true),
            (sendfile("sendfile", other_fd(), sock()), true),
            (sendfile("sendfile64", other_fd(), sock()), true),
            // Failed receives
            (
                make_failed_syscall(
                    "read",
                    vec![sock(), int_literal(0), int_literal(16)],
                    "EAGAIN",
                ),
                false,
            ),
            (
                make_failed_syscall(
                    "recvfrom",
                    vec![
                        sock(),
                        int_literal(0),
                        int_literal(16),
                        int_literal(0),
                        null(),
                        null(),
                    ],
                    "EAGAIN",
                ),
                false,
            ),
            // Sends to the socket
            (splice(other_fd(), sock()), false),
            (sendfile("sendfile", sock(), other_fd()), false),
        ] {
            let mut activities = vec![inet_activity(
                SocketProtocol::Udp,
                NetworkActivityKind::SocketCreation,
                SetSpecifier::All,
            )];
            if received {
                activities.push(inet_activity(
                    SocketProtocol::Udp,
                    NetworkActivityKind::SendRecv,
                    SetSpecifier::All,
                ));
            }
            assert_network_activities(
                vec![inet_socket("SOCK_DGRAM", "socket:[7]"), call],
                activities,
            );
        }
    }

    #[test]
    fn recv_unnamed_peer_socket_state() {
        let _ = simple_logger::SimpleLogger::new().init();

        let udp_socket = || inet_socket("SOCK_DGRAM", "socket:[7]");
        let connect = |addr| make_syscall("connect", vec![sock(), addr, int_literal(16)], 0);
        let connect_peer = || connect(inet_sockaddr("127.0.0.3"));
        let disconnect = || {
            connect(Expression::Struct(HashMap::from([(
                "sa_family".to_owned(),
                named_symbol("AF_UNSPEC"),
            )])))
        };
        let disconnect_through = |fd| {
            let mut sc = disconnect();
            sc.args[0] = fd;
            sc
        };
        let in_child = |mut sc: Syscall| {
            sc.pid = 2000;
            sc
        };
        let peer = || SetSpecifier::One("127.0.0.3".parse::<IpAddr>().unwrap().into());
        let created = || {
            inet_activity(
                SocketProtocol::Udp,
                NetworkActivityKind::SocketCreation,
                SetSpecifier::All,
            )
        };
        let received =
            |address| inet_activity(SocketProtocol::Udp, NetworkActivityKind::SendRecv, address);
        let connected =
            |address| inet_activity(SocketProtocol::Udp, NetworkActivityKind::Connect, address);
        for (calls, activities) in [
            // A socket with its details in metadata
            (
                vec![
                    inet_socket("SOCK_DGRAM", "UDP:[7]"),
                    read(fd_expr(3, "UDP:[127.0.0.1:41021]")),
                ],
                vec![created(), received(SetSpecifier::All)],
            ),
            // Other files reusing the descriptor number of the socket
            (
                vec![
                    inet_socket("SOCK_DGRAM", "UDP:[7]"),
                    read(fd_expr(3, "/tmp/file")),
                ],
                vec![created()],
            ),
            (
                vec![
                    inet_socket("SOCK_DGRAM", "UDP:[7]"),
                    read(fd_expr(3, "pipe:[5]")),
                ],
                vec![created()],
            ),
            (
                vec![
                    inet_socket("SOCK_DGRAM", "UDP:[7]"),
                    read(fd_expr(3, "TCP:[127.0.0.1:1->127.0.0.2:2]")),
                ],
                vec![created()],
            ),
            // A stream socket receives only once connected to a named peer
            (
                vec![inet_socket("SOCK_STREAM", "socket:[7]"), read(sock())],
                vec![inet_activity(
                    SocketProtocol::Tcp,
                    NetworkActivityKind::SocketCreation,
                    SetSpecifier::All,
                )],
            ),
            // A connected socket receives only from its peer
            (
                vec![udp_socket(), connect_peer(), recvfrom(named_symbol("NULL"))],
                vec![created(), connected(peer())],
            ),
            (
                vec![
                    udp_socket(),
                    connect_peer(),
                    recvmmsg(
                        "recvmmsg",
                        mmsghdrs(vec![inet_sockaddr("127.0.0.3")], true),
                        1025,
                    ),
                ],
                vec![created(), connected(peer()), received(peer())],
            ),
            (
                vec![
                    udp_socket(),
                    connect_peer(),
                    disconnect(),
                    recvfrom(named_symbol("NULL")),
                ],
                vec![
                    created(),
                    connected(peer()),
                    connected(SetSpecifier::None),
                    received(SetSpecifier::All),
                ],
            ),
            // A failed connect leaves the socket unconnected
            (
                vec![
                    udp_socket(),
                    make_failed_syscall(
                        "connect",
                        vec![sock(), inet_sockaddr("127.0.0.3"), int_literal(16)],
                        "EAGAIN",
                    ),
                    recvfrom(named_symbol("NULL")),
                ],
                vec![created(), connected(peer()), received(SetSpecifier::All)],
            ),
            // A disconnect applies to every descriptor of the socket
            (
                vec![
                    udp_socket(),
                    connect_peer(),
                    make_syscall("dup", vec![sock()], 4),
                    disconnect_through(fd_expr(4, "socket:[7]")),
                    recvfrom(named_symbol("NULL")),
                ],
                vec![
                    created(),
                    connected(peer()),
                    connected(SetSpecifier::None),
                    received(SetSpecifier::All),
                ],
            ),
            (
                vec![
                    udp_socket(),
                    connect_peer(),
                    make_syscall("fork", vec![], 2000),
                    disconnect(),
                    in_child(recvfrom(named_symbol("NULL"))),
                ],
                vec![
                    created(),
                    connected(peer()),
                    connected(SetSpecifier::None),
                    received(SetSpecifier::All),
                ],
            ),
            // A disconnect through a descriptor designating another socket leaves the socket connected
            (
                vec![
                    udp_socket(),
                    connect_peer(),
                    make_syscall("dup", vec![sock()], 4),
                    make_syscall("dup2", vec![fd_expr(5, "socket:[8]"), int_literal(4)], 4),
                    disconnect_through(fd_expr(4, "socket:[8]")),
                    recvfrom(named_symbol("NULL")),
                ],
                vec![created(), connected(peer())],
            ),
            (
                vec![
                    udp_socket(),
                    connect_peer(),
                    make_syscall("fork", vec![], 2000),
                    in_child(disconnect_through(fd_expr(3, "UNIX:[9]"))),
                    recvfrom(named_symbol("NULL")),
                ],
                vec![created(), connected(peer()), connected(SetSpecifier::None)],
            ),
        ] {
            assert_network_activities(calls, activities);
        }
    }

    #[test]
    fn send_through_duplicate() {
        let _ = simple_logger::SimpleLogger::new().init();

        let fcntl = |name, cmd, ret| {
            make_syscall(name, vec![sock(), named_symbol(cmd), int_literal(0)], ret)
        };
        for (call, fd, sent) in [
            (make_syscall("dup", vec![sock()], 7), 7, true),
            (
                make_syscall("dup2", vec![sock(), int_literal(7)], 7),
                7,
                true,
            ),
            (
                make_syscall(
                    "dup3",
                    vec![sock(), int_literal(7), named_symbol("O_CLOEXEC")],
                    7,
                ),
                7,
                true,
            ),
            (fcntl("fcntl", "F_DUPFD", 7), 7, true),
            (fcntl("fcntl", "F_DUPFD_CLOEXEC", 7), 7, true),
            (fcntl("fcntl64", "F_DUPFD_CLOEXEC", 7), 7, true),
            // Other commands return no descriptor
            (
                make_syscall("fcntl", vec![sock(), named_symbol("F_GETFL")], 2),
                2,
                false,
            ),
            // A failed call returns no descriptor
            (
                make_failed_syscall("dup", vec![sock()], "EMFILE"),
                -1,
                false,
            ),
        ] {
            let mut activities = vec![inet_activity(
                SocketProtocol::Udp,
                NetworkActivityKind::SocketCreation,
                SetSpecifier::All,
            )];
            if sent {
                activities.push(inet_activity(
                    SocketProtocol::Udp,
                    NetworkActivityKind::SendRecv,
                    SetSpecifier::One("127.0.0.5".parse::<IpAddr>().unwrap().into()),
                ));
            }
            assert_network_activities(
                vec![
                    inet_socket("SOCK_DGRAM", "socket:[7]"),
                    call,
                    sendto(1000, fd_expr(fd, "socket:[7]")),
                ],
                activities,
            );
        }
    }

    /// Build a `msghdr` expression naming a socket address, with a control message of an array
    fn cmsg_msghdr(name: Expression, cmsg_type: &str, data: Vec<Expression>) -> Expression {
        let cmsg = Expression::Struct(HashMap::from([
            ("cmsg_level".to_owned(), named_symbol("SOL_SOCKET")),
            ("cmsg_type".to_owned(), named_symbol(cmsg_type)),
            (
                "cmsg_data".to_owned(),
                Expression::Collection {
                    complement: false,
                    values: data.into_iter().map(|item| (None, item)).collect(),
                    truncated: false,
                },
            ),
        ]));
        Expression::Struct(HashMap::from([
            ("msg_name".to_owned(), name),
            (
                "msg_control".to_owned(),
                Expression::Collection {
                    complement: false,
                    values: vec![(None, cmsg)],
                    truncated: false,
                },
            ),
        ]))
    }

    /// Build a call of a process sending or receiving a descriptor through a Unix socket
    fn pass_fd(name: &str, pid: pid_t, fd: Expression) -> Syscall {
        let unix_sock = fd_expr(4, "UNIX-STREAM:[20]");
        let msg = cmsg_msghdr(named_symbol("NULL"), "SCM_RIGHTS", vec![fd]);
        let mut sc = if name.ends_with("mmsg") {
            let msgs = Expression::Collection {
                complement: false,
                values: vec![(
                    None,
                    Expression::Struct(HashMap::from([("msg_hdr".to_owned(), msg)])),
                )],
                truncated: false,
            };
            make_syscall(
                name,
                vec![unix_sock, msgs, int_literal(1), int_literal(0)],
                1,
            )
        } else {
            make_syscall(name, vec![unix_sock, msg, int_literal(0)], 1)
        };
        sc.pid = pid;
        sc
    }

    #[test]
    fn use_passed_socket() {
        let _ = simple_logger::SimpleLogger::new().init();

        let pidfd_getfd = |pidfd, target: &str| {
            let mut sc = make_syscall(
                "pidfd_getfd",
                vec![fd_expr(11, pidfd), fd_expr(3, target), int_literal(0)],
                12,
            );
            sc.pid = 2000;
            sc.ret_val.as_mut().unwrap().metadata = Some(target.as_bytes().to_vec());
            sc
        };
        let dup = |fd| {
            let mut sc = make_syscall("dup", vec![fd], 6);
            sc.pid = 2000;
            sc
        };
        let bound = "UDP:[127.0.0.1:5000]";
        for (created, passing, used, recorded) in [
            // Passed by each pair of calls, in either trace order
            (
                "socket:[7]",
                vec![
                    pass_fd("sendmsg", 1000, fd_expr(3, "socket:[7]")),
                    pass_fd("recvmsg", 2000, fd_expr(5, "socket:[7]")),
                ],
                fd_expr(5, "socket:[7]"),
                true,
            ),
            (
                "socket:[7]",
                vec![
                    pass_fd("recvmsg", 2000, fd_expr(5, "socket:[7]")),
                    pass_fd("sendmsg", 1000, fd_expr(3, "socket:[7]")),
                ],
                fd_expr(5, "socket:[7]"),
                true,
            ),
            (
                "socket:[7]",
                vec![
                    pass_fd("sendmmsg", 1000, fd_expr(3, "socket:[7]")),
                    pass_fd("recvmmsg", 2000, fd_expr(5, "socket:[7]")),
                ],
                fd_expr(5, "socket:[7]"),
                true,
            ),
            // Passed bound, its details decoded, in either trace order
            (
                "UDP:[7]",
                vec![
                    pass_fd("sendmsg", 1000, fd_expr(3, bound)),
                    pass_fd("recvmsg", 2000, fd_expr(5, bound)),
                ],
                fd_expr(5, bound),
                true,
            ),
            (
                "UDP:[7]",
                vec![
                    pass_fd("recvmsg", 2000, fd_expr(5, bound)),
                    pass_fd("sendmsg", 1000, fd_expr(3, bound)),
                ],
                fd_expr(5, bound),
                true,
            ),
            // Duplicated before its sender's line
            (
                "UDP:[7]",
                vec![
                    pass_fd("recvmsg", 2000, fd_expr(5, bound)),
                    dup(fd_expr(5, bound)),
                    pass_fd("sendmsg", 1000, fd_expr(3, bound)),
                ],
                fd_expr(6, bound),
                true,
            ),
            // Taken from its process, unbound or bound
            (
                "UDP:[7]",
                vec![pidfd_getfd("pid:1000", "UDP:[7]")],
                fd_expr(12, "UDP:[7]"),
                true,
            ),
            (
                "UDP:[7]",
                vec![pidfd_getfd("pid:1000", bound)],
                fd_expr(12, bound),
                true,
            ),
            // Taken from a process outside the tracer's PID namespace
            (
                "UDP:[7]",
                vec![pidfd_getfd("anon_inode:[pidfd]", "UDP:[9]")],
                fd_expr(12, "UDP:[9]"),
                false,
            ),
            // Received under the number of an inherited socket, from outside the service
            (
                "UDP:[7]",
                vec![
                    make_syscall("fork", vec![], 2000),
                    pass_fd("recvmsg", 2000, fd_expr(3, "UDP:[9]")),
                ],
                fd_expr(3, "UDP:[9]"),
                false,
            ),
            // Received without metadata under the number of an inherited socket
            (
                "UDP:[7]",
                vec![
                    make_syscall("fork", vec![], 2000),
                    pass_fd("recvmsg", 2000, int_literal(3)),
                ],
                int_literal(3),
                false,
            ),
            // Sent through the number of a tracked socket that an untracked one reuses
            (
                "UDP:[7]",
                vec![
                    pass_fd("sendmsg", 1000, fd_expr(3, "TCP:[10]")),
                    pass_fd("recvmsg", 2000, fd_expr(5, "TCP:[10]")),
                ],
                fd_expr(5, "TCP:[10]"),
                false,
            ),
        ] {
            let mut activities = vec![inet_activity(
                SocketProtocol::Udp,
                NetworkActivityKind::SocketCreation,
                SetSpecifier::All,
            )];
            if recorded {
                activities.extend([
                    inet_activity(
                        SocketProtocol::Udp,
                        NetworkActivityKind::SendRecv,
                        SetSpecifier::One("127.0.0.5".parse::<IpAddr>().unwrap().into()),
                    ),
                    ProgramAction::NetworkActivity(
                        NetworkActivity {
                            af: SetSpecifier::One(SocketFamily::Ipv4),
                            proto: SetSpecifier::One(SocketProtocol::Udp),
                            kind: SetSpecifier::One(NetworkActivityKind::Bind),
                            local_port: SetSpecifier::One(NonZeroU16::new(5000).unwrap().into()),
                            address: SetSpecifier::None,
                        }
                        .into(),
                    ),
                ]);
            }
            let bind = make_bind_inet(2000, fd_number(&used).unwrap().into(), 5000);
            assert_network_activities(
                [
                    vec![inet_socket("SOCK_DGRAM", created)],
                    passing,
                    vec![sendto(2000, used), bind],
                ]
                .concat(),
                activities,
            );
        }
    }

    #[test]
    fn recv_unnamed_peer_ipv6() {
        let _ = simple_logger::SimpleLogger::new().init();

        let activity =
            |af, kind| network_activity(af, SocketProtocol::Udp, kind, SetSpecifier::All);
        let created = activity(SocketFamily::Ipv6, NetworkActivityKind::SocketCreation);
        let received = |af| activity(af, NetworkActivityKind::SendRecv);
        for (bindv6only, activities) in [
            // A dual-stack socket also receives from IPv4 peers
            (
                false,
                vec![
                    created.clone(),
                    received(SocketFamily::Ipv4),
                    received(SocketFamily::Ipv6),
                ],
            ),
            (true, vec![created.clone(), received(SocketFamily::Ipv6)]),
        ] {
            let mut socket = make_syscall(
                "socket",
                vec![
                    named_symbol("AF_INET6"),
                    named_symbol("SOCK_DGRAM"),
                    named_symbol("IPPROTO_IP"),
                ],
                3,
            );
            socket.ret_val.as_mut().unwrap().metadata = Some(b"socket:[7]".to_vec());
            let syscalls = [socket, read(sock())].map(|sc| Ok(SyscallItem::Complete(Box::new(sc))));
            assert_eq!(
                summarize(syscalls, &[], ProgramState::new("/", bindv6only)).unwrap(),
                [
                    activities,
                    vec![ProgramAction::Syscalls(
                        ["socket".into(), "read".into()].into()
                    )]
                ]
                .concat()
            );
        }
    }

    #[test]
    fn accept_unnamed_peer() {
        let _ = simple_logger::SimpleLogger::new().init();

        let null = || named_symbol("NULL");
        let pointer = || int_literal(0x7ffc_9a69_7f90);
        let fd =
            |metadata: Option<&str>| metadata.map_or_else(|| int_literal(3), |m| fd_expr(3, m));
        let socket = |af: &str, metadata: Option<&str>| {
            let mut sc = make_syscall(
                "socket",
                vec![
                    named_symbol(af),
                    named_symbol("SOCK_STREAM"),
                    named_symbol("IPPROTO_IP"),
                ],
                3,
            );
            sc.ret_val.as_mut().unwrap().metadata = metadata.map(|m| m.as_bytes().to_vec());
            sc
        };
        let activity = |af, kind, address| network_activity(af, SocketProtocol::Tcp, kind, address);
        let created = |af| activity(af, NetworkActivityKind::SocketCreation, SetSpecifier::All);
        let accepted = |af, address| activity(af, NetworkActivityKind::Accept, address);
        let ip = |addr: &str| SetSpecifier::One(addr.parse::<IpAddr>().unwrap().into());
        for (af, created_metadata, listening, peer, activities) in [
            (
                "AF_INET",
                Some("TCP:[7]"),
                Some("TCP:[127.0.0.1:41022]"),
                Some("TCP:[127.0.0.1:41022->127.0.0.2:54817]"),
                vec![accepted(SocketFamily::Ipv4, ip("127.0.0.2"))],
            ),
            (
                "AF_INET6",
                Some("TCPv6:[7]"),
                Some("TCPv6:[[::]:35791]"),
                Some("TCPv6:[[::1]:35791->[::1]:59754]"),
                vec![accepted(SocketFamily::Ipv6, ip("::1"))],
            ),
            // A dual-stack socket accepting an IPv4 peer
            (
                "AF_INET6",
                Some("TCPv6:[7]"),
                Some("TCPv6:[[::]:35791]"),
                Some("TCPv6:[[::ffff:127.0.0.1]:35791->[::ffff:127.0.0.3]:35299]"),
                vec![
                    accepted(SocketFamily::Ipv4, ip("127.0.0.3")),
                    accepted(SocketFamily::Ipv6, ip("::ffff:127.0.0.3")),
                ],
            ),
            // Accepted sockets whose metadata names no peer
            (
                "AF_INET6",
                Some("TCPv6:[7]"),
                Some("TCPv6:[[::]:35791]"),
                Some("TCPv6:[4913846]"),
                vec![
                    accepted(SocketFamily::Ipv4, SetSpecifier::All),
                    accepted(SocketFamily::Ipv6, SetSpecifier::All),
                ],
            ),
            (
                "AF_INET",
                Some("socket:[7]"),
                Some("socket:[7]"),
                Some("socket:[6]"),
                vec![accepted(SocketFamily::Ipv4, SetSpecifier::All)],
            ),
            (
                "AF_UNIX",
                Some("UNIX-STREAM:[7]"),
                Some("UNIX-STREAM:[7]"),
                Some("UNIX-STREAM:[55->54]"),
                vec![accepted(
                    SocketFamily::Other("AF_UNIX".to_owned()),
                    SetSpecifier::All,
                )],
            ),
            (
                "AF_INET",
                None,
                None,
                None,
                vec![accepted(SocketFamily::Ipv4, SetSpecifier::All)],
            ),
            // Another socket reusing the descriptor number of the listening one
            (
                "AF_INET",
                Some("TCP:[7]"),
                Some("UNIX-STREAM:[8]"),
                Some("UNIX-STREAM:[9->8]"),
                vec![],
            ),
        ] {
            for (name, mut args) in [
                ("accept", vec![null(), null()]),
                // An address buffer of zero length
                ("accept", vec![pointer(), pointer()]),
                (
                    "accept4",
                    vec![null(), null(), named_symbol("SOCK_CLOEXEC")],
                ),
                (
                    "accept4",
                    vec![pointer(), pointer(), named_symbol("SOCK_CLOEXEC")],
                ),
            ] {
                args.insert(0, fd(listening));
                let mut call = make_syscall(name, args, 4);
                call.ret_val.as_mut().unwrap().metadata = peer.map(|m| m.as_bytes().to_vec());
                assert_network_activities(
                    vec![socket(af, created_metadata), call],
                    [vec![created(af.parse().unwrap())], activities.clone()].concat(),
                );
            }
        }
        // A failed accept returns no socket
        assert_network_activities(
            vec![
                socket("AF_INET", Some("TCP:[7]")),
                make_failed_syscall(
                    "accept4",
                    vec![
                        fd(Some("TCP:[127.0.0.1:41022]")),
                        null(),
                        null(),
                        named_symbol("SOCK_CLOEXEC"),
                    ],
                    "EAGAIN",
                ),
            ],
            vec![created(SocketFamily::Ipv4)],
        );
    }
}
