"""Use sockets a parent process passes to its child, or takes from it, in a given case."""

import ctypes
import os
import socket
import sys

# Port the child binds through a passed TCP socket
TCP_PORT = 1236
# Port a UDP socket is bound to before it is passed or taken
UDP_PORT = 1237

(case,) = sys.argv[1:]
parent_end, child_end = socket.socketpair()
child = os.fork()
if child == 0:
    parent_end.close()
else:
    child_end.close()
match case, child:
    case "unbound" | "bound", 0:
        _, fds, _, _ = socket.recv_fds(child_end, 1, 2)
        udp = socket.socket(fileno=fds[0])
        if case == "unbound":
            udp.sendto(b"x", ("127.0.0.2", 9))
            socket.socket(fileno=fds[1]).bind(("127.0.0.1", TCP_PORT))
        else:
            udp.sendto(b"x", ("127.0.0.3", 9))
        sys.exit()
    case "unbound" | "bound", _:
        # Created after the fork, the child gets them only from the parent
        socks = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]
        if case == "unbound":
            socks.append(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        else:
            socks[0].bind(("127.0.0.1", UDP_PORT))
        socket.send_fds(parent_end, [b"x"], [s.fileno() for s in socks])
    case "pidfd_getfd", 0:
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind(("127.0.0.1", UDP_PORT))
        child_end.send(str(udp.fileno()).encode())
        # Keep the socket open until the parent took it
        child_end.recv(1)
        sys.exit()
    case "pidfd_getfd", _:
        libc = ctypes.CDLL(None, use_errno=True)
        fd = libc.pidfd_getfd(os.pidfd_open(child), int(parent_end.recv(16)), 0)
        if fd < 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err))
        socket.socket(fileno=fd).sendto(b"x", ("127.0.0.4", 9))
        parent_end.send(b"x")
    case _:
        raise ValueError(case)
sys.exit(os.waitstatus_to_exitcode(os.waitpid(child, 0)[1]))
