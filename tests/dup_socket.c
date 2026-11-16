/* Use a socket through a copy of its descriptor made by a given call: send a UDP datagram to a port of 127.0.0.5,
 * bind a TCP socket to a port of 127.0.0.1, or disconnect a UDP socket bound to a port of 127.0.0.1 from its peer
 * then wait for incoming traffic through the original descriptor, failing after 5 seconds without any */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <err.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

/* Copy a descriptor with a call */
static int copy_fd(const char *call, int fd) {
    int copy;
    if (strcmp(call, "dup") == 0) {
        copy = dup(fd);
    } else if (strcmp(call, "dup2") == 0) {
        copy = dup2(fd, 10);
    } else if (strcmp(call, "dup3") == 0) {
        copy = dup3(fd, 10, O_CLOEXEC);
    } else if (strcmp(call, "F_DUPFD") == 0) {
        copy = fcntl(fd, F_DUPFD, 10);
    } else if (strcmp(call, "F_DUPFD_CLOEXEC") == 0) {
        copy = fcntl(fd, F_DUPFD_CLOEXEC, 10);
    } else {
        errx(2, "Unknown call %s", call);
    }
    if (copy == -1) {
        err(1, "%s", call);
    }
    return copy;
}

/* Build an IPv4 socket address */
static struct sockaddr_in inet_sockaddr(const char *addr, int port) {
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(port)};
    if (inet_pton(AF_INET, addr, &sa.sin_addr) != 1) {
        errx(2, "Invalid address %s", addr);
    }
    return sa;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        errx(2, "Usage: %s send|bind|disconnect CALL PORT", argv[0]);
    }
    const char *action = argv[1];
    const char *call = argv[2];
    int port = atoi(argv[3]);
    int fd = socket(AF_INET, strcmp(action, "bind") == 0 ? SOCK_STREAM : SOCK_DGRAM, 0);
    if (fd == -1) {
        err(1, "socket");
    }
    if (strcmp(action, "send") == 0) {
        struct sockaddr_in dst = inet_sockaddr("127.0.0.5", port);
        if (sendto(copy_fd(call, fd), "x", 1, 0, (struct sockaddr *)&dst, sizeof(dst)) == -1) {
            err(1, "sendto");
        }
        return 0;
    }
    struct sockaddr_in local = inet_sockaddr("127.0.0.1", port);
    if (strcmp(action, "bind") == 0) {
        if (bind(copy_fd(call, fd), (struct sockaddr *)&local, sizeof(local)) == -1) {
            err(1, "bind");
        }
        return 0;
    }
    if (strcmp(action, "disconnect") != 0) {
        errx(2, "Unknown action %s", action);
    }
    struct sockaddr_in peer = inet_sockaddr("127.0.0.3", 9);
    struct sockaddr unspec = {.sa_family = AF_UNSPEC};
    char buf;
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) == -1) {
        err(1, "bind");
    }
    if (connect(fd, (struct sockaddr *)&peer, sizeof(peer)) == -1) {
        err(1, "connect");
    }
    /* Terminates the process */
    alarm(5);
    if (strcmp(call, "fork") == 0) {
        /* The parent disconnects, the child receives */
        int pipe_fds[2];
        if (pipe(pipe_fds) == -1) {
            err(1, "pipe");
        }
        pid_t child = fork();
        if (child == -1) {
            err(1, "fork");
        }
        if (child == 0) {
            /* A forked child inherits no alarm */
            alarm(5);
            if (read(pipe_fds[0], &buf, 1) != 1) {
                err(1, "read");
            }
            if (recv(fd, &buf, 1, 0) == -1) {
                err(1, "recv");
            }
            return 0;
        }
        if (connect(fd, &unspec, sizeof(unspec)) == -1) {
            err(1, "connect");
        }
        if (write(pipe_fds[1], "x", 1) != 1) {
            err(1, "write");
        }
        int status;
        if (waitpid(child, &status, 0) == -1) {
            err(1, "waitpid");
        }
        return !WIFEXITED(status) || WEXITSTATUS(status) != 0;
    }
    if (connect(copy_fd(call, fd), &unspec, sizeof(unspec)) == -1) {
        err(1, "connect");
    }
    if (recv(fd, &buf, 1, 0) == -1) {
        err(1, "recv");
    }
    return 0;
}
