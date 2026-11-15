/* Wait for incoming traffic on a port of 127.0.0.1 through a call naming no peer, failing after 5 seconds
 * without any */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <err.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        errx(2, "Usage: %s CALL PORT", argv[0]);
    }
    const char *call = argv[1];
    int stream = strncmp(call, "accept", strlen("accept")) == 0;
    int fd = socket(AF_INET, stream ? SOCK_STREAM : SOCK_DGRAM, 0);
    if (fd == -1) {
        err(1, "socket");
    }
    /* Binds the port of a previous run whose connection is still closing */
    int reuse = 1;
    if (stream && setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == -1) {
        err(1, "setsockopt");
    }
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(atoi(argv[2])),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        err(1, "bind");
    }
    if (stream && listen(fd, 1) == -1) {
        err(1, "listen");
    }
    /* Terminates the process */
    alarm(5);
    char buf[16];
    struct iovec iov = {.iov_base = buf, .iov_len = sizeof(buf)};
    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1};
    struct mmsghdr mmsg = {.msg_hdr = msg};
    int pipe_fds[2];
    if (pipe(pipe_fds) == -1) {
        err(1, "pipe");
    }
    ssize_t ret;
    if (strcmp(call, "recvfrom") == 0) {
        ret = recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);
    } else if (strcmp(call, "recvfrom-empty-addr") == 0) {
        /* An address buffer of zero length */
        struct sockaddr_in src;
        socklen_t src_len = 0;
        ret = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&src, &src_len);
    } else if (strcmp(call, "recvfrom-short-addr") == 0) {
        /* An address buffer too short for the IP address */
        struct sockaddr_in src;
        socklen_t src_len = sizeof(src.sin_family);
        ret = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&src, &src_len);
    } else if (strcmp(call, "recvmsg") == 0) {
        ret = recvmsg(fd, &msg, 0);
    } else if (strcmp(call, "recvmmsg") == 0) {
        ret = recvmmsg(fd, &mmsg, 1, 0, NULL);
    } else if (strcmp(call, "read") == 0) {
        ret = read(fd, buf, sizeof(buf));
    } else if (strcmp(call, "readv") == 0) {
        ret = readv(fd, &iov, 1);
    } else if (strcmp(call, "preadv2") == 0) {
        /* The current position, the only offset a socket accepts */
        ret = preadv2(fd, &iov, 1, -1, 0);
    } else if (strcmp(call, "splice") == 0) {
        ret = splice(fd, NULL, pipe_fds[1], NULL, sizeof(buf), 0);
    } else if (strcmp(call, "sendfile") == 0) {
        /* A pipe, the only output of a socket input */
        ret = sendfile(pipe_fds[1], fd, NULL, sizeof(buf));
    } else if (strcmp(call, "accept") == 0) {
        ret = accept(fd, NULL, NULL);
    } else if (strcmp(call, "accept4") == 0) {
        ret = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
    } else {
        errx(2, "Unknown call %s", call);
    }
    if (ret == -1) {
        err(1, "%s", call);
    }
    return 0;
}
