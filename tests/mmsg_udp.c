/* Send a UDP datagram to a port of 127.0.0.1 through sendmmsg, or receive one there through recvmmsg */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        errx(2, "Usage: %s sendmmsg|recvmmsg PORT", argv[0]);
    }
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        err(1, "socket");
    }
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(atoi(argv[2])),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    char buf[1] = "x";
    struct iovec iov = {.iov_base = buf, .iov_len = sizeof(buf)};
    struct mmsghdr msg = {
        .msg_hdr = {.msg_name = &addr, .msg_namelen = sizeof(addr), .msg_iov = &iov, .msg_iovlen = 1},
    };
    if (strcmp(argv[1], "sendmmsg") == 0) {
        if (sendmmsg(fd, &msg, 1, 0) != 1) {
            err(1, "sendmmsg");
        }
    } else if (strcmp(argv[1], "recvmmsg") == 0) {
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
            err(1, "bind");
        }
        struct timeval timeout = {.tv_sec = 10};
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1) {
            err(1, "setsockopt");
        }
        /* Receives the sender's address */
        if (recvmmsg(fd, &msg, 1, 0, NULL) != 1) {
            err(1, "recvmmsg");
        }
    } else {
        errx(2, "Unknown call %s", argv[1]);
    }
    return 0;
}
