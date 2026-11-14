/* Send UDP datagrams to a port of 127.0.0.1 through sendmmsg, or receive them there through recvmmsg after sending a
 * datagram to 127.0.0.4 on that port */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>

int main(int argc, char *argv[]) {
    if (argc != 4) {
        errx(2, "Usage: %s sendmmsg|recvmmsg PORT COUNT", argv[0]);
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
    unsigned int count = atoi(argv[3]);
    char buf[1] = "x";
    struct iovec iov = {.iov_base = buf, .iov_len = sizeof(buf)};
    /* A name per message, each receiving the address of its sender */
    struct sockaddr_in *names = calloc(count, sizeof(*names));
    struct mmsghdr *msgs = calloc(count, sizeof(*msgs));
    if (names == NULL || msgs == NULL) {
        err(1, "calloc");
    }
    for (unsigned int i = 0; i < count; i++) {
        names[i] = addr;
        msgs[i].msg_hdr = (struct msghdr){
            .msg_name = &names[i], .msg_namelen = sizeof(names[i]), .msg_iov = &iov, .msg_iovlen = 1};
    }
    if (strcmp(argv[1], "sendmmsg") == 0) {
        /* The kernel sends at most UIO_MAXIOV messages per call */
        if (sendmmsg(fd, msgs, count, 0) != (count < UIO_MAXIOV ? count : UIO_MAXIOV)) {
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
        /* Signals the socket is bound */
        struct sockaddr_in ready_addr = addr;
        ready_addr.sin_addr.s_addr = htonl(0x7f000004);
        if (sendto(fd, buf, sizeof(buf), 0, (struct sockaddr *)&ready_addr, sizeof(ready_addr)) == -1) {
            err(1, "sendto");
        }
        /* Receives the senders' addresses */
        if (recvmmsg(fd, msgs, count, 0, NULL) != count) {
            err(1, "recvmmsg");
        }
    } else {
        errx(2, "Unknown call %s", argv[1]);
    }
    return 0;
}
