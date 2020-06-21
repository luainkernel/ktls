#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <linux/tls.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define TLS_LUA 99

int main() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("socket creation");
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr("103.118.42.79");
    sa.sin_port = htons(443);
    socklen_t socklen = sizeof(sa);
    if (connect(sock, (struct sockaddr*)&sa, socklen)) {
        perror("socket connect");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(sock, SOL_TCP, TCP_ULP, "tls", sizeof("tls")) == -1) {
        perror("tls init");
        exit(EXIT_FAILURE);
    }
    char* script="print('hello world')";
    if (setsockopt(sock, SOL_TLS, TLS_LUA, script, strlen(script) + 1) == -1) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    close(sock);
    return EXIT_SUCCESS;
}
