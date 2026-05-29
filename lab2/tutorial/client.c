// client.c

#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s host port\n", argv[0]);
        return EXIT_FAILURE;
    }
    char *host = argv[1];
    int port = atoi(argv[2]);

    int cfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (cfd == -1) {
        perror("socket error");
        return EXIT_FAILURE;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(host); // 方式一
    // inet_pton(AF_INET, host, &addr.sin_addr.s_addr); // 方式二
    addr.sin_port = htons(port);

    int ret = connect(cfd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret == -1) {
        perror("connect error");
        return EXIT_FAILURE;
    }

    printf("[Client] The remote server is connected -> %s:%d\n", host, port);

    char buf[BUFSIZ];
    ssize_t size;
    for (int i = 0; i < 10; i++) {
        printf("================================\n");
	printf("           round %d\n", i);
        printf("================================\n");
        printf("[Client] Please enter content:\n");
        memset(buf, 0x00, sizeof(buf));
        if ((size = read(STDIN_FILENO, buf, sizeof(buf))) <= 0) {
            continue;
        }

        if ((size = send(cfd, buf, strlen(buf), 0)) == -1) { // 往内核的发送缓冲区中写入数据（由内核决定何时发送数据）
            perror("send() error");
            break;
        }

        memset(buf, 0x00, sizeof(buf));
        size = recv(cfd, buf, sizeof(buf), 0);
        if (size == -1) {
            perror("recv() error");
            break;
        }
        if (size == 0) { // zero indicates end of file
            printf("[Client] The server is shut down\n");
            break;
        }
        printf("[Client] Reply from server: %s\n", buf);
    }
    close(cfd);
    printf("[Client] The client is closed\n");
    return EXIT_SUCCESS;
}
