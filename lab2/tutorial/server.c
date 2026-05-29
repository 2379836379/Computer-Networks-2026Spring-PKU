// server.c

#include <arpa/inet.h>
#include <ctype.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s port\n", argv[0]);
        return EXIT_FAILURE;
    }
    int port = atoi(argv[1]);

    // 1、创建监听用的文件描述符
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd == -1) {
        perror("socket error");
        return EXIT_FAILURE;
    }

    // 2、将监听文件描述符和IP端口信息绑定
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY); // 表示任意可用IP
    addr.sin_port = htons(port);              // 转换成网络字节序（大端字节序）

    int ret = bind(lfd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret == -1) {
        perror("bind error");
        return EXIT_FAILURE;
    }

    // 3、监听文件描述符
    if ((ret = listen(lfd, 128)) == -1) {
        perror("listen error");
        return EXIT_FAILURE;
    }

    printf("[Server] [%d]The server is running at %s:%d\n", getpid(), inet_ntoa(addr.sin_addr), port);

    // 4、接受一个socket连接（从已连接队列中获取一个连接进行服务），并返回连接文件描述符。
    struct sockaddr_in clientAddr;                // 输入参数
    socklen_t clientAddrLen = sizeof(clientAddr); // 同时作为输入和输出参数
    int cfd = accept(lfd, (struct sockaddr *)&clientAddr, &clientAddrLen);
    if (cfd == -1) {
        perror("accept error");
        return EXIT_FAILURE;
    }
    char clientIP[16];
    memset(clientIP, 0x00, sizeof(clientIP));
    inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, sizeof(clientIP)); // 将网络字节序的整数IP转换成主机字节序的点分十进制字符串
    int clientPort = ntohs(clientAddr.sin_port);                          // 将网络字节序转换成主机字节序
    printf("[Server] Accept client: %s:%d\n", clientIP, clientPort);

    // 5、读写连接
    char buf[BUFSIZ];
    ssize_t size;
    for (;;) {
        // 初始化buffer
        memset(buf, 0x00, sizeof(buf));
        // 读取客户端信息
        size = recv(cfd, buf, sizeof(buf), 0);
        if (size == 0) { // zero indicates end of file
            printf("[Server] The client is closed\n");
            break;
        }
        if (size == -1) {
            perror("recv() error");
            continue;
        }
        printf("[Server] recv(): %s\n", buf);

        for (int i = 0; i < strlen(buf); i++) {
            buf[i] = toupper(buf[i]);
        }

        // 发送信息给客户端
        size = send(cfd, buf, strlen(buf), 0);
        if (size == -1) {
            perror("send() error");
            continue;
        }
        printf("[Server] send(): %s\n", buf);
    }

    close(lfd);
    close(cfd);

    printf("[Server] The server is shut down\n");
    return EXIT_SUCCESS;
}
