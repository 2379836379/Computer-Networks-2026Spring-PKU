#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

/*======================================================================
 *  实验七 入口程序（数据驱动测试版）
 *
 *  用法：./inc <name> <config> <mode>
 *    name   : router 或 host1/host2/...
 *    config : ranks.cfg
 *    mode   : route | transport | shift | allreduce
 *
 *  数据流（与测试脚本约定）：
 *    - 发送内容来自文件 input-<rank>.data（每行一个 int32）；
 *    - 收到的结果写入文件 output-<rank>.data；
 *    - 由测试脚本按各原语的语义比对文件内容判定成败。
 *
 *  config 每行： rank,host_name,host_iface,router_iface,host_ip
 *====================================================================*/

#define MSG_SIZE   (1024 * 1024)    /* transport/shift/allreduce 的消息大小 */
#define ROUTE_SIZE PAYLOAD_LEN      /* route 单分组测试的大小 */

static config_entry_t cfgs[MAX_GROUP_SIZE];
static int n = 0;

static int load_config(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) { perror("open config"); return -1; }
    char line[256];
    while (fgets(line, sizeof(line), fp) && n < MAX_GROUP_SIZE) {
        if (line[0] == '#' || line[0] == '\n') continue;
        config_entry_t *e = &cfgs[n];
        char ip[32];
        if (sscanf(line, "%d,%31[^,],%31[^,],%31[^,],%31s",
                   &e->rank, e->host_name, e->host_iface, e->router_iface, ip) != 5) {
            fprintf(stderr, "bad config line: %s", line);
            continue;
        }
        if (inet_pton(AF_INET, ip, &e->host_ip) != 1) {
            fprintf(stderr, "bad ip: %s\n", ip);
            continue;
        }
        n++;
    }
    fclose(fp);
    return n;
}

static uint32_t ip_of_rank(int r) {
    for (int i = 0; i < n; i++) if (cfgs[i].rank == r) return cfgs[i].host_ip;
    return 0;
}
static int my_rank_of(const char *name) {
    for (int i = 0; i < n; i++) if (strcmp(cfgs[i].host_name, name) == 0) return cfgs[i].rank;
    return -1;
}

/* 从 input-<rank>.data 读取 int32 到 buf（最多 maxints 个，不足补 0） */
static void read_input(int rank, int32_t *buf, uint32_t maxints) {
    char fn[64];
    snprintf(fn, sizeof(fn), "input-%d.data", rank);
    FILE *fp = fopen(fn, "r");
    if (!fp) { perror(fn); exit(1); }
    uint32_t c = 0; long v;
    while (c < maxints && fscanf(fp, "%ld", &v) == 1) buf[c++] = (int32_t)v;
    for (; c < maxints; c++) buf[c] = 0;
    fclose(fp);
}

/* 把 int32 缓冲区写入 output-<rank>.data（每行一个整数） */
static void write_output(int rank, const int32_t *buf, uint32_t nints) {
    char fn[64];
    snprintf(fn, sizeof(fn), "output-%d.data", rank);
    FILE *fp = fopen(fn, "w");
    if (!fp) { perror(fn); return; }
    for (uint32_t i = 0; i < nints; i++) fprintf(fp, "%d\n", buf[i]);
    fclose(fp);
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <name> <config> <mode>\n", argv[0]);
        fprintf(stderr, "  mode: route | transport | shift | allreduce\n");
        return 1;
    }
    const char *name = argv[1];
    const char *cfg  = argv[2];
    const char *mode = argv[3];

    if (load_config(cfg) <= 0) { fprintf(stderr, "no config\n"); return 1; }

    /*============ 路由器 ============*/
    if (strcmp(name, "router") == 0) {
        init_router(cfgs, n);
        if (strcmp(mode, "allreduce") == 0) INC();
        else                                Router();
        return 0;
    }

    /*============ 主机 ============*/
    init_host(cfgs, n, name);
    int rank = my_rank_of(name);

    if (strcmp(mode, "route") == 0 || strcmp(mode, "transport") == 0) {
        uint32_t sz = (strcmp(mode, "route") == 0) ? ROUTE_SIZE : MSG_SIZE;
        uint32_t nints = sz / sizeof(int32_t);
        /* rank 0 -> rank N-1 的点对点收发 */
        if (rank == 0) {
            int32_t *src = malloc(sz);
            read_input(0, src, nints);
            int c = init_conn(0, ip_of_rank(0), ip_of_rank(n - 1));
            m_send(c, src, sz, OP_TRANSMISSION);
            printf("[host] rank0 %s send done\n", mode); fflush(stdout);
            free(src);
        } else if (rank == n - 1) {
            int32_t *dst = calloc(1, sz);
            int c = init_conn(0, ip_of_rank(n - 1), ip_of_rank(0));
            m_recv(c, dst, sz, OP_TRANSMISSION);
            write_output(rank, dst, nints);
            printf("[host] rank%d %s recv done\n", rank, mode); fflush(stdout);
            free(dst);
        } else {
            sleep(2);   /* 不参与 */
        }
    }
    else if (strcmp(mode, "shift") == 0 || strcmp(mode, "allreduce") == 0) {
        uint32_t nints = MSG_SIZE / sizeof(int32_t);
        int32_t *src = malloc(MSG_SIZE);
        int32_t *dst = calloc(1, MSG_SIZE);
        read_input(rank, src, nints);
        if (strcmp(mode, "shift") == 0) shift(0, (char *)src, (char *)dst, MSG_SIZE);
        else                            allreduce(0, (char *)src, (char *)dst, MSG_SIZE);
        write_output(rank, dst, nints);
        printf("[host] rank%d %s done\n", rank, mode); fflush(stdout);
        free(src); free(dst);
    }
    else {
        fprintf(stderr, "unknown mode: %s\n", mode);
        return 1;
    }
    return 0;
}
