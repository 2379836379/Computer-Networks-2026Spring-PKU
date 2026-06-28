#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>

/*======================================================================
 *  实验七：在网计算  —— 学生模板
 *
 *  下面带有
 *      start of your code  ...  end of your code
 *  标记的函数体需要你来补全。其余部分（libpcap 收发、接收缓冲区、各类
 *  初始化、转发表/聚合器数据结构、辅助函数）已经给出，可直接使用：
 *
 *    辅助/IO（已给）：
 *      now_us()                                  取当前时间(微秒)
 *      build_frame(...)                          组装一帧 MTP 报文
 *      conn_send(cn, seq, ack_flag, op, buf, n)  在某连接上发一个分组
 *      conn_pop(cn, &msg)                        从某连接接收缓冲区取一个分组(非阻塞)
 *      router_forward(frame, len, dst_ip)        路由器按目的 IP 转发一帧
 *      dev_pop(&pk)                              路由器从共享缓冲区取一帧(非阻塞)
 *      broadcast_slot(seq)                       路由器把某聚合完成的 slot 广播给所有连接
 *
 *  完整正确实现见 ../answer/lab.c（仅供对照，请独立完成）。
 *====================================================================*/

/*======================================================================
 *  通用工具（已给）
 *====================================================================*/

uint64_t now_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + tv.tv_usec;
}

/* 标准 Internet 校验和（16 位反码求和） */
static uint16_t ip_checksum(const void *data, int len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t sum = 0;
    int i;
    for (i = 0; i + 1 < len; i += 2)
        sum += (uint16_t)((p[i] << 8) | p[i + 1]);
    if (len & 1)
        sum += (uint16_t)(p[len - 1] << 8);
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)(~sum & 0xffff);
}

/* 组装一帧 MTP 报文到 buf，返回总长度。已给。 */
static int build_frame(uint8_t *buf,
                       uint32_t src_ip, uint32_t dst_ip,
                       uint16_t conn_id, uint32_t seq,
                       uint8_t ack_flag, uint8_t op,
                       const void *payload, uint16_t plen) {
    eth_header_t *eth = (eth_header_t *)buf;
    memset(eth->dst_mac, 0xff, 6);
    memset(eth->src_mac, 0x00, 6);
    eth->ether_type = htons(ETH_TYPE_IP);

    ip_header_t *ip = (ip_header_t *)(buf + sizeof(eth_header_t));
    ip->version_ihl = 0x45;
    ip->tos = 0;
    ip->total_len = htons(sizeof(ip_header_t) + sizeof(mtp_header_t) + plen);
    ip->id = 0;
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IP_PROTO_MTP;
    ip->checksum = 0;
    ip->src_ip = src_ip;
    ip->dst_ip = dst_ip;
    ip->checksum = htons(ip_checksum(ip, sizeof(ip_header_t)));

    mtp_header_t *mtp = (mtp_header_t *)(buf + sizeof(eth_header_t) + sizeof(ip_header_t));
    mtp->conn_id = htons(conn_id);
    mtp->seq_num = htonl(seq);
    mtp->ack_flag = ack_flag;
    mtp->op = op;

    if (plen > 0 && payload)
        memcpy(buf + HDR_LEN, payload, plen);

    return (int)(HDR_LEN + plen);
}

/*======================================================================
 *  主机端
 *====================================================================*/
// 通信组，每个 rank 的静态配置信息，每一项包括：
//      - rank
//      - host_name
//      - host_iface
//      - router_iface
//      - host_ip
static config_entry_t g_cfg[MAX_GROUP_SIZE];
// 组数
static int            g_n = 0;
// 自身的rank
static int            g_rank = -1;
static uint32_t       g_my_ip = 0;
// 抓包/发包句柄
static pcap_t        *g_host_handle = NULL;
static pthread_mutex_t g_tx_lock = PTHREAD_MUTEX_INITIALIZER;
//当前主机已经初始化的连接”。每个 conn_t 里有：
//    - in_use：这一项是否有效
//    - conn_id：连接号
//    - local_ip / remote_ip：本端和对端 IP
//    - queue[RXQ_SIZE]：这条连接的接收缓冲区
//    - head / tail：环形队列读写位置
//    - lock：保护这条连接队列的锁
static conn_t         g_conns[MAX_CONNS];
static int            g_conn_count = 0;

/* 经 pcap 发送一帧（多线程发送加锁）。已给。 */
// 发到router对端
static void host_inject(uint8_t *frame, int len) {
    pthread_mutex_lock(&g_tx_lock);
    pcap_inject(g_host_handle, frame, len);
    pthread_mutex_unlock(&g_tx_lock);
}

/* 在某条连接上发送一个 MTP 分组。已给。 */
static void conn_send(conn_t *cn, uint32_t seq, uint8_t ack_flag, uint8_t op,
                      const void *payload, uint16_t plen) {
    uint8_t frame[HDR_LEN + PAYLOAD_LEN];
    int len = build_frame(frame, cn->local_ip, cn->remote_ip,
                          cn->conn_id, seq, ack_flag, op, payload, plen);
    host_inject(frame, len);
}

/* 后台接收线程：抓本机网卡进入的帧，按 conn_id 分发到对应连接的接收缓冲区。已给。 */
// 主机内部的分发
static void *host_rx_thread(void *arg) {
    (void)arg;
    struct pcap_pkthdr *hdr;
    const u_char *pkt;
    int rc;
    // 从网卡持续抓包
    while ((rc = pcap_next_ex(g_host_handle, &hdr, &pkt)) >= 0) {
        if (rc == 0) continue;
        // 过短
        if (hdr->caplen < HDR_LEN) continue;
        // 非ip
        const eth_header_t *eth = (const eth_header_t *)pkt;
        if (ntohs(eth->ether_type) != ETH_TYPE_IP) continue;
        // 非mtp
        const ip_header_t *ip = (const ip_header_t *)(pkt + sizeof(eth_header_t));
        if (ip->protocol != IP_PROTO_MTP) continue;
        // 自身
        if (ip->src_ip == g_my_ip) continue;

        int ip_ihl = (ip->version_ihl & 0x0f) * 4;
        const mtp_header_t *mtp =
            (const mtp_header_t *)(pkt + sizeof(eth_header_t) + ip_ihl);
        int plen = ntohs(ip->total_len) - ip_ihl - (int)sizeof(mtp_header_t);
        if (plen < 0) plen = 0;
        if (plen > PAYLOAD_LEN) plen = PAYLOAD_LEN;
        // 查找conn-id
        uint16_t conn_id = ntohs(mtp->conn_id);
        conn_t *cn = NULL;
        for (int i = 0; i < g_conn_count; i++)
            if (g_conns[i].in_use && g_conns[i].conn_id == conn_id) { cn = &g_conns[i]; break; }
        if (!cn) continue;
        // 放进该连接的接收队列
        pthread_mutex_lock(&cn->lock);
        int nh = (cn->head + 1) % RXQ_SIZE;
        // 如果队列满了丢弃
        if (nh != cn->tail) {
            rx_msg_t *m = &cn->queue[cn->head];
            m->op = mtp->op;
            m->ack_flag = mtp->ack_flag;
            m->seq_num = ntohl(mtp->seq_num);
            /* 只拷贝实际存在的载荷字节（数据分组为 PAYLOAD_LEN，ACK 为 0） */
            if (plen > 0)
                memcpy(m->payload, pkt + sizeof(eth_header_t) + ip_ihl + sizeof(mtp_header_t), plen);
            cn->head = nh;
        }
        pthread_mutex_unlock(&cn->lock);
    }
    return NULL;
}

/* 从连接缓冲区取一个分组（非阻塞）；返回 1 成功，0 空。已给。 */
static int conn_pop(conn_t *cn, rx_msg_t *out) {
    int ok = 0;
    pthread_mutex_lock(&cn->lock);
    if (cn->tail != cn->head) {
        *out = cn->queue[cn->tail];
        cn->tail = (cn->tail + 1) % RXQ_SIZE;
        ok = 1;
    }
    pthread_mutex_unlock(&cn->lock);
    return ok;
}

/* 已给。 */
void init_host(config_entry_t *cfgs, int n, const char *host_name) {
    // 通信组初始化
    g_n = n;
    memcpy(g_cfg, cfgs, sizeof(config_entry_t) * n);
    // 找到自己
    for (int i = 0; i < n; i++)
        if (strcmp(cfgs[i].host_name, host_name) == 0) {
            g_rank = cfgs[i].rank;
            g_my_ip = cfgs[i].host_ip;
            break;
        }
    if (g_rank < 0) {
        fprintf(stderr, "init_host: host %s not found in config\n", host_name);
        exit(1);
    }
    // 找到本机应该打开的网卡名
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *iface = NULL;
    for (int i = 0; i < n; i++)
        if (cfgs[i].rank == g_rank) iface = cfgs[i].host_iface;
    // 打开网卡
    g_host_handle = pcap_open_live(iface, DEV_BUF_SIZE, 1, 1, errbuf);
    if (!g_host_handle) {
        fprintf(stderr, "pcap_open_live(%s) failed: %s\n", iface, errbuf);
        exit(1);
    }
    // 只抓入方向数据
    pcap_setdirection(g_host_handle, PCAP_D_IN);
    // 启动后台收包线程
    pthread_t tid;
    pthread_create(&tid, NULL, host_rx_thread, NULL);
    printf("[host] %s rank=%d iface=%s ready\n", host_name, g_rank, iface);
    fflush(stdout);
}

/* 已给。 */
// 返回连接表的索引
int init_conn(uint16_t conn_id, uint32_t local_ip, uint32_t remote_ip) {
    // 检查连接表是否已满
    if (g_conn_count >= MAX_CONNS) return -1;
    conn_t *cn = &g_conns[g_conn_count];
    memset(cn, 0, sizeof(conn_t));
    cn->in_use = 1;
    cn->conn_id = conn_id;
    cn->local_ip = local_ip;
    cn->remote_ip = remote_ip;
    cn->head = cn->tail = 0;
    pthread_mutex_init(&cn->lock, NULL);
    return g_conn_count++;
}

/*------------- 可靠传输：发送端（待补全）-------------
 * 固定窗口 + 超时重传 + 独立 ACK（选择重传），初始序列号为 0。
 * 假设 size 是 PAYLOAD_LEN 的整数倍，故每个分组都是满载荷 PAYLOAD_LEN。 */
int m_send(int conn, const void *buf, uint32_t size, uint8_t op) {
    if (conn < 0 || conn >= g_conn_count) return -1;
    conn_t *cn = &g_conns[conn];
    // 分组
    uint32_t npkts = size / PAYLOAD_LEN;
    if (npkts == 0) return 0;

    /***********************
     * start of your code
     *
     * 提示（可用 conn_pop / conn_send / now_us）：
     *  1. 申请数组：acked[npkts]（是否已确认）、sent_at[npkts]（上次发送时间）；base=0
     *  2. while (base < npkts):
     *     a. 收 ACK：while conn_pop(cn,&m): 若 m.ack_flag==1 且 m.seq_num<npkts -> acked[seq]=1
     *     b. 滑动后沿：while base<npkts 且 acked[base] -> base++
     *     c. 发送窗口 [base, min(base+WINDOW, npkts)) 内的分组：
     *        若未 acked 且 (sent_at[s]==0 或 now-sent_at[s]>=RTO_US):
     *           conn_send(cn, s, 0, op, (uint8_t*)buf + s*PAYLOAD_LEN, PAYLOAD_LEN)
     *           sent_at[s] = now
     *     d. usleep(200) 避免空转
     *  3. 释放数组
     **********************/
    // 确认进度
    uint8_t *acked = calloc(npkts, sizeof(uint8_t));
    // 上次发送时间
    uint64_t *sent_at = calloc(npkts, sizeof(uint64_t));
    // 发送窗口左边界
    uint32_t base = 0;

    if (!acked || !sent_at) {
        free(acked);
        free(sent_at);
        return -1;
    }

    while (base < npkts) {
        rx_msg_t m;
        // 从这条连接的接收队列里取一个消息
        while (conn_pop(cn, &m)) {
            if (m.ack_flag == 1 && m.seq_num < npkts)
                acked[m.seq_num] = 1;
        }
        // 推进窗口
        while (base < npkts && acked[base]) base++;
        // 新窗口
        uint64_t now = now_us();
        uint32_t end = base + WINDOW;
        if (end > npkts) end = npkts;
        for (uint32_t s = base; s < end; s++) {
            if (!acked[s] && (sent_at[s] == 0 || now - sent_at[s] >= RTO_US)) {
                conn_send(cn, s, 0, op,
                          (const uint8_t *)buf + s * PAYLOAD_LEN, PAYLOAD_LEN);
                sent_at[s] = now;
            }
        }
        if (base < npkts) usleep(200);
    }

    free(acked);
    free(sent_at);
    /***********************
     * end of your code
     **********************/
    return (int)size;
}

/*------------- 可靠传输：接收端（待补全）-------------
 * 假设 size 是 PAYLOAD_LEN 的整数倍，故每个数据分组都是满载荷 PAYLOAD_LEN。 */
int m_recv(int conn, void *buf, uint32_t size, uint8_t op) {
    if (conn < 0 || conn >= g_conn_count) return -1;
    conn_t *cn = &g_conns[conn];

    uint32_t npkts = size / PAYLOAD_LEN;
    if (npkts == 0) return 0;

    /***********************
     * start of your code
     *
     * 提示（可用 conn_pop / conn_send / now_us）：
     *  1. 申请 recvd[npkts]；got=0；complete_at=0
     *  2. while (1):
     *     a. while conn_pop(cn,&m):
     *          只处理数据分组(m.ack_flag==0) 且 m.seq_num<npkts
     *          若该分组未收过：把 m.payload 的 PAYLOAD_LEN 字节拷到 buf 的 seq*PAYLOAD_LEN 偏移；
     *          recvd[seq]=1；got++
     *          无论是否重复，都 conn_send(cn, m.seq_num, 1, op, NULL, 0) 回 ACK
     *     b. 若 got>=npkts：首次记录 complete_at=now；
     *          否则若 now-complete_at>500000(0.5s) 则 break（其间继续补发 ACK）
     *     c. 若本轮没收到任何分组，usleep(200)
     *  3. 释放数组
     **********************/
    // 分组是否已经收过
    uint8_t *recvd = calloc(npkts, sizeof(uint8_t));
    // 收到数量
    uint32_t got = 0;
    uint64_t complete_at = 0;

    if (!recvd) return -1;

    while (1) {
        int saw_pkt = 0;
        rx_msg_t m;
        while (conn_pop(cn, &m)) {
            saw_pkt = 1;
            if (m.ack_flag == 0 && m.seq_num < npkts) {
                if (!recvd[m.seq_num]) {
                    memcpy((uint8_t *)buf + m.seq_num * PAYLOAD_LEN,
                           m.payload, PAYLOAD_LEN);
                    recvd[m.seq_num] = 1;
                    got++;
                }
                conn_send(cn, m.seq_num, 1, op, NULL, 0);
            }
        }

        uint64_t now = now_us();
        if (got >= npkts) {
            if (complete_at == 0) {
                complete_at = now;
            } else if (now - complete_at > 500000) {
                break;
            }
        }

        if (!saw_pkt) usleep(200);
    }

    free(recvd);
    /***********************
     * end of your code
     **********************/
    return (int)size;
}

/*------------- 环形集合通信 ------------- */
typedef struct {
    int      conn;
    char    *buf;
    uint32_t size;
    uint8_t  op;
} recv_args_t;

/* 接收线程入口（已给） */
static void *recv_worker(void *a) {
    recv_args_t *ra = (recv_args_t *)a;
    m_recv(ra->conn, ra->buf, ra->size, ra->op);
    return NULL;
}

/* 环形集合通信（待补全）：向后继发 src，从前驱收到 dst。 */
static int ring_collective(char *src, char *dst, uint32_t size, uint8_t op) {
    int N = g_n, j = g_rank;
    uint32_t succ_ip = g_cfg[(j + 1) % N].host_ip;
    uint32_t pred_ip = g_cfg[(j - 1 + N) % N].host_ip;

    /***********************
     * start of your code
     *
     * 提示（可用 init_conn / m_send / m_recv / recv_worker）：
     *  1. 后继连接 succ_conn = init_conn(本机 rank j, g_my_ip, succ_ip)  —— 用于发送
     *  2. 前驱连接 pred_conn = init_conn((j-1+N)%N, g_my_ip, pred_ip)    —— 用于接收
     *  3. 用 pthread 起一个线程跑 recv_worker（传 {pred_conn, dst, size, op}），
     *     当前线程调用 m_send(succ_conn, src, size, op)
     *  4. pthread_join 等接收线程结束
     **********************/
    /*
    因为这里要“同时发和收”。
    如果不用线程，顺序执行会有问题：
    先 m_send() 再 m_recv()，大家都可能先发再收，容易互相等待 ACK，卡住
    先 m_recv() 再 m_send()，大家都先等着收，也不行
    所以正确做法是并发：一个线程负责收，主线程负责发    
    */
    
    int succ_conn = init_conn((uint16_t)j, g_my_ip, succ_ip);
    int pred_conn = init_conn((uint16_t)((j - 1 + N) % N), g_my_ip, pred_ip);
    pthread_t tid;
    recv_args_t ra = {
        .conn = pred_conn,
        .buf = dst,
        .size = size,
        .op = op,
    };

    if (succ_conn < 0 || pred_conn < 0) return -1;
    if (pthread_create(&tid, NULL, recv_worker, &ra) != 0) return -1;

    int send_ret = m_send(succ_conn, src, size, op);
    pthread_join(tid, NULL);
    return send_ret < 0 ? send_ret : 0;
    /***********************
     * end of your code
     **********************/
}

int shift(int group_id, char *src_addr, char *dst_addr, uint32_t size) {
    (void)group_id;
    return ring_collective(src_addr, dst_addr, size, OP_TRANSMISSION);
}

int allreduce(int group_id, char *src_addr, char *dst_addr, uint32_t size) {
    (void)group_id;
    return ring_collective(src_addr, dst_addr, size, OP_ALLREDUCE);
}

/*======================================================================
 *  路由器端
 *====================================================================*/
// 端口表
static net_device_t  g_devs[MAX_GROUP_SIZE];
static int           g_dev_count = 0;
// buf
static dev_buffer_t  g_dev_buf;
// 转发表
static route_entry_t g_route[MAX_GROUP_SIZE];
static int           g_route_count = 0;
// 连接表
static conn_ctx_t    g_conn_ctx[MAX_GROUP_SIZE];
static int           g_group_n = 0;
// 聚合器
static agtr_t       *g_agtr = NULL;

/* 路由器某端口抓包线程（已给） */
static void *dev_capture_thread(void *arg) {
    net_device_t *dev = (net_device_t *)arg;
    struct pcap_pkthdr *hdr;
    const u_char *pkt;
    int rc;
    while ((rc = pcap_next_ex(dev->handle, &hdr, &pkt)) >= 0) {
        if (rc == 0) continue;
        pthread_mutex_lock(&g_dev_buf.lock);
        int nh = (g_dev_buf.head + 1) % DEV_RING_SIZE;
        if (nh != g_dev_buf.tail) {
            dev_pkt_t *e = &g_dev_buf.packets[g_dev_buf.head];
            e->device = dev;
            e->len = hdr->caplen > DEV_BUF_SIZE ? DEV_BUF_SIZE : hdr->caplen;
            memcpy(e->data, pkt, e->len);
            g_dev_buf.head = nh;
        } else {
            fprintf(stderr, "[router] packet buffer full, drop\n");
        }
        pthread_mutex_unlock(&g_dev_buf.lock);
    }
    return NULL;
}

/* 按目的 IP 查转发表，从对应端口注入该帧。已给。 */
static void router_forward(const uint8_t *frame, int len, uint32_t dst_ip) {
    const char *out_port = NULL;
    for (int i = 0; i < g_route_count; i++)
        if (g_route[i].dst_ip == dst_ip) { out_port = g_route[i].out_port; break; }
    if (!out_port) return;
    for (int i = 0; i < g_dev_count; i++)
        if (strcmp(g_devs[i].name, out_port) == 0) {
            pcap_inject(g_devs[i].handle, frame, len);
            return;
        }
}

/* 已给。 */
void init_router(config_entry_t *cfgs, int n) {
    // 初始化buf
    char errbuf[PCAP_ERRBUF_SIZE];
    memset(&g_dev_buf, 0, sizeof(g_dev_buf));
    pthread_mutex_init(&g_dev_buf.lock, NULL);

    for (int i = 0; i < n && g_dev_count < MAX_GROUP_SIZE; i++) {
        const char *port = cfgs[i].router_iface;
        int dup = 0;
        for (int k = 0; k < g_dev_count; k++)
            if (strcmp(g_devs[k].name, port) == 0) dup = 1;
        if (dup) continue;

        net_device_t *dev = &g_devs[g_dev_count];
        strncpy(dev->name, port, sizeof(dev->name) - 1);
        dev->index = g_dev_count;
        dev->handle = pcap_open_live(port, DEV_BUF_SIZE, 1, 1, errbuf);
        if (!dev->handle) {
            fprintf(stderr, "pcap_open_live(%s) failed: %s\n", port, errbuf);
            continue;
        }
        pcap_setdirection(dev->handle, PCAP_D_IN);
        // 为每个端口启动一个抓包线程
        pthread_create(&dev->thread_id, NULL, dev_capture_thread, dev);
        g_dev_count++;
    }
    // 构建转发表
    for (int i = 0; i < n; i++) {
        g_route[g_route_count].dst_ip = cfgs[i].host_ip;
        strncpy(g_route[g_route_count].out_port, cfgs[i].router_iface,
                sizeof(g_route[g_route_count].out_port) - 1);
        g_route_count++;
    }
    //  记录通信组大小
    g_group_n = n;
    for (int k = 0; k < n; k++) {
        g_conn_ctx[k].conn_id = (uint16_t)k;
        g_conn_ctx[k].src_ip  = cfgs[k].host_ip;
        g_conn_ctx[k].dst_ip  = cfgs[(k + 1) % n].host_ip;
        g_conn_ctx[k].rank    = k;
    }
    // 聚合器
    g_agtr = calloc(AGTR_ARRAY_SIZE, sizeof(agtr_t));   /* calloc 清零，初始各 slot 即干净 */
    if (!g_agtr) { fprintf(stderr, "agtr alloc failed\n"); exit(1); }
    printf("[router] opened %d ports, group_n=%d, agtr_slots=%d, window=%d\n",
           g_dev_count, g_group_n, AGTR_ARRAY_SIZE, WINDOW);
    fflush(stdout);
}

/* 从共享缓冲区取一帧（非阻塞）。已给。 */
static int dev_pop(dev_pkt_t *out) {
    int ok = 0;
    pthread_mutex_lock(&g_dev_buf.lock);
    if (g_dev_buf.tail != g_dev_buf.head) {
        *out = g_dev_buf.packets[g_dev_buf.tail];
        g_dev_buf.tail = (g_dev_buf.tail + 1) % DEV_RING_SIZE;
        ok = 1;
    }
    pthread_mutex_unlock(&g_dev_buf.lock);
    return ok;
}

/* 把某个已聚合完成的 slot 广播给所有连接（取模寻址）。已给。 */
static void broadcast_slot(uint32_t seq) {
    agtr_t *a = &g_agtr[seq % AGTR_ARRAY_SIZE];
    uint8_t frame[HDR_LEN + PAYLOAD_LEN];
    for (int k = 0; k < g_group_n; k++) {
        conn_ctx_t *cc = &g_conn_ctx[k];
        int len = build_frame(frame, cc->src_ip, cc->dst_ip,
                              (uint16_t)k, seq, 0, OP_ALLREDUCE,
                              a->payload, PAYLOAD_LEN);
        router_forward(frame, len, cc->dst_ip);
    }
}

/* 聚合器复用：清空“一个窗口外”的 slot（gen 仅用于定位物理 slot）。已给。 */
static void clear_slot(uint32_t gen) {
    agtr_t *a = &g_agtr[gen % AGTR_ARRAY_SIZE];
    a->bitmap = 0;
    memset(a->payload, 0, sizeof(a->payload));
}

/*------------- 普通路由器：只按目的 IP 转发（待补全）------------- */
void Router(void) {
    printf("[router] running as ROUTER (forward only)\n");
    fflush(stdout);
    while (1) {
        dev_pkt_t pk;
        if (!dev_pop(&pk)) { usleep(200); continue; }

        /***********************
         * start of your code
         *
         * 提示（可用 router_forward）：
         *  1. 解析 eth：若 ether_type 不是 IP 则跳过
         *  2. 解析 ip：若 protocol 不是 IP_PROTO_MTP 则跳过
         *  3. router_forward(pk.data, pk.len, ip->dst_ip) 按目的 IP 转发
         **********************/
        eth_header_t *eth = (eth_header_t *)pk.data;
        if (ntohs(eth->ether_type) != ETH_TYPE_IP) continue;

        ip_header_t *ip = (ip_header_t *)(pk.data + sizeof(eth_header_t));
        if (ip->protocol != IP_PROTO_MTP) continue;

        router_forward(pk.data, pk.len, ip->dst_ip);
        /***********************
         * end of your code
         **********************/
    }
}

/*------------- 在网计算路由器：转发 + 聚合（待补全）------------- */
void INC(void) {
    printf("[router] running as INC (forward + aggregate)\n");
    fflush(stdout);
    uint32_t full_mask = (g_group_n >= 32) ? 0xffffffffu : ((1u << g_group_n) - 1);

    while (1) {
        dev_pkt_t pk;
        if (!dev_pop(&pk)) { usleep(200); continue; }

        /* 解析（已给） */
        eth_header_t *eth = (eth_header_t *)pk.data;
        if (ntohs(eth->ether_type) != ETH_TYPE_IP) continue;
        ip_header_t *ip = (ip_header_t *)(pk.data + sizeof(eth_header_t));
        if (ip->protocol != IP_PROTO_MTP) continue;

        int ip_ihl = (ip->version_ihl & 0x0f) * 4;
        mtp_header_t *mtp = (mtp_header_t *)(pk.data + sizeof(eth_header_t) + ip_ihl);
        /* 载荷指针（数据分组载荷恒为 PAYLOAD_LEN）： */
        int32_t *payload = (int32_t *)(pk.data + sizeof(eth_header_t) + ip_ihl + sizeof(mtp_header_t));

        /***********************
         * start of your code
         *
         * 提示（可用 router_forward / broadcast_slot / clear_slot；聚合器为全局 g_agtr[]，
         *       取模寻址 g_agtr[seq % AGTR_ARRAY_SIZE]）：
         *  1. 若 mtp->ack_flag==1 或 mtp->op != OP_ALLREDUCE：
         *        router_forward(pk.data, pk.len, ip->dst_ip)；continue   // ACK/非聚合数据直接转发
         *  2. 取 k = ntohs(mtp->conn_id)（=贡献者 rank）、seq = ntohl(mtp->seq_num)；
         *     边界检查 0<=k<g_group_n。 a = &g_agtr[seq % AGTR_ARRAY_SIZE]; bit = 1u<<k
         *  3. 叠加：若 (a->bitmap & bit)==0（本 rank 尚未叠加），把 payload[] 的 PAYLOAD_LEN/4 个 int32
         *     累加进 a->payload，并 a->bitmap|=bit。（已叠加则跳过，避免重复累加；载荷长度固定无需记录）
         *  4. 判完成：若 a->bitmap != full_mask -> 丢弃（什么都不做）；
         *     若 a->bitmap == full_mask -> clear_slot(seq + WINDOW); broadcast_slot(seq)
         *     （重传命中已满的 slot 时，第 3 步不会重复叠加，这里会重新广播 -> 幂等恢复）
         **********************/
        if (mtp->ack_flag == 1 || mtp->op != OP_ALLREDUCE) {
            router_forward(pk.data, pk.len, ip->dst_ip);
            continue;
        }

        uint16_t k = ntohs(mtp->conn_id);
        uint32_t seq = ntohl(mtp->seq_num);
        if (k >= (uint16_t)g_group_n) continue;

        agtr_t *a = &g_agtr[seq % AGTR_ARRAY_SIZE];
        uint32_t bit = 1u << k;

        if ((a->bitmap & bit) == 0) {
            for (int i = 0; i < PAYLOAD_LEN / (int)sizeof(int32_t); i++)
                a->payload[i] += payload[i];
            a->bitmap |= bit;
        }

        if (a->bitmap != full_mask) continue;

        clear_slot(seq + WINDOW);
        broadcast_slot(seq);
        /***********************
         * end of your code
         **********************/
    }
}
