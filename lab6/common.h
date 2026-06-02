#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <pcap.h>
#include <pthread.h>
#include <arpa/inet.h>

/************************************************************************
 *  实验七：在网计算（In-Network Computing）
 *
 *  与之前基于 socket 的版本不同，本实验完全基于 libpcap 收发原始帧：
 *  我们保留以太网首部和 IP 首部，但在 IP 之上自己实现一个极简的传输
 *  协议 MTP（Mini Transport Protocol）。这样应用层可以严格控制每一个
 *  分组（packet）的边界与载荷长度，从而让交换机/路由器中的“聚合单元”
 *  与分组载荷长度严格一致 —— 这是在网计算正确性的前提。
 ************************************************************************/

/*================== 系统参数 ==================*/

#define PAYLOAD_LEN   1024        /* 每个数据分组的固定载荷长度（字节）   */
#define IP_PROTO_MTP  253         /* IP 上层协议号：253/254 为 RFC3692    */
                                  /* 实验保留值，内核没有对应处理逻辑     */
#define ETH_TYPE_IP   0x0800

#define MAX_GROUP_SIZE 8          /* 通信组最大成员数                    */
#define MAX_CONNS      8          /* 单个主机最多维护的连接数            */

/* 固定滑动窗口大小（单位：分组），本实验不做拥塞控制 */
#define WINDOW        32
/* 固定超时重传时间（微秒） */
#define RTO_US        50000       /* 50 ms */

/* 聚合器数组长度（单位：slot）。聚合器需要循环复用，必须 >= 2*WINDOW：
 * 序列号 s 用 slot (s % AGTR_ARRAY_SIZE)，相邻两“代”相差一个窗口落在不同 slot，
 * 一“代”聚合成功后清空“一个窗口外”的 slot，为后续序列号腾出位置。
 * 取最小值 2*WINDOW，可让默认 1MB 消息（>>该数组）充分触发复用。 */
#define AGTR_ARRAY_SIZE (2 * WINDOW)

/*================== Operation 取值 ==================*/

#define OP_TRANSMISSION 1         /* 普通可靠传输（路由/传输/Shift）     */
#define OP_ALLREDUCE    2         /* AllReduce，触发交换机内聚合         */

/*================== 协议首部 ==================*/

/* 以太网首部 */
typedef struct {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ether_type;
} __attribute__((packed)) eth_header_t;

/* IP 首部（IHL=5，无选项） */
typedef struct {
    uint8_t  version_ihl;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;          /* 网络序 */
    uint32_t dst_ip;          /* 网络序 */
} __attribute__((packed)) ip_header_t;

/* 极简传输协议首部 MTP —— 仅 4 个字段 */
typedef struct {
    uint16_t conn_id;         /* 连接号                               */
    uint32_t seq_num;         /* 序列号（按分组计，从 0 开始）        */
    uint8_t  ack_flag;        /* 0 = 数据分组，1 = ACK 分组           */
    uint8_t  op;              /* Operation：OP_TRANSMISSION/ALLREDUCE */
} __attribute__((packed)) mtp_header_t;

#define HDR_LEN (sizeof(eth_header_t) + sizeof(ip_header_t) + sizeof(mtp_header_t))

/*================== 主机端配置 ==================*/

/* 一行配置描述一个 rank（环中的一个成员） */
typedef struct {
    int      rank;                 /* 环中的编号，0..N-1            */
    char     host_name[32];        /* 容器/命名空间名，如 host1     */
    char     host_iface[32];       /* 主机网卡名，如 host1-eth0     */
    char     router_iface[32];     /* 路由器侧对端网卡名            */
    uint32_t host_ip;              /* 主机 IP（网络序）             */
} config_entry_t;

/*================== 主机端：连接 + 接收缓冲区 ==================*/

/* 主机接收线程抓到原始包后，会把有用信息整理成一个 rx_msg_t
 * 解析后的一个到达分组（放入连接的接收缓冲区）。
 * 数据分组载荷固定为 PAYLOAD_LEN（假设消息是整数倍），故无需记录载荷长度。 */
typedef struct {
    uint8_t  op;                    //这个包属于普通传输还是 allreduce
    uint8_t  ack_flag;              // 数据包还是 ACK
    uint32_t seq_num;               // 序号
    uint8_t  payload[PAYLOAD_LEN];  // 载荷固定 1024 字节
} rx_msg_t;

/* 每条连接维护一个接收缓冲区（环形队列）。
 * 后台接收线程按 conn_id 把分组分发到对应连接的缓冲区。 */
#define RXQ_SIZE 4096
typedef struct {
    int             in_use;         // 这条连接是否正在使用
    uint16_t        conn_id;       /* 连接号                        */
    uint32_t        local_ip;      /* 本端 IP（网络序）             */
    uint32_t        remote_ip;     /* 对端 IP（网络序）             */

    rx_msg_t        queue[RXQ_SIZE];// 连接的接收缓冲区
    volatile int    head;          /* 由接收线程写入    队列写指针            */
    volatile int    tail;          /* 由 m_send / m_recv 读取  队列读指针     */
    pthread_mutex_t lock;           // 互斥锁
} conn_t;

/*================== 路由器/交换机端 ==================*/

/* 网络设备（一个端口） */
typedef struct {
    char      name[32];
    pcap_t   *handle;   // pcap 句柄，用它抓包和注入数据
    pthread_t thread_id;
    int       index;
} net_device_t;

/* 路由器抓到的一帧 */
#define DEV_BUF_SIZE 2048
typedef struct {
    net_device_t *device;           // 这帧是从哪个端口进来的
    uint8_t       data[DEV_BUF_SIZE];
    uint32_t      len;
} dev_pkt_t;

/* 路由器的分组缓冲区（所有端口共享一个环形队列） */
#define DEV_RING_SIZE 16384
typedef struct {
    dev_pkt_t       packets[DEV_RING_SIZE];
    volatile int    head;
    volatile int    tail;
    pthread_mutex_t lock;
} dev_buffer_t;

/* 转发表项：目的 IP -> 出端口 */
typedef struct {
    uint32_t dst_ip;               /* 网络序 */
    char     out_port[32];
} route_entry_t;

/* 连接上下文（按 conn_id 索引）：描述环中一条连接 k: host[k]->host[k+1] */
typedef struct {
    uint16_t conn_id;
    uint32_t src_ip;               /* host[k] */
    uint32_t dst_ip;               /* host[k+1] */
    int      rank;                 /* = k，用于聚合位图的比特位 */
} conn_ctx_t;

/* 聚合器：一个 slot 聚合所有 rank 在同一序列号上的载荷。
 * 循环复用时，靠“聚合集齐即清空一个窗口外的 slot”+“旧序列号已滑出窗口不会再发”
 * 来保证 slot 始终只服务当前序列号，因此无需保存序列号标签来甄别迟到的旧分组
 * （前提假设：网络中没有延迟极久的陈旧分组）。 */
typedef struct {
    uint32_t bitmap;               /* 已聚合的 rank 位图 */
    int32_t  payload[PAYLOAD_LEN / sizeof(int32_t)];  /* 按 int32 求和（固定 PAYLOAD_LEN）*/
} agtr_t;

/*================== 对外函数声明 ==================*/

/* 主机端 */
void init_host(config_entry_t *cfgs, int n, const char *host_name);
int  init_conn(uint16_t conn_id, uint32_t local_ip, uint32_t remote_ip);
int  m_send(int conn, const void *buf, uint32_t size, uint8_t op);
int  m_recv(int conn, void *buf, uint32_t size, uint8_t op);
int  shift(int group_id, char *src_addr, char *dst_addr, uint32_t size);
int  allreduce(int group_id, char *src_addr, char *dst_addr, uint32_t size);

/* 路由器端 */
void init_router(config_entry_t *cfgs, int n);
void Router(void);     /* 普通转发 */
void INC(void);        /* 转发 + 在网聚合 */

/* 工具 */
uint64_t now_us(void);

#endif /* COMMON_H */
