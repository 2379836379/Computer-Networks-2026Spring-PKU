#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <math.h>
#include <fcntl.h>
#include <errno.h>

#define LOG



static ccb_table_t conn_table = {0};

int init_connection(const char* local_ip, uint16_t local_port,
                   const char* remote_ip, uint16_t remote_port) {
    if (conn_table.count >= CCB_TABLE_SIZE) {
        return -1;
    }

    ccb_t* ccb = &conn_table.entries[conn_table.count];
    memset(ccb, 0, sizeof(ccb_t));
    ccb->udp_sock = -1;

    // 设置连接信息
    strncpy(ccb->local_ip, local_ip, sizeof(ccb->local_ip)-1);
    ccb->local_ip[sizeof(ccb->local_ip)-1] = '\0';
    ccb->local_port = local_port;
    strncpy(ccb->remote_ip, remote_ip, sizeof(ccb->remote_ip)-1);
    ccb->remote_ip[sizeof(ccb->remote_ip)-1] = '\0';
    ccb->remote_port = remote_port;

    // 初始化窗口参数
    // 发送窗口起点
    ccb->window_base = 0;
    // 发送窗口大小
    ccb->window_size = 1;
    // 估计的往返时间，用于计算Rto
    ccb->rtt_estimated = 0.2; // 200ms
    // RTT 的偏差变化
    ccb->rtt_variation = 0;
    // 接收进度：下一个期望收到的包序号
    ccb->recv_progress = 0;
    // 记录接收端完成全部数据接收的时间
    memset(&ccb->recv_complete_time, 0, sizeof(struct timeval));


    /***********************
     * start of your code
     **********************/

    // 创建UDP socket SOCK_DGRAM
    ccb->udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (ccb->udp_sock < 0) {
        return -1;
    }

    // 绑定本地地址
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(local_port);
    // 将点分十进制字符串转换为二进制网络字节序
    if (inet_pton(AF_INET, local_ip, &local_addr.sin_addr) != 1) {
        close(ccb->udp_sock);
        ccb->udp_sock = -1;
        return -1;
    }
    // 将套接字与一个本地地址和端口绑定
    if (bind(ccb->udp_sock, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        close(ccb->udp_sock);
        ccb->udp_sock = -1;
        return -1;
    }

    // 设置远端地址
    memset(&ccb->remote_addr, 0, sizeof(ccb->remote_addr));
    ccb->remote_addr.sin_family = AF_INET;
    ccb->remote_addr.sin_port = htons(remote_port);
    if (inet_pton(AF_INET, remote_ip, &ccb->remote_addr.sin_addr) != 1) {
        close(ccb->udp_sock);
        ccb->udp_sock = -1;
        return -1;
    }

     /***********************
     * end of your code
     **********************/
    return conn_table.count++;
}

void close_connection(int conn_id) {
    if (conn_id < 0 || conn_id >= conn_table.count) {
        return;
    }

    ccb_t* ccb = &conn_table.entries[conn_id];
    if (ccb->udp_sock >= 0) {
        close(ccb->udp_sock);
    }
    memset(ccb, 0, sizeof(ccb_t));
    ccb->udp_sock = -1;
}

// 更新RTT估计
static void update_rtt(ccb_t* ccb, double rtt_sample) {
    /***********************
     * start of your code
     **********************/
    const double alpha = 0.125;
    const double beta = 0.25;

    if (ccb->rtt_estimated <= 0) {
        ccb->rtt_estimated = rtt_sample;
        ccb->rtt_variation = rtt_sample / 2.0;
        return;
    }
    ccb->rtt_variation =
        (1.0 - beta) * ccb->rtt_variation +
        beta * fabs(rtt_sample - ccb->rtt_estimated);

    ccb->rtt_estimated =
        (1.0 - alpha) * ccb->rtt_estimated +
        alpha * rtt_sample;
    /***********************
     * end of your code
     **********************/
}

// 拥塞控制
// 根据网络是否“拥堵”动态调整 window_size
static void congestion_control(ccb_t* ccb, int is_timeout) {
    struct timeval now;
    gettimeofday(&now, NULL);
    
    /***********************
     * start of your code
     **********************/
    double protection_interval = ccb->rtt_estimated + 4.0 * ccb->rtt_variation;
    if (protection_interval <= 0) {
        protection_interval = 0.2;
    }
    double elapsed =
        (now.tv_sec - ccb->last_congestion.tv_sec) +
        (now.tv_usec - ccb->last_congestion.tv_usec) / 1000000.0;

    if(is_timeout){
        // 检查是否在保护期内，如果不在
        // 未发生过拥塞/超过间隔
        if ((ccb->last_congestion.tv_sec == 0 &&
            ccb->last_congestion.tv_usec == 0)||
            elapsed >= protection_interval) {
            // 超时处理
            // 窗口减半，不小于1
            ccb->window_size /= 2.0;
            if (ccb->window_size < 1.0) {
                ccb->window_size = 1.0;
            }
            // 进入拥塞避免
            ccb->congestion_state = 1;
            // 记录保护期开始
            ccb->last_congestion = now;
        }
    }
    else{
        // ACK处理
        if (ccb->congestion_state == 0) {
            // 慢启动阶段：每个ACK窗口+1
            ccb->window_size += 1.0;
        } else {
            // 拥塞避免阶段：每个ACK窗口+1/window_size
            ccb->window_size += 1.0 / ccb->window_size;
        }
    }

    /***********************
     * end of your code
     **********************/

}

int m_send(int conn_id, const void* buf, size_t len) {
    if (conn_id < 0 || conn_id >= conn_table.count) {
        return -1;
    }

    ccb_t* ccb = &conn_table.entries[conn_id];
    
    // 检查缓冲区长度
    if (len > MTP_MAX_MSG_LEN) {
        fprintf(stderr, "Message too large\n");
        return -1;
    }
    if (len == 0) {
        return 0;
    }

    // 初始化数组
    memset(ccb->timestamps, 0, sizeof(struct timeval) * MTP_MAX_SEGMENTS);
    memset(ccb->acks_received, 0, sizeof(uint8_t) * MTP_MAX_SEGMENTS);
    memset(ccb->retrans_records, 0, sizeof(uint32_t) * MTP_MAX_SEGMENTS);
    ccb->window_base = 0;

    // 计算最大序列号
    // 最大分组数量
    
    // 时间顺序是：
    // 先算总共有多少个分组 max_seq
    // 在窗口里遍历 seq
    // 先检查这个 seq 对应分组是否已 ACK、是否超时
    // 如果需要发送，才根据 seq 从 buf 里切出那一段数据，封装成 packet 发出去

    uint32_t max_seq = (len + MTP_PAYLOAD_LEN - 1) / MTP_PAYLOAD_LEN;
    ccb->max_seq = max_seq;

    // 设置非阻塞模式
    int flags = fcntl(ccb->udp_sock, F_GETFL, 0);
    if (flags < 0 || fcntl(ccb->udp_sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        return -1;
    }


    // 发送循环
    while (1) {
        //printf("send\n");
        //fflush(stdout);
        int had_activity = 0;

        /***********************
         * start of your code
         **********************/

        char recv_buf[sizeof(mtp_header_t)];
        // from_addr 用来接收这个 UDP 包是谁发来的
        struct sockaddr_in from_addr;
        while(1){
            socklen_t from_len = sizeof(from_addr);
            // 从 UDP socket 里收一个报文，放进 recv_buf
            ssize_t recv_len = recvfrom(ccb->udp_sock, recv_buf, sizeof(recv_buf), 0,
                                (struct sockaddr*)&from_addr, &from_len);
            if (recv_len <= 0) {
                if (recv_len < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    return -1;
                }
                break;
            }
            if ((size_t)recv_len < sizeof(mtp_header_t)) {
                continue;
            }
            if (from_addr.sin_addr.s_addr != ccb->remote_addr.sin_addr.s_addr ||
                from_addr.sin_port != ccb->remote_addr.sin_port) {
                continue;
            }
        
            // 解析头部
            mtp_header_t* header = (mtp_header_t*)recv_buf;
            uint32_t ack_seq = ntohl(header->seq_num);
            uint16_t ack_flag = ntohs(header->ack_flag);
            // ACK包
            if (ack_flag == 1 && ack_seq < max_seq) {
                // 更新ACK数组，下标对应分组序号，分组 是一次发送的数据块
                if (!ccb->acks_received[ack_seq]) {
                    ccb->acks_received[ack_seq] = 1;
                    had_activity = 1;
                    // 仅对非重传分组更新RTT
                    // 一旦重传了，收到这个 ACK不能确定对应关系
                    if (ccb->retrans_records[ack_seq] == 0) {
                        struct timeval now;
                        gettimeofday(&now, NULL);
                        double sample =
                            (now.tv_sec - ccb->timestamps[ack_seq].tv_sec) +
                            (now.tv_usec - ccb->timestamps[ack_seq].tv_usec) / 1000000.0;
                        if (sample > 0) {
                            update_rtt(ccb, sample);
                        }
                    }
                    // 拥塞控制，不因为超时调用为0
                    congestion_control(ccb, 0);
                }
            }
        }
        
        // 滑动窗口
        while (ccb->window_base < max_seq && ccb->acks_received[ccb->window_base]) {
            ccb->window_base++;
        }
        // 发送分组
        // 当前这一轮，发送窗口的右边界
        uint32_t window_end = ccb->window_base + (uint32_t)ccb->window_size;
        if (window_end > max_seq) {
            window_end = max_seq;
        }

        struct timeval now;
        gettimeofday(&now, NULL);
        //  rto = SRTT + 4 × RTTVAR   
        double rto = ccb->rtt_estimated + 4.0 * ccb->rtt_variation;
        if (rto <= 0) {
            rto = 0.2;
        }
        //  检查超时
        for (uint32_t seq = ccb->window_base; seq < window_end; seq++) {
            if (ccb->acks_received[seq]) {
                continue;
            }

            int need_send = 0;
            // 未发送过
            if (ccb->timestamps[seq].tv_sec == 0 &&
                ccb->timestamps[seq].tv_usec == 0) {
                need_send = 1;
            } else {
                double elapsed =
                    (now.tv_sec - ccb->timestamps[seq].tv_sec) +
                    (now.tv_usec - ccb->timestamps[seq].tv_usec) / 1000000.0;

                if (elapsed >= rto) {
                    // 超时处理：拥塞控制，记录重传
                    congestion_control(ccb, 1);
                    ccb->retrans_records[seq]++;
                    need_send = 1;
                }
            }

            // 超时或者第一次发送：构造并发送分组
            if (need_send) {
                // 组的缓冲
                char packet[sizeof(mtp_header_t) + MTP_PAYLOAD_LEN];
                // 
                mtp_header_t* header = (mtp_header_t*)packet;

                // 原始数据的起始字节下标，原始数据是参数void* buf
                size_t offset = (size_t)seq * MTP_PAYLOAD_LEN;
                // 长度
                size_t payload_len = MTP_PAYLOAD_LEN;
                // 针对最后一组
                if (offset + payload_len > len) {
                    payload_len = len - offset;
                }
                // 分组序号
                header->seq_num = htonl(seq);
                // 0为数据包
                header->ack_flag = htons(0);
                // 分组有效载荷有多长
                header->payload_len = htons((uint16_t)payload_len);

                memcpy(packet + sizeof(mtp_header_t), (const char*)buf + offset, payload_len);
                // send
                ssize_t sent = sendto(ccb->udp_sock, packet,
                                      sizeof(mtp_header_t) + payload_len, 0,
                                      (struct sockaddr*)&ccb->remote_addr,
                                      sizeof(ccb->remote_addr));
                if (sent < 0 ||
                    (size_t)sent != sizeof(mtp_header_t) + payload_len) {
                    return -1;
                }
                // 记录发送时间
                gettimeofday(&ccb->timestamps[seq], NULL);
                had_activity = 1;
            
            }
        }

        // 检查完成度
        if (ccb->window_base >= max_seq) {
            break;
        }
        /***********************
         * end of your code
         **********************/
        if (!had_activity) {
            usleep(100);
        }
    }

    return 0;
}

// 构造ACK分组
static void build_ack_packet(mtp_header_t* header, uint32_t seq_num) {
    header->seq_num = htonl(seq_num);
    header->ack_flag = htons(1);
    header->payload_len = htons(0);
}

int m_recv(int conn_id, void* buf, size_t len) {
    // 连接编号
    if (conn_id < 0 || conn_id >= conn_table.count) {
        return -1;
    }
    // 取出这个连接对应的控制块 ccb
    ccb_t* ccb = &conn_table.entries[conn_id];
    
    // 检查缓冲区长度
    if (len > MTP_MAX_MSG_LEN) {
        fprintf(stderr, "Buffer too small for message\n");
        return -1;
    }
    if (len == 0) {
        return 0;
    }

    // 初始化数组
    // 收到分组
    memset(ccb->recv_records, 0, sizeof(uint8_t) * MTP_MAX_SEGMENTS);
    // 收到的前缀
    ccb->recv_progress = 0;
    memset(&ccb->recv_complete_time, 0, sizeof(struct timeval));

    /***********************
     * start of your code
     **********************/

    // 计算最大序列号
    uint32_t max_seq = (len + MTP_PAYLOAD_LEN - 1) / MTP_PAYLOAD_LEN;
    // 设置非阻塞模式
    int flags = fcntl(ccb->udp_sock, F_GETFL, 0);
    if (flags < 0 || fcntl(ccb->udp_sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        return -1;
    }
    /***********************
     * end of your code
     **********************/

    // 接收循环
    while (1) {
        //printf("rec\n");
        //fflush(stdout);
        /***********************
         * start of your code
         **********************/

        char packet[sizeof(mtp_header_t) + MTP_PAYLOAD_LEN];
        struct sockaddr_in from_addr;
        socklen_t from_len = sizeof(from_addr);

        ssize_t recv_len = recvfrom(ccb->udp_sock, packet, sizeof(packet), 0,
                                    (struct sockaddr*)&from_addr, &from_len);
        if (recv_len < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                return -1;
            }
        } else if ((size_t)recv_len >= sizeof(mtp_header_t) &&
                   from_addr.sin_addr.s_addr == ccb->remote_addr.sin_addr.s_addr &&
                   from_addr.sin_port == ccb->remote_addr.sin_port) {
            // 解析头部
            mtp_header_t* header = (mtp_header_t*)packet;
            uint32_t seq = ntohl(header->seq_num);
            uint16_t ack_flag = ntohs(header->ack_flag);
            uint16_t payload_len = ntohs(header->payload_len);

            // 排除ACK
            if (ack_flag == 0 &&
                seq < max_seq &&
                payload_len <= MTP_PAYLOAD_LEN &&
                (size_t)recv_len == sizeof(mtp_header_t) + payload_len) {
                size_t offset = (size_t)seq * MTP_PAYLOAD_LEN;

                if (offset + payload_len <= len) {
                    // 写入接收缓冲区
                    memcpy((char*)buf + offset, packet + sizeof(mtp_header_t), payload_len);

                    // 发送ACK
                    mtp_header_t ack_header;
                    build_ack_packet(&ack_header, seq);
                    if (sendto(ccb->udp_sock, &ack_header, sizeof(ack_header), 0,
                               (struct sockaddr*)&ccb->remote_addr,
                               sizeof(ccb->remote_addr)) < 0) {
                        return -1;
                    }

                    // 更新接收记录
                    ccb->recv_records[seq] = 1;

                    // 更新接收进度
                    while (ccb->recv_progress < max_seq &&
                           ccb->recv_records[ccb->recv_progress]) {
                        ccb->recv_progress++;
                    }
                }
            }
        }
        

        // 完成度检查
        if (ccb->recv_progress == max_seq) {
            struct timeval now;
            // 首次完成，记录时间
            if (ccb->recv_complete_time.tv_sec == 0 &&
                ccb->recv_complete_time.tv_usec == 0) {
                gettimeofday(&ccb->recv_complete_time, NULL);
            }

            gettimeofday(&now, NULL);
            double elapsed =
                (now.tv_sec - ccb->recv_complete_time.tv_sec) +
                (now.tv_usec - ccb->recv_complete_time.tv_usec) / 1000000.0;

            // 检查是否超过0.5秒
            // 因为发送方可能由于 ACK 丢失，已经开始重传某些分组。
            // 如果接收方一收齐就立刻退出，就可能来不及给这些重传包回 ACK，发送方会一直卡着。
            if (elapsed >= 0.5) {
                break;
            }
        }

        if (recv_len < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            usleep(1000);
        }
        /***********************
         * end of your code
         **********************/
    }

    if (ccb->recv_progress != max_seq) {
        return -1;
    }

    return (int)len;
}
