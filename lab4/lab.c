#include <sys/types.h>
#include <sys/time.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include "common.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>

#include <sys/types.h>   // 提供 u_char, u_short, u_int 等类型
#include <pcap.h>        // 或者其他需要的头文件


#define LOG 


/* Global variables */
// common
net_device_t devices[MAX_DEVICES];
int device_count = 0;
packet_buffer_t pkt_buffer;

// switch
forwarding_db_t fdb;  // Forwarding database

// router
#define MAX_ROUTES 32
#define DV_INTERVAL 1000000  // 1 second
#define DV_SLEEP 500000      // 0.5 second
#define PCAP_READ_TIMEOUT_MS 1

/* Routing table */
typedef struct {
    route_entry_t entries[MAX_ROUTES];
    int count;
} routing_table_t;

/* Control plane message buffer */
typedef struct {
    packet_entry_t packets[MAX_PACKETS];
    int head;
    int tail;
    pthread_mutex_t lock;
} cp_buffer_t;

routing_table_t rt;  // Routing table
cp_buffer_t cp_buf;  // Control plane message buffer
pthread_mutex_t rt_lock = PTHREAD_MUTEX_INITIALIZER;
extern char device_name[100];

/* Forward declarations */
void *control_plane_thread(void *arg);
int load_rules_from_file(const char *filename);


/************************************
 * Helper functions
 ***********************************/
 
void print_mac(const uint8_t *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
void print_ip(uint32_t ip) {
    printf("%u.%u.%u.%u\n", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
}

void format_ip(uint32_t ip, char *buf, size_t len) {
    snprintf(buf, len, "%u.%u.%u.%u",
        (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
}

static unsigned int mask_to_prefix_len(uint32_t mask) {
    unsigned int prefix_len = 0;
    while (mask & 0x80000000u) {
        prefix_len++;
        mask <<= 1;
    }
    return prefix_len;
}


/************************************
 *  common
 ***********************************/



int common_init(){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    
    // Initialize packet buffer
    memset(&pkt_buffer, 0, sizeof(pkt_buffer));
    pkt_buffer.head = pkt_buffer.tail = 0;
    pthread_mutex_init(&pkt_buffer.lock, NULL);

    // Find all network devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return -1;
    }

    // Filter and store switch/host devices
    pcap_if_t *d;
    for (d = alldevs; d != NULL && device_count < MAX_DEVICES; d = d->next) {
        if (strncmp(d->name, "device", 6) == 0 ||
            strncmp(d->name, "host", 4) == 0) {
            
            strncpy(devices[device_count].name, d->name, 31);
            devices[device_count].index = device_count;
            
            // Open device for capture
            devices[device_count].handle = pcap_open_live(d->name,
                PACKET_BUF_SIZE, 1, PCAP_READ_TIMEOUT_MS, errbuf);
            if (!devices[device_count].handle) {
                fprintf(stderr, "Couldn't open device %s: %s\n",
                    d->name, errbuf);
                continue;
            }

            if (pcap_setdirection(devices[device_count].handle, PCAP_D_IN) == -1) {
                fprintf(stderr, "Warning: couldn't set capture direction on %s: %s\n",
                    d->name, pcap_geterr(devices[device_count].handle));
            }

            // Create capture thread
            if (pthread_create(&devices[device_count].thread_id,
                NULL, capture_thread, &devices[device_count]) != 0) {
                fprintf(stderr, "Failed to create thread for %s\n", d->name);
                pcap_close(devices[device_count].handle);
                continue;
            }

            device_count++;
        }
    }

    pcap_freealldevs(alldevs);
    printf("Initialized %d network devices\n", device_count);
    return device_count > 0 ? 0 : -1;
}



/************************************
 *  hub
 ***********************************/

int send_packet(net_device_t *dev, const uint8_t *data, uint32_t len) {
    if (pcap_inject(dev->handle, data, len) == -1) {
        fprintf(stderr, "Error sending packet on %s: %s\n",
               dev->name, pcap_geterr(dev->handle));
        return -1;
    }
    return 0;
}

void Hub() {
    common_init();
    while (1) {
        // 上锁buffer
        pthread_mutex_lock(&pkt_buffer.lock);
        
        // Check if buffer is empty
        if (pkt_buffer.head == pkt_buffer.tail) {
            // 解锁
            pthread_mutex_unlock(&pkt_buffer.lock);
            usleep(1000); // Sleep 1ms if buffer is empty
            continue;
        }
        
        // Get packet from buffer
        packet_entry_t *entry = &pkt_buffer.packets[pkt_buffer.tail];
        pkt_buffer.tail = (pkt_buffer.tail + 1) % MAX_PACKETS;
        pthread_mutex_unlock(&pkt_buffer.lock);
        
        // Forward packet to all other devices
        /*************************************
         * start of your code
         *************************************/
        for (int i = 0; i < device_count; i++) {
            if (&devices[i] != entry->device) {
                send_packet(&devices[i], entry->data, entry->len);
            }
        }
        
        /*************************************
         * end of your code
         *************************************/

    }
}


/************************************
 *  switch
 ***********************************/



void Switch(){
    common_init();
    // 初始化交换机的转发表 fdb
    // fdb 里存的是“MAC 地址 -> 所在设备”的映射
    // fdb.entries[i].mac 存一个 MAC 地址
    // fdb.entries[i].device 存这个 MAC 对应在哪个设备/端口上；记录的是设备名字符串
    // fdb.count 表示当前已经记录了多少条映射
    memset(&fdb, 0, sizeof(fdb));  // Initialize forwarding database

    while (1) {
        pthread_mutex_lock(&pkt_buffer.lock);
        
        // Check if buffer is empty
        if (pkt_buffer.head == pkt_buffer.tail) {
            pthread_mutex_unlock(&pkt_buffer.lock);
            usleep(1000); // Sleep 1ms if buffer is empty
            continue;
        }
        
        // Get packet from buffer
        packet_entry_t *entry = &pkt_buffer.packets[pkt_buffer.tail];
        pkt_buffer.tail = (pkt_buffer.tail + 1) % MAX_PACKETS;
        pthread_mutex_unlock(&pkt_buffer.lock);
        

        /*************************************
         * start of your code
         *************************************/
         
        // Get Ethernet header
        // 获取 eth->src_mac/eth->dst_mac
        // entry->data 里存的本来就是“抓到的原始以太网帧字节流”，
        // 而以太网帧开头的前 14 字节正好就是 Ethernet header
        if (entry->len < sizeof(eth_header_t)) {
            continue;
        }

        eth_header_t *eth = (eth_header_t *)entry->data;
        
        // Learn source MAC address
        int found_src = 0;
        for (int i = 0; i < fdb.count; i++) {
            if (memcmp(fdb.entries[i].mac, eth->src_mac, 6) == 0) {
                // 更新源mac对应的设备
                strncpy(fdb.entries[i].device, entry->device->name, 31);
                fdb.entries[i].device[31] = '\0';
                found_src = 1;
                break;
            }
        }
        if (!found_src && fdb.count < MAX_DEVICES) {
            memcpy(fdb.entries[fdb.count].mac, eth->src_mac, 6);
            strncpy(fdb.entries[fdb.count].device, entry->device->name, 31);
            fdb.entries[fdb.count].device[31] = '\0';
            fdb.count++;
        }
        
        // Forward packet
        int found_dst = -1;
        for (int i = 0; i < fdb.count; i++) {
            if (memcmp(fdb.entries[i].mac, eth->dst_mac, 6) == 0) {
                found_dst = i;
                break;
            }
        }

        // case 1: Found destination, forward to that device
        if (found_dst != -1) {
            for (int i = 0; i < device_count; i++) {
                //当前这个 devices[i] 的名字是否等于转发表中记录的目标设备名
                if (strcmp(devices[i].name, fdb.entries[found_dst].device) == 0 &&
                    &devices[i] != entry->device) {
                    send_packet(&devices[i], entry->data, entry->len);
                    break;
                }
            }
        }
                
        // case 2: Flood to all ports except ingress
        else {
            for (int i = 0; i < device_count; i++) {
                if (&devices[i] != entry->device) {
                    send_packet(&devices[i], entry->data, entry->len);
                }
            }
        }
        /*************************************
         * end of your code
         *************************************/
        
    }
}

 /************************************
 *  router
 ***********************************/

void Router(){

    // Initialize common components
    if (common_init() != 0) {
        fprintf(stderr, "Failed to initialize router\n");
        return;
    }

    // Initialize routing table and control plane buffer
    // routing table，路由表
    memset(&rt, 0, sizeof(rt));
    // 控制平面缓冲区
    memset(&cp_buf, 0, sizeof(cp_buf));
    pthread_mutex_init(&cp_buf.lock, NULL);
    pthread_mutex_init(&rt_lock, NULL);

    // Load rules from file if exists
    if (load_rules_from_file("rules.txt") != 0) {
        fprintf(stderr, "No rules.txt found or error loading rules\n");
    }

    // Start control plane thread
    pthread_t cp_thread;
    // control_plane_thread是入口函数，while (1)
    if (pthread_create(&cp_thread, NULL, control_plane_thread, NULL) != 0) {
        fprintf(stderr, "Failed to create control plane thread\n");
        return;
    }

    usleep(DV_SLEEP); // Ensure control plane thread starts

    // Main router loop
    while (1) {
        pthread_mutex_lock(&pkt_buffer.lock);
        
        // Check if buffer is empty
        if (pkt_buffer.head == pkt_buffer.tail) {
            pthread_mutex_unlock(&pkt_buffer.lock);
            usleep(1000); // Sleep 1ms if buffer is empty
            continue;
        }
        
        // Get packet from buffer
        packet_entry_t *entry = &pkt_buffer.packets[pkt_buffer.tail];
        pkt_buffer.tail = (pkt_buffer.tail + 1) % MAX_PACKETS;
        pthread_mutex_unlock(&pkt_buffer.lock);

        // Check if it's a DV packet
        if (entry->len < sizeof(eth_header_t)) {
            continue;
        }

        eth_header_t *eth = (eth_header_t *)entry->data;
        if (ntohs(eth->ether_type) == ETH_TYPE_DV) {
            if (entry->len < sizeof(eth_header_t) + sizeof(dv_packet_t)) {
                continue;
            }
            // Add to control plane buffer
            pthread_mutex_lock(&cp_buf.lock);
            if ((cp_buf.head + 1) % MAX_PACKETS != cp_buf.tail) {
                memcpy(&cp_buf.packets[cp_buf.head], entry, sizeof(packet_entry_t));
                cp_buf.head = (cp_buf.head + 1) % MAX_PACKETS;
            }
            pthread_mutex_unlock(&cp_buf.lock);
            continue;
        }


        /*********************************
         * start of your code
         ********************************/

        if (ntohs(eth->ether_type) != 0x0800 ||
            entry->len < sizeof(eth_header_t) + sizeof(ip_header_t)) {
            continue;
        }

        // Forward packet based on longest-prefix match.
        ip_header_t *ip = (ip_header_t *)(entry->data + sizeof(eth_header_t));
        uint32_t dst_ip = ntohl(ip->dst_ip);
        int best_route = -1;

        pthread_mutex_lock(&rt_lock);
        for (int i = 0; i < rt.count; i++) {
            if ((dst_ip & rt.entries[i].mask) != rt.entries[i].dest_ip) {
                continue;
            }

            if (best_route == -1 ||
                rt.entries[i].mask > rt.entries[best_route].mask ||
                (rt.entries[i].mask == rt.entries[best_route].mask &&
                 rt.entries[i].distance < rt.entries[best_route].distance)) {
                best_route = i;
            }
        }

        if (best_route != -1) {
            char out_dev[32];
            strncpy(out_dev, rt.entries[best_route].out_dev, sizeof(out_dev) - 1);
            out_dev[sizeof(out_dev) - 1] = '\0';
            pthread_mutex_unlock(&rt_lock);

            for (int j = 0; j < device_count; j++) {
                if (strcmp(devices[j].name, out_dev) == 0) {
                    send_packet(&devices[j], entry->data, entry->len);
                    break;
                }
            }
        } else {
            pthread_mutex_unlock(&rt_lock);
            char dst_buf[16];
            format_ip(dst_ip, dst_buf, sizeof(dst_buf));
            fprintf(stderr, "[%s] drop dst=%s at %llu us\n",
                device_name, dst_buf,
                (unsigned long long)get_current_time_us());
        }
        /*********************************
         * end of your code
         ********************************/
    }
}

int load_rules_from_file(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) return -1;

    char line[256];
    while (fgets(line, sizeof(line), fp) && rt.count < MAX_ROUTES) {
        char network[32], out_dev[32];
        unsigned int prefix_len, distance;
        
        if (sscanf(line, "%s %s %u", network, out_dev, &distance) == 3) {
            // Parse CIDR notation
            uint32_t ip = 0, mask = 0;
            char *slash = strchr(network, '/');
            if (slash) {
                *slash = '\0';
                prefix_len = atoi(slash + 1);
                if (prefix_len > 32) continue;
                
                // Convert IP string to number
                struct in_addr addr;
                if (inet_pton(AF_INET, network, &addr) != 1) continue;
                ip = ntohl(addr.s_addr);
                
                // Create mask from prefix length
                mask = prefix_len ? ~((1u << (32 - prefix_len)) - 1u) : 0;
                
                // Add to routing table
                rt.entries[rt.count].dest_ip = ip & mask;
                rt.entries[rt.count].mask = mask;
                strncpy(rt.entries[rt.count].out_dev, out_dev, 31);
                rt.entries[rt.count].distance = distance;
                rt.count++;
            }
        }
    }
    fclose(fp);
    return 0;
}

void *control_plane_thread(void *arg) {
    (void)arg; // Explicitly mark as unused
    // 记录上一次广播路由表的时间
    uint64_t last_broadcast = get_current_time_us();

    while (1) {
        // Process control plane messages
        pthread_mutex_lock(&cp_buf.lock);
        if (cp_buf.head != cp_buf.tail) {
            packet_entry_t *entry = &cp_buf.packets[cp_buf.tail];
            cp_buf.tail = (cp_buf.tail + 1) % MAX_PACKETS;
            pthread_mutex_unlock(&cp_buf.lock);
            int route_changed = 0;
            
            /*********************************
            * start of your code
            ********************************/
            // Process DV packet and update routing table
            dv_packet_t *dv = (dv_packet_t *)(entry->data + sizeof(eth_header_t));
            uint32_t dest_ip = ntohl(dv->dest_ip);
            uint32_t mask = ntohl(dv->mask);
            // 经过邻居+1
            uint32_t distance = ntohl(dv->distance) + 1; 

            // Check if destination exists in routing table
            int found = 0;

            pthread_mutex_lock(&rt_lock);
            for (int i = 0; i < rt.count; i++) {
                if (rt.entries[i].dest_ip == dest_ip &&
                    rt.entries[i].mask == mask) {
                    found = 1;

                    // 如果新路径更短，就更新
                    if (distance < rt.entries[i].distance) {
                        rt.entries[i].distance = distance;
                        strncpy(rt.entries[i].out_dev, entry->device->name, 31);
                        rt.entries[i].out_dev[31] = '\0';
                        route_changed = 1;
                        char dst_buf[16];
                        format_ip(dest_ip, dst_buf, sizeof(dst_buf));
                        fprintf(stderr, "[%s] update route %s/%u via %s dist=%u at %llu us\n",
                            device_name, dst_buf, mask_to_prefix_len(mask), entry->device->name, distance,
                            (unsigned long long)get_current_time_us());
                    }
                    break;
                }
            }
            // Add new entry if destination not found and table not full
            if (!found && rt.count < MAX_ROUTES) {
                rt.entries[rt.count].dest_ip = dest_ip;
                rt.entries[rt.count].mask = mask;
                rt.entries[rt.count].distance = distance;
                strncpy(rt.entries[rt.count].out_dev, entry->device->name, 31);
                rt.entries[rt.count].out_dev[31] = '\0';
                rt.count++;
                route_changed = 1;
                char dst_buf[16];
                format_ip(dest_ip, dst_buf, sizeof(dst_buf));
                fprintf(stderr, "[%s] add route %s/%u via %s dist=%u at %llu us\n",
                    device_name, dst_buf, mask_to_prefix_len(mask), entry->device->name, distance,
                    (unsigned long long)get_current_time_us());
            }
            pthread_mutex_unlock(&rt_lock);


            /*********************************
            * end of your code
            ********************************/

            if (route_changed) {
                last_broadcast = get_current_time_us();
            }

        } else {
            pthread_mutex_unlock(&cp_buf.lock);
            usleep(DV_SLEEP);
        }
        
        /*********************************
        * start of your code
        ********************************/

        // Broadcast routing table periodically
        uint64_t now = get_current_time_us();
        if (now - last_broadcast >= DV_INTERVAL) {
            last_broadcast = now;

            // 遍历路由表中的每一项
            pthread_mutex_lock(&rt_lock);
            for (int i = 0; i < rt.count; i++) {
                // 从每个设备广播出去
                for (int j = 0; j < device_count; j++) {
                    uint8_t packet[sizeof(eth_header_t) + sizeof(dv_packet_t)];
                    memset(packet, 0, sizeof(packet));
                
                    // eth 指向开头，按 Ethernet 头解释
                    // dv 指向后半段，按 DV 包解释
                    eth_header_t *eth = (eth_header_t *)packet;
                    dv_packet_t *dv = (dv_packet_t *)(packet + sizeof(eth_header_t));

                    // MAC 可以随便填，这里简单写一个广播目的 MAC
                    memset(eth->dst_mac, 0xff, 6);
                    memset(eth->src_mac, 0x00, 6);
                    eth->ether_type = htons(ETH_TYPE_DV);

                    dv->dest_ip = htonl(rt.entries[i].dest_ip);
                    dv->mask = htonl(rt.entries[i].mask);
                    dv->distance = htonl(rt.entries[i].distance);

                    send_packet(&devices[j], packet, sizeof(packet));
                }
            }
            pthread_mutex_unlock(&rt_lock);
        }
        /*********************************
        * start of your code
        ********************************/
    }
    return NULL;
}

uint64_t get_current_time_us() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000 + tv.tv_usec;
}

/************************************
 *  Packet capture thread
 ***********************************/

void *capture_thread(void *arg) {
    net_device_t *dev = (net_device_t *)arg;
    struct pcap_pkthdr header;
    const u_char *packet;
    
    printf("Starting capture on %s\n", dev->name);
    
    while (1) {
        packet = pcap_next(dev->handle, &header);
        if (!packet) continue;        
        
        pthread_mutex_lock(&pkt_buffer.lock);
        
        // Check if buffer is full
        if ((pkt_buffer.head + 1) % MAX_PACKETS == pkt_buffer.tail) {
            fprintf(stderr, "Packet buffer full, dropping packet\n");
            pthread_mutex_unlock(&pkt_buffer.lock);
            continue;
        }
        
        // Store packet in buffer

        packet_entry_t *entry = &pkt_buffer.packets[pkt_buffer.head];
        entry->device = dev;
        entry->len = header.len > PACKET_BUF_SIZE ? PACKET_BUF_SIZE : header.len;
        entry->timestamp = header.ts.tv_sec * 1000000 + header.ts.tv_usec;
        memcpy(entry->data, packet, entry->len);
        
        pkt_buffer.head = (pkt_buffer.head + 1) % MAX_PACKETS;
        pthread_mutex_unlock(&pkt_buffer.lock);
    }
    
    return NULL;
}
