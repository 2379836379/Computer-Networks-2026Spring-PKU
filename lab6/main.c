

#include <stdio.h>
#include <stdint.h>
#include <pcap.h> // Required for pcap_t
#include <pthread.h>
#include <stdlib.h> // Required for EXIT_FAILURE
#include <netinet/in.h>
#include <netinet/tcp.h> // Required for TCP_MAXSEG
#include <netinet/ip.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/ethernet.h> // Required for ETHERTYPE_IP
#include <sys/socket.h>
#include <linux/if_ether.h>



char server_ip[16] = "10.0.0.2";
uint16_t server_port = 30001;

char client_ip[16] = "10.0.0.1";
uint16_t client_port = 20001;



#define PACKET_BUF_SIZE 2048 // Size of packet buffer
#define MAX_PACKETS 1024 // Maximum number of packets in the buffer

/* Network device information */
typedef struct {
    char name[32];          // Device name
    pcap_t *handle;         // pcap handle
    pthread_t thread_id;    // Capture thread ID
    int index;              // Device index
} net_device_t;

/* Packet buffer entry */
typedef struct { 
    net_device_t *device;   // Ingress device
    uint8_t data[PACKET_BUF_SIZE]; // Packet data
    uint32_t len;           // Packet length
    uint64_t timestamp;     // Capture timestamp
} packet_entry_t;

/* Global packet buffer */
typedef struct {
    packet_entry_t packets[MAX_PACKETS];
    int head;
    int tail;
    pthread_mutex_t lock;
} packet_buffer_t;

typedef struct {
    // match
    uint32_t dst_ip;          // Destination IP address
    // action
    char out_port[16];        // Output port (string)
} forward_entry_t;



// Define Ethernet header structure
typedef struct {
    uint8_t dest_mac[6];   // Destination MAC address
    uint8_t src_mac[6];    // Source MAC address
    uint16_t ether_type;   // Ethernet type
} eth_header_t;


// Define IP header structure
typedef struct {
    uint8_t version_ihl;    // Version and Internet Header Length
    uint8_t tos;            // Type of Service
    uint16_t total_length;  // Total Length
    uint16_t id;            // Identification
    uint16_t flags_offset;  // Flags and Fragment Offset
    uint8_t ttl;            // Time to Live
    uint8_t protocol;       // Protocol
    uint16_t checksum;      // Header Checksum
    uint32_t src_ip;        // Source IP Address
    uint32_t dst_ip;        // Destination IP Address
} ip_header_t;


typedef struct {
    uint16_t src_port;     // Source port
    uint16_t dst_port;     // Destination port
    uint32_t seq_num;      // Sequence number
    uint32_t ack_num;      // Acknowledgment number
    uint8_t  data_offset;  // Data offset (4 bits) + Reserved (6 bits) + Flags (6 bits)
    uint8_t  flag;          // Flags
    uint16_t window_size;  // Window size
    uint16_t checksum;     // Checksum
    uint16_t urgent_ptr;   // Urgent pointer
} __attribute__((packed)) tcp_header_t;

#define TCP_TS_OPTIONS 42  
struct tcp_ts_config {
    uint8_t ignore_zero_ecr:1;
    uint8_t padding:7;
};


net_device_t devices[16];
int device_count = 0;
packet_buffer_t pkt_buffer;
// forward table
forward_entry_t forward_table[16]; // Array of forwarding entries
int num_fwd_rules = 0;




void *bg_capture(void *arg) {
    net_device_t *dev = (net_device_t *)arg;
    struct pcap_pkthdr header;
    const unsigned char *packet;

    printf("Starting capture on %s\n", dev->name);
    fflush(stdout);

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
        entry->len = header.len;
        entry->timestamp = header.ts.tv_sec * 1000000 + header.ts.tv_usec;
        memcpy(entry->data, packet, header.len > PACKET_BUF_SIZE ? PACKET_BUF_SIZE : header.len);

        pkt_buffer.head = (pkt_buffer.head + 1) % MAX_PACKETS;
        pthread_mutex_unlock(&pkt_buffer.lock);
    }

    return NULL;
}

uint16_t calculate_checksum(void *vdata, size_t length) {
    uint16_t *data = vdata;
    uint32_t acc = 0;

    for (size_t i = 0; i < (length / 2); i++) {
        acc += ntohs(data[i]);
        if (acc > 0xFFFF) {
            acc -= 0xFFFF;
        }
    }

    if (length & 1) {
        acc += ntohs(((uint8_t *)data)[length - 1] << 8);
        if (acc > 0xFFFF) {
            acc -= 0xFFFF;
        }
    }

    return htons(~acc);
}


void forward_packet(packet_entry_t *pkt_entry, uint32_t dst_ip) {  // helper
    // print packet dip
    char dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &dst_ip, dst_ip_str, sizeof(dst_ip_str));
    printf("Forwarding packet to IP: %s, packet length is %d\n", dst_ip_str, pkt_entry->len);
    fflush(stdout);

    // Find the output port based on the destination IP 
    char *out_port = NULL;
    for (int i = 0; i < num_fwd_rules; i++) {
        char rule_dst_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &forward_table[i].dst_ip, rule_dst_ip_str, sizeof(rule_dst_ip_str));
        printf("Checking rule: %s, %s\n", rule_dst_ip_str, forward_table[i].out_port);
        fflush(stdout);

        if (strcmp(rule_dst_ip_str, dst_ip_str) == 0) {
            out_port = forward_table[i].out_port;
            break;
        }
    }
    if (out_port == NULL) {
        fprintf(stderr, "No matching forwarding rule for %u\n", dst_ip);
        return;
    }

    // Parse IP header
    ip_header_t *ip_header = (ip_header_t *)(pkt_entry->data + sizeof(eth_header_t));
    ip_header->checksum = 0; // Reset checksum
    ip_header->checksum = calculate_checksum(ip_header, sizeof(ip_header_t));

    // Parse TCP header
    tcp_header_t *tcp_header = (tcp_header_t *)(pkt_entry->data + sizeof(eth_header_t) + sizeof(ip_header_t));
    tcp_header->checksum = 0; // Reset checksum
    tcp_header->checksum = calculate_checksum(tcp_header, ntohs(ip_header->total_length) - sizeof(ip_header_t));

    for(int i = 0; i < device_count; i++) {
        if (strcmp(devices[i].name, out_port) == 0) {
            // Send packet to the output port
            pcap_inject(devices[i].handle, pkt_entry->data, pkt_entry->len);
            break;
        }
    }
}



int run_switch() {    
    // setup packet io 
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
    for (d = alldevs; d != NULL && device_count < 16; d = d->next) {
        if (strncmp(d->name, "switch", 6) == 0 ) {

            strncpy(devices[device_count].name, d->name, 31);
            devices[device_count].index = device_count;

            // Open device for capture
            devices[device_count].handle = pcap_open_live(d->name,
                PACKET_BUF_SIZE, 1, 1000, errbuf);
            if (!devices[device_count].handle) {
                fprintf(stderr, "Couldn't open device %s: %s\n",
                    d->name, errbuf);
                continue;
            }

            // Create capture thread
            if (pthread_create(&devices[device_count].thread_id,
                NULL, bg_capture, &devices[device_count]) != 0) {
                fprintf(stderr, "Failed to create thread for %s\n", d->name);
                pcap_close(devices[device_count].handle);
                continue;
            }
            device_count++;
        }
    }
    pcap_freealldevs(alldevs);

    // configure forwarding table
    num_fwd_rules = 0;
    // 10.0.0.1 => switch-eth0
    // 10.0.0.2 => switch-eth1
    forward_table[0].dst_ip = inet_addr("10.0.0.1");
    strncpy(forward_table[0].out_port, "switch-eth0", 16);
    num_fwd_rules++;

    forward_table[1].dst_ip = inet_addr("10.0.0.2");
    strncpy(forward_table[1].out_port, "switch-eth1", 16);
    num_fwd_rules++;


    while (1) {
        packet_entry_t pkt_entry;
        pthread_mutex_lock(&pkt_buffer.lock);

        // Check if buffer is empty
        if (pkt_buffer.head == pkt_buffer.tail) {
            pthread_mutex_unlock(&pkt_buffer.lock);
            usleep(1000); // Sleep 1ms if buffer is empty
            continue;
        }

        // Get packet from buffer
        memcpy(&pkt_entry, &pkt_buffer.packets[pkt_buffer.tail], sizeof(packet_entry_t));
        pkt_buffer.tail = (pkt_buffer.tail + 1) % MAX_PACKETS;
        pthread_mutex_unlock(&pkt_buffer.lock);

        
        // classification
        // get src_ip, src_port, dst_ip, dst_port, ackflag, synflag
        // parse Ethernet header
        eth_header_t *eth_header = (eth_header_t *)(pkt_entry.data);
        if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) continue; // not IP packet
        // parse IP header
        ip_header_t *ip_header = (ip_header_t *)(pkt_entry.data + sizeof(eth_header_t));

        
        uint32_t dst_ip = ip_header->dst_ip;

        forward_packet(&pkt_entry, dst_ip);

    }

    return 0;
}


int run_server() {
    printf("Running server...\n");
    fflush(stdout);
    // Placeholder for server run logic
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = ntohs(server_port); // Use ntohs to convert port number
    uint32_t server_ip_addr;
    if (inet_pton(AF_INET, server_ip, &server_ip_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        return -1;
    }
    server_addr.sin_addr.s_addr = server_ip_addr; // Convert IP address to network byte order

    printf("set up server_addr %s:%d\n", server_ip, server_port);
    fflush(stdout);
    
    // Create a socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    
    // configure socket MSS
    int mss = 1024;
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof(mss)) < 0) {
        perror("Error setting MSS");
        close(sockfd);
        return -1;
    }

    printf("set up socket %d option MSS %d\n", sockfd, mss);
    fflush(stdout);

    if (sockfd < 0) {
        perror("Error creating socket");
        return -1;
    }

    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        close(sockfd);
        return -1;
    }
    
    if (setsockopt(sockfd, SOL_SOCKET, SO_NO_CHECK, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        close(sockfd);
        return -1;
    }

    struct tcp_ts_config cfg = { .ignore_zero_ecr = 1 };
    setsockopt(sockfd, IPPROTO_TCP, TCP_TS_OPTIONS, &cfg, sizeof(cfg));
    


    // bind, listen, accept
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error binding socket");
        close(sockfd);
        return -1;
    }


    printf("Server: done with bind to %s:%d\n", server_ip, server_port);
    fflush(stdout);

    if (listen(sockfd, 3) < 0) {
        perror("Error listening on socket");
        close(sockfd);
        return -1;
    }

    printf("done with listen on %s:%d\n", server_ip, server_port);
    fflush(stdout);
    // Accept a connection
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int connfd = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
    if (connfd < 0) {
        perror("Error accepting connection");
        close(sockfd);
        return -1;
    }
    close(sockfd); // Close the listening socket

    printf("done with accept on %s:%d\n", server_ip, server_port);
    fflush(stdout);

    while(1) {
        // Receive data from the socket
        char buffer[1024];
        ssize_t bytes_received = recv(connfd, buffer, sizeof(buffer), 0);
        if (bytes_received <= 0) {
            break;
        }
        printf("Received %zd bytes\n", bytes_received);
    }
    
    perror("Error receiving data");
    close(connfd); // Close the connection socket

    return 0;
}

int run_client() {
    printf("Running client...\n");
    fflush(stdout);
    // create socket, bind, connect
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Error creating socket");
        return -1;
    }
    printf("set up socket %d\n", sockfd);
    fflush(stdout);


    setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &(int){1}, sizeof(int));

    // configure socket MSS
    int mss = 1024;
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof(mss)) < 0) {
        perror("Error setting MSS");
        close(sockfd);
        return -1;
    }
    printf("set up socket %d option MSS %d\n", sockfd, mss);
    fflush(stdout);

    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = ntohs(client_port); // Use ntohs to convert port number
    uint32_t client_ip_addr;
    if (inet_pton(AF_INET, client_ip, &client_ip_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        close(sockfd);
        return -1;
    }
    client_addr.sin_addr.s_addr = client_ip_addr; // Convert IP address to network byte order
    if (bind(sockfd, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        perror("Error binding socket");
        close(sockfd);
        return -1;
    }
    printf("Client: done with bind to %s:%d\n", client_ip, client_port);
    fflush(stdout);

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = ntohs(server_port);
    uint32_t server_ip_addr;
    if (inet_pton(AF_INET, server_ip, &server_ip_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        close(sockfd);
        return -1;
    }
    server_addr.sin_addr.s_addr = server_ip_addr; // Convert IP address to network byte order

    // print server_addr
    char temp_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &server_addr.sin_addr, temp_ip_str, sizeof(temp_ip_str));
    printf("Client to connect to %s:%d\n", temp_ip_str, ntohs(server_addr.sin_port));
    fflush(stdout);

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error connecting to server");
        close(sockfd);
        return -1;
    }
    printf("Client: connected to server %s:%d\n", server_ip, server_port);
    fflush(stdout);
    
    for(int i = 0; i < 10; i++) {
        char buffer[1024];
        snprintf(buffer, sizeof(buffer), "Hello from client %d", i);
        ssize_t bytes_sent = send(sockfd, buffer, sizeof(buffer), 0);
        if (bytes_sent < 0) {
            perror("Error sending data");
            break;
        }
        printf("Sent %zd bytes\n", bytes_sent);
    }
    close(sockfd); // Close the connection socket

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <host_name>\n", argv[0]);
        return 1;
    }

    if(strcmp(argv[1], "switch") == 0) {
        run_switch();
    } else if (strcmp(argv[1], "server") == 0) {
        run_server();
    } else if (strcmp(argv[1], "client") == 0) {
        run_client();
    } else {
        fprintf(stderr, "Unknown argument: %s\n", argv[1]);
        return 1;
    }

    return 0;
}