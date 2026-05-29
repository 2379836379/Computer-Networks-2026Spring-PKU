from scapy.all import *


################################################################################
# Part 1. sniffing and Ethernet parsing 
################################################################################

Trace1 = "http.pcap"


from threading import Thread
from time import sleep
import requests


def MySniff():
    print("sniffing start")
    #################################
    ###### start of your code #######
    #################################
    packets = sniff(timeout = 5)
    print(len(packets))
    wrpcap(Trace1, packets)
    #################################
    ###### end of your code #########
    #################################
    print("sniffing stop")

    
def MyHttp():
    print("http start")
    x = requests.get('http://gaia.cs.umass.edu/wireshark-labs/HTTP-ethereal-lab-file3.html')
    print(x.status_code)
    sleep(1)
    print("http stop")


def Q1():
    t1 = Thread(target=MySniff)
    t2 = Thread(target=MyHttp)
    t1.start()
    sleep(1)
    t2.start()
    t2.join()
    t1.join()
    return "done"


def Q2():
    src_mac= ""
    dst_mac = ""
    #################################
    ###### start of your code #######
    #################################
    packets = rdpcap(Trace1)

    for pkt in packets:
        if pkt.haslayer(TCP):
            if pkt[TCP].dport == 80:
                src_mac = pkt.src
                dst_mac = pkt.dst
    #################################
    ###### end of your code #########
    #################################
    return src_mac, dst_mac
    


def Q3():    
    theType = 0
    theProto = 0    
    time = 0
    #################################
    ###### start of your code #######
    #################################
    packets = rdpcap(Trace1)

    for pkt in packets:
        if pkt.haslayer(TCP):
            if pkt[TCP].dport == 80:
                http_request = pkt
    
    req_src_ip = http_request[IP].src
    req_dst_ip = http_request[IP].dst
    req_src_port = http_request[TCP].sport
    req_dst_port = http_request[TCP].dport
    req_seq = http_request[TCP].seq
    
    # 查找对应的 ACK 应答
    for pkt in packets:
        if pkt.haslayer(TCP) and 'A' in pkt[TCP].flags:
            # 检查是否是对应的应答（IP和端口互换）
            if (pkt[IP].src == req_dst_ip and pkt[IP].dst == req_src_ip and
                pkt[TCP].sport == req_dst_port and pkt[TCP].dport == req_src_port):
                theType = pkt.type  # 二层 type
                theProto = pkt[IP].proto  # 三层 proto
                time = pkt.time  # 时间戳

    #################################
    ###### end of your code #########
    #################################
    return theType, theProto, time
            


################################################################################
# Part 2. Trace analysis 
################################################################################

Trace2='univ.pcap'

def Q4():
    theLength = 0
    #################################
    ###### start of your code #######
    #################################
    packets = rdpcap(Trace2)
    theLength = len(packets)
    #################################
    ###### end of your code #########
    #################################
    return theLength

def Q5():
    num_tcp = 0
    num_udp = 0
    num_ip = 0
    #################################
    ###### start of your code #######
    #################################
    packets = rdpcap(Trace2)
    theLength = len(packets)
    for pkt in packets:
        if pkt.haslayer(IP) or pkt.haslayer(IPv6):
            num_ip += 1
        if pkt.haslayer(TCP):
            num_tcp += 1
        if pkt.haslayer(UDP):
            num_udp += 1
    #################################
    ###### end of your code #########
    #################################
    return num_ip, num_tcp, num_udp

def Q6():
    flows = set()
    #################################
    ###### start of your code #######
    #################################
    packets = rdpcap(Trace2)   

    for pkt in packets:
        if pkt.haslayer(TCP):
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
            elif pkt.haslayer(IPv6):
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst
            else:
                continue
            
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            
            # 排序端点，确保无论哪个方向都得到相同的流标识
            flow_key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)]))
            flows.add(flow_key)
    #################################
    ###### end of your code #########
    #################################
    return len(flows)

def Q7():
    min_length = 0
    max_length = 0
    median_length = 0
    #################################
    ###### start of your code #######
    #################################
    packets = rdpcap(Trace2)
    packet_lengths = []

    for pkt in packets:
        if pkt.haslayer(IP):
            ip_total_len = pkt[IP].len
        elif pkt.haslayer(IPv6):
            ip_total_len = 40 + pkt[IPv6].plen
        else:
            continue

        # 统计链路层头部长度（Ethernet + optional VLAN tags），不包含 FCS。
        l2_header_len = 14 if pkt.haslayer(Ether) else 0
        payload = pkt.payload
        while isinstance(payload, Dot1Q):
            l2_header_len += 4
            payload = payload.payload

        packet_lengths.append(l2_header_len + ip_total_len)
    
    if not packet_lengths:
        return (0, 0, 0)

    packet_lengths.sort()
    min_length = packet_lengths[0]
    max_length = packet_lengths[-1]
    n = len(packet_lengths)
    if n % 2 == 1:
        median_length = packet_lengths[n // 2]
    else:
        median_length = (packet_lengths[n // 2 - 1] + packet_lengths[n // 2]) / 2
    #################################
    ###### end of your code #########
    #################################
    return min_length, median_length, max_length
