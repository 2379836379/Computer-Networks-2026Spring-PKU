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
    pass
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
    pass
    #################################
    ###### end of your code #########
    #################################
    return src_mac, dst_mac
    


def Q3():    
    theType = 0
    theProto = 0    
    #################################
    ###### start of your code #######
    #################################
    pass
    #################################
    ###### end of your code #########
    #################################
    return theType, theProto
            


################################################################################
# Part 2. Trace analysis 
################################################################################

Trace2='univ.pcap'

def Q4():
    theLength = 0
    #################################
    ###### start of your code #######
    #################################
    pass
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
    pass
    #################################
    ###### end of your code #########
    #################################
    return num_ip, num_tcp, num_udp

def Q6():
    flows = set()
    #################################
    ###### start of your code #######
    #################################
    pass
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
    pass
    #################################
    ###### end of your code #########
    #################################
    return min_length, median_length, max_length

