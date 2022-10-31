from ctypes import c_int, c_uint, c_uint64
from ssl import PROTOCOL_TLS
from bcc import BPF
from sys import argv
import struct
import socket
import ctypes as ct


ETH_P_IP = 8
IPPROTO_TCP = 6
IPPROTO_UDP = 17


def help():
    print("USAGE: %s [-b block protocol] [--p port] [--a ip adress]" % argv[0])
    exit()

def usage():
    print("USAGE: %s" % argv[0])
    print("Try '%s -h' for more options." % argv[0])
    exit()


def clean_up(*argv):
    for arg in argv:
        arg.clear()

ports = []
prtcls = []
adrs = []

'''
 can pass as many same args as I want
 can't pass several protocols and several ports
'''
if len(argv) > 1: 
    if(argv[1] == "-b"):
        if(argv[2] == "tcp"):
            prtcls.append(IPPROTO_TCP)
        if(argv[2] == "udp"):
            prtcls.append(IPPROTO_UDP)
        if(argv[2] == "ip"):
            prtcls.append(ETH_P_IP)
        for i in range(2,len(argv)):
            if(argv[i] == "-p" and argv[i+1].isdigit()):
                if(1 <= int(argv[i+1]) <= 65535):
                    ports.append(int(argv[i+1]))
    else:    
        usage()


device = "enp0s6"
b = BPF(src_file="source_xdp.c")
fn = b.load_func("capture", BPF.XDP)
b.attach_xdp(device, fn, 0)
print(prtcls)
print(ports)
for p in prtcls:
    b["block_proto"].push(ct.c_int(p))
for p in ports:
    b["block_port"].push(ct.c_int(p))


pkts_count = 0
try:
    while 1:
        #b.trace_print()
        l2 = b.get_table("l2")
        l3_ip = b.get_table("l3_ip")
        l4_tcp = b.get_table("l4_tcp")
        l4_udp = b.get_table("l4_udp") 
        if(len(l3_ip.items()) != 0):  
            pkts_count += 1
            print("====================")
            ip = l3_ip.items()[0][0]
            print(f"IP  [ADDR_S: {socket.inet_ntoa(struct.pack('!I', ip.saddr))}, ADDR_D: {socket.inet_ntoa(struct.pack('!I', ip.daddr))}, ttl: {ip.ttl}, id: {ip.id}, len: {ip.tot_len}, id: {ip.id}]")
            if(len(l4_tcp.items()) != 0):
                tcp = l4_tcp.items()[0][0]
                flags = ""
                if(tcp.fin):
                    flags += 'F,'
                if(tcp.syn):
                    flags += 'S,'
                if(tcp.rst):
                    flags += 'R,'
                if(tcp.psh):
                    flags += 'P,'
                if(tcp.ack):
                    flags += 'A,'
                if(tcp.urg):
                    flags += 'U,'
                if(tcp.ece):
                    flags += 'E,'
                if(tcp.cwr):
                    flags += 'E,'
                flags = flags[:-1]
                print(f"TCP [PORT_S: {tcp.source}, PORT_D: {tcp.dest}, FLAGS[{flags}], ack: {tcp.ack_seq}, seq: {tcp.seq}]")
            elif(len(l4_udp.items()) != 0):
                udp = l4_udp.items()[0][0]
                print(f"UDP [PORT_S: {udp.source}, PORT_D: {udp.dest}]")
        clean_up(b["l2"], b["l3_ip"], b["l4_tcp"], b["l4_udp"])
except KeyboardInterrupt:
    print(f"\n{pkts_count} packets recieved by filter")
    clean_up(b["l2"], b["l3_ip"], b["l4_tcp"], b["l4_udp"])

b.remove_xdp(device, 0)
