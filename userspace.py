from bcc import BPF
from bcc.utils import printb
import time
import struct
import socket

CLEANUP_PACKETS = 10
MAX_AGE = 10


device = "enp0s6"
b = BPF(src_file="source_xdp.c")
fn = b.load_func("capture", BPF.XDP)
b.attach_xdp(device, fn, 0)

while 1:
    l2 = b.get_table("l2")
    l3_ip = b.get_table("l3_ip")
    l4_tcp = b.get_table("l4_tcp")
    l4_udp = b.get_table("l4_udp")

    if(len(l3_ip.items()) != 0): 
        print("====================")
        ip = l3_ip.items()[0][0]
        print(f"IP ADDR_S: {socket.inet_ntoa(struct.pack('!I', ip.saddr))} ADDR_D: {socket.inet_ntoa(struct.pack('!I', ip.daddr))}")
        if(len(l4_tcp.items()) != 0):
            tcp = l4_tcp.items()[0][0]
            print(f"TCP PORT_S: {int.from_bytes(struct.pack('!I', tcp.source), 'big')} DEST_D: {int.from_bytes(struct.pack('!I', tcp.dest), 'big')}")
        if(len(l4_udp.items()) != 0):
            udp = l4_udp.items()[0][0]
            print(f"UDP PORT_S: {int.from_bytes(struct.pack('!I', udp.source), 'big')} DEST_D: {int.from_bytes(struct.pack('!I', udp.dest), 'big')}")
    l2.clear()
    l3_ip.clear()
    l4_tcp.clear()
    l4_udp.clear()

b.remove_xdp(device, 0)
