import argparse
from bcc import BPF
import sys
import struct
import socket
import ctypes as ct


ETH_P_IP = 8
ETH_P_ARP = 1544
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ICMP = 1


parser = argparse.ArgumentParser(prog="userspace")

parser.add_argument("iface", help="network interface to listen (e.g. eth0)", type=str)
parser.add_argument("-proto", "--protocol", nargs="+", help="Specify protocol(s) and port(s), eg tcp:22, udp:53-63", type=str)
parser.add_argument("-p", "--port", nargs="+", help="Specify port(s)", type=int)
parser.add_argument("-a", "--action", help="What to do? (listen, block)", type=str)
args = parser.parse_args()

print(args)

def parse_ports(ports_str):
    ports = ct.c_uint16(0)
    ports_str.split("-")
    for i in ports_str:
        ports = ports | ct.c_uint16(int(i))
    return ports


def get_protocols(protocols):
    protocols_checked = {}
    for i in protocols:
        i.split(":")
    for i in protocols:
        if(i[0].lower() == "eth" or i[0].lower() == "ethernet"):
            protocols_checked[-1] = parse_ports(i[1])
        if(i.lower() == "ip"):
            protocols_checked[ETH_P_IP] = parse_ports(i[1])
        if(i.lower() == "tcp"):
            protocols_checked[IPPROTO_TCP] = parse_ports(i[1])
        if(i.lower() == "udp"):
            protocols_checked[IPPROTO_UDP] = parse_ports(i[1])
        if(i.lower() == "icmp"):
            protocols_checked[IPPROTO_ICMP] = parse_ports(i[1])
        if(i.lower() == "arp"):
            protocols_checked[ETH_P_ARP] = parse_ports(i[1])
    return protocols_checked


def check_ports(ports):
    for i in ports:
        if(i < 0 or i > 65536):
            sys.exit("Invalid port number")



def pass_info_to_block_map(protocols, ports, map):
    for i in protocols:
        map[ct.c_int(i)] = ct.c_uint16(protocols)




b = BPF(src_file="source_xdp.c")
fn = b.load_func("capture", BPF.XDP)
b.attach_xdp(args.iface, fn, 0)




