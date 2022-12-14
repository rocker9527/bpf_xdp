import argparse
from bcc import BPF
from pylibpcap import OpenPcap
import sys
import struct
import socket
import ctypes as ct
import time
import ipaddress

ETH_P_IP = 8
ETH_P_ARP = 1544
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ICMP = 1


parser = argparse.ArgumentParser(prog="filter")

parser.add_argument("iface", help="network interface to listen (e.g. eth0)", type=str)
parser.add_argument("-protocol", "--protocol", nargs="+", help="Specify protocol(s) and port(s), eg tcp:22, udp:53-63", type=str)
parser.add_argument("-p", "--port", nargs="+", help="Specify port(s)", type=int)
parser.add_argument("-c", "--capture", help="Capture to pcap file (deault dump.pcap)", type=str, default="dump.pcap")
parser.add_argument("-ip", "--ip", nargs="+", help="Specify ip-address(es)", type=str)
parser.add_argument("-mac", "--mac", nargs="+", help="Specify mac-address(es)", type=str)
args = parser.parse_args()


def clean_up(map):
    map.clear()


def parse_ports(ports_str):
    ports = ct.c_uint16(0)
    ports_str.split("-")
    for i in ports_str:
        if(int(i) < 0 or int(i) > 65536):
            sys.exit("Invalid port number")
        ports |= ct.c_uint16(int(i))
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


def get_ip(str_ips):
    ips = []
    for i in str_ips:
        ips.append(ct.c_uint16(int(ipaddress.ip_address(i))))
    return ips


def get_mac(str_macs):
    macs = []
    for i in str_macs:
        macs.append(ct.c_uint16(int(i.translate(None, ":.-"), 16)))
    return macs


def detach(device, b):
    print("Detaching from XDP hook...")
    b.remove_xdp(device, 0)
    print("done")


def pass_info_to_block_map(protocols, map):
    p = get_protocols(protocols)
    for i in p:
        map[ct.c_int(i)] = p[i]


def pass_info_to_ip_map(ips, map):
    p = get_ip(ips)
    for i in range(len(p)):
        map[ct.c_int(i)] = ct.c_uint16(p[i])


def pass_info_to_mac_map(macs, map):
    p = get_mac(macs)
    for i in range(len(p)):
        map[ct.c_int(i)] = ct.c_uint16(p[i])   

def store_raw_pkt(raw):
    with OpenPcap(args.capture, "a") as f:
        f.write(raw)


def callback(ctx, data, size):
    raw = b["packet"].event(data)
    store_raw_pkt(raw)

b = BPF(src_file="source_xdp.c")
fn = b.load_func("capture", BPF.XDP)
b.attach_xdp(args.iface, fn, 0)
pass_info_to_block_map(args.protocols, b["block"])
pass_info_to_ip_map(args.protocols, b["ip_b"])
pass_info_to_mac_map(args.protocols, b["mac_b"])
if(args.capture):
    b['packet'].open_ring_buffer(callback)


try:
    while 1:
        b.ring_buffer_poll()
except KeyboardInterrupt:
    count = b["drop_count"].items[0][0]
    print(f"\n{count} packets recieved by filter")
    clean_up(b["block"])
    clean_up(b["ip_b"])
    clean_up(b["mac_b"])
    sys.exit()


detach(b, args.iface)