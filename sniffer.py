# packet sniffing test
# NOT A COMPLETE PROGRAM, MERELY A TEST TO SEE HOW TO SNIFF PACKETS ON LINUX
# *sniff sniff*

from sys import exit
from scapy.layers.inet import IP, TCP
import scapy.all as sc

def print_packet(packet: sc.Packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        print(f'TCP: {src_ip}:{src_port} -> {dst_ip}:{dst_port}')

try:
    sc.sniff(iface= "eth0", prn= lambda pkt: print_packet(pkt), store= 0)
except KeyboardInterrupt:
    print("Done.")
    exit(0)