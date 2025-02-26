'''
Packet sniffer. Sniffs packets to get IP, TCP, and TLS headers, packet inter-arrivals, flow size, and flow volume.
'''
from sys import exit
from scapy.layers.tls.all import TLS
from scapy.layers.inet import IP, TCP
from scapy.sessions import TCPSession
import scapy.all as scapy

def print_packet(packet: scapy.Packet):
    if packet.haslayer(TCP) and packet.haslayer(TLS):
        # IP Header
        ip_ver = packet[IP].version
        inter_head_len = packet[IP].ihl
        type_of_service = packet[IP].tos
        length = packet[IP].len
        id = packet[IP].id
        ip_flags = packet[IP].flags
        frag_off = packet[IP].frag
        time_to_live = packet[IP].ttl
        protocol = packet[IP].proto
        ip_chksum = packet[IP].chksum
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        ip_options = packet[IP].options
        # TCP Header
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        sequence = packet[TCP].seq
        acknowledgement = packet[TCP].ack
        tcp_do = packet[TCP].dataofs
        reserve = packet[TCP].reserved
        tcp_flags = packet[TCP].flags
        tcp_window = packet[TCP].window
        tcp_chksum = packet[TCP].chksum
        urgent_pointer = packet[TCP].urgptr
        tcp_options = packet[TCP].options
        # TLS Header
        tls_type = packet[TLS].type
        tls_ver = packet[TLS].version
        tls_len = packet[TLS].len
        tls_iv = packet[TLS].iv
        tls_msglist = packet[TLS].msg
        mac_addr = packet[TLS].mac
        tls_padding = packet[TLS].pad
        tls_padlen = packet[TLS].padlen
        print(f'TCP: {src_ip}:{src_port} -> {dst_ip}:{dst_port}')
try:
    scapy.sniff(session= TCPSession, iface= "eth0", prn= lambda pkt: print_packet(pkt), store= 0)
except KeyboardInterrupt:
    print("Done.")
    exit(0)