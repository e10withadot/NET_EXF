'''
Packet sniffer. Sniffs packets to get IP, TCP, and TLS headers, packet inter-arrivals, flow size, and flow volume.
'''
from sys import exit
import scapy.all as scapy
from scapy.layers.tls.all import TLS
from scapy.layers.inet import IP, TCP
from scapy.sessions import TCPSession
import time

# global variables
start_time: float
flow_volume: int
flow_size: int

def write_to_file(packet: scapy.Packet):
    if packet.haslayer(TCP) and packet.haslayer(TLS):
        # calculate packet inter-arrivals
        inter_arrival: str = None
        if start_time:
            end_time = time.time()
            inter_arrival = (str)(end_time - start_time)
            start_time= end_time
        else:
            start_time= time.time()
        # Packet data
        ip_header = f'''
##### IP Header
**Version:** {packet[IP].version}
**Internet Header Length:** {packet[IP].ihl}
**Type of Service:** {packet[IP].tos}
**Total Length:** {packet[IP].len}
**Identification:** {packet[IP].id}
**IP Flags:** {packet[IP].flags}
**Fragment Offset:** {packet[IP].frag}
**Time to Live(TTL):** {packet[IP].ttl}
**Protocol:** {packet[IP].proto}
**Header Checksum:** {packet[IP].chksum}
**Source Address:** {packet[IP].src}
**Destination Address:** {packet[IP].dst}
**IP Options:** {packet[IP].options}\n
        '''
        tcp_header = f'''
##### TCP Header
**Source Port:** {packet[TCP].sport}
**Destination Port:** {packet[TCP].dport}
**Sequence:** {packet[TCP].seq}
**ACK:** {packet[TCP].ack}
**TCP Header Length:** {packet[TCP].dataofs}
**Reserved:** {packet[TCP].reserved}
**TCP Flags:** {packet[TCP].flags}
**TCP Window:** {packet[TCP].window}
**Header Checksum:** {packet[TCP].chksum}
**Urgent Pointer:** {packet[TCP].urgptr}
**TCP Options:** {packet[TCP].options}\n
        '''
        tls_header = f'''
##### TLS Header
**Content Type:** {packet[TLS].type}
**Version:** {packet[TLS].version}
**TLS Header Length:** {packet[TLS].len}
**IV:** {packet[TLS].iv}
**Message List:** {packet[TLS].msg}
**MAC:** {packet[TLS].mac}
**Padding:** {packet[TLS].pad}
**Padding Length:** {packet[TLS].padlen}\n
        '''
        misc = f'''
##### Miscellanous Data
**Packet Size:** {len(packet)}
**Packet Inter-Arrival:** {inter_arrival} sec
---------------------------------------------\n
        '''
        # write to file
        with open('output.md', 'a') as output:
            output.write(ip_header+tcp_header+tls_header+misc)
        # adjust global values
        flow_size+=1
        flow_volume+=len(packet)
try:
    scapy.sniff(session= TCPSession, iface= "eth0", prn= lambda pkt: write_to_file(pkt), store= 0)
except KeyboardInterrupt:
    # write global data
    data = f'''
##### Global Data
**Flow Volume:** {flow_volume}
**Flow Size:** {flow_size}
    '''
    with open('output.md', 'a') as output:
        output.write()
    # finish
    print("Done.")
    exit(0)