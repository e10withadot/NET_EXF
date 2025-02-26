'''
Packet sniffer. Sniffs packets to get IP, TCP, and TLS headers, packet inter-arrivals, flow size, and flow volume.
'''
import scapy.all as scapy
from scapy.layers.tls.all import TLS
from scapy.layers.inet import IP, TCP
from scapy.sessions import TCPSession
import time

class PacketSniffer:
    '''
    Sniffs packets and extracts data.
    '''
    def __init__(self):
        self.start_time: float = 0
        self.flow_volume: int = 0
        self.flow_size: int = 0

    def write_to_file(self, packet: scapy.Packet):
        '''
        Writes packet data to .md file.
        '''
        if packet.haslayer(TCP) and packet.haslayer(TLS):
            # calculate packet inter-arrivals
            inter_arrival: str = None
            if self.start_time:
                end_time = time.time()
                inter_arrival = (str)(end_time - self.start_time)
                self.start_time= end_time
            else:
                self.start_time= time.time()
            # Packet data
            pkt_head = f'## Packet {self.flow_size+1}'
            ip_header = f'''
### IP Header
**Version:** {packet[IP].version}\n
**Internet Header Length:** {packet[IP].ihl}\n
**Type of Service:** {packet[IP].tos}\n
**Total Length:** {packet[IP].len}\n
**Identification:** {packet[IP].id}\n
**IP Flags:** {packet[IP].flags}\n
**Fragment Offset:** {packet[IP].frag}\n
**Time to Live(TTL):** {packet[IP].ttl}\n
**Protocol:** {packet[IP].proto}\n
**Header Checksum:** {packet[IP].chksum}\n
**Source Address:** {packet[IP].src}\n
**Destination Address:** {packet[IP].dst}\n
**IP Options:** {packet[IP].options}\n'''
            tcp_header = f'''
### TCP Header
**Source Port:** {packet[TCP].sport}\n
**Destination Port:** {packet[TCP].dport}\n
**Sequence:** {packet[TCP].seq}\n
**ACK:** {packet[TCP].ack}\n
**TCP Header Length:** {packet[TCP].dataofs}\n
**Reserved:** {packet[TCP].reserved}\n
**TCP Flags:** {packet[TCP].flags}\n
**TCP Window:** {packet[TCP].window}\n
**Header Checksum:** {packet[TCP].chksum}\n
**Urgent Pointer:** {packet[TCP].urgptr}\n
**TCP Options:** {packet[TCP].options}\n'''
# **Message List:** {packet[TLS].msg}
            tls_header = f'''
### TLS Header
**Content Type:** {packet[TLS].type}\n
**Version:** {packet[TLS].version}\n
**TLS Header Length:** {packet[TLS].len}\n
**IV:** {packet[TLS].iv}\n
**MAC:** {packet[TLS].mac}\n
**Padding:** {packet[TLS].pad}\n
**Padding Length:** {packet[TLS].padlen}\n'''
            misc = f'''
### Miscellanous Data
**Packet Size:** {len(packet)}\n
**Packet Inter-Arrival:** {inter_arrival} sec\n\n'''
            # write to file
            with open('output.md', 'a') as output:
                output.write(pkt_head+ip_header+tcp_header+tls_header+misc)
            # adjust global values
            self.flow_size+=1
            self.flow_volume+=len(packet)

    def run(self):
        '''
        Run the Packet sniffer.
        '''
        try:
            scapy.sniff(session= TCPSession, iface= "eth0", prn= lambda pkt: self.write_to_file(pkt), store= 0)
        except KeyboardInterrupt:
            # write global data
            data = f'''
##### Global Data
**Flow Volume:** {self.flow_volume}
**Flow Size:** {self.flow_size}'''
            with open('output.md', 'a') as output:
                output.write()
            # finish
            print("Done.")
    
sniffer = PacketSniffer()
sniffer.run()