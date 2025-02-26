'''
Packet sniffer. Sniffs packets to get IP, TCP, and TLS headers, packet inter-arrivals, flow size, and flow volume.
'''
import csv
import scapy.all as scapy
from scapy.layers.tls.all import TLS
from scapy.layers.inet import IP, TCP
from scapy.sessions import TCPSession

def file_is_empty(filename: str) -> bool:
    '''
    Returns True if file is empty or doesn't exist, false otherwise.
    '''
    try:
        with open(filename, 'r') as file:
            first_char = file.read(1)
            if not first_char:
                return True
        return False
    except FileNotFoundError:
        return True

class PacketSniffer:
    def __init__(self):
        self.packet_no: int = 0
    
    def write_to_file(self, packet: scapy.Packet):
        '''
        Writes packet data to a .csv file.
        '''
        if packet.haslayer(TCP) and packet.haslayer(TLS):
            # write to file
            is_empty = file_is_empty('packets.csv')
            with open('packets.csv', 'a') as packets:
                writer= csv.writer(packets, delimiter=',')
                # write first row if needed
                if is_empty:
                    writer.writerow([
                        "Packet No.",
                        "Packet Size",
                        "IP Version",
                        "Internet Header Length(IHL)",
                        "Type of Service",
                        "IP Packet Length",
                        "Identification",
                        "IP Flags",
                        "Fragment Offset",
                        "Time to Live(TTL)",
                        "Protocol",
                        "IP Checksum",
                        "Source Address",
                        "Destination Address",
                        "IP Options",
                        "Source Port",
                        "Destination Port",
                        "Seq",
                        "ACK",
                        "TCP Header Length",
                        "Reserved",
                        "TCP Flags",
                        "TCP Window",
                        "TCP Checksum",
                        "Urgent Pointer",
                        "TCP Options",
                        "Content Type",
                        "TLS Version",
                        "TLS Header Length",
                        "IV",
                        "MAC",
                        "TLS Padding",
                        "TLS Padding Length"
                    ])
                # row for current packet
                writer.writerow([
                    self.packet_no,
                    len(packet),
                    packet[IP].version,
                    packet[IP].ihl,
                    packet[IP].tos,
                    packet[IP].len,
                    packet[IP].id,
                    packet[IP].flags,
                    packet[IP].frag,
                    packet[IP].ttl,
                    packet[IP].proto,
                    packet[IP].chksum,
                    packet[IP].src,
                    packet[IP].dst,
                    packet[IP].options,
                    packet[TCP].sport,
                    packet[TCP].dport,
                    packet[TCP].seq,
                    packet[TCP].ack,
                    packet[TCP].dataofs,
                    packet[TCP].reserved,
                    packet[TCP].flags,
                    packet[TCP].window,
                    packet[TCP].chksum,
                    packet[TCP].urgptr,
                    packet[TCP].options,
                    packet[TLS].type,
                    packet[TLS].version,
                    packet[TLS].len,
                    packet[TLS].iv,
                    packet[TLS].mac,
                    packet[TLS].pad,
                    packet[TLS].padlen
                ])
            # increase packet no
            self.packet_no+=1

    def run(self):
        try:
            scapy.sniff(session= TCPSession, iface= "eth0", prn= lambda pkt: self.write_to_file(pkt), store= 0)
        except KeyboardInterrupt:
            # finish
            print("Done.")

sniffer = PacketSniffer()
print("Started packet sniffing. Ctrl + C to quit.")
sniffer.run()