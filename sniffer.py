'''
Packet sniffer. Sniffs packets to get IP, TCP, and TLS headers.
'''
import csv
import scapy.all as scapy
from scapy.layers.tls.all import TLS
from scapy.layers.inet import IP, TCP

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
    '''
    Interface for packet sniffing.
    '''
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
                        "TLS Header Length"
                    ])
                r_list= [
                    self.packet_no,
                    len(packet), 
                ]
                # find IP headers
                try:
                    r_list.extend([
                        packet[IP].version,
                        packet[IP].ihl,
                        packet[IP].tos,
                        len(packet[IP]),
                        packet[IP].id,
                        packet[IP].flags,
                        packet[IP].frag,
                        packet[IP].ttl,
                        packet[IP].proto,
                        packet[IP].chksum,
                        packet[IP].src,
                        packet[IP].dst,
                        packet[IP].options,
                    ])
                except:
                    raise OSError('Could not find IP header.')
                # find TCP headers
                try:
                    r_list.extend([
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
                    ])
                except:
                    raise OSError('Could not find TCP header.')
                try:
                    r_list.extend([
                        packet[TLS].type,
                        packet[TLS].version,
                        packet[TLS].len
                    ])
                except:
                    raise OSError('Could not find TLS header.')
                # row for current packet
                writer.writerow(r_list)
            # increase packet no
            self.packet_no+=1

    def run(self, iface: str):
        scapy.sniff(iface= iface, prn= lambda pkt: self.write_to_file(pkt), store= 0)
        
# get interface
if_list = scapy.get_if_list()
options = '\n'.join([f'\t({i}) {if_name}' for i, if_name in enumerate(if_list)])
try:
    c= int(input(f'Which interface would you like to use? (Ctrl + C to quit)\n{options}\n'))
except KeyboardInterrupt:
    print('\nOperation Cancelled.')
    exit()
# run packet sniffer
sniffer = PacketSniffer()
print("Started packet sniffing. (Ctrl + C to quit)")
try:
    sniffer.run(if_list[c])
except KeyboardInterrupt:
    exit()