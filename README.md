# Project Summary
This is our final assignment for the Communication Networks course in Ariel University. It includes answers to questions about the Internet Layer, Transport Layer, and Application Layer. It also summarizes 3 articles concerning improving and iterating on these technologies, and an analysis of internet traffic with graphs, which use the Python scripts in this repository.
# Python Scripts
## Explanation
### `sniffer.py`
Sniffs TCP packets from the selected interface and extracts the following fields into a 'packets.csv' file:
- **Packet No.**
- **Packet Size**
- **IP Version**
- **Internet Header Length (IHL)**
- **Type of Service**
- **IP Packet Length**
- **Identification**
- **IP Flags**
- **Fragment Offset**
- **Time to Live (TTL)**
- **Protocol**
- **IP Checksum**
- **Source Address**
- **Destination Address**
- **IP Options**
- **Source Port**
- **Destination Port**
- **Sequence Number (Seq)**
- **Acknowledgment Number (ACK)**
- **TCP Header Length**
- **Reserved**
- **TCP Flags**
- **TCP Window**
- **TCP Checksum**
- **Urgent Pointer**
- **TCP Options**
- **Content Type**
- **TLS Version**
- **TLS Header Length**
###### If you want to record packets for different actions separately, please delete or move the existing `packets.csv` file before sniffing. If you don't do this, the new packet information will append to the end of the existing file.
#### Exceptions
When using the sniffer, the following exceptions may occur:
**OSError: Could not find IP Header-** The sniffer was unable to read data from the IP header. This could be because the IP header doesn't exist in the given packet, either because it's not a TCP packet, it came out fragmented, or is a NoneType.
**OSError: Could not find TCP Header-** The sniffer was unable to read data from the TCP header. This could be because the TCP header doesn't exist in the given packet, either because it's not a TCP packet, it came out fragmented, or is a NoneType.
**OSError: Could not find TLS Header-** The sniffer was unable to read data from the TLS header. This could be because the TLS header doesn't exist in the given packet, either because it's not a TCP packet, it came out fragmented, or is a NoneType.
### `plotter.py`
Creates plots based on the information given in the `packets.csv` file. You can choose any field from the csv file, and have it generate a bar graph in relation with the number of packets that include that field.
## Running the Python scripts
### Dependencies
- `sniffer.py` uses `scapy` for packet sniffing.
- `plotter.py` uses `matplotlib` for graph plotting.

Both can be installed with :
```bash
python3 -m pip install [package]
```
### How to run
#### `sniffer.py`
```bash
sudo python3 sniffer.py
```
#### `plotter.py`
```bash
python3 plotter.py
```
###### If 'python3' doesn't work, use 'python'
