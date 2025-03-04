# Python Scripts
## Explanation
### `sniffer.py`
Sniffs TCP packets from the selected interface and extracts the following information into a 'packets.csv' file:
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
### `plotter.py`
Creates plots based on the information given in the `packets.csv` file. You can choose any field from the csv file, and have it generate a bar graph in relation with the number of packets that include that field.
## Running the Python scripts
### Dependencies
- `sniffer.py` uses `scapy` for packet sniffing.
- `plotter.py` uses `matplotlib` for graph plotting.

Both can be installed with:
```bash
python -m pip install [package]
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
###### if 'python3' doesn't work, use 'python'
