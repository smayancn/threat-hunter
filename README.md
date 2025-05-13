# Threat Hunter

A comprehensive network packet capture and analysis toolkit designed for threat detection, network monitoring, and security analysis.

## Core Features

### Packet Capture & Analysis
- Multiple capture methods (Scapy, raw sockets, tcpdump)
- Real-time packet processing and analysis
- Support for various network protocols (TCP, UDP, ICMP, HTTP, DNS, ARP, DHCP, SNMP, TLS)
- Packet filtering and sorting capabilities
- Detailed packet inspection and decoding

### GUI Interface
- Modern, user-friendly interface with dark/light theme support
- Real-time packet visualization
- Protocol-based color coding
- Advanced search and filtering
- Multiple view options (Raw, Hex, Decoded)
- Interactive charts and statistics

### Analytics & Reporting
- Protocol distribution analysis
- Traffic pattern detection
- Top talkers identification
- HTTP request analysis
- CSV import/export functionality
- Detailed traffic reports

### Testing & Simulation
- Suspicious traffic generation for testing
- Various attack pattern simulations
- Network stress testing capabilities
- Customizable test scenarios

## Project Structure

### Core Files

#### `sniffer.py`
Core packet capture engine with features:
- Multiple capture methods (Scapy, tcpdump, raw sockets)
- Interface detection and management
- Packet processing and analysis
- CSV output formatting
- Capture statistics and reporting
- Cross-platform support

Key functions:
- `capture_network_details()`: Main capture function
- `_capture_with_scapy()`: Scapy-based capture
- `_capture_with_tcpdump()`: tcpdump-based capture
- `capture_with_socket()`: Raw socket capture
- `get_available_interfaces()`: Network interface detection

#### `analyzer.py`
Network traffic analysis module with features:
- Traffic pattern analysis
- Protocol distribution statistics
- IP address analysis
- HTTP traffic analysis
- Report generation

Key functions:
- `analyze_network_traffic()`: Main analysis function
- `format_analysis_report()`: Report formatting
- Statistical analysis of captured data
- Top talkers identification
- Protocol distribution calculation

#### `sniffer_gui.py`
Graphical user interface with features:
- Real-time packet display
- Multiple view options
- Advanced filtering
- Protocol-based coloring
- Interactive charts
- Dark/light theme support
- CSV import/export

Key components:
- Packet list view with sorting
- Detailed packet inspection
- Protocol distribution charts
- Search and filter capabilities

#### `colab.py`
- A Python script designed for capturing network packets using Scapy.
- Processes captured packets in real-time to extract detailed information.
- Supports a wide range of protocols including Ether, IP, TCP, UDP, HTTP, DNS, ICMP, ARP, DHCP, SNMP, and TLS.
- Extracts protocol-specific fields (e.g., HTTP method/host, DNS query/answer, ICMP type/code, ARP opcodes, DHCP message types, SNMP details, TLS handshake info).
- Saves the processed packet data into a CSV file for further analysis.
- Useful for network monitoring, basic traffic analysis, and educational purposes.
- Includes functionality to suppress Scapy's default output during capture for a cleaner user experience.

#### `sus-gen.py`
Suspicious traffic generator for testing with features:
- Various attack pattern simulations
- Network stress testing
- Customizable packet generation
- Multiple protocol support

Key functions:
- `send_malformed_ip_extreme()`: Malformed IP packets
- `send_christmas_tree_extreme()`: TCP Christmas Tree packets
- `send_impossible_packet_combo()`: Invalid packet combinations
- `send_highly_fragmented()`: Fragmentation testing
- `send_invalid_icmp()`: ICMP attack simulation

## Installation

### Requirements
- Python 3.6+
- Required packages:
  ```
  scapy>=2.4.5
  pandas>=1.3.0
  tkinter
  matplotlib>=3.4.0
  netifaces>=0.11.0
  ```

### Setup
```bash
# Clone the repository
git clone https://github.com/smayancn/threat-hunter.git
cd threat-hunter

# Install dependencies
pip install -r requirements.txt
```

## Usage

### GUI Application
```bash
python sniffer_gui.py
```

### Command Line Capture
```bash
python sniffer.py [interface] [duration] [output_file]
```

### Traffic Analysis
```bash
python analyzer.py [capture_file.csv]
```

### Generate Test Traffic
```bash
python sus-gen.py [interface] [duration]
```

## Keyboard Shortcuts

- `Ctrl + F`: Focus search
- `F5`: Start capture
- `F6`: Stop capture
- `Ctrl + L`: Clear display
- `Ctrl + C`: Copy selected packet
- `Delete`: Remove selected packet
- `Ctrl + S`: Save capture
- `Ctrl + O`: Open capture file

## Advanced Features

### Packet Filtering
- Protocol-based filtering
- IP address filtering
- Port-based filtering
- Custom regex filters
- Real-time search

### Analysis Capabilities
- Protocol distribution
- Traffic patterns
- Top talkers
- HTTP analysis
- Suspicious activity detection

### Visualization
- Protocol charts
- Traffic flow diagrams
- Real-time statistics
- Custom color schemes
- Interactive graphs

## Security Notice

The suspicious traffic generator (`sus-gen.py`) is intended for testing purposes only. Use it responsibly and only in controlled environments.

## Contributing

Contributions are welcome! Please follow these steps:
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
