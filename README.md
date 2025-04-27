# Threat Hunter

A comprehensive network packet capture and analysis toolkit designed for threat detection and network monitoring.

## Features

- **Network Packet Capture**: Capture network packets from various interfaces with multiple capture methods
- **GUI Interface**: User-friendly interface for capturing, analyzing, and visualizing network traffic
- **Traffic Analysis**: Analyze captured traffic for suspicious activities and patterns
- **Protocol Support**: Detect and categorize various protocols (TCP, UDP, ICMP, HTTP, DNS, etc.)
- **Visualization**: Visualize network traffic patterns and protocol distribution
- **Suspicious Traffic Generator**: Test detection capabilities with simulated malicious traffic

## Components

- `sniffer.py` - Core packet capture functionality
- `analyzer.py` - Network traffic analysis tools
- `sniffer_gui.py` - Graphical user interface for the toolkit
- `sus-gen.py` - Suspicious traffic generator for testing

## Requirements

- Python 3.6+
- Required packages:
  - scapy
  - pandas
  - tkinter
  - matplotlib (optional, for visualization)
  - netifaces (optional, for better interface detection)

## Installation

```bash
# Clone the repository
git clone https://github.com/smayancn/threat-hunter.git
cd threat-hunter

# Install required dependencies
pip install scapy pandas matplotlib netifaces
```

## Usage

### GUI Application

```bash
python sniffer_gui.py
```

The GUI provides an intuitive interface to:
- Select network interfaces
- Configure capture settings
- Start/stop packet capture
- View and analyze captured packets
- Apply filters to captured traffic
- Visualize traffic statistics

### Command Line Capture

```bash
python sniffer.py [interface] [duration] [output_file]
```

Example:
```bash
python sniffer.py eth0 60 capture.csv
```

### Traffic Analysis

```bash
python analyzer.py capture.csv
```

### Generate Test Traffic (for testing detection capabilities)

```bash
python sus-gen.py [interface] [duration]
```
**Warning**: Only use the suspicious traffic generator in isolated test environments.

## Features in Detail

### Packet Capture
- Multiple capture methods (socket-based, scapy-based)
- Support for various network interfaces
- Packet filtering capabilities
- CSV output format

### Traffic Analysis
- Protocol distribution statistics
- Top source and destination IP addresses
- HTTP request analysis
- Traffic rate calculation

### GUI Features
- Dark/light theme support
- Real-time packet display
- Detailed packet inspection
- Protocol-based color coding
- Packet filtering
- CSV import/export

## License

See the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
