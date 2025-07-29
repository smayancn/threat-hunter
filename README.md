# 🛡️ FlowInspect: Real-Time Packet Analysis Framework

A comprehensive network packet capture and analysis toolkit designed for threat detection, network monitoring, and security analysis with advanced machine learning capabilities.

## 🎯 **Core Capabilities**

### **Multi-Method Packet Capture**
- **Scapy-based capture** (primary method with full protocol support)
- **Raw socket capture** (low-level, cross-platform)
- **tcpdump integration** (fallback method)
- **Real-time processing** with threaded packet handling
- **Interface auto-detection** (Windows/Linux/macOS)

### **Protocol Support Matrix**
| **Layer** | **Protocols** |
|-----------|---------------|
| **Application** | HTTP, HTTPS, DNS, DHCP, SNMP, FTP, SSH, TLS |
| **Transport** | TCP (with flags), UDP, SCTP |
| **Network** | IP, ICMP, IPv6-ICMP, IGMP, OSPF |
| **Data Link** | Ethernet, ARP |
| **Security** | ESP, AH, GRE |

## 🖥️ **User Interfaces**

### **GUI Application (`sniffer_gui.py`)**
- **Real-time packet visualization** with color-coded protocols
- **Multiple view modes**: Raw, Hex, Decoded, Technical, User-friendly
- **Advanced filtering**: Protocol, IP, port, regex-based
- **Dark/Light theme** support
- **Interactive charts** and statistics
- **CSV import/export** functionality
- **Wireshark-style** packet inspection

### **Command Line (`sniffer.py`)**
- **Interactive mode** with interface selection
- **Batch mode** with arguments
- **Compact version** (235 lines, 87% size reduction)
- **Cross-platform** compatibility

## 📊 **Analysis & Intelligence**

### **Traffic Analysis (`analyzer.py`)**
- **Protocol distribution** statistics
- **Top talkers** identification (IPs, ports)
- **Traffic pattern** detection
- **HTTP request** analysis
- **Bandwidth utilization** metrics
- **Detailed reporting** with visualizations

### **Machine Learning Threat Detection (`threat_detector.py`)**
- **Dual-model comparison**: Basic vs. Advanced data
- **Random Forest** classification
- **Feature engineering**: 40+ extracted features
- **Threat scoring** and classification
- **Performance metrics**: Accuracy, precision, recall, F1-score
- **Suspicious pattern detection**:
  - DNS queries to malicious TLDs
  - HTTP attacks (SQL injection, XSS)
  - Port scanning attempts
  - Unusual flag combinations

## 🔍 **Deep Packet Inspection**

### **Protocol-Specific Analysis**
- **TCP**: Flag analysis (SYN, ACK, FIN, RST, PSH, URG, ECE, CWR)
- **HTTP**: Methods, headers, paths, status codes
- **DNS**: Query types (A, AAAA, MX, TXT), responses
- **TLS**: Version detection, handshake analysis
- **ICMP**: Type/code identification
- **ARP**: Operation codes and mappings

### **Security Features**
- **Attack detection**: Port scans, DDoS, malformed packets
- **Encryption analysis**: Secure vs. insecure protocols
- **Packet direction**: Inbound/outbound/local/external
- **Anomaly detection**: Unusual patterns and behaviors

## 🧪 **Testing & Simulation**

### **Suspicious Traffic Generator (`sus-gen.py`)**
- **Attack simulations**: Christmas Tree, NULL scans
- **Malformed packets**: Invalid headers, impossible combinations
- **Stress testing**: High-volume traffic generation
- **Protocol-specific attacks**: DNS flooding, HTTP exploits
- **Network reconnaissance**: Port scanning patterns

## 📈 **Data Management**

### **Export Formats**
- **CSV output** with comprehensive packet details
- **Real-time statistics** tracking
- **Protocol charts** and visualizations
- **Detailed reports** with threat analysis

### **Data Fields Captured**
```
Timestamp, Source/Dest MAC, Source/Dest IP, Source/Dest Port,
Protocol, Length, TTL, TCP Flags, Window Size, ICMP Type/Code,
DNS Query, HTTP Method/Host/Path, Packet Direction, TLS Info
```

## 🎯 **Machine Learning Demonstration**

### **Core Concept: Value of Detailed Packet Data**
This project demonstrates how **detailed network packet data** leads to significantly better ML-based threat detection compared to basic packet capture.

### **Comparison Models**
1. **Basic Model** (`sniffer.py` → `capture_20250521-222829.csv`)
   - Extracts fundamental packet information (IPs, ports, basic protocol, length)
   - Limited feature set for ML training

2. **Advanced Model** (`colab.py` → `network_logs.csv`)
   - Extracts 40+ detailed protocol-specific features
   - Rich contextual dataset for superior ML performance

### **Enhanced Detection Capabilities**
The advanced model can identify:
- DNS queries to malicious TLDs (`.xyz`, `.tk`, `.pw`)
- HTTP attacks targeting `/wp-login.php`, `/admin`, `/shell`
- Obsolete TLS versions indicating security risks
- ICMP patterns suggesting network reconnaissance
- Sophisticated attack patterns missed by basic analysis

**Result**: The ML model trained with detailed data achieves **noticeably higher accuracy** and better overall performance in detecting network threats.

## 🚀 **Installation & Setup**

### **Requirements**
- Python 3.6+
- Administrative privileges for packet capture
- Required packages:
  ```
  scapy>=2.4.5
  pandas>=1.3.0
  scikit-learn>=1.0.0
  matplotlib>=3.4.0
  tkinter
  netifaces>=0.11.0
  ```

### **Quick Start**
```bash
# Clone the repository
git clone https://github.com/smayancn/threat-hunter.git
cd threat-hunter

# Install dependencies
pip install -r requirements.txt

# Run GUI application
python sniffer_gui.py

# Or run command line capture
python sniffer.py
```

## 📖 **Usage Examples**

### **GUI Application**
```bash
python sniffer_gui.py
```

### **Command Line Capture**
```bash
# Interactive mode
python sniffer.py

# Specific interface and duration
python sniffer.py -i "WiFi" -t 60 -o capture_results

# Packet count limit
python sniffer.py -c 1000 -m scapy
```

### **Traffic Analysis**
```bash
python analyzer.py capture_file.csv
```

### **ML Threat Detection Demo**
```bash
# Run complete ML demonstration
python run_demo.py

# Custom datasets
python run_demo.py --basic-csv basic_data.csv --detailed-csv detailed_data.csv
```

### **Generate Test Traffic**
```bash
python sus-gen.py [interface] [duration]
```

## ⌨️ **Keyboard Shortcuts**

| **Shortcut** | **Action** |
|--------------|------------|
| `Ctrl + F` | Focus search |
| `F5` | Start capture |
| `F6` | Stop capture |
| `Ctrl + L` | Clear display |
| `Ctrl + C` | Copy selected packet |
| `Delete` | Remove selected packet |
| `Ctrl + S` | Save capture |
| `Ctrl + O` | Open capture file |

## 🔧 **Advanced Features**

### **Packet Filtering**
- Protocol-based filtering (TCP, UDP, HTTP, DNS, etc.)
- IP address and port filtering
- Custom regex filters
- Real-time search with instant results

### **Visualization**
- Protocol distribution charts
- Traffic flow diagrams
- Real-time statistics dashboard
- Interactive graphs with drill-down capability
- Custom color schemes for protocol identification

### **Security Analysis**
- Intrusion detection with ML-based threat scoring
- Traffic baseline establishment
- Anomaly identification in network patterns
- Behavioral analysis of network communications
- IoC (Indicators of Compromise) detection

## 🛡️ **Security Applications**

### **Network Monitoring**
- **Intrusion detection** with ML-based threat scoring
- **Traffic baseline** establishment
- **Anomaly identification** in network patterns
- **Compliance monitoring** for security policies

### **Threat Hunting**
- **Behavioral analysis** of network communications
- **IoC detection** (Indicators of Compromise)
- **Attack pattern** recognition
- **Forensic analysis** with detailed packet inspection

### **Educational Use**
- **Protocol learning** with user-friendly explanations
- **Network security training** with real packet examples
- **Hands-on experience** with packet analysis techniques

## ⚠️ **Security Notice**

The suspicious traffic generator (`sus-gen.py`) is intended for **testing purposes only**. Use it responsibly and only in controlled environments. Always ensure you have proper authorization before capturing network traffic.

## 🤝 **Contributing**

Contributions are welcome! Please follow these steps:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Create a Pull Request

## 📄 **License**

This project is licensed under the MIT License - see the LICENSE file for details.

---

**🎯 Key Differentiator**: The advanced sniffer (`colab.py`) extracts **40+ detailed features** compared to basic tools, resulting in **significantly higher ML threat detection accuracy** - demonstrating the critical importance of comprehensive packet analysis for effective network security.
