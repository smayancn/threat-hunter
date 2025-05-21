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
- It leverages Scapy for its powerful packet dissection capabilities, which simplifies the extraction of detailed protocol information compared to lower-level approaches like raw sockets that would require manual parsing of packet headers.
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

# Network Threat Detection ML Demonstration

This project demonstrates how more detailed network packet data, specifically from an enhanced packet sniffer (`colab.py`), leads to significantly better Machine Learning-based threat detection compared to a basic sniffer (`sniffer.py`).

## Project Components

1.  **Packet Sniffers**:
    *   `threat-hunter/sniffer.py`: A basic network packet capture tool. It extracts fundamental packet information (IPs, ports, basic protocol, length, simple TCP flags) and saves it to a CSV (e.g., `capture_20250521-222829.csv`).
    *   `threat-hunter/colab.py`: An advanced network packet capture tool. This sniffer goes much deeper, extracting protocol-specific details for TCP, UDP, DNS, HTTP, TLS, ICMP, ARP, DHCP, and SNMP. It provides a rich, contextual dataset (e.g., `network_logs.csv`).

2.  **Machine Learning Threat Detector (`threat_detector.py`)**:
    *   A Python script that implements a robust ML pipeline using `scikit-learn`.
    *   It can train and evaluate two separate Random Forest models:
        *   One model using the basic data from `sniffer.py`.
        *   Another model using the detailed data from `colab.py`.
    *   The script is designed to explicitly compare the performance of these two models, showcasing the accuracy improvement gained from the detailed dataset.
    *   Refer to `ml_demo.md` for a detailed explanation of the ML model's architecture and functioning.

3.  **Demonstration Runner (`run_demo.py`)**:
    *   A utility script to automate the demonstration.
    *   It uses your pre-captured CSV files (`capture_20250521-222829.csv` for basic, `network_logs.csv` for detailed).
    *   Invokes `threat_detector.py` to train both models and generate a comparison report and visualizations.

## Core Concept: The Value of Detailed Packet Data

The primary goal of this project is to illustrate a crucial concept in network security and machine learning:

**The more context and detail you provide to a machine learning model, the better it can perform, especially in complex tasks like network threat detection.**

*   **Basic Sniffer (`sniffer.py`) Limitations**: While `sniffer.py` captures essential packet headers, it lacks the depth to understand the *behavior* within those packets. For an ML model, this means relying on very general patterns which might lead to higher false positives or missed threats.

*   **Advanced Sniffer (`colab.py`) Advantages**: `colab.py` excels by parsing deeper into various protocols. For example:
    *   **HTTP**: It extracts methods, hostnames, paths, and status codes.
    *   **DNS**: It identifies query names, types (e.g., A, AAAA, MX, TXT), and even response data.
    *   **TLS**: It can see the TLS version (flagging outdated, insecure versions), content types (handshake, application data), and handshake types (client hello, server hello).
    *   **ICMP**: It captures type and code, crucial for identifying pings, unreachable messages, or potential scanning activities.
    *   **Other Protocols**: It also pulls specific fields for ARP, DHCP, and SNMP.

This granular level of detail provides the ML model in `threat_detector.py` with a much richer feature set. The model can then learn more sophisticated and specific patterns that are indicative of malicious activity. For instance, it can learn that:

*   A DNS query to a known malicious TLD (e.g., `.xyz`, `.tk`) is suspicious.
*   An HTTP GET request to `/wp-login.php` followed by multiple failed login attempts (derived from subsequent packets if logs were stateful, or just the attempt itself) is a sign of a brute-force attack.
*   The use of an obsolete TLS version (e.g., TLS 1.0) is a security risk.
*   Certain ICMP type/code combinations can indicate network reconnaissance.

These are insights a model trained on basic data would likely miss, leading to the demonstrably higher accuracy of the model using `colab.py`'s output.

## How to Run the Demonstration

1.  **Prerequisites**:
    *   Python 3.x
    *   Required Python packages: `pandas`, `numpy`, `scikit-learn`, `matplotlib`, `seaborn`, `joblib`.
    *   Ensure `scapy` is installed for the sniffers (`pip install scapy`).
    *   (Optional but recommended for `sniffer.py` on Windows) `Npcap` for optimal packet capture: [Npcap Website](https://npcap.com/)

2.  **Prepare Data**:
    *   Ensure you have your two CSV datasets:
        *   `capture_20250521-222829.csv` (generated by `sniffer.py` or a similar basic tool).
        *   `network_logs.csv` (generated by `colab.py` or a similar detailed tool).
    *   Place these files in the root directory of the project, or specify their paths using command-line arguments when running `run_demo.py`.

3.  **Run the Demo Script**:
    Open your terminal in the project's root directory and execute:
    ```bash
    python run_demo.py
    ```
    *   To use different CSV files, you can specify them:
        ```bash
        python run_demo.py --basic-csv path/to/your/basic_data.csv --detailed-csv path/to/your/detailed_data.csv
        ```

4.  **Review Results**:
    *   The script will train both models and print a summary of their performance to the console.
    *   Detailed comparison results will be saved in `demo_output/models/comparison_results.txt`.
    *   Visualization plots (feature importance, confusion matrix, ROC curve) for each model will be saved in the `demo_output/models/` directory (e.g., `basic_model_threat_detection_results.png`, `detailed_model_threat_detection_results.png`).

## Expected Outcome

You should observe that the ML model trained with the detailed data from `network_logs.csv` (`colab.py`) achieves a noticeably higher accuracy and better overall performance in detecting network threats compared to the model trained with the basic data from `capture_20250521-222829.csv` (`sniffer.py`). This highlights the direct benefit of investing in more comprehensive network traffic data collection for building effective security analytics. 

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
