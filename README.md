# Threat Hunter

A comprehensive network traffic analysis and threat detection system combining rule-based and machine learning approaches to identify suspicious network activity in real-time.

## 🔍 Project Overview

This project offers a dual-approach network security solution:

1. **Rule-Based Detection**: Identifies suspicious traffic using known patterns, flag combinations, and port analysis
2. **Machine Learning Detection**: Uses adaptive models to identify anomalies and predict traffic patterns

Unlike traditional security tools, Threat Hunter:
- Works with standard packet capture formats and Zeek logs
- Detects both known attack signatures and novel threats
- Provides clear context about why traffic is flagged
- Adapts over time through continuous learning

## ⚙️ Components

### 1. Network Traffic Capture
- `sniff1.py`: Packet sniffer that captures network traffic and saves to CSV
- Compatible with Wireshark/Zeek logs and other network captures

### 2. Analysis & Detection
- `network_ml.py`: The core analysis engine with two detection methods:
  - **Simple Rule-Based Detection**: Analyzes TCP flags, ports, and traffic patterns
  - **Machine Learning Models**: Random Forest for direction prediction, Isolation Forest for anomaly detection

### 3. Real-Time Monitoring
- `sniff_predict.py`: Captures and analyzes packets in real-time with the trained model

## 🛡️ Detection Capabilities

### Flag-Based Detection
- SYN+FIN combinations (common in scanning)
- XMAS scan detection (FIN+PSH+URG)
- NULL scan detection
- Unusual flag frequencies

### Port-Based Detection
- Known malicious ports (31337, 1337, 4444, etc.)
- Connection to vulnerable services
- Port scanning detection

### Traffic Pattern Analysis
- Port scanning behavior
- ICMP flooding
- Unusual packet sizes
- Uncommon protocols

### ML-Based Detection
- Traffic direction classification
- Statistical outlier detection
- Flow-based anomaly detection

## 📊 Features & Analytics

- **Direction Classification**: Inbound, Outbound, Local, External traffic
- **Suspicion Scoring**: 0-1 score indicating confidence in malicious nature
- **Contextual Analysis**: Specific reasons why traffic is flagged
- **Statistical Analysis**: Summary of traffic patterns and anomalies

## 🚀 Getting Started

### Prerequisites
```bash
pip install pandas numpy scikit-learn
```

### Step 1: Capture Network Traffic (Optional)
```bash
sudo python sniff1.py eth0 60  # Capture 60 seconds on interface eth0
```

### Step 2: Analyze Traffic
```bash
python network_ml.py
```
Then select "Analyze network traffic" from the menu and provide your capture file path.

### Step 3: Real-Time Monitoring
```bash
sudo python sniff_predict.py eth0 30 network_model.pkl
```

## 🔄 Command Line Options

### Analyze Traffic
```bash
python network_ml.py --analyze your_capture.csv --output results.csv
```

### Start API Server for Integration
```bash
python network_ml.py --serve --model network_models.pkl --port 5000
```

## 📈 Use Cases

- **Security Operations**: Quickly identify suspicious traffic in your network
- **Forensic Analysis**: Analyze captured traffic for signs of compromise
- **Threat Hunting**: Proactively search for indicators of attack
- **Network Monitoring**: Understand traffic patterns and anomalies

## 🔧 Advanced Features

- **Adaptive Learning**: Models improve over time with feedback
- **API Integration**: REST API for integration with other security tools
- **Detailed Reporting**: CSV exports with complete analysis results
- **Multi-vector Analysis**: Correlates multiple suspicious indicators

## 🔜 Future Enhancements

- Integration with MITRE ATT&CK framework
- Enhanced visualization dashboard
- Support for encrypted traffic analysis
- Cloud-based deployment options

---

## Technical Details

### Rule-Based Detection
The system uses a comprehensive set of rules to identify suspicious traffic:

- **TCP Flag Analysis**: Detects abnormal flag combinations
- **Port Scanning Detection**: Identifies hosts connecting to many different ports
- **Service Analysis**: Flags connections to potentially vulnerable services
- **Protocol Inspection**: Looks for unusual protocol usage and packet characteristics

### Machine Learning Detection
Employs multiple ML techniques:

- **Random Forest**: Classifies traffic direction with high accuracy
- **Isolation Forest**: Identifies statistical outliers in network flows
- **K-means Clustering**: Groups similar traffic to establish baseline patterns

Both approaches work together to provide a comprehensive network security solution that balances known threat detection with novel anomaly discovery.

# Network Traffic Analysis with Machine Learning

This project analyzes network traffic data captured by a packet sniffer and uses machine learning to predict traffic direction.

## Files

- `sniff1.py` - The original packet sniffer that captures network traffic and saves it to CSV
- `network_ml.py` - Trains a machine learning model on the captured data
- `sniff_predict.py` - Real-time packet capture with direction prediction using the trained model
- `log1.csv` - Captured network traffic data

## Requirements

Install the required Python packages:

```bash
pip install pandas numpy scikit-learn netifaces
```

## Usage

### Step 1: Capture network traffic (optional if you already have log1.csv)

```bash
sudo python sniff1.py [interface_name] [capture_time_in_seconds]
```

For example:
```bash
sudo python sniff1.py eth0 60
```

This will create a log file (e.g., log1.csv) with captured network traffic.

### Step 2: Train the ML model

```bash
python network_ml.py [path_to_csv_file]
```

For example:
```bash
python network_ml.py log1.csv
```

This will train a Random Forest model on your data and save it as `network_model.pkl`.

### Step 3: Capture new traffic and predict in real-time

```bash
sudo python sniff_predict.py [interface_name] [capture_time_in_seconds] [model_path]
```

For example:
```bash
sudo python sniff_predict.py eth0 30 network_model.pkl
```

I have thoroughly enhanced `network_ml.py` with significant optimizations and new features, making it a robust, production-ready solution for network anomaly detection. 

## Enhancements & Features

### 1. Optimized Data Processing & Feature Engineering

- **Vectorized Operations:** Replaced lambda functions with more efficient vectorized operations.
- **Enhanced Feature Set:** Added flow-based features such as packets per flow, inter-arrival times, and flow volume.
- **Entropy-Based Features:** Implemented entropy calculations for IPs, ports, and timing patterns.
- **Statistical Anomaly Detection:** Introduced Z-score-based packet size analysis.
- **Timing Pattern Analysis:** Incorporated business hours detection and time-based features.

### 2. Model Improvements

- **Hyperparameter Tuning:** Used `GridSearchCV` to optimize models.
- **StratifiedKFold:** Improved cross-validation for more reliable model performance.
- **Adaptive Thresholds:** Implemented cluster-specific anomaly thresholds for higher accuracy.
- **Feature Importance Analysis:** Provided insights into the most influential features.
- **Normalized Anomaly Scores:** Ensured a consistent 0-1 scale for both models.

### 3. Technical Improvements

- **Improved Serialization:** Switched from `pickle` to `joblib` for faster model loading and saving.
- **Memory Management:** Integrated garbage collection for handling large datasets efficiently.
- **Error Handling:** Added robust error handling for production stability.
- **Performance Metrics:** Included timing metrics for real-time optimization feedback.

### 4. Added Features

- **REST API Server:** Exposed models through a `FastAPI` endpoint for real-time predictions.
- **Command-Line Interface:** Implemented a flexible CLI for training, analyzing, and serving models.
- **Batch Analysis:** Enabled analysis of new datasets using trained models.
- **Detailed Anomaly Context:** Automated reasoning about detected anomalies.
- **CSV Export:** Automated export of analysis results.

## Usage

The enhanced code now supports multiple functionalities:

### Train a New Model
```bash
python network_ml.py --input log1.csv --output network_models.pkl
```

### Analyze New Data with an Existing Model
```bash
python network_ml.py --analyze new_data.csv --model network_models.pkl
```

### Start API Server for Real-Time Predictions
```bash
python network_ml.py --serve --model network_models.pkl --port 5000
```

This implementation incorporates the latest best practices in machine learning for network security and provides a complete, production-ready solution.
# Improved Packet Direction Detection

I've made comprehensive improvements to packet direction detection, ensuring that no packet is ever labeled as "N/A". Now, every packet is classified correctly based on available data.

## Enhancements

### 1. Handling ICMP and Other IP Protocols Without Ports
- Implemented IP address-based direction detection.
- Classifies packets as:
  - **Inbound**: Traffic coming into the local network from outside.
  - **Outbound**: Traffic leaving the local network to the internet.
  - **Local**: Traffic between local machines.
  - **External**: Traffic between two external machines (rare, but possible).

### 2. Handling Non-IPv4 Protocols (e.g., IPv6, etc.)
- First attempts to use IP addresses if available.
- Falls back to MAC address-based heuristics:
  - **Broadcast**: Packets sent to broadcast/multicast addresses.
  - **Unknown**: Only assigned when direction truly cannot be determined.

### 3. Comprehensive Direction Labels
- **Inbound**: Packets coming into the network.
- **Outbound**: Packets leaving the network.
- **Local**: Communication between internal machines.
- **External**: Communication between two external devices.
- **Broadcast**: Broadcast/multicast packets (typically notifications).
- **Unknown**: Used only when no direction can be determined with certainty.

## Impact
- **More accurate traffic classification.**
- **No more "N/A" labels.**
- **Enhanced visibility into network activity.**

This improvement ensures a thorough and accurate classification of all packets, providing more useful data for network analysis. 🚀



