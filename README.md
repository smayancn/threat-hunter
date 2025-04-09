# threat-hunter
v2 working
# Adaptive Threat Hunting: A Machine Learning-Based Real-Time Network Anomaly Detection System

## 📌 Objective
This project aims to build an **adaptive, real-time threat-hunting system** using machine learning to detect network anomalies. Unlike traditional rule-based systems, it analyzes Zeek logs, correlates multi-source logs, automates incident response, and continuously improves through adaptive learning.



## 📖 Introduction
Traditional cybersecurity measures fall short in identifying novel and sophisticated threats. Our system:
- Monitors **Zeek logs** (conn, dns, http, ssl)
- Detects known/unknown attacks (e.g., brute force, DDoS, malware C2, exfiltration)
- Uses **Random Forest** and **Isolation Forest** for detection
- Automates responses via **IPTables** or alerting
- Adapts over time using feedback and threat intel (MITRE ATT&CK, AbuseIPDB)



## ❗ Problem Statement
Existing threat detection methods rely on static rules or manual investigation, leading to:
- Missed detection of zero-days or novel threats
- High false positives
- Slow or no mitigation

This project builds a **real-time, self-improving** system capable of detecting, analyzing, and responding to threats **automatically** using ML models.



## ⚙️ Technical Overview

### 🔹 Data Sources
- **Zeek Logs**: `conn.log`, `dns.log`, `http.log`, `ssl.log`
- **Public Datasets**: CIC-IDS2017, UNSW-NB15

### 🔹 Machine Learning Models
- **Supervised**: Random Forest, XGBoost, SVM
- **Unsupervised**: Isolation Forest, One-Class SVM
- **Evaluation**: Precision, Recall, F1-score, False Positives

### 🔹 Feature Engineering
- Feature extraction from raw logs
- Correlation between log sources
- Feature selection via PCA / RFE

### 🔹 Detection
- Detects anomalies using supervised and unsupervised models
- Flags traffic exceeding anomaly thresholds
- Uses multi-vector signals for improved APT detection

### 🔹 Incident Response
- **Auto-blocking** via IPTables / Windows Firewall
- Alerting (email/webhook/logs)
- Correlation with threat intel for context-aware mitigation

### 🔹 Self-Improvement
- Anomaly feedback stored for retraining
- Periodic retraining via Cron
- Model versioning using Joblib/Pickle
- IOC integration from AbuseIPDB, MITRE ATT&CK



## 🔍 APT Detection Strategy

### Multi-Vector Analysis
| Layer       | Source Log | Detection Strategy |
|-------------|------------|--------------------|
| Network     | conn.log   | Long-term external comms |
| DNS         | dns.log    | Frequent rare domain lookups |
| HTTP        | http.log   | Persistent external C2 |
| SSL         | ssl.log    | Self-signed or uncommon certs |

### Adaptive Learning
- Anomaly feedback loops
- Scheduled retraining
- Integration with IOC databases



## 🔄 Modules

| Module | Description |
|--------|-------------|
| `Data Collection` | Zeek + Wireshark logs |
| `Preprocessing` | Pandas/NumPy pipelines |
| `Feature Extraction` | IPs, ports, protocols, bytes, durations |
| `ML Detection` | RF/IF model scoring |
| `Incident Response` | IPTables, alerts, logs |
| `Adaptive Learning` | Cron-based retraining |
| `Threat Intelligence` | MITRE ATT&CK, AbuseIPDB APIs |



## 🧰 Tools & Technologies

- **Network Monitoring**: Zeek, Wireshark
- **Programming**: Python, Pandas, NumPy
- **ML Libraries**: Scikit-Learn
- **Model Storage**: Joblib, Pickle
- **Automation**: Subprocess, Cron, Logging
- **Response**: IPTables, Windows Firewall
- **Threat Intel**: MITRE ATT&CK API, AbuseIPDB



## 🚀 Future Enhancements

- Integration of **deep learning models** (LSTM, autoencoders)
- **Cloud-based deployment** (AWS/Docker)
- **Encrypted traffic analysis** without decryption
- **Extended dataset support** and IOC enrichment



## ✅ Conclusion

This project offers a **robust, scalable, and adaptive solution** to network threat detection, combining:
- Real-time monitoring
- Adaptive ML-driven detection
- Proactive automated response
- Continuous learning from live traffic and intelligence feeds

Our solution is ideal for **enterprise deployment** and enhances network security with minimal manual intervention.



## 📚 References

1. [Threat Hunting Using a Machine Learning Approach](https://norma.ncirl.ie/4518/1/yashshukla.pdf)  
2. [Development of Threat Hunting Model](https://american-cse.org/csci2022-ieee/pdfs/CSCI20222lPzsUSRQukMlxf8K2x89I/202800b011/202800b011.pdf)  
3. [The Role of Machine Learning in Cybersecurity](https://dl.acm.org/doi/10.1145/3545574)  
4. [Analysis of Cyber Attack Vectors](https://www.researchgate.net/publication/305700087_Analysis_of_Cyber_Attack_Vectors)

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


> 📂 For source code, models, and logs – check the `/src`, `/models`, and `/logs` directories in this repository.

