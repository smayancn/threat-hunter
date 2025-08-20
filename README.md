# 🛡️ Network Packet Analysis & ML Preprocessing Pipeline

A focused network packet capture and preprocessing toolkit designed for machine learning-based threat detection. This project demonstrates how detailed packet analysis combined with feature engineering significantly improves ML model performance for network security applications.

##  **Core Components**

### **1. Advanced Packet Capture (`[USE]colab.py`)**
A comprehensive Scapy-based packet sniffer that extracts **40+ detailed features** from network traffic for superior ML model training.

#### **Key Features:**
- **Multi-protocol support**: TCP, UDP, HTTP, HTTPS/TLS, DNS, ICMP, ARP
- **Deep packet inspection** with protocol-specific analysis
- **Interactive interface selection** with auto-detection
- **Rich feature extraction** optimized for ML applications
- **CSV export** with structured data format

#### **Captured Data Fields:**
```
Packet #, Timestamp, Source/Dest MAC, Source/Dest IP, Protocol,
Source/Dest Port, Length, TTL, TCP Flags, UDP Length,
HTTP Method/Host/Path/Status, DNS ID/QR/QName/QType,
ICMP Type/Code, ARP Opcode/IP Src/Dst
```

### **2. ML-Ready Data Preprocessing (`preprocess.py`)**
An intelligent preprocessing pipeline that transforms raw packet data into ML-ready features through automated feature engineering and data cleaning.

#### **Feature Engineering Capabilities:**
- **Temporal features**: Hour, weekend/business hours detection
- **Network topology**: Private IP identification, well-known port detection
- **Protocol analysis**: TCP flag combinations, service identification
- **Security indicators**: Attack pattern detection, anomalous behavior flags
- **HTTP analysis**: Method classification, status code categorization
- **DNS analysis**: Query length, request/response classification
- **Statistical features**: Packet size analysis, payload ratios

#### **Advanced Preprocessing:**
- **Automated data cleaning** with missing value handling
- **Feature scaling** using StandardScaler
- **Label encoding** for categorical variables
- **Smart column detection** and type conversion
- **Suspicious pattern identification**

##  **Protocol-Specific Analysis**

### **TCP Analysis**
- **Flag combinations**: SYN, ACK, FIN, RST, PSH, URG, ECE, CWR
- **Attack detection**: SYN floods, FIN scans, port scans
- **Connection analysis**: State tracking and anomaly detection

### **HTTP/HTTPS Analysis**
- **Method extraction**: GET, POST, PUT, DELETE detection
- **Status code analysis**: Success (2xx), client errors (4xx), server errors (5xx)
- **Path analysis**: Attack targeting detection (admin panels, shells)
- **TLS version detection**: Security protocol analysis

### **DNS Analysis**
- **Query/Response classification**: Request vs. response identification
- **Query type analysis**: A, AAAA, MX, TXT record detection
- **Malicious domain detection**: Suspicious TLD identification
- **Query length analysis**: Anomalous DNS behavior detection

### **Network Layer Analysis**
- **ICMP analysis**: Type/code identification for reconnaissance detection
- **ARP monitoring**: Request/reply tracking for network mapping
- **IP analysis**: Private vs. public address classification

##  **Machine Learning Integration**

### **Feature Categories (40+ Features)**
1. **Basic Network Features** (7 features)
   - IP addresses (private/public classification)
   - Port numbers (well-known port detection)
   - Packet length and protocol type

2. **Temporal Features** (4 features)
   - Time of day analysis
   - Business hours detection
   - Weekend/weekday classification
   - Night-time activity flags

3. **TCP-Specific Features** (8 features)
   - Individual flag detection (SYN, ACK, FIN, RST, PSH)
   - Attack pattern flags (SYN flood, FIN scan)
   - Connection state analysis

4. **Application Layer Features** (12+ features)
   - HTTP method and status analysis
   - DNS query characteristics
   - Service detection (HTTP, HTTPS, DNS, SSH, FTP)
   - Protocol-specific anomaly detection

5. **Security Features** (10+ features)
   - Attack pattern identification
   - Suspicious behavior flags
   - Encryption analysis
   - Anomaly detection indicators

### **Preprocessing Output**
- **Normalized feature matrix** ready for ML algorithms
- **Standardized data format** across all features
- **Missing value imputation** with intelligent defaults
- **Categorical encoding** for non-numeric features

##  **Installation & Setup**

### **Requirements**
- Python 3.6+
- Administrative privileges for packet capture
- Required packages:
  ```
  scapy>=2.4.5
  pandas>=1.3.0
  scikit-learn>=1.0.0
  numpy>=1.21.0
  netifaces>=0.11.0
  ```

### **Quick Start**
```bash
# Clone the repository
git clone https://github.com/smayancn/threat-hunter.git
cd threat-hunter

# Install dependencies
pip install scapy pandas scikit-learn numpy netifaces

# Run packet capture
python [USE]colab.py

# Process captured data
python preprocess.py
```

## 📖 **Usage Guide**

### **Step 1: Packet Capture (`[USE]colab.py`)**
```bash
# Run interactive packet capture
python [USE]colab.py

# Follow prompts to:
# 1. Select network interface
# 2. Set capture duration (default: 5 seconds)
# 3. Automatic CSV export to 'network_logs.csv'
```

**Example Session:**
```
Available Network Interfaces:
1. WiFi (192.168.1.100)
2. Ethernet (10.0.0.50)

Select interface [1]: 1
Capture duration [5]: 10

Capturing on WiFi for 10s...
Saved 1,247 packets to /path/to/network_logs.csv
```

### **Step 2: Data Preprocessing (`preprocess.py`)**
```bash
# Auto-detect and process CSV files
python preprocess.py

# Processes: network_logs.csv → network_logs_processed.csv
```

**Preprocessing Features:**
- **Automatic file detection** of CSV files in directory
- **Interactive file selection** if multiple CSV files exist
- **Feature engineering** with 40+ extracted features
- **Data normalization** and scaling for ML readiness
- **Clean output** with processed feature matrix

### **Complete Workflow Example**
```bash
# 1. Capture network traffic
python [USE]colab.py
# → Generates: network_logs.csv

# 2. Preprocess for ML
python preprocess.py
# → Generates: network_logs_processed.csv

# 3. Use processed data for ML training/analysis
# (Ready for scikit-learn, TensorFlow, PyTorch, etc.)
```

## 🔧 **Advanced Configuration**

### **Capture Customization (`[USE]colab.py`)**
```python
# Modify capture parameters in script:
duration = 30  # Capture for 30 seconds
filename = "custom_capture.csv"  # Custom output filename

# Protocol-specific filters can be added:
# - TCP port filtering
# - HTTP method filtering
# - DNS query type filtering
```

### **Preprocessing Options (`preprocess.py`)**
```python
# Custom preprocessing parameters:
- Missing value threshold: 10% (columns with >90% missing data removed)
- Row completeness threshold: 50% (rows with >50% missing data removed)
- Feature scaling: StandardScaler (zero mean, unit variance)
- Categorical encoding: LabelEncoder for string features
```

##  **Output Data Formats**

### **Raw Capture Output (`network_logs.csv`)**
Contains 25 columns with detailed packet information:
```csv
#,Time,Source MAC,Destination MAC,Source IP,Destination IP,Protocol,
Source Port,Destination Port,Length,TTL,TCP Flags,UDP Length,
HTTP Method,HTTP Host,HTTP Path,HTTP Status,DNS ID,DNS QR,
DNS QName,DNS QType,ICMP Type,ICMP Code,ARP Opcode,ARP IP Src,ARP IP Dst
```

### **Processed ML Data (`network_logs_processed.csv`)**
Contains 40+ engineered features ready for ML:
```csv
packet_num,length,ttl,source_port,destination_port,hour,is_weekend,
is_business_hours,is_night_time,source_is_private,destination_is_private,
source_is_well_known,destination_is_well_known,is_tcp,is_udp,is_icmp,
is_large_packet,has_syn,has_ack,has_fin,has_rst,has_psh,is_syn_flood,
is_fin_scan,has_http,is_get,is_post,is_http_success,is_http_error,
has_dns,is_dns_query,dns_query_len,is_http_port,is_https_port,
is_dns_port,is_ssh_port,is_ftp_port,...
```

##  **Machine Learning Applications**

### **Ready for ML Frameworks**
The processed data is immediately compatible with:
- **scikit-learn**: Classification, regression, clustering
- **TensorFlow/Keras**: Deep learning models
- **PyTorch**: Neural network architectures
- **XGBoost/LightGBM**: Gradient boosting models

### **Example ML Integration**
```python
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# Load processed data
df = pd.read_csv('network_logs_processed.csv')

# Prepare features (X) and labels (y) - labels need to be added separately
X = df.drop(['packet_num'], axis=1)  # Remove non-feature columns
# y = your_labels  # Add threat/normal labels for supervised learning

# Train ML model
model = RandomForestClassifier(n_estimators=100)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
model.fit(X_train, y_train)
```

##  **Security Applications**

### **Threat Detection Use Cases**
- **Network intrusion detection** using behavioral analysis
- **Malware communication detection** through traffic patterns
- **DDoS attack identification** via packet flag analysis
- **Port scanning detection** using connection pattern analysis
- **Data exfiltration detection** through unusual traffic volumes

### **Feature Engineering for Security**
- **Attack signature detection**: TCP flag combinations indicating scans
- **Temporal anomalies**: Traffic patterns outside normal business hours
- **Protocol anomalies**: Unexpected service usage on non-standard ports
- **Volume anomalies**: Unusually large packets or high frequency communications


**Core Value Proposition**: This pipeline demonstrates how **detailed packet feature extraction** combined with **intelligent preprocessing** creates superior datasets for ML-based network security applications, achieving significantly better threat detection accuracy than basic packet capture approaches.
