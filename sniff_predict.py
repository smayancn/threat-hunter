import socket
import struct
import time
import csv
import os
import pandas as pd
import numpy as np
import pickle
from network_ml import predict_traffic
from sniffer import get_mac_address, get_protocol_name, ETH_FRAME_LEN
import warnings
warnings.filterwarnings("ignore")

def capture_and_predict(interface, model_path="network_models.pkl", capture_time=10):
    """Capture network packets and predict their direction and detect anomalies in real-time."""
    try:
        # Check if model exists
        if not os.path.exists(model_path):
            print(f"Error: Model file {model_path} not found.")
            print("Please run network_ml.py first to train and save the model.")
            return

        # Create a raw socket
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        sock.bind((interface, 0))
        
        print(f"Listening for network packets on {interface} for {capture_time} seconds...")
        print(f"Using model from {model_path} for prediction and anomaly detection")
        
        start_time = time.time()
        
        # Set a timeout to prevent blocking forever
        sock.settimeout(1.0)
        
        # Stats
        total_packets = 0
        predictions = {"Inbound": 0, "Outbound": 0, "Unknown": 0}
        high_confidence = 0  # Predictions with > 80% confidence
        anomalous_packets = 0
        severe_anomalies = 0  # Anomalies with score > 0.8
        
        # List to store suspected anomalies for reporting
        anomaly_log = []
        
        # Known suspicious ports and behaviors for additional context
        suspicious_ports = [0, 31337, 4444, 12345, 6667, 6668, 6669, 1080, 1337, 9001, 9002]
        
        common_protocols = {
            'TCP': {'common_ports': [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5900, 8080]},
            'UDP': {'common_ports': [53, 67, 68, 69, 123, 161, 162, 514, 1900, 5353]},
            'ICMP': {'allowed': True},
        }
        
        # Terminal color codes for better visibility
        colors = {
            'red': '\033[91m',
            'green': '\033[92m',
            'yellow': '\033[93m',
            'cyan': '\033[96m',
            'pink': '\033[95m',
            'bold': '\033[1m', 
            'end': '\033[0m'
        }
        
        print(f"\n{colors['bold']}Starting packet capture and analysis...{colors['end']}\n")
        
        while time.time() - start_time < capture_time:
            try:
                raw_data, addr = sock.recvfrom(65536)
                
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                
                # Parse ethernet header
                if len(raw_data) < ETH_FRAME_LEN:
                    continue  # Skip if packet is too short
                    
                dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', raw_data[:ETH_FRAME_LEN])
                
                src_mac_str = get_mac_address(src_mac)
                dest_mac_str = get_mac_address(dest_mac)
                packet_length = len(raw_data)
                
                # Default values
                src_ip, dest_ip = "N/A", "N/A"
                protocol = "Unknown"
                src_port, dest_port = -1, -1
                tcp_flags = ""
                
                # Handle IPv4 packets
                if eth_proto == 0x0800:
                    total_packets += 1
                    
                    try:
                        ip_header = raw_data[ETH_FRAME_LEN:ETH_FRAME_LEN + 20]  # IPv4 header is at least 20 bytes
                        if len(ip_header) >= 20:
                            # First byte contains version and header length
                            version_header_len = ip_header[0]
                            header_len = (version_header_len & 0xF) * 4  # Header length in bytes
                            
                            # Get the protocol number
                            proto = ip_header[9]
                            
                            # Get source and destination IP addresses
                            src_ip = socket.inet_ntoa(ip_header[12:16])
                            dest_ip = socket.inet_ntoa(ip_header[16:20])
                            
                            # Get protocol name
                            protocol = get_protocol_name(proto).split(' ')[0]  # Just get the short name
                            
                            # Handle TCP packets
                            if proto == 6:  # TCP
                                tcp_header_start = ETH_FRAME_LEN + header_len
                                
                                # Make sure we have enough data for the TCP header
                                if len(raw_data) >= tcp_header_start + 14:
                                    tcp_header = raw_data[tcp_header_start:tcp_header_start + 14]
                                    
                                    # Parse TCP header parts
                                    src_port, dest_port, seq, ack, offset_reserved_flags = struct.unpack('! H H L L H', tcp_header)
                                    
                                    # Extract TCP flags
                                    flags = offset_reserved_flags & 0x003F  # Mask to get only the flags
                                    
                                    # Build flags string
                                    flag_names = []
                                    if flags & 0x01: flag_names.append("FIN")
                                    if flags & 0x02: flag_names.append("SYN")
                                    if flags & 0x04: flag_names.append("RST")
                                    if flags & 0x08: flag_names.append("PSH")
                                    if flags & 0x10: flag_names.append("ACK")
                                    if flags & 0x20: flag_names.append("URG")
                                    
                                    # Generate flags string
                                    if flag_names:
                                        tcp_flags = " ".join(flag_names)
                            
                            # Handle UDP packets
                            elif proto == 17:  # UDP
                                udp_header_start = ETH_FRAME_LEN + header_len
                                
                                # Make sure we have enough data for the UDP header
                                if len(raw_data) >= udp_header_start + 8:
                                    udp_header = raw_data[udp_header_start:udp_header_start + 8]
                                    src_port, dest_port, length, checksum = struct.unpack('! H H H H', udp_header)
                    
                    except Exception as e:
                        print(f"Error parsing packet: {str(e)}")
                        continue
                    
                    # Create features for ML prediction and anomaly detection
                    current_time = pd.to_datetime(timestamp)
                    packet_data = {
                        'Protocol': protocol,
                        'Packet Length': packet_length,
                        'Source Port': src_port,
                        'Destination Port': dest_port,
                        'Hour': current_time.hour,
                        'Minute': current_time.minute,
                        'Day': current_time.day_of_week,
                        'Has_SYN': 1 if 'SYN' in tcp_flags else 0,
                        'Has_ACK': 1 if 'ACK' in tcp_flags else 0,
                        'Has_FIN': 1 if 'FIN' in tcp_flags else 0,
                        'Has_RST': 1 if 'RST' in tcp_flags else 0,
                        'Has_PSH': 1 if 'PSH' in tcp_flags else 0,
                        'Has_URG': 1 if 'URG' in tcp_flags else 0,
                        'Is_Local_Source': 1 if src_ip.startswith(('10.', '192.168.', '172.16.')) else 0,
                        'Is_Local_Dest': 1 if dest_ip.startswith(('10.', '192.168.', '172.16.')) else 0
                    }
                    
                    # Add enhanced features for anomaly detection
                    common_ports = [20, 21, 22, 23, 25, 53, 80, 123, 143, 443, 445, 465, 587, 993, 995, 3306, 3389, 5900, 8080, 8443]
                    packet_data['Is_Common_SrcPort'] = 1 if src_port in common_ports else 0
                    packet_data['Is_Common_DestPort'] = 1 if dest_port in common_ports else 0
                    
                    # Flag potentially suspicious port combinations
                    suspicious_port_combinations = [(0, 0), (-1, -1), (0, 31337), (31337, 0)]
                    packet_data['Has_Suspicious_Ports'] = 1 if (src_port, dest_port) in suspicious_port_combinations else 0
                    
                    # Flag unusual TCP flag combinations
                    packet_data['Has_Unusual_Flags'] = 0
                    # SYN+FIN combination (often used in scanning)
                    if packet_data['Has_SYN'] == 1 and packet_data['Has_FIN'] == 1:
                        packet_data['Has_Unusual_Flags'] = 1
                    # All flags set (Christmas tree packet)
                    if (packet_data['Has_SYN'] == 1 and packet_data['Has_FIN'] == 1 and 
                        packet_data['Has_ACK'] == 1 and packet_data['Has_PSH'] == 1 and 
                        packet_data['Has_URG'] == 1 and packet_data['Has_RST'] == 1):
                        packet_data['Has_Unusual_Flags'] = 1
                    # NULL flags (no flags set in TCP)
                    if (protocol == 'TCP' and packet_data['Has_SYN'] == 0 and packet_data['Has_FIN'] == 0 and 
                        packet_data['Has_ACK'] == 0 and packet_data['Has_PSH'] == 0 and 
                        packet_data['Has_URG'] == 0 and packet_data['Has_RST'] == 0):
                        packet_data['Has_Unusual_Flags'] = 1
                       
                    
                    # Flag unusual packet sizes
                    packet_data['Is_Unusual_Size'] = 0
                    # Very large packets
                    if packet_length > 1500:  # Larger than typical MTU
                        packet_data['Is_Unusual_Size'] = 1
                    # Very small non-ACK packets
                    if packet_length < 50 and packet_data['Has_ACK'] == 0:
                        packet_data['Is_Unusual_Size'] = 1
                    
                    # IP pair frequency (simplified for real-time)
                    packet_data['IP_Pair_Frequency'] = 1
                    
                    # Create dataframe from single packet data
                    packet_df = pd.DataFrame([packet_data])
                    
                    # Predict using model
                    try:
                        results = predict_traffic(model_path, packet_df)
                        
                        direction = results['direction'][0]
                        direction_prob = results['direction_probability'][0]
                        is_anomaly = results['is_anomaly'][0]
                        anomaly_score = results['anomaly_score'][0]
                        
                        if direction_prob > 0.8:
                            high_confidence += 1
                        
                        # Count predictions
                        predictions[direction] += 1
                        
                        # Check for anomalies
                        is_suspicious = False
                        suspicious_reasons = []
                        
                        # Count anomalies detected by the model
                        if is_anomaly == 1:
                            anomalous_packets += 1
                            is_suspicious = True
                            suspicious_reasons.append(f"ML anomaly score: {anomaly_score:.2f}")
                            
                            # Track severe anomalies
                            if anomaly_score > 0.8:
                                severe_anomalies += 1
                        
                        # Additional rule-based checks
                        if src_port in suspicious_ports or dest_port in suspicious_ports:
                            is_suspicious = True
                            suspicious_reasons.append(f"Suspicious port: {src_port if src_port in suspicious_ports else dest_port}")
                        
                        if packet_data['Has_Unusual_Flags'] == 1:
                            is_suspicious = True
                            suspicious_reasons.append(f"Unusual TCP flags: {tcp_flags}")
                        
                        if packet_data['Is_Unusual_Size'] == 1:
                            is_suspicious = True
                            suspicious_reasons.append(f"Unusual packet size: {packet_length}")
                            
                        # Print packet info with predictions
                        if is_suspicious:
                            # Add to anomaly log
                            anomaly_log.append({
                                'timestamp': timestamp,
                                'src_ip': src_ip, 
                                'src_port': src_port,
                                'dest_ip': dest_ip,
                                'dest_port': dest_port,
                                'protocol': protocol,
                                'flags': tcp_flags,
                                'length': packet_length,
                                'anomaly_score': anomaly_score,
                                'reasons': suspicious_reasons
                            })
                            
                            # Print suspicious packet with red highlight
                            print(f"{colors['red']}[{timestamp}] {src_ip}:{src_port} → {dest_ip}:{dest_port} | {protocol} | Flags: {tcp_flags}{colors['end']}")
                            print(f"{colors['red']}  → Direction: {direction} (Confidence: {direction_prob:.2f}){colors['end']}")
                            print(f"{colors['red']}  → SUSPICIOUS: Anomaly score: {anomaly_score:.2f}, Reasons: {', '.join(suspicious_reasons)}{colors['end']}")
                        else:
                            # Print normal packet
                            print(f"[{timestamp}] {src_ip}:{src_port} → {dest_ip}:{dest_port} | {protocol} | Flags: {tcp_flags}")
                            print(f"  → Direction: {direction} (Confidence: {direction_prob:.2f})")
                        
                    except Exception as e:
                        print(f"Prediction error: {str(e)}")
                        predictions["Unknown"] += 1
                
            except socket.timeout:
                # Just continue on timeout
                continue
            except Exception as e:
                print(f"Error capturing packet: {str(e)}")
        
        # Print summary
        print(f"\n{colors['bold']}--- Analysis Summary ---{colors['end']}")
        print(f"Total packets analyzed: {total_packets}")
        if total_packets > 0:
            print(f"Inbound packets: {predictions['Inbound']} ({predictions['Inbound']/total_packets*100:.1f}%)")
            print(f"Outbound packets: {predictions['Outbound']} ({predictions['Outbound']/total_packets*100:.1f}%)")
            print(f"Unknown direction: {predictions['Unknown']}")
            print(f"High confidence predictions (>80%): {high_confidence} ({high_confidence/total_packets*100:.1f}%)")
            print(f"{colors['yellow']}Anomalous packets: {anomalous_packets} ({anomalous_packets/total_packets*100:.1f}%){colors['end']}")
            print(f"{colors['red']}Severe anomalies (score > 0.8): {severe_anomalies} ({severe_anomalies/total_packets*100:.1f}%){colors['end']}")
        
        # Print detailed anomaly report if any anomalies were detected
        if anomalous_packets > 0:
            print(f"\n{colors['bold']}--- Anomaly Details ---{colors['end']}")
            for i, anomaly in enumerate(anomaly_log[:10]):  # Show top 10 anomalies
                print(f"{colors['red']}Anomaly #{i+1}:{colors['end']}")
                print(f"  Time: {anomaly['timestamp']}")
                print(f"  Connection: {anomaly['src_ip']}:{anomaly['src_port']} → {anomaly['dest_ip']}:{anomaly['dest_port']}")
                print(f"  Protocol: {anomaly['protocol']}, Flags: {anomaly['flags']}, Length: {anomaly['length']}")
                print(f"  Anomaly Score: {anomaly['anomaly_score']:.2f}")
                print(f"  Reasons: {', '.join(anomaly['reasons'])}")
            
            if len(anomaly_log) > 10:
                print(f"\n... and {len(anomaly_log) - 10} more anomalies")
                
            # Save anomalies to CSV
            anomaly_file = "network_anomalies.csv"
            try:
                with open(anomaly_file, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=[
                        'timestamp', 'src_ip', 'src_port', 'dest_ip', 'dest_port', 
                        'protocol', 'flags', 'length', 'anomaly_score', 'reasons'
                    ])
                    writer.writeheader()
                    for anomaly in anomaly_log:
                        # Join reasons into a string
                        anomaly['reasons'] = '; '.join(anomaly['reasons'])
                        writer.writerow(anomaly)
                print(f"\nDetailed anomaly report saved to {anomaly_file}")
            except Exception as e:
                print(f"Error saving anomaly report: {str(e)}")
        
        return anomaly_log
    
    except PermissionError:
        print("Error: Root/Administrator privileges required to capture packets.")
        print("Try running the script with sudo (Linux/Mac) or as Administrator (Windows).")
    except socket.error as e:
        print(f"Socket error: {str(e)}")
        print("Check if the interface name is correct and that the network interface exists.")
    except Exception as e:
        print(f"Unexpected error: {str(e)}")

if __name__ == "__main__":
    import sys
    
    # Parse command line arguments
    if len(sys.argv) > 1:
        interface = sys.argv[1]
        capture_time = int(sys.argv[2]) if len(sys.argv) > 2 else 10
        model_path = sys.argv[3] if len(sys.argv) > 3 else "network_models.pkl"
    else:
        # Get available interfaces
        available_interfaces = []
        if os.name == 'posix':  # Linux/Mac
            try:
                import netifaces
                available_interfaces = netifaces.interfaces()
            except ImportError:
                print("Tip: Install 'netifaces' package for automatic interface detection")
                print("     pip install netifaces")
                available_interfaces = ["lo", "eth0", "wlan0", "en0"]  # Common defaults
        else:  # Windows
            available_interfaces = ["Ethernet", "Wi-Fi"]
        
        print("Available network interfaces (these might not be accurate):")
        for i, iface in enumerate(available_interfaces):
            print(f"{i+1}. {iface}")
        
        interface = input("\nEnter interface name (e.g., eth0, wlan0, en0): ")
        capture_time = int(input("Enter capture time in seconds (default: 10): ") or 10)
        model_path = input("Enter model path (default: network_models.pkl): ") or "network_models.pkl"
    
    print("\n--- Network Traffic Analysis with Anomaly Detection ---")
    print(f"make sure the model is trained with the network_models.pkl")
    print(f"Starting packet capture and analysis on {interface} for {capture_time} seconds...")
    
    capture_and_predict(interface, model_path, capture_time)
