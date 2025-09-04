# network scanner + write to csv + SYN flood detection/prevention logic WIP

import scapy.all as scapy
import time
import joblib
from collections import defaultdict
from datetime import datetime
import os
import csv

#initial configuration
INTERFACE = "eth0" #switch to eth0 for linux, keep as none for windows
USE_ML = False
MODEL_PATH = "model.joblib"
FEATURE_ORDER = ["timestamp", "src_ip", "dest_ip", "src_port", "dest_port", "packet_size", "protocol", "tcp_flags_str", "label"]

# Rule-based detection parameters
MONITOR_WINDOW = 5
SYN_THRESHOLD = 10 
ACK_RATIO_LIMIT = 0.2
ICMP_THRESHOLD = 20  # ICMP packets per window
BLOCK_DURATION = 15

# global variables
syn_counts = defaultdict(int)
icmp_counts = defaultdict(int)  # Track ICMP packets per IP
handshakes = defaultdict(lambda: {"syn": 0, "ack": 0})
first_seen = {}
icmp_first_seen = {}  # Track ICMP timing separately
blocked_ips = {}
ml_model = None
attack_history = defaultdict(list)  # Track attack history per IP
last_attack_log = defaultdict(float)  # Prevent spam logging

LOG_FILE = "packet_log.csv"
ATTACK_LOG_FILE = "attack_detections.csv"

#check for ML mode 
if USE_ML:
    ml_model = joblib.load(MODEL_PATH)

# write to CSV file

def init_csv(): # Initialize CSV file for logging
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, mode="w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(FEATURE_ORDER)
    
    # Initialize attack log file
    if not os.path.exists(ATTACK_LOG_FILE):
        with open(ATTACK_LOG_FILE, mode="w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp", "attack_type", "source_ip", "packet_count", "ack_count", 
                "ratio_or_type", "time_window", "packets_per_second", "attack_duration",
                "first_packet_time", "last_packet_time", "action_taken"
            ])


def log_packet_to_csv(src_ip, dest_ip, features, label="benign"): # appends packet data to the CSV log file
    with open(LOG_FILE, mode="a", newline="") as f:
        writer = csv.writer(f)
        row = [datetime.now().isoformat(), src_ip, dest_ip] + features + [label]
        writer.writerow(row)

def log_attack_details(ip_src, attack_type, syn_count, ack_count, time_window, action):
    """Log detailed attack information to CSV and console"""
    now = datetime.now()
    
    # Calculate metrics
    syn_ack_ratio = ack_count / syn_count if syn_count > 0 else 0
    packets_per_second = syn_count / time_window if time_window > 0 else 0
    
    # Get attack timing info - use appropriate timing based on attack type
    if attack_type == "ICMP_FLOOD":
        first_seen_time = icmp_first_seen.get(ip_src, now.timestamp())
    else:  # SYN_FLOOD
        first_seen_time = first_seen.get(ip_src, now.timestamp())
    
    attack_duration = now.timestamp() - first_seen_time
    
    # Record attack history
    attack_history[ip_src].append({
        'timestamp': now.timestamp(),
        'syn_count': syn_count,
        'ack_count': ack_count,
        'duration': attack_duration
    })
    
    # Streamlined console logging with attack type specific details
    print(f"\n[ATTACK] {attack_type} from {ip_src} - {now.strftime('%H:%M:%S')}")
    
    if attack_type == "ICMP_FLOOD":
        print(f"  ICMP_Packets:{syn_count} Rate:{packets_per_second:.1f}pps Duration:{attack_duration:.1f}s")
    else:  # SYN_FLOOD
        print(f"  SYN:{syn_count} ACK:{ack_count} Ratio:{syn_ack_ratio:.2f} Rate:{packets_per_second:.1f}pps")
    
    if len(attack_history[ip_src]) > 1:
        print(f"  Repeat offender ({len(attack_history[ip_src])} incidents)")
    
    # Log to CSV with attack-type specific data
    with open(ATTACK_LOG_FILE, mode="a", newline="") as f:
        writer = csv.writer(f)
        
        if attack_type == "ICMP_FLOOD":
            ratio_or_type = "ICMP_Echo_Request"
            packet_count = syn_count  # For ICMP, syn_count contains ICMP packet count
            ack_count_val = ""  # No ACK packets for ICMP
        else:  # SYN_FLOOD
            ratio_or_type = f"{syn_ack_ratio:.3f}"
            packet_count = syn_count
            ack_count_val = ack_count
        
        row = [
            now.isoformat(), attack_type, ip_src, packet_count, ack_count_val,
            ratio_or_type, time_window, f"{packets_per_second:.2f}", 
            f"{attack_duration:.2f}", datetime.fromtimestamp(first_seen_time).isoformat(),
            now.isoformat(), action
        ]
        writer.writerow(row)

def show_statistics():
    """Display periodic statistics"""
    total_incidents = sum(len(history) for history in attack_history.values())
    
    # Count active monitoring for different attack types
    active_syn_monitoring = len([ip for ip, count in syn_counts.items() if count > 0])
    active_icmp_monitoring = len([ip for ip, count in icmp_counts.items() if count > 0])
    
    if len(blocked_ips) > 0 or total_incidents > 0 or active_syn_monitoring > 0 or active_icmp_monitoring > 0:
        status_parts = []
        if len(blocked_ips) > 0:
            status_parts.append(f"Blocked:{len(blocked_ips)}")
        if total_incidents > 0:
            status_parts.append(f"Incidents:{total_incidents}")
        if active_syn_monitoring > 0:
            status_parts.append(f"SYN_Watch:{active_syn_monitoring}")
        if active_icmp_monitoring > 0:
            status_parts.append(f"ICMP_Watch:{active_icmp_monitoring}")
        
        print(f"[STATUS] {' '.join(status_parts)} - {datetime.now().strftime('%H:%M:%S')}")
        
        # Show blocked IPs with remaining time
        if blocked_ips:
            for ip, block_time in blocked_ips.items():
                remaining = BLOCK_DURATION - (datetime.now() - block_time).seconds
                print(f"  {ip} ({max(0, remaining)}s remaining)")
        
        # Show top suspicious IPs for both SYN and ICMP
        suspicious_ips = []
        
        # Check SYN activity
        for ip, count in syn_counts.items():
            if count > 0:
                acks = handshakes[ip]["ack"]
                ratio = acks / count if count > 0 else 0
                suspicious_ips.append((ip, f"SYN:{count}/ACK:{acks}", ratio if count >= SYN_THRESHOLD * 0.5 else 0))
        
        # Check ICMP activity  
        for ip, count in icmp_counts.items():
            if count > 0:
                suspicious_ips.append((ip, f"ICMP:{count}", count if count >= ICMP_THRESHOLD * 0.5 else 0))
        
        # Show most suspicious IPs
        if suspicious_ips:
            top_suspicious = sorted(suspicious_ips, key=lambda x: x[2], reverse=True)[:3]
            for ip, activity, _ in top_suspicious:
                if _ > 0:  # Only show if actually suspicious
                    print(f"  {ip}: {activity}")


# This function extracts features from the packet
# It returns a list of features including source port, destination port, packet size, protocol type
# and TCP flags. 
def extract_features(packet):
    src_port = None
    dest_port = None
    protocol = 0
    tcp_flags_str = ""

    if scapy.TCP in packet:
        src_port = packet[scapy.TCP].sport
        dest_port = packet[scapy.TCP].dport
        tcp_flags_str = packet[scapy.TCP].sprintf("%TCP.flags%")  # eg: S, SA or PA
        protocol = 6
    elif scapy.UDP in packet:
        src_port = packet[scapy.UDP].sport
        dest_port = packet[scapy.UDP].dport
        protocol = 17
    elif scapy.ICMP in packet:
        protocol = 1

    packet_size = len(packet)

    return [src_port or 0, dest_port or 0, packet_size, protocol, tcp_flags_str]

# Packet handler function
# This function processes each captured packet
# it extracts features, applies rule-based detection, and logs the packet.
def packet_handler(packet):
    if scapy.IP in packet:
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        features = extract_features(packet)

        label = "benign" #not a threat

        # Debug: Print packet info to verify capture is working
        #print(f"Captured packet: {ip_src} -> {ip_dst} ({packet.summary()})")

        if USE_ML and ml_model:
            prediction = ml_model.predict([features])[0]
            label = prediction
            if prediction != "benign":
                print(f"[ML DETECTED] {prediction} from {ip_src}")
                block_ip(ip_src)
        else:
            # Check for TCP-based attacks (SYN floods)
            if scapy.TCP in packet:
                tcp_flags_str = features[-1]  # last element = string flags
                label = rule_based_detection(ip_src, tcp_flags_str)
            
            # Check for ICMP-based attacks (ping floods)
            elif scapy.ICMP in packet:
                icmp_type = packet[scapy.ICMP].type
                # Only check for ICMP Echo Requests (ping floods)
                if icmp_type == 8:  # ICMP Echo Request
                    icmp_result = icmp_flood_detection(ip_src)
                    if icmp_result != "benign":
                        label = icmp_result

        log_packet_to_csv(ip_src, ip_dst, features, label)


# rule-based detection function
# this function implements a simple SYN flood detection mechanism
# it counts SYN packets and checks if the ratio of SYN to ACK packets exceeds a threshold.
# if it does, it blocks the source IP address.
def rule_based_detection(ip_src, tcp_flags):
    now = time.time()

    if "S" in tcp_flags:
        if ip_src not in first_seen:
            first_seen[ip_src] = now
            syn_counts[ip_src] = 1
        else:
            if now - first_seen[ip_src] <= MONITOR_WINDOW:
                syn_counts[ip_src] += 1
            else:
                first_seen[ip_src] = now
                syn_counts[ip_src] = 1
        handshakes[ip_src]["syn"] += 1

    if "A" in tcp_flags:
        handshakes[ip_src]["ack"] += 1

    syns = handshakes[ip_src]["syn"]
    acks = handshakes[ip_src]["ack"]
    
    # Check for SYN flood attack
    if syn_counts[ip_src] >= SYN_THRESHOLD and acks < syns * ACK_RATIO_LIMIT:
        # Prevent spam logging - only log once per 10 seconds per IP
        if now - last_attack_log[ip_src] > 10:
            time_window = now - first_seen[ip_src]
            log_attack_details(ip_src, "SYN_FLOOD", syn_counts[ip_src], acks, time_window, "IP_BLOCKED")
            last_attack_log[ip_src] = now
        
        block_ip(ip_src)
        return "syn_flood"
    
    # Log suspicious activity (high SYN count but not yet blocking threshold)
    elif syn_counts[ip_src] >= SYN_THRESHOLD * 0.7:  # 70% of threshold
        if now - last_attack_log.get(f"{ip_src}_suspicious", 0) > 30:  # Log every 30 seconds
            print(f"[SUSPICIOUS] {ip_src} - {syn_counts[ip_src]}/{SYN_THRESHOLD} SYN packets")
            last_attack_log[f"{ip_src}_suspicious"] = now
    
    return "benign"

def icmp_flood_detection(ip_src):
    """Detect ICMP ping flood attacks"""
    now = time.time()
    
    # Track ICMP packets in time window
    if ip_src not in icmp_first_seen:
        icmp_first_seen[ip_src] = now
        icmp_counts[ip_src] = 1
    else:
        if now - icmp_first_seen[ip_src] <= MONITOR_WINDOW:
            icmp_counts[ip_src] += 1
        else:
            # Reset window
            icmp_first_seen[ip_src] = now
            icmp_counts[ip_src] = 1
    
    # Check if threshold exceeded
    if icmp_counts[ip_src] >= ICMP_THRESHOLD:
        # Prevent spam logging
        if now - last_attack_log.get(f"{ip_src}_icmp", 0) > 10:
            time_window = now - icmp_first_seen[ip_src]
            packets_per_second = icmp_counts[ip_src] / time_window if time_window > 0 else 0
            
            log_attack_details(ip_src, "ICMP_FLOOD", icmp_counts[ip_src], 0, time_window, "IP_BLOCKED")
            last_attack_log[f"{ip_src}_icmp"] = now
        
        block_ip(ip_src)
        return "icmp_flood"
    
    # Log suspicious ICMP activity
    elif icmp_counts[ip_src] >= ICMP_THRESHOLD * 0.7:
        if now - last_attack_log.get(f"{ip_src}_icmp_suspicious", 0) > 30:
            print(f"[SUSPICIOUS] {ip_src} - {icmp_counts[ip_src]}/{ICMP_THRESHOLD} ICMP packets")
            last_attack_log[f"{ip_src}_icmp_suspicious"] = now
    
    return "benign"

## block and unblock IPs

def block_ip(ip): # blocks an IP address based on SYN flood detection
    if ip not in blocked_ips:
        print(f"[BLOCK] {ip} for {BLOCK_DURATION}s")
        
        import subprocess
        try:
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            blocked_ips[ip] = datetime.now()
        except Exception as e:
            print(f"[ERROR] Failed to block {ip}: {e}")

def unblock_expired_ips(): # unblocks IPs that have been blocked for more than the specified duration
    now = datetime.now()
    expired = [ip for ip, t in blocked_ips.items() if (now - t).seconds > BLOCK_DURATION]
    for ip in expired:
        block_duration_actual = (now - blocked_ips[ip]).seconds
        print(f"[UNBLOCK] {ip} after {block_duration_actual}s")
        
        import subprocess
        try:
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            del blocked_ips[ip]
            
            # Log the unblock action to attack log
            with open(ATTACK_LOG_FILE, mode="a", newline="") as f:
                writer = csv.writer(f)
                row = [
                    now.isoformat(), "IP_UNBLOCKED", ip, "", "", "", "", "", 
                    block_duration_actual, "", now.isoformat(), "IP_UNBLOCKED"
                ]
                writer.writerow(row)
                
        except Exception as e:
            print(f"[ERROR] Failed to unblock {ip}: {e}")

#main 

# Check if running with sufficient privileges
import os
if os.geteuid() != 0:
    print("WARNING: Not running as root. Packet capture may not work properly.")
    print("Try running with: sudo python3 iptables.py")

init_csv()
print(f"\nThreat Hunter - DoS Attack Detection")
print(f"Interface: {INTERFACE}")
print(f"Thresholds: SYN={SYN_THRESHOLD} ICMP={ICMP_THRESHOLD} ACK_Ratio={ACK_RATIO_LIMIT} Block={BLOCK_DURATION}s")
print(f"Logs: {LOG_FILE}, {ATTACK_LOG_FILE}")
print("Starting packet capture...")

# Improved AsyncSniffer configuration
try:
    sniffer = scapy.AsyncSniffer(
        iface=INTERFACE, 
        prn=packet_handler, 
        store=False,
        filter="ip"  # Only capture IP packets to reduce noise
    )
    sniffer.start()
    print("Sniffer started successfully!")
except Exception as e:
    print(f"Failed to start sniffer: {e}")
    print("Make sure you have the correct permissions and the interface exists.")
    exit(1)

try:
    stats_counter = 0
    while True:
        time.sleep(1)
        unblock_expired_ips()
        
        # Show statistics every 60 seconds
        stats_counter += 1
        if stats_counter >= 60:
            show_statistics()
            stats_counter = 0
except KeyboardInterrupt:
    print("\nStopping...")
    try:
        if sniffer.running:
            sniffer.stop()
    except (AttributeError, Exception) as e:
        print(f"Warning: Could not stop sniffer cleanly: {e}")
        # Force stop by joining the thread if available
        try:
            if hasattr(sniffer, 'thread') and sniffer.thread:
                sniffer.thread.join(timeout=2)
        except:
            pass
    print("Sniffer stopped.")
