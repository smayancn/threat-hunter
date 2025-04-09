#!/usr/bin/env python3
"""
Suspicious Packet Generator

This script generates and sends various types of suspicious network traffic to test
network intrusion detection systems and anomaly detection models.

WARNING: This script is for EDUCATIONAL PURPOSES ONLY.
         Use only on networks you own or have explicit permission to test.
         Unauthorized network scanning is illegal in many jurisdictions.

Usage:
    python suspicious_packet_generator.py [interface] [duration] [intensity]

Example:
    python suspicious_packet_generator.py eth0 30 
 
"""

import os
import sys
import time
import random
import socket
import struct
import argparse
import ipaddress
from scapy.all import (
    send, sendp, IP, TCP, UDP, ICMP, Ether, RandIP, RandMAC,
    RandShort, Raw, fragment, Padding, rdpcap, wrpcap
)
from scapy.layers.inet import IPOption_RR

# Set of known suspicious ports often used by malware
SUSPICIOUS_PORTS = [
    0, 1, 31337, 4444, 12345, 6667, 6668, 6669, 1080,
    1337, 9001, 9002, 8080, 8888, 21, 22, 23, 25, 53
]

# Intensity levels for attack simulation
INTENSITY_LEVELS = {
    "low": {"delay": 1.0, "count": 5, "fragments": 2},
    "medium": {"delay": 0.5, "count": 15, "fragments": 5},
    "high": {"delay": 0.1, "count": 30, "fragments": 10}
}

def get_local_ip():
    """Get the local IP address of the machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "192.168.1.100"  # Default fallback

def get_network_range(ip):
    """Get the network range for the given IP."""
    try:
        # Assume a /24 network
        network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
        return network
    except Exception:
        # Fallback to a default network
        return ipaddress.IPv4Network("192.168.1.0/24")

def generate_random_payload(min_size=10, max_size=1500):
    """Generate random payload data of varying sizes."""
    size = random.randint(min_size, max_size)
    return os.urandom(size)

def send_syn_flood(interface, target_ip, count=10, delay=0.5):
    """Generate SYN flood packets."""
    print(f"[+] Generating SYN flood to {target_ip} ({count} packets)")
    
    for _ in range(count):
        # Random source IP and port
        src_ip = str(RandIP())
        src_port = random.randint(1024, 65535)
        dst_port = random.choice(SUSPICIOUS_PORTS + [80, 443, 8080])
        
        # Create the SYN packet
        packet = Ether(dst=RandMAC(), src=RandMAC()) / \
                 IP(src=src_ip, dst=target_ip) / \
                 TCP(sport=src_port, dport=dst_port, flags="S")
        
        sendp(packet, iface=interface, verbose=0)
        time.sleep(delay)

def send_christmas_tree_packets(interface, target_ip, count=5, delay=0.5):
    """Send Christmas Tree packets (with all TCP flags set)."""
    print(f"[+] Sending Christmas Tree packets to {target_ip} ({count} packets)")
    
    for _ in range(count):
        src_ip = str(RandIP())
        src_port = random.randint(1024, 65535)
        dst_port = random.choice(SUSPICIOUS_PORTS + [80, 443, 8080])
        
        # Set all TCP flags (FIN, SYN, RST, PSH, ACK, URG)
        packet = Ether(dst=RandMAC(), src=RandMAC()) / \
                 IP(src=src_ip, dst=target_ip) / \
                 TCP(sport=src_port, dport=dst_port, flags="FSRPAU")
        
        sendp(packet, iface=interface, verbose=0)
        time.sleep(delay)

def send_null_packets(interface, target_ip, count=5, delay=0.5):
    """Send NULL packets (with no TCP flags set)."""
    print(f"[+] Sending NULL packets to {target_ip} ({count} packets)")
    
    for _ in range(count):
        src_ip = str(RandIP())
        src_port = random.randint(1024, 65535)
        dst_port = random.choice(SUSPICIOUS_PORTS + [80, 443, 8080])
        
        # No flags set
        packet = Ether(dst=RandMAC(), src=RandMAC()) / \
                 IP(src=src_ip, dst=target_ip) / \
                 TCP(sport=src_port, dport=dst_port, flags=0)
        
        sendp(packet, iface=interface, verbose=0)
        time.sleep(delay)

def send_fin_scan(interface, target_ip, count=5, delay=0.5):
    """Send FIN scan packets."""
    print(f"[+] Sending FIN scan packets to {target_ip} ({count} packets)")
    
    for _ in range(count):
        src_ip = str(RandIP())
        src_port = random.randint(1024, 65535)
        dst_port = random.choice(SUSPICIOUS_PORTS + [80, 443, 8080])
        
        # Only FIN flag set
        packet = Ether(dst=RandMAC(), src=RandMAC()) / \
                 IP(src=src_ip, dst=target_ip) / \
                 TCP(sport=src_port, dport=dst_port, flags="F")
        
        sendp(packet, iface=interface, verbose=0)
        time.sleep(delay)

def send_xmas_scan(interface, target_ip, count=5, delay=0.5):
    """Send XMAS scan packets (FIN, PSH, URG flags set)."""
    print(f"[+] Sending XMAS scan packets to {target_ip} ({count} packets)")
    
    for _ in range(count):
        src_ip = str(RandIP())
        src_port = random.randint(1024, 65535)
        dst_port = random.choice(SUSPICIOUS_PORTS + [80, 443, 8080])
        
        # FIN, PSH, URG flags set
        packet = Ether(dst=RandMAC(), src=RandMAC()) / \
                 IP(src=src_ip, dst=target_ip) / \
                 TCP(sport=src_port, dport=dst_port, flags="FPU")
        
        sendp(packet, iface=interface, verbose=0)
        time.sleep(delay)

def send_unusual_icmp(interface, target_ip, count=5, delay=0.5):
    """Send unusual ICMP packets."""
    print(f"[+] Sending unusual ICMP packets to {target_ip} ({count} packets)")
    
    for _ in range(count):
        src_ip = str(RandIP())
        
        # Unusual ICMP types (beyond echo request/reply)
        icmp_type = random.choice([3, 5, 9, 10, 13, 15, 17])
        payload = generate_random_payload(100, 1400)
        
        packet = Ether(dst=RandMAC(), src=RandMAC()) / \
                 IP(src=src_ip, dst=target_ip) / \
                 ICMP(type=icmp_type, code=random.randint(0, 15)) / \
                 Raw(load=payload)
        
        sendp(packet, iface=interface, verbose=0)
        time.sleep(delay)

def send_fragmented_packets(interface, target_ip, num_fragments=5, delay=0.5):
    """Send highly fragmented packets."""
    print(f"[+] Sending fragmented packets to {target_ip} ({num_fragments} fragments)")
    
    src_ip = str(RandIP())
    dst_port = random.choice(SUSPICIOUS_PORTS)
    
    # Create a large packet
    payload = generate_random_payload(1500, 3000)
    packet = IP(src=src_ip, dst=target_ip) / \
             TCP(sport=RandShort(), dport=dst_port) / \
             Raw(load=payload)
    
    # Fragment the packet
    fragments = fragment(packet, fragsize=200)
    
    # Send the fragments
    for frag in fragments:
        sendp(Ether() / frag, iface=interface, verbose=0)
        time.sleep(delay)

def send_syn_ack_with_data(interface, target_ip, count=5, delay=0.5):
    """Send SYN+ACK packets with data (unusual)."""
    print(f"[+] Sending SYN+ACK packets with data to {target_ip} ({count} packets)")
    
    for _ in range(count):
        src_ip = str(RandIP())
        src_port = random.randint(1024, 65535)
        dst_port = random.choice(SUSPICIOUS_PORTS + [80, 443])
        
        payload = generate_random_payload(50, 200)
        
        # SYN+ACK flags (unusual with data)
        packet = Ether(dst=RandMAC(), src=RandMAC()) / \
                 IP(src=src_ip, dst=target_ip) / \
                 TCP(sport=src_port, dport=dst_port, flags="SA") / \
                 Raw(load=payload)
        
        sendp(packet, iface=interface, verbose=0)
        time.sleep(delay)

def send_unusual_udp(interface, target_ip, count=5, delay=0.5):
    """Send unusual UDP packets."""
    print(f"[+] Sending unusual UDP packets to {target_ip} ({count} packets)")
    
    for _ in range(count):
        src_ip = str(RandIP())
        src_port = random.choice(SUSPICIOUS_PORTS)
        dst_port = random.choice(SUSPICIOUS_PORTS)
        
        # Very small or very large payload
        if random.choice([True, False]):
            payload = generate_random_payload(1, 10)  # Very small
        else:
            payload = generate_random_payload(1400, 1500)  # Large
        
        packet = Ether(dst=RandMAC(), src=RandMAC()) / \
                 IP(src=src_ip, dst=target_ip) / \
                 UDP(sport=src_port, dport=dst_port) / \
                 Raw(load=payload)
        
        sendp(packet, iface=interface, verbose=0)
        time.sleep(delay)

def send_malformed_ip(interface, target_ip, count=5, delay=0.5):
    """Send malformed IP packets."""
    print(f"[+] Sending malformed IP packets to {target_ip} ({count} packets)")
    
    for _ in range(count):
        # Create invalid IP options
        packet = Ether(dst=RandMAC(), src=RandMAC()) / \
                 IP(src=str(RandIP()), dst=target_ip, ihl=15, options=[IPOption_RR()]) / \
                 TCP(sport=RandShort(), dport=random.choice(SUSPICIOUS_PORTS))
        
        try:
            sendp(packet, iface=interface, verbose=0)
        except Exception:
            # Fall back to a simpler malformed packet
            packet = Ether(dst=RandMAC(), src=RandMAC()) / \
                     IP(src=str(RandIP()), dst=target_ip, ttl=1) / \
                     TCP(sport=RandShort(), dport=random.choice(SUSPICIOUS_PORTS))
            sendp(packet, iface=interface, verbose=0)
        
        time.sleep(delay)

def main():
    parser = argparse.ArgumentParser(description="Generate suspicious network traffic for testing detection systems")
    parser.add_argument("interface", nargs="?", help="Network interface to use", default="")
    parser.add_argument("duration", nargs="?", type=int, help="Duration in seconds to run", default=30)
    parser.add_argument("intensity", nargs="?", help="Traffic intensity (low, medium, high)", default="medium")
    
    args = parser.parse_args()
    
    # Get interface if not provided
    if not args.interface:
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
        
        args.interface = input("\nEnter interface name (e.g., eth0, wlan0, en0): ")
    
    # Get duration if not provided
    if not args.duration:
        try:
            duration_input = input("Enter duration in seconds (default: 30): ")
            args.duration = int(duration_input) if duration_input else 30
        except ValueError:
            print("Invalid duration. Using default of 30 seconds.")
            args.duration = 30
    
    # Get intensity if not provided
    if not args.intensity:
        while True:
            intensity_input = input("Enter intensity level (low, medium, high) [default: medium]: ").lower()
            if not intensity_input:
                args.intensity = "medium"
                break
            elif intensity_input in INTENSITY_LEVELS:
                args.intensity = intensity_input
                break
            else:
                print("Invalid intensity level. Please choose from: low, medium, high")
    
    # Check intensity level
    if args.intensity.lower() not in INTENSITY_LEVELS:
        print(f"Invalid intensity level. Using medium instead of {args.intensity}")
        args.intensity = "medium"
    
    intensity = INTENSITY_LEVELS[args.intensity.lower()]
    
    # Determine target IP (local network)
    local_ip = get_local_ip()
    network = get_network_range(local_ip)
    
    # Get target IPs (skip our own IP)
    target_ips = [str(ip) for ip in network if str(ip) != local_ip]
    if not target_ips:
        # Fallback if no valid IPs
        target_ips = ["10.0.0.1", "192.168.1.1"]
    
    print("\n" + "="*50)
    print(" SUSPICIOUS NETWORK TRAFFIC GENERATOR")
    print(" FOR EDUCATIONAL PURPOSES ONLY")
    print("="*50)
    print(f"Interface: {args.interface}")
    print(f"Duration: {args.duration} seconds")
    print(f"Intensity: {args.intensity}")
    print(f"Local IP: {local_ip}")
    print(f"Target network: {network}")
    print("="*50 + "\n")
    
    print("WARNING: This script generates traffic that may be flagged as malicious.")
    print("         Use only on networks you own or have permission to test.")
    confirmation = input("Continue? (y/n): ")
    
    if confirmation.lower() != 'y':
        print("Aborted.")
        sys.exit(0)
    
    start_time = time.time()
    end_time = start_time + args.duration
    
    try:
        # Load scapy
        print("\nInitializing scapy...")
        
        print("\nStarting traffic generation...")
        
        # Run attack simulations until duration expires
        while time.time() < end_time:
            # Pick a random target IP from the network
            target_ip = random.choice(target_ips)
            
            # Choose a random attack type
            attack_type = random.choice([
                send_syn_flood,
                send_christmas_tree_packets,
                send_null_packets,
                send_fin_scan,
                send_xmas_scan,
                send_unusual_icmp,
                send_fragmented_packets,
                send_syn_ack_with_data,
                send_unusual_udp,
                send_malformed_ip
            ])
            
            # Execute the attack with appropriate intensity parameters
            attack_type(
                args.interface, 
                target_ip, 
                count=intensity["count"], 
                delay=intensity["delay"]
            )
            
            # Add a small delay between different attack types
            time.sleep(intensity["delay"] * 2)
            
            # Show progress
            remaining = max(0, end_time - time.time())
            print(f"Time remaining: {remaining:.1f} seconds", end="\r")
        
        print("\nTraffic generation completed!")
    
    except KeyboardInterrupt:
        print("\nTraffic generation stopped by user.")
    except ImportError as e:
        print(f"\nError: {e}")
        print("\nPlease install scapy:")
        print("    pip install scapy")
    except Exception as e:
        print(f"\nError: {e}")
    
    print("\nDone!")

if __name__ == "__main__":
    main() 
