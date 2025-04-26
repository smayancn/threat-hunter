#!/usr/bin/env python3


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

# Intensity levels for attack simulation - modified for extreme intensity
INTENSITY_LEVELS = {
    "extreme": {"delay": 0.05, "count": 50, "fragments": 20}
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
        return "127.0.0.1"  # Default to localhost

def get_network_range(ip):
    """Get the network range for the given IP."""
    try:
        # Just return localhost for targeting own machine
        return [ip]
    except Exception:
        return ["127.0.0.1"]

def generate_random_payload(min_size=10, max_size=1500):
    """Generate random payload data of varying sizes."""
    size = random.randint(min_size, max_size)
    return os.urandom(size)

def send_malformed_ip_extreme(interface, target_ip, count=50, delay=0.05):
    """Send extremely malformed IP packets."""
    print(f"[+] Sending extremely malformed IP packets to {target_ip} ({count} packets)")
    
    for _ in range(count):
        # Create maximally invalid IP options
        packet = Ether(dst=RandMAC(), src=RandMAC()) / \
                 IP(src=str(RandIP()), dst=target_ip, ihl=15, options=[IPOption_RR()], 
                    version=15, flags=7) / \
                 TCP(sport=RandShort(), dport=random.choice(SUSPICIOUS_PORTS), 
                     flags="FSRPAU", seq=0xFFFFFFFF, window=0)
        
        try:
            sendp(packet, iface=interface, verbose=0)
        except Exception:
            # Fall back to a simpler extremely malformed packet
            packet = Ether(dst=RandMAC(), src=RandMAC()) / \
                     IP(src=str(RandIP()), dst=target_ip, ttl=1, flags=7) / \
                     TCP(sport=RandShort(), dport=random.choice(SUSPICIOUS_PORTS), 
                         flags="FSRPAU")
            sendp(packet, iface=interface, verbose=0)
        
        time.sleep(delay)

def send_christmas_tree_extreme(interface, target_ip, count=50, delay=0.05):
    """Send Christmas Tree packets with extremely suspicious characteristics."""
    print(f"[+] Sending extreme Christmas Tree packets to {target_ip} ({count} packets)")
    
    for _ in range(count):
        src_ip = str(RandIP())
        src_port = random.choice(SUSPICIOUS_PORTS)
        dst_port = random.choice(SUSPICIOUS_PORTS)
        
        # Set all TCP flags (FIN, SYN, RST, PSH, ACK, URG) - highly unusual
        packet = Ether(dst=RandMAC(), src=RandMAC()) / \
                 IP(src=src_ip, dst=target_ip, flags=7) / \
                 TCP(sport=src_port, dport=dst_port, flags="FSRPAU", 
                     options=[('Timestamp', (0xFFFFFFFF, 0))])
        
        sendp(packet, iface=interface, verbose=0)
        time.sleep(delay)

def send_impossible_packet_combo(interface, target_ip, count=50, delay=0.05):
    """Send impossible TCP flag combinations."""
    print(f"[+] Sending impossible TCP flag combinations to {target_ip} ({count} packets)")
    
    for _ in range(count):
        src_ip = str(RandIP())
        src_port = random.choice(SUSPICIOUS_PORTS)
        dst_port = random.choice(SUSPICIOUS_PORTS)
        
        # SYN+RST+FIN combo (impossible in normal traffic)
        packet = Ether(dst=RandMAC(), src=RandMAC()) / \
                 IP(src=src_ip, dst=target_ip) / \
                 TCP(sport=src_port, dport=dst_port, flags="SRF")
        
        sendp(packet, iface=interface, verbose=0)
        time.sleep(delay)

def send_highly_fragmented(interface, target_ip, count=50, delay=0.05):
    """Send extremely fragmented packets with suspicious data."""
    print(f"[+] Sending highly fragmented packets to {target_ip} ({count} packets)")
    
    for _ in range(count):
        src_ip = str(RandIP())
        dst_port = random.choice(SUSPICIOUS_PORTS)
        
        # Create a large packet with suspicious content
        payload = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" + os.urandom(2000)
        packet = IP(src=src_ip, dst=target_ip, flags=1) / \
                 TCP(sport=RandShort(), dport=dst_port, flags="SF") / \
                 Raw(load=payload)
        
        # Fragment the packet into tiny fragments
        fragments = fragment(packet, fragsize=100)
        
        # Send the fragments
        for frag in fragments:
            sendp(Ether() / frag, iface=interface, verbose=0)
            time.sleep(delay)

def send_invalid_icmp(interface, target_ip, count=50, delay=0.05):
    """Send invalid ICMP packets."""
    print(f"[+] Sending invalid ICMP packets to {target_ip} ({count} packets)")
    
    for _ in range(count):
        src_ip = str(RandIP())
        
        # Invalid ICMP types and codes
        icmp_type = random.choice([41, 42, 43, 44])  # Invalid types
        payload = b"\x00\xff\x00\xff" * 100  # Suspicious pattern
        
        packet = Ether(dst=RandMAC(), src=RandMAC()) / \
                 IP(src=src_ip, dst=target_ip) / \
                 ICMP(type=icmp_type, code=200) / \
                 Raw(load=payload)
        
        sendp(packet, iface=interface, verbose=0)
        time.sleep(delay)

def main():
    parser = argparse.ArgumentParser(description="Generate suspicious network traffic")
    parser.add_argument("interface", nargs="?", help="Network interface to use", default="")
    parser.add_argument("duration", nargs="?", type=int, help="Duration in seconds to run", default=60)
    
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
            duration_input = input("Enter duration in seconds (default: 60): ")
            args.duration = int(duration_input) if duration_input else 60
        except ValueError:
            print("Invalid duration. Using default of 60 seconds.")
            args.duration = 60
    
    intensity = INTENSITY_LEVELS["extreme"]
    
    # Get local IP as target
    local_ip = get_local_ip()
    target_ips = [local_ip]
    
   
    print(f"Interface: {args.interface}")
    print(f"Duration: {args.duration} seconds")
    print(f"Target IP (your machine): {local_ip}")
    
    
    confirmation = input("Continue? (y/n): ")
    
    if confirmation.lower() != 'y':
        print("Aborted.")
        sys.exit(0)
    
    start_time = time.time()
    end_time = start_time + args.duration
    
    try:
        # Load scapy
        print("\nInitializing scapy...")
        
        print("\nStarting suspicious traffic generation...")
        
        # Run attack simulations until duration expires
        while time.time() < end_time:
            # Always target local machine
            target_ip = local_ip
            
            # Choose an extreme attack type
            attack_type = random.choice([
                send_malformed_ip_extreme,
                send_christmas_tree_extreme,
                send_impossible_packet_combo,
                send_highly_fragmented,
                send_invalid_icmp
            ])
            
            # Execute the attack with extreme intensity parameters
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
        
        print("\nExtreme traffic generation completed!")
    
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
