import socket
import time
import struct
import csv
import datetime
from typing import Dict, List, Any, Optional, Tuple

# Add scapy import for cross-platform packet capture
try:
    from scapy.all import sniff, Ether, IP, TCP, UDP
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    print("Warning: scapy library not found. Please install it with 'pip install scapy'")

# Protocol mapping
PROTOCOL_MAP = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
}

# IP Protocol mapping
IP_PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
}

def get_protocol_name(protocol_number: int) -> str:
    """Returns the protocol name for a given Ethernet protocol number."""
    return PROTOCOL_MAP.get(protocol_number, f"Unknown ({protocol_number:04x})")

def get_ip_protocol_name(protocol_number: int) -> str:
    """Returns the protocol name for a given IP protocol number."""
    return IP_PROTOCOL_MAP.get(protocol_number, f"Unknown ({protocol_number})")

def extract_ethernet_header(data: bytes) -> Tuple[str, str, int, str]:
    """Extract and parse the Ethernet header."""
    eth_header = struct.unpack("!6s6sH", data[:14])
    dest_mac = ":".join(f"{b:02x}" for b in eth_header[0])
    src_mac = ":".join(f"{b:02x}" for b in eth_header[1])
    protocol_number = eth_header[2]
    protocol_name = get_protocol_name(protocol_number)
    return dest_mac, src_mac, protocol_number, protocol_name

def extract_ipv4_data(data: bytes) -> Dict[str, Any]:
    """Extract specific data and parameters from an IPv4 packet."""
    ip_header = data[14:34]
    version_ihl = ip_header[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    ip_header_length = ihl * 4
    
    ttl = ip_header[8]
    protocol_number = ip_header[9]
    protocol_name = get_ip_protocol_name(protocol_number)
    src_ip = ".".join(map(str, ip_header[12:16]))
    dest_ip = ".".join(map(str, ip_header[16:20]))
    
    return {
        "ip_version": version,
        "ip_header_length": ip_header_length,
        "ttl": ttl,
        "ip_protocol": protocol_number,
        "ip_protocol_name": protocol_name,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
    }

def extract_tcp_data(data: bytes, ip_header_length: int = 20) -> Dict[str, Any]:
    """Extract specific data and parameters from a TCP packet."""
    tcp_offset = 14 + ip_header_length  # Ethernet header (14) + IP header
    tcp_header = data[tcp_offset:tcp_offset+20]
    
    if len(tcp_header) < 20:
        return {"tcp_error": "Incomplete TCP header"}
    
    src_port = struct.unpack("!H", tcp_header[0:2])[0]
    dest_port = struct.unpack("!H", tcp_header[2:4])[0]
    
    flags = struct.unpack("!B", tcp_header[13:14])[0]
    
    return {
        "src_port": src_port,
        "dest_port": dest_port,
        "flags": flags
    }

def extract_udp_data(data: bytes, ip_header_length: int = 20) -> Dict[str, Any]:
    """Extract specific data and parameters from a UDP packet."""
    udp_offset = 14 + ip_header_length  # Ethernet header (14) + IP header
    udp_header = data[udp_offset:udp_offset+8]
    
    if len(udp_header) < 8:
        return {"udp_error": "Incomplete UDP header"}
    
    src_port = struct.unpack("!H", udp_header[0:2])[0]
    dest_port = struct.unpack("!H", udp_header[2:4])[0]
    length = struct.unpack("!H", udp_header[4:6])[0]
    
    return {
        "src_port": src_port,
        "dest_port": dest_port,
        "length": length
    }

def extract_features(data: bytes) -> Dict[str, Any]:
    """Extract features from the network packet."""
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Extract Ethernet header
    dest_mac, src_mac, protocol_number, protocol_name = extract_ethernet_header(data)
    
    # Initialize packet info with Ethernet data
    packet_info = {
        "timestamp": timestamp,
        "src_mac": src_mac,
        "dest_mac": dest_mac,
        "eth_protocol": protocol_number,
        "packet_size": len(data),
    }
    
    # Process based on protocol
    if protocol_name == "IPv4":
        ipv4_info = extract_ipv4_data(data)
        packet_info.update(ipv4_info)
        
        ip_header_length = ipv4_info.get("ip_header_length", 20)
        ip_protocol = ipv4_info.get("ip_protocol")
        
        # Extract TCP or UDP data if present
        if ip_protocol == 6:  # TCP
            tcp_info = extract_tcp_data(data, ip_header_length)
            packet_info.update(tcp_info)
        elif ip_protocol == 17:  # UDP
            udp_info = extract_udp_data(data, ip_header_length)
            packet_info.update(udp_info)
    
    return packet_info

def capture_packets(duration: int = 5, packet_limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """
    Capture network packets for a specified duration or up to a packet limit.
    
    Args:
        duration: Time in seconds to capture packets (default: 5)
        packet_limit: Maximum number of packets to capture (default: None)
        
    Returns:
        List of dictionaries containing packet information
    """
    if not HAS_SCAPY:
        print("Error: scapy library is required for packet capture. Please install it with 'pip install scapy'")
        return []
    
    packets = []
    packet_count = 0
    stop_time = time.time() + duration
    
    def packet_callback(pkt):
        nonlocal packet_count
        nonlocal packets
        
        # Extract packet features
        packet_info = {
            "timestamp": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "packet_size": len(pkt),
        }
        
        # Extract Ethernet information
        if Ether in pkt:
            packet_info["src_mac"] = pkt[Ether].src
            packet_info["dest_mac"] = pkt[Ether].dst
            packet_info["eth_protocol"] = pkt[Ether].type
        
        # Extract IP information
        if IP in pkt:
            packet_info["ip_version"] = pkt[IP].version
            packet_info["ip_header_length"] = pkt[IP].ihl * 4
            packet_info["ttl"] = pkt[IP].ttl
            packet_info["ip_protocol"] = pkt[IP].proto
            packet_info["ip_protocol_name"] = get_ip_protocol_name(pkt[IP].proto)
            packet_info["src_ip"] = pkt[IP].src
            packet_info["dest_ip"] = pkt[IP].dst
            
            # Extract TCP information
            if TCP in pkt:
                packet_info["src_port"] = pkt[TCP].sport
                packet_info["dest_port"] = pkt[TCP].dport
                packet_info["flags"] = pkt[TCP].flags
                
            # Extract UDP information
            elif UDP in pkt:
                packet_info["src_port"] = pkt[UDP].sport
                packet_info["dest_port"] = pkt[UDP].dport
                packet_info["length"] = pkt[UDP].len
        
        packets.append(packet_info)
        packet_count += 1
        
        # Stop if we've reached the packet limit or duration
        should_stop = time.time() >= stop_time
        if packet_limit is not None:
            should_stop = should_stop or packet_count >= packet_limit
        
        return should_stop  # Return True to stop sniffing
    
    try:
        # Temporarily redirect stdout to suppress output from sniff
        import sys
        import os
        
        # Start packet capture - don't use count parameter as it can cause NoneType comparison errors
        with open(os.devnull, 'w') as devnull:
            old_stdout = sys.stdout
            sys.stdout = devnull
            try:
                result = sniff(prn=packet_callback, 
                    store=False, 
                    timeout=duration)
            finally:
                sys.stdout = old_stdout
        
        # If a packet limit was specified, trim the packets list
        if packet_limit is not None and len(packets) > packet_limit:
            packets = packets[:packet_limit]
            
        return packets
    
    except Exception as e:
        print(f"Error: {e}")
        return []

def save_to_csv(packets: List[Dict[str, Any]], file_name: str = "network_logs.csv") -> bool:
    """
    Save captured packets to a CSV file.
    
    Args:
        packets: List of packet dictionaries
        file_name: Output CSV file name
        
    Returns:
        True if successful, False otherwise
    """
    if not packets:
        return False
        
    try:
        with open(file_name, "w", newline="") as file:
            # Get all unique keys from all packets
            fieldnames = set()
            for packet in packets:
                fieldnames.update(packet.keys())
            
            writer = csv.DictWriter(file, fieldnames=sorted(fieldnames))
            writer.writeheader()
            
            for packet in packets:
                writer.writerow(packet)
        
        return True
    
    except Exception as e:
        print(f"Error saving to CSV: {e}")
        return False

def main():
    """Main function to run the network packet capture and analysis tool."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Network Packet Capture Tool")
    parser.add_argument("-t", "--time", type=int, default=None, help="Duration of packet capture in seconds")
    parser.add_argument("-n", "--num", type=int, default=None, help="Maximum number of packets to capture (default: no limit)")
    parser.add_argument("-o", "--output", type=str, default="network_logs.csv", help="Output CSV file (default: network_logs.csv)")
    
    args = parser.parse_args()
    
    # Prompt user for capture duration if not provided
    duration = args.time
    if duration is None:
        while True:
            try:
                user_input = input("Enter capture duration in seconds (default: 5): ")
                if not user_input.strip():
                    duration = 5
                    break
                duration = int(user_input)
                if duration <= 0:
                    print("Duration must be a positive number.")
                    continue
                break
            except ValueError:
                print("Please enter a valid number.")
    
    print(f"Starting packet capture for {duration} seconds...")
    
    # Capture packets
    packets = capture_packets(duration=duration, packet_limit=args.num)
    
    if packets:
        # Save to CSV
        success = save_to_csv(packets, args.output)
        if success:
            print(f"Successfully captured {len(packets)} packets and saved to {args.output}")
        else:
            print("Failed to save packets to CSV file")
    else:
        print("No packets were captured")

if __name__ == "__main__":
    main()