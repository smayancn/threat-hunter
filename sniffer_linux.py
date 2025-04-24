import socket
import struct
import time
import csv
import os

ETH_FRAME_LEN = 14

def get_mac_address(bytes_addr):
    """Convert a byte sequence into a MAC address string."""
    return ':'.join(format(b, '02x') for b in bytes_addr)

def get_unique_log_filename(prefix='log'):
    """Generate a unique log filename (log1.csv, log2.csv, etc.)."""
    log_index = 1
    while os.path.exists(f'{prefix}{log_index}.csv'):
        log_index += 1
    return f'{prefix}{log_index}.csv'
  
def get_protocol_name(proto):
    """Return the protocol name based on the protocol number."""
    protocols = {
        0: "HOPOPT (IPv6 Hop-by-Hop Option) - RFC 8200",
        1: "ICMP (Internet Control Message Protocol) - RFC 792",
        2: "IGMP (Internet Group Management Protocol) - RFC 1112",
        3: "GGP (Gateway-to-Gateway Protocol) - RFC 823",
        4: "IP-in-IP (IP in IP Encapsulation) - RFC 2003",
        5: "ST (Internet Stream Protocol) - RFC 1190, RFC 1819",
        6: "TCP (Transmission Control Protocol) - RFC 793",
        7: "CBT (Core-based trees) - RFC 2189",
        8: "EGP (Exterior Gateway Protocol) - RFC 888",
        9: "IGP (Interior Gateway Protocol) - No specific RFC",
        10: "BBN-RCC-MON (BBN RCC Monitoring) - No RFC",
        11: "NVP-II (Network Voice Protocol) - RFC 741",
        12: "PUP (Xerox PUP) - No RFC",
        13: "ARGUS (ARGUS) - No RFC",
        14: "EMCON (EMCON) - No RFC",
        15: "XNET (Cross Net Debugger) - IEN 158",
        16: "CHAOS (Chaos) - No RFC",
        17: "UDP (User Datagram Protocol) - RFC 768",
        18: "MUX (Multiplexing) - IEN 90",
        19: "DCN-MEAS (DCN Measurement Subsystems) - No RFC",
        20: "HMP (Host Monitoring Protocol) - RFC 869",
        21: "PRM (Packet Radio Measurement) - No RFC",
        22: "XNS-IDP (XEROX NS IDP) - No RFC",
        23: "TRUNK-1 (Trunk-1) - No RFC",
        24: "TRUNK-2 (Trunk-2) - No RFC",
        25: "LEAF-1 (Leaf-1) - No RFC",
        26: "LEAF-2 (Leaf-2) - No RFC",
        27: "RDP (Reliable Data Protocol) - RFC 908",
        28: "IRTP (Internet Reliable Transaction Protocol) - RFC 938",
        29: "ISO-TP4 (ISO Transport Protocol Class 4) - RFC 905",
        30: "NETBLT (Bulk Data Transfer Protocol) - RFC 998",
        31: "MFE-NSP (MFE Network Services Protocol) - No RFC",
        32: "MERIT-INP (MERIT Internodal Protocol) - No RFC",
        33: "DCCP (Datagram Congestion Control Protocol) - RFC 4340",
        34: "3PC (Third Party Connect Protocol) - No RFC",
        35: "IDPR (Inter-Domain Policy Routing Protocol) - RFC 1479",
        36: "XTP (Xpress Transport Protocol) - No RFC",
        37: "DDP (Datagram Delivery Protocol) - No RFC",
        38: "IDPR-CMTP (IDPR Control Message Transport Protocol) - No RFC",
        39: "TP++ (TP++ Transport Protocol) - No RFC",
        40: "IL (IL Transport Protocol) - No RFC",
        41: "IPv6 (IPv6 Encapsulation) - RFC 2473",
        42: "SDRP (Source Demand Routing Protocol) - RFC 1940",
        43: "IPv6-Route (Routing Header for IPv6) - RFC 8200",
        44: "IPv6-Frag (Fragment Header for IPv6) - RFC 8200",
        45: "IDRP (Inter-Domain Routing Protocol) - No RFC",
        46: "RSVP (Resource Reservation Protocol) - RFC 2205",
        47: "GRE (Generic Routing Encapsulation) - RFC 2784, RFC 2890",
        48: "DSR (Dynamic Source Routing Protocol) - RFC 4728",
        49: "BNA (Burroughs Network Architecture) - No RFC",
        50: "ESP (Encapsulating Security Payload) - RFC 4303",
        51: "AH (Authentication Header) - RFC 4302",
        52: "I-NLSP (Integrated Net Layer Security Protocol) - TUBA",
        53: "SwIPe (SwIPe) - RFC 5237",
        54: "NARP (NBMA Address Resolution Protocol) - RFC 1735",
        55: "MOBILE (IP Mobility - Min Encap) - RFC 2004",
        56: "TLSP (Transport Layer Security Protocol) - No RFC",
        57: "SKIP (Simple Key-Management for Internet Protocol) - RFC 2356",
        58: "IPv6-ICMP (ICMP for IPv6) - RFC 4443, RFC 4884",
        59: "IPv6-NoNxt (No Next Header for IPv6) - RFC 8200",
        60: "IPv6-Opts (Destination Options for IPv6) - RFC 8200",
        61: "Any host internal protocol - No RFC",
        62: "CFTP (CFTP) - No RFC",
        63: "Any local network - No RFC",
        64: "SAT-EXPAK (SATNET and Backroom EXPAK) - No RFC",
        65: "KRYPTOLAN (Kryptolan) - No RFC",
        66: "RVD (MIT Remote Virtual Disk Protocol) - No RFC",
        67: "IPPC (Internet Pluribus Packet Core) - No RFC",
        68: "Any distributed file system - No RFC",
        69: "SAT-MON (SATNET Monitoring) - No RFC",
        70: "VISA (VISA Protocol) - No RFC",
        71: "IPCU (Internet Packet Core Utility) - No RFC",
        72: "CPNX (Computer Protocol Network Executive) - No RFC",
        73: "CPHB (Computer Protocol Heart Beat) - No RFC",
        74: "WSN (Wang Span Network) - No RFC",
        75: "PVP (Packet Video Protocol) - No RFC",
        76: "BR-SAT-MON (Backroom SATNET Monitoring) - No RFC",
        77: "SUN-ND (SUN ND PROTOCOL-Temporary) - No RFC",
        78: "WB-MON (WIDEBAND Monitoring) - No RFC",
        79: "WB-EXPAK (WIDEBAND EXPAK) - No RFC",
        80: "ISO-IP (International Organization for Standardization Internet Protocol) - No RFC",
        81: "VMTP (Versatile Message Transaction Protocol) - RFC 1045",
        82: "SECURE-VMTP (Secure Versatile Message Transaction Protocol) - RFC 1045",
        83: "VINES (VINES) - No RFC",
        84: "TTP (Transaction Transport Protocol) - Obsoleted March 2023",
        85: "NSFNET-IGP (NSFNET-IGP) - No RFC",
        86: "DGP (Dissimilar Gateway Protocol) - No RFC",
        87: "TCF (TCF) - No RFC",
        88: "EIGRP (EIGRP) - Informational RFC 7868",
        89: "OSPF (Open Shortest Path First) - RFC 2328",
        90: "Sprite-RPC (Sprite RPC Protocol) - No RFC",
        91: "LARP (Locus Address Resolution Protocol) - No RFC",
        92: "MTP (Multicast Transport Protocol) - No RFC",
        93: "AX.25 (AX.25) - No RFC",
        94: "OS (KA9Q NOS compatible IP over IP tunneling) - No RFC",
        95: "MICP (Mobile Internetworking Control Protocol) - No RFC",
        96: "SCC-SP (Semaphore Communications Sec. Pro) - No RFC",
        97: "ETHERIP (Ethernet-within-IP Encapsulation) - RFC 3378",
        98: "ENCAP (Encapsulation Header) - RFC 1241",
        99: "Any private encryption scheme - No RFC",
        100: "GMTP (GMTP) - No RFC",
        101: "IFMP (Ipsilon Flow Management Protocol) - No RFC",
        102: "PNNI (PNNI over IP) - No RFC",
        103: "PIM (Protocol Independent Multicast) - No RFC",
        104: "ARIS (IBM's ARIS Protocol) - No RFC",
        105: "SCPS (Space Communications Protocol Standards) - SCPS-TP",
        106: "QNX (QNX) - No RFC",
        107: "A/N (Active Networks) - No RFC",
        108: "IPComp (IP Payload Compression Protocol) - RFC 3173",
        109: "SNP (Sitara Networks Protocol) - No RFC",
        110: "Compaq-Peer (Compaq Peer Protocol) - No RFC",
        111: "IPX-in-IP (IPX in IP) - No RFC",
        112: "VRRP (Virtual Router Redundancy Protocol) - RFC 5798",
        113: "PGM (PGM Reliable Transport Protocol) - RFC 3208",
        114: "Any 0-hop protocol - No RFC",
        115: "L2TP (Layer Two Tunneling Protocol Version 3) - RFC 3931",
        116: "DDX (D-II Data Exchange) - No RFC",
        117: "IATP (Interactive Agent Transfer Protocol) - No RFC",
        118: "STP (Schedule Transfer Protocol) - No RFC",
        119: "SRP (SpectraLink Radio Protocol) - No RFC",
        120: "UTI (Universal Transport Interface Protocol) - No RFC",
        121: "SMP (Simple Message Protocol) - No RFC",
        122: "SM (Simple Multicast Protocol) - No RFC",
        123: "PTP (Performance Transparency Protocol) - No RFC",
        124: "IS-IS over IPv4 (Intermediate System to Intermediate System) - RFC 1142 and RFC 1195",
        125: "FIRE (Flexible Intra-AS Routing Environment) - No RFC",
        126: "CRTP (Combat Radio Transport Protocol) - No RFC",
        127: "CRUDP (Combat Radio User Datagram) - No RFC",
        128: "SSCOPMCE (Service-Specific Connection-Oriented Protocol) - ITU-T Q.2111",
        129: "IPLT (No RFC)",
        130: "SPS (Secure Packet Shield) - No RFC",
        131: "PIPE (Private IP Encapsulation within IP) - No RFC",
        132: "SCTP (Stream Control Transmission Protocol) - RFC 4960",
        133: "FC (Fibre Channel) - No RFC",
        134: "RSVP-E2E-IGNORE (Reservation Protocol End-to-End Ignore) - RFC 3175",
        135: "Mobility Header (Mobility Extension Header for IPv6) - RFC 6275",
        136: "UDPLite (Lightweight User Datagram Protocol) - RFC 3828",
        137: "MPLS-in-IP (Multiprotocol Label Switching Encapsulated in IP) - RFC 4023, RFC 5332",
        138: "manet (MANET Protocols) - RFC 5498",
        139: "HIP (Host Identity Protocol) - RFC 5201",
        140: "Shim6 (Site Multihoming by IPv6 Intermediation) - RFC 5533",
        141: "WESP (Wrapped Encapsulating Security Payload) - RFC 5840",
        142: "ROHC (Robust Header Compression) - RFC 5856",
        143: "Ethernet (Segment Routing over IPv6) - RFC 8986",
        144: "AGGFRAG (AGGFRAG Encapsulation Payload for ESP) - RFC 9347",
        145: "NSH (Network Service Header) - draft-ietf-spring-nsh-sr",
        146-252: "Unassigned - No RFC",
        253-254: "Use for experimentation and testing - RFC 3692",
        255: "Reserved - No RFC",
        0x0806: "ARP (Address Resolution Protocol) - No RFC",
    }
    return protocols.get(proto, f"Unknown Protocol ({proto})")

def capture_network_details(interface, capture_time=5):
    """Capture network packets for a given time period and save details to two CSV files:
       1. all_packets.csv - Contains all packets including ARP
       2. non_arp.csv - Contains only non-ARP packets
    """
    try:
        # Create a raw socket
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        sock.bind((interface, 0))
        
        print(f"Listening for network packets on {interface} for {capture_time} seconds...")
        
        start_time = time.time()
        
        # Generate unique filenames for both CSVs
        all_packets_filename = get_unique_log_filename(prefix='all_packets')
        non_arp_filename = get_unique_log_filename(prefix='non_arp')
        
        print(f"Saving all packets to {all_packets_filename}")
        print(f"Saving non-ARP packets to {non_arp_filename}")
        
        # Counters for statistics
        total_packets = 0
        packet_count = 0  # Non-ARP packets
        tcp_count = 0
        tcp_with_flags = 0
        arp_count = 0
        
        # CSV column headers
        headers = [
            'Timestamp', 'Source MAC', 'Destination MAC', 'Source IP', 'Destination IP', 
            'Protocol', 'Packet Length', 'Source Port', 'Destination Port', 'TCP Flags', 'Packet Direction'
        ]
        
        # Initialize both CSV files
        with open(all_packets_filename, 'w', newline='') as all_file, \
             open(non_arp_filename, 'w', newline='') as non_arp_file:
            
            all_writer = csv.writer(all_file)
            non_arp_writer = csv.writer(non_arp_file)
            
            # Write headers to both files
            all_writer.writerow(headers)
            non_arp_writer.writerow(headers)
            
            # Set a timeout to prevent blocking forever
            sock.settimeout(1.0)
            
            while time.time() - start_time < capture_time:
                try:
                    raw_data, addr = sock.recvfrom(65536)
                    total_packets += 1  # Count all packets
                    
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
                    src_port, dest_port = "N/A", "N/A"
                    tcp_flags = "N/A"
                    packet_direction = "N/A"
                    
                    # Handle ARP packets
                    if eth_proto == 0x0806:
                        arp_count += 1
                        
                        try:
                            arp_header = raw_data[ETH_FRAME_LEN:ETH_FRAME_LEN + 28]  # ARP header is 28 bytes
                            if len(arp_header) >= 28:
                                hw_type, proto_type, hw_size, proto_size, op_code, src_mac_arp, src_ip_arp, dest_mac_arp, dest_ip_arp = struct.unpack("! H H B B H 6s 4s 6s 4s", arp_header)
                                
                                src_ip = socket.inet_ntoa(src_ip_arp)
                                dest_ip = socket.inet_ntoa(dest_ip_arp)
                                protocol = "ARP"
                                
                                # 1 = ARP request, 2 = ARP reply
                                packet_direction = "Outbound" if op_code == 1 else "Inbound" if op_code == 2 else "Unknown"
                        except Exception as e:
                            protocol = f"ARP (Parsing Error: {str(e)})"
                        
                        # Write ARP packet to all_packets.csv only
                        all_writer.writerow([
                            timestamp, src_mac_str, dest_mac_str, src_ip, dest_ip, 
                            protocol, packet_length, src_port, dest_port, tcp_flags, packet_direction
                        ])
                    
                    # Handle IPv4 packets
                    elif eth_proto == 0x0800:
                        packet_count += 1  # Count non-ARP packets
                        try:
                            ip_header = raw_data[ETH_FRAME_LEN:ETH_FRAME_LEN + 20]  # IPv4 header is at least 20 bytes
                            if len(ip_header) >= 20:
                                # First byte contains version and header length
                                version_header_len = ip_header[0]
                                header_len = (version_header_len & 0xF) * 4  # Header length in bytes
                                
                                # Get the protocol number (TCP=6, UDP=17, ICMP=1)
                                proto = ip_header[9]
                                
                                # Get source and destination IP addresses
                                src_ip = socket.inet_ntoa(ip_header[12:16])
                                dest_ip = socket.inet_ntoa(ip_header[16:20])
                                
                                # Get protocol name
                                protocol = get_protocol_name(proto).split(' ')[0]  # Just get the short name
                                
                                # Handle TCP packets
                                if proto == 6:  # TCP
                                    tcp_count += 1
                                    tcp_header_start = ETH_FRAME_LEN + header_len
                                    
                                    # Make sure we have enough data for the TCP header
                                    if len(raw_data) >= tcp_header_start + 14:
                                        tcp_header = raw_data[tcp_header_start:tcp_header_start + 14]
                                        
                                        # Parse TCP header parts
                                        src_port, dest_port, seq, ack, offset_reserved_flags = struct.unpack('! H H L L H', tcp_header)
                                        
                                        # Extract TCP flags (bits 8-15 of the 13th & 14th bytes)
                                        # The offset is in the high 4 bits, and flags in lower bits
                                        flags = offset_reserved_flags & 0x003F  # Mask to get only the flags (lowest 6 bits)
                                        
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
                                            tcp_with_flags += 1
                                        
                                        # Determine packet direction based on port numbers
                                        if src_port < 1024 and dest_port > 1024:
                                            packet_direction = "Inbound"
                                        elif dest_port < 1024 and src_port > 1024:
                                            packet_direction = "Outbound"
                                        else:
                                            packet_direction = "Unknown"
                                
                                # Handle UDP packets
                                elif proto == 17:  # UDP
                                    udp_header_start = ETH_FRAME_LEN + header_len
                                    
                                    # Make sure we have enough data for the UDP header
                                    if len(raw_data) >= udp_header_start + 8:
                                        udp_header = raw_data[udp_header_start:udp_header_start + 8]
                                        src_port, dest_port, length, checksum = struct.unpack('! H H H H', udp_header)
                                        
                                        # Determine packet direction based on port numbers
                                        if src_port < 1024 and dest_port > 1024:
                                            packet_direction = "Inbound"
                                        elif dest_port < 1024 and src_port > 1024:
                                            packet_direction = "Outbound"
                                        else:
                                            packet_direction = "Unknown"
                                
                                # Handle ICMP and other IP protocols (no ports)
                                else:
                                    # For protocols without ports, use N/A for port values
                                    src_port, dest_port = "N/A", "N/A"
                                    
                                    # Determine packet direction based on IP addresses for all other protocols
                                    # Define private IP address prefixes
                                    private_prefixes = ('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', 
                                                       '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', 
                                                       '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '127.')
                                    
                                    # Check if source is private
                                    is_src_private = any(src_ip.startswith(prefix) for prefix in private_prefixes)
                                    
                                    # Check if destination is private
                                    is_dst_private = any(dest_ip.startswith(prefix) for prefix in private_prefixes)
                                    
                                    # If source IP is local and destination is not, it's outbound
                                    if is_src_private and not is_dst_private:
                                        packet_direction = "Outbound"
                                    # If destination IP is local and source is not, it's inbound
                                    elif not is_src_private and is_dst_private:
                                        packet_direction = "Inbound"
                                    # If both are local
                                    elif is_src_private and is_dst_private:
                                        packet_direction = "Local"
                                    # If both are external
                                    else:
                                        packet_direction = "External"
                        except Exception as e:
                            protocol = f"IPv4 (Error: {str(e)})"
                            
                        # Write IPv4 packet to both CSV files
                        row_data = [
                            timestamp, src_mac_str, dest_mac_str, src_ip, dest_ip, 
                            protocol, packet_length, src_port, dest_port, tcp_flags, packet_direction
                        ]
                        all_writer.writerow(row_data)
                        non_arp_writer.writerow(row_data)
                    
                    # Handle other packet types (only to all_packets.csv)
                    else:
                        # For other Ethernet protocols like IPv6 etc., still try to determine direction
                        if src_ip != "N/A" and dest_ip != "N/A":
                            # Define private IP address prefixes
                            private_prefixes = ('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', 
                                              '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', 
                                              '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '127.')
                            
                            # Check if source and destination are private
                            is_src_private = any(src_ip.startswith(prefix) for prefix in private_prefixes)
                            is_dst_private = any(dest_ip.startswith(prefix) for prefix in private_prefixes)
                            
                            if is_src_private and not is_dst_private:
                                packet_direction = "Outbound"
                            elif not is_src_private and is_dst_private:
                                packet_direction = "Inbound"
                            elif is_src_private and is_dst_private:
                                packet_direction = "Local"
                            else:
                                packet_direction = "External"
                        else:
                            # For protocols we can't determine direction, use MAC-based heuristic
                            # Broadcast/multicast MACs are usually inbound notifications
                            if dest_mac_str.startswith("ff:ff:ff") or dest_mac_str.startswith("01:00:5e"):
                                packet_direction = "Broadcast"
                            else:
                                packet_direction = "Unknown"
                                
                        all_writer.writerow([
                            timestamp, src_mac_str, dest_mac_str, src_ip, dest_ip, 
                            protocol, packet_length, src_port, dest_port, tcp_flags, packet_direction
                        ])
                    
                except socket.timeout:
                    # Just continue on timeout
                    continue
                except Exception as e:
                    print(f"Error capturing packet: {str(e)}")
        
        print(f"Packet capture complete.")
        print(f"All packets ({total_packets} total) saved to {all_packets_filename}")
        print(f"Non-ARP packets ({packet_count} total) saved to {non_arp_filename}")
        print(f"ARP packets: {arp_count}")
        print(f"TCP packets: {tcp_count}")
        print(f"TCP packets with flags: {tcp_with_flags}")
        
        # Return both filenames as a tuple
        return (all_packets_filename, non_arp_filename)
    
    except PermissionError:
        print("Error: Root/Administrator privileges required to capture packets.")
        print("Try running the script with sudo (Linux/Mac) or as Administrator (Windows).")
        return None
    except socket.error as e:
        print(f"Socket error: {str(e)}")
        print("Check if the interface name is correct and that the network interface exists.")
        return None
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return None

if __name__ == "__main__":
    import sys
    
    # Parse command line arguments
    if len(sys.argv) > 1:
        interface = sys.argv[1]
        capture_time = int(sys.argv[2]) if len(sys.argv) > 2 else 60
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
        capture_time = int(input("Enter capture time in seconds (default: 60): ") or 60)
    
    print(f"\nStarting packet capture on {interface} for {capture_time} seconds...")
    result = capture_network_details(interface, capture_time)
    
    if result:
        all_packets_file, non_arp_file = result
        print("\nCapture completed successfully!")
        print(f"To train your ML model on all packets (including ARP): python network_ml.py --input {all_packets_file}")
        print(f"To train your ML model on non-ARP packets only: python network_ml.py --input {non_arp_file}")
