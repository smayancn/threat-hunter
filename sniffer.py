import socket
import struct
import time
import csv
import os
import sys
from datetime import datetime

# Try to import scapy - needed for packet capture
try:
    import scapy.all as scapy
    from scapy.layers import http
    has_scapy = True
except ImportError:
    has_scapy = False
    print("Warning: Scapy not installed. Some features may not work.")
    print("Install with: pip install scapy")

ETH_FRAME_LEN = 14

def get_windows_if_list():
    """Get list of network interfaces on Windows with friendly names"""
    interfaces = []
    try:
        # Try Windows-specific approach first - this should give the most user-friendly results
        if os.name == 'nt':
            import subprocess
            
            # Use 'netsh' command to get wireless interfaces
            try:
                # Get wireless interfaces
                wifi_output = subprocess.check_output("netsh wlan show interfaces", shell=True).decode('utf-8', errors='ignore')
                if "There is no wireless interface on the system" not in wifi_output:
                    for line in wifi_output.split('\n'):
                        line = line.strip()
                        if line.startswith('Name'):
                            wifi_name = line.split(':', 1)[1].strip()
                            interfaces.append(f"WiFi: {wifi_name}")
            except:
                pass  # Command might fail if no WiFi
            
            # Use ipconfig to get all interfaces
            ipconfig_output = subprocess.check_output("ipconfig /all", shell=True).decode('utf-8', errors='ignore')
            
            # Parse the output
            current_interface = None
            description = None
            collecting_data = False
            
            for line in ipconfig_output.split('\n'):
                line = line.strip()
                
                # Start of a new adapter section
                if "adapter" in line.lower() and line.endswith(':'):
                    current_interface = line.split("adapter")[1].strip().rstrip(':')
                    description = None
                    collecting_data = True
                    continue
                
                if collecting_data:
                    # Look for description
                    if "description" in line.lower() and ':' in line:
                        description = line.split(':', 1)[1].strip()
                    
                    # Look for MAC address to confirm it's a physical interface
                    if "physical address" in line.lower() and ':' in line:
                        mac = line.split(':', 1)[1].strip()
                        if mac != "00-00-00-00-00-00" and description:
                            # Skip interfaces already found as WiFi
                            if not any(description in wifi for wifi in interfaces if wifi.startswith("WiFi:")):
                                # Determine type based on description
                                if 'wi-fi' in description.lower() or 'wireless' in description.lower() or 'wlan' in description.lower():
                                    interfaces.append(f"WiFi: {description}")
                                elif 'ethernet' in description.lower() or 'local area connection' in description.lower():
                                    interfaces.append(f"Ethernet: {description}")
                                else:
                                    interfaces.append(f"Other: {description}")
        
        # If no interfaces found with Windows-specific methods, try scapy
        if not interfaces and has_scapy:
            all_interfaces = scapy.get_if_list()
            
            for iface in all_interfaces:
                if iface != 'lo' and iface != 'any':  # Skip loopback and 'any' interface
                    interfaces.append(f"Network Interface: {iface}")
        
        # If still no interfaces, try socket as a last resort
        if not interfaces:
            hostname = socket.gethostname()
            ip_addresses = socket.gethostbyname_ex(hostname)[2]
            for i, ip in enumerate(ip_addresses):
                if ip != '127.0.0.1':  # Skip loopback
                    interfaces.append(f"Network Interface {i+1}: {ip}")
    
    except Exception as e:
        print(f"Error getting interfaces: {e}")
        # Provide at least a fallback option
        interfaces.append("Default Interface")
        
    return interfaces

def get_mac_address(bytes_addr):
    """Convert a byte sequence into a MAC address string."""
    return ':'.join(format(b, '02x') for b in bytes_addr)

def get_next_available_filename(prefix='all_packets', extension='.csv'):
    """Get the next available filename in sequence (all_packets1.csv, all_packets2.csv, etc.)"""
    index = 1
    while os.path.exists(f"{prefix}{index}{extension}"):
        index += 1
    return f"{prefix}{index}{extension}"

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
    """Capture network packets for a given time period and save details to a CSV file."""
    try:
        # Extract the actual interface name if it's in our friendly format
        actual_interface = interface
        if ':' in interface:
            # Extract the actual interface name after the colon
            actual_interface = interface.split(':', 1)[1].strip()
            
            # For Windows, if we have Ethernet/WiFi prefix, we need to look up the real interface name
            if os.name == 'nt' and has_scapy:
                # Try to find the real interface name from scapy
                interface_found = False
                
                try:
                    # Check all windows interfaces
                    if hasattr(scapy, 'get_windows_if_list'):
                        for iface in scapy.get_windows_if_list():
                            if actual_interface in iface['description']:
                                actual_interface = iface['name']
                                interface_found = True
                                break
                        
                        if not interface_found:
                            # If not found, try using the first available interface
                            interfaces = scapy.get_if_list()
                            if interfaces:
                                actual_interface = interfaces[0]
                                print(f"Warning: Interface not found, using {actual_interface} instead")
                except Exception as e:
                    print(f"Error finding interface: {e}")
                    # Continue with the interface name we have

        # Get the next available filename in sequence
        csv_file = get_next_available_filename()
        
        # Print absolute path for debugging
        print(f"Full path to CSV file: {os.path.abspath(csv_file)}")
        
        # Check if we're on Windows or Linux
        if os.name == 'nt' and has_scapy:  # Windows with Scapy
            print(f"Starting capture on interface {interface} for {capture_time} seconds...")
            try:
                packets = scapy.sniff(iface=actual_interface, timeout=capture_time)
                print(f"Captured {len(packets)} packets")
                
                # Process packets for CSV
                with open(csv_file, 'w', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    # Comprehensive header with all relevant network details
                    writer.writerow([
                        'timestamp', 'source_mac', 'destination_mac', 'source_ip', 'destination_ip', 
                        'source_port', 'destination_port', 'protocol', 'length', 'ttl',
                        'tcp_flags', 'tcp_window', 'icmp_type', 'icmp_code', 'dns_query',
                        'http_method', 'http_host', 'http_path', 'packet_direction'
                    ])
                    
                    for packet in packets:
                        # Basic packet info
                        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        protocol = "Unknown"
                        src_mac = "N/A"
                        dst_mac = "N/A"
                        src_ip = "N/A"
                        dst_ip = "N/A"
                        src_port = "N/A"
                        dst_port = "N/A"
                        length = len(packet)
                        ttl = "N/A"
                        tcp_flags = "N/A"
                        tcp_window = "N/A"
                        icmp_type = "N/A"
                        icmp_code = "N/A"
                        dns_query = "N/A"
                        http_method = "N/A"
                        http_host = "N/A"
                        http_path = "N/A"
                        packet_direction = "Unknown"
                        
                        # Ethernet layer
                        if packet.haslayer(scapy.Ether):
                            eth_layer = packet[scapy.Ether]
                            src_mac = eth_layer.src
                            dst_mac = eth_layer.dst
                        
                        # IP layer
                        if packet.haslayer(scapy.IP):
                            ip_layer = packet[scapy.IP]
                            src_ip = ip_layer.src
                            dst_ip = ip_layer.dst
                            protocol = ip_layer.proto
                            ttl = ip_layer.ttl
                            
                            # Determine packet direction
                            private_prefixes = ('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', 
                                              '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', 
                                              '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '127.')
                            
                            src_private = any(src_ip.startswith(prefix) for prefix in private_prefixes)
                            dst_private = any(dst_ip.startswith(prefix) for prefix in private_prefixes)
                            
                            if src_private and not dst_private:
                                packet_direction = "Outbound"
                            elif not src_private and dst_private:
                                packet_direction = "Inbound"
                            elif src_private and dst_private:
                                packet_direction = "Local"
                            else:
                                packet_direction = "External"
                            
                            # TCP layer
                            if packet.haslayer(scapy.TCP):
                                tcp_layer = packet[scapy.TCP]
                                src_port = tcp_layer.sport
                                dst_port = tcp_layer.dport
                                protocol = "TCP"
                                tcp_window = tcp_layer.window
                                
                                # TCP Flags
                                flags = []
                                if tcp_layer.flags.F: flags.append("FIN")
                                if tcp_layer.flags.S: flags.append("SYN")
                                if tcp_layer.flags.R: flags.append("RST")
                                if tcp_layer.flags.P: flags.append("PSH")
                                if tcp_layer.flags.A: flags.append("ACK")
                                if tcp_layer.flags.U: flags.append("URG")
                                if tcp_layer.flags.E: flags.append("ECE")
                                if tcp_layer.flags.C: flags.append("CWR")
                                tcp_flags = " ".join(flags) if flags else "None"
                                
                                # HTTP layer
                                if packet.haslayer(http.HTTPRequest):
                                    http_layer = packet[http.HTTPRequest]
                                    protocol = "HTTP"
                                    http_host = http_layer.Host.decode() if http_layer.Host else "N/A"
                                    http_path = http_layer.Path.decode() if http_layer.Path else "N/A"
                                    http_method = http_layer.Method.decode() if http_layer.Method else "N/A"
                            
                            # UDP layer
                            elif packet.haslayer(scapy.UDP):
                                udp_layer = packet[scapy.UDP]
                                src_port = udp_layer.sport
                                dst_port = udp_layer.dport
                                protocol = "UDP"
                                
                                # DNS layer
                                if packet.haslayer(scapy.DNS):
                                    dns_layer = packet[scapy.DNS]
                                    protocol = "DNS"
                                    if dns_layer.qr == 0:  # Query
                                        if dns_layer.qd and dns_layer.qd.qname:
                                            dns_query = dns_layer.qd.qname.decode()
                            
                            # ICMP layer
                            elif packet.haslayer(scapy.ICMP):
                                icmp_layer = packet[scapy.ICMP]
                                protocol = "ICMP"
                                icmp_type = icmp_layer.type
                                icmp_code = icmp_layer.code
                        
                        # ARP layer
                        elif packet.haslayer(scapy.ARP):
                            arp_layer = packet[scapy.ARP]
                            protocol = "ARP"
                            src_ip = arp_layer.psrc
                            dst_ip = arp_layer.pdst
                            packet_direction = "Broadcast" if dst_ip == "255.255.255.255" else "Local"
                        
                        # Write the row to CSV
                        writer.writerow([
                            timestamp, src_mac, dst_mac, src_ip, dst_ip, 
                            src_port, dst_port, protocol, length, ttl,
                            tcp_flags, tcp_window, icmp_type, icmp_code, dns_query,
                            http_method, http_host, http_path, packet_direction
                        ])
                
                print(f"Saved CSV file: {csv_file}")
                return (csv_file, csv_file)  # Return the same file twice for API compatibility
                
            except Exception as e:
                print(f"Error during packet capture: {str(e)}")
                return None
        else:  # Unix/Linux or Windows without Scapy
            # Generate an appropriate filename for raw socket capture
            result = capture_with_socket(actual_interface, capture_time)
            
            if result:
                # Raw socket capture creates CSV - return it
                print(f"Saved CSV file using raw socket method: {result}")
                return (result, result)  # Return the same file twice for API compatibility
            
            return None
            
    except Exception as e:
        print(f"Unexpected error in capture_network_details: {str(e)}")
        return None

def capture_with_scapy(interface, capture_time=5):
    """Use scapy for packet capture on Windows systems"""
    try:
        # Try to import scapy
        try:
            from scapy.all import sniff, Ether, IP, TCP, UDP, ARP, ICMP
        except ImportError:
            print("Error: Scapy is required for packet capture on Windows.")
            print("Please install it with: pip install scapy")
            return None

        print(f"Listening for network packets on {interface} for {capture_time} seconds...")
        
        # Generate unique filename for the CSV
        all_packets_filename = get_next_available_filename(prefix='all_packets')
        
        print(f"Saving all packets to {all_packets_filename}")
        
        # Counters for statistics
        total_packets = 0
        tcp_count = 0
        tcp_with_flags = 0
        arp_count = 0
        
        # CSV column headers
        headers = [
            'Timestamp', 'Source MAC', 'Destination MAC', 'Source IP', 'Destination IP', 
            'Protocol', 'Packet Length', 'Source Port', 'Destination Port', 'TCP Flags', 'Packet Direction'
        ]
        
        # Initialize CSV file
        with open(all_packets_filename, 'w', newline='') as all_file:
            all_writer = csv.writer(all_file)
            
            # Write headers to file
            all_writer.writerow(headers)
            
            # Define packet processing function
            def process_packet(packet):
                nonlocal total_packets, tcp_count, tcp_with_flags, arp_count
                
                total_packets += 1
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                
                # Default values
                src_mac_str = "N/A"
                dest_mac_str = "N/A"
                src_ip = "N/A"
                dest_ip = "N/A"
                protocol = "Unknown"
                packet_length = len(packet)
                src_port = "N/A"
                dest_port = "N/A"
                tcp_flags = "N/A"
                packet_direction = "N/A"
                
                # Extract Ethernet information
                if Ether in packet:
                    src_mac_str = packet[Ether].src
                    dest_mac_str = packet[Ether].dst
                
                # Handle ARP packets
                if ARP in packet:
                    arp_count += 1
                    protocol = "ARP"
                    src_ip = packet[ARP].psrc
                    dest_ip = packet[ARP].pdst
                    
                    # 1 = ARP request, 2 = ARP reply
                    op_code = packet[ARP].op
                    packet_direction = "Outbound" if op_code == 1 else "Inbound" if op_code == 2 else "Unknown"
                    
                    # Write ARP packet to CSV
                    all_writer.writerow([
                        timestamp, src_mac_str, dest_mac_str, src_ip, dest_ip, 
                        protocol, packet_length, src_port, dest_port, tcp_flags, packet_direction
                    ])
                
                # Handle IP packets
                elif IP in packet:
                    src_ip = packet[IP].src
                    dest_ip = packet[IP].dst
                    
                    # Get protocol
                    ip_proto = packet[IP].proto
                    protocol = get_protocol_name(ip_proto).split(' ')[0]  # Just get the short name
                    
                    # Handle TCP packets
                    if TCP in packet:
                        tcp_count += 1
                        src_port = packet[TCP].sport
                        dest_port = packet[TCP].dport
                        
                        # Extract TCP flags
                        flags = []
                        if packet[TCP].flags.F: flags.append("FIN")
                        if packet[TCP].flags.S: flags.append("SYN")
                        if packet[TCP].flags.R: flags.append("RST")
                        if packet[TCP].flags.P: flags.append("PSH")
                        if packet[TCP].flags.A: flags.append("ACK")
                        if packet[TCP].flags.U: flags.append("URG")
                        
                        if flags:
                            tcp_flags = " ".join(flags)
                            tcp_with_flags += 1
                        
                        # Determine packet direction based on port numbers
                        if src_port < 1024 and dest_port > 1024:
                            packet_direction = "Inbound"
                        elif dest_port < 1024 and src_port > 1024:
                            packet_direction = "Outbound"
                        else:
                            packet_direction = "Unknown"
                    
                    # Handle UDP packets
                    elif UDP in packet:
                        src_port = packet[UDP].sport
                        dest_port = packet[UDP].dport
                        
                        # Determine packet direction based on port numbers
                        if src_port < 1024 and dest_port > 1024:
                            packet_direction = "Inbound"
                        elif dest_port < 1024 and src_port > 1024:
                            packet_direction = "Outbound"
                        else:
                            packet_direction = "Unknown"
                    
                    # Handle ICMP and other IP protocols
                    else:
                        # Determine packet direction based on IP addresses
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
                    
                    # Write IP packet to CSV
                    row_data = [
                        timestamp, src_mac_str, dest_mac_str, src_ip, dest_ip, 
                        protocol, packet_length, src_port, dest_port, tcp_flags, packet_direction
                    ]
                    all_writer.writerow(row_data)
                
                # Handle other packet types
                else:
                    # For protocols we can't determine direction, use MAC-based heuristic
                    if dest_mac_str.startswith("ff:ff:ff") or dest_mac_str.startswith("01:00:5e"):
                        packet_direction = "Broadcast"
                    else:
                        packet_direction = "Unknown"
                        
                    all_writer.writerow([
                        timestamp, src_mac_str, dest_mac_str, src_ip, dest_ip, 
                        protocol, packet_length, src_port, dest_port, tcp_flags, packet_direction
                    ])
            
            # Start packet capture
            try:
                sniff(iface=interface, prn=process_packet, timeout=capture_time)
            except KeyboardInterrupt:
                print("Packet capture stopped by user.")
            
        print(f"Packet capture complete.")
        print(f"All packets ({total_packets} total) saved to {all_packets_filename}")
        print(f"ARP packets: {arp_count}")
        print(f"TCP packets: {tcp_count}")
        print(f"TCP packets with flags: {tcp_with_flags}")
        
        return all_packets_filename
        
    except Exception as e:
        print(f"Error during packet capture: {str(e)}")
        print("If using Windows, make sure you have Npcap installed: https://npcap.com/")
        return None

def capture_with_socket(interface, capture_time=5):
    """Use raw sockets for packet capture on Linux/Unix/Windows without Scapy."""
    try:
        # Create a raw socket and bind to the specified interface
        if os.name == 'nt':  # Windows
            print("Warning: Windows raw socket capture has limited functionality.")
            print("For better results, please install scapy: pip install scapy")
            print("and npcap: https://npcap.com/")
            # Create a raw socket on Windows (requires admin privileges)
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        else:  # Linux/Unix
            # Create a raw socket, receive at ethernet level
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        
        # Set socket to promiscuous mode
        try:
            if os.name == 'nt':  # Windows
                s.bind((interface, 0))
                # Enable promiscuous mode on Windows
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:  # Linux/Unix
                s.bind((interface, 0))
        except socket.error as e:
            print(f"Socket bind error: {e}")
            return None
        
        # Prepare to capture packets
        start_time = time.time()
        end_time = start_time + capture_time
        
        # Set timeout to 1 second to allow clean exit
        s.settimeout(1)
        
        # Initialize counters
        total_packets = 0
        arp_count = 0
        tcp_count = 0
        tcp_with_flags = 0
        
        # Get the next available filename
        all_packets_filename = get_next_available_filename()
        
        print(f"Saving all packets to {all_packets_filename}")
        
        # Open CSV file for writing
        with open(all_packets_filename, 'w', newline='') as all_file:
            # Create CSV writers
            all_writer = csv.writer(all_file)
            
            # Write headers
            all_writer.writerow(['timestamp', 'source_mac', 'dest_mac', 'source_ip', 'dest_ip', 
                               'protocol', 'length', 'source_port', 'dest_port', 'tcp_flags', 'packet_direction'])
            
            # Capture packets
            print(f"Starting packet capture for {capture_time} seconds...")
            
            # Main capture loop
            while time.time() < end_time:
                try:
                    # Receive a packet
                    raw_data = s.recv(65535)
                    total_packets += 1
                    
                    # Get timestamp for this packet
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    
                    # Get packet length
                    packet_length = len(raw_data)
                    
                    # Default values for fields
                    src_mac_str = "N/A"
                    dest_mac_str = "N/A"
                    src_ip = "N/A"
                    dest_ip = "N/A"
                    protocol = "Unknown"
                    src_port = "N/A"
                    dest_port = "N/A"
                    tcp_flags = "N/A"
                    packet_direction = "Unknown"
                    
                    # Parse Ethernet header for MAC addresses
                    try:
                        if os.name != 'nt':  # Linux/Unix has Ethernet header
                            dest_mac = raw_data[0:6]
                            src_mac = raw_data[6:12]
                            dest_mac_str = get_mac_address(dest_mac)
                            src_mac_str = get_mac_address(src_mac)
                    except:
                        pass  # Skip if parsing fails
                    
                    # Try to identify Ethernet protocol type
                    try:
                        if os.name != 'nt':  # Linux/Unix
                            eth_protocol = raw_data[12:14]
                            protocol_type = struct.unpack("!H", eth_protocol)[0]
                        else:  # Windows (no Ethernet header)
                            protocol_type = 0x0800  # Assume IPv4
                            
                        # Process based on protocol type
                        if protocol_type == 0x0806:  # ARP
                            protocol = "ARP"
                            arp_count += 1
                            
                        elif protocol_type == 0x0800:  # IPv4
                            # Parse IPv4 header
                            if os.name == 'nt':  # Windows (no Ethernet header)
                                version_header_length = raw_data[0]
                                header_len = (version_header_length & 0xF) * 4
                                protocol_num = raw_data[9]
                                src_ip = socket.inet_ntoa(raw_data[12:16])
                                dest_ip = socket.inet_ntoa(raw_data[16:20])
                            else:  # Linux/Unix (with Ethernet header)
                                version_header_length = raw_data[ETH_FRAME_LEN]
                                header_len = (version_header_length & 0xF) * 4
                                protocol_num = raw_data[ETH_FRAME_LEN + 9]
                                src_ip = socket.inet_ntoa(raw_data[ETH_FRAME_LEN + 12:ETH_FRAME_LEN + 16])
                                dest_ip = socket.inet_ntoa(raw_data[ETH_FRAME_LEN + 16:ETH_FRAME_LEN + 20])
                            
                            # Get protocol name
                            protocol = get_protocol_name(protocol_num)
                            
                            # Handle TCP
                            if protocol_num == 6:  # TCP
                                tcp_count += 1
                                
                                # TCP header starts after the IP header
                                tcp_header_start = ETH_FRAME_LEN + header_len if os.name != 'nt' else header_len
                                
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
                            elif protocol_num == 17:  # UDP
                                udp_header_start = ETH_FRAME_LEN + header_len if os.name != 'nt' else header_len
                                
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
                        
                    # Write IPv4 packet to CSV
                    row_data = [
                        timestamp, src_mac_str, dest_mac_str, src_ip, dest_ip, 
                        protocol, packet_length, src_port, dest_port, tcp_flags, packet_direction
                    ]
                    all_writer.writerow(row_data)
                
                except socket.timeout:
                    # Just continue on timeout
                    continue
                except Exception as e:
                    print(f"Error capturing packet: {str(e)}")
        
        print(f"Packet capture complete.")
        print(f"All packets ({total_packets} total) saved to {all_packets_filename}")
        print(f"ARP packets: {arp_count}")
        print(f"TCP packets: {tcp_count}")
        print(f"TCP packets with flags: {tcp_with_flags}")
        
        # Return the filename
        return all_packets_filename
    
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
            try:
                from scapy.all import get_windows_if_list
                interfaces_info = get_windows_if_list()
                available_interfaces = [iface['name'] for iface in interfaces_info]
            except ImportError:
                print("Tip: Install 'scapy' package for automatic interface detection on Windows")
                print("     pip install scapy")
                print("Also install Npcap from: https://npcap.com/")
                available_interfaces = ["Ethernet", "Wi-Fi"]
        
        print("Available network interfaces (these might not be accurate):")
        for i, iface in enumerate(available_interfaces):
            print(f"{i+1}. {iface}")
        
        interface = input("\nEnter interface name (e.g., eth0, wlan0, en0, 'Wi-Fi'): ")
        capture_time = int(input("Enter capture time in seconds (default: 60): ") or 60)
    
    print(f"\nStarting packet capture on {interface} for {capture_time} seconds...")
    print(f"Platform: {os.name} - using {'Scapy' if os.name == 'nt' else 'Raw Sockets'} for packet capture")
    
    if os.name == 'nt':  # Windows
        print("Note: On Windows, this script requires:")
        print("1. Administrator privileges")
        print("2. Npcap installed (https://npcap.com/)")
        print("3. Scapy library (pip install scapy)")
    else:  # Linux/Unix
        print("Note: On Linux/Unix, this script requires root privileges (run with sudo)")
    
    result = capture_network_details(interface, capture_time)
    
    if result:
        print("\nCapture completed successfully!")
        print(f"To analyze the captured packets: python analyzer.py --analyze {result}") 