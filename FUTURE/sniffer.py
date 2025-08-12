import socket
import struct
import time
import csv
import os
import sys
from datetime import datetime
from collections import defaultdict
import argparse
import subprocess

# Terminal color functions
def green(text):
    """Returns text in green color for terminal output."""
    return f"\033[92m{text}\033[0m"

def yellow(text):
    """Returns text in yellow color for terminal output."""
    return f"\033[93m{text}\033[0m"

# Standard imports that don't require installation
try:
    import threading
    has_threading = True
except ImportError:
    has_threading = False

# Optional imports for enhanced functionality
try:
    import scapy.all as scapy
    from scapy.layers import http
    has_scapy = True
except ImportError:
    has_scapy = False
    print("Warning: Scapy not installed. Some features may not work.")
    print("Install with: pip install scapy")

# Try to import netifaces for better interface detection
try:
    import netifaces
    has_netifaces = True
except ImportError:
    has_netifaces = False

ETH_FRAME_LEN = 14

# Global variables for interface information
_INTERFACE_DETAILS = []

def get_windows_if_list():
    """Get list of network interfaces on Windows with friendly names and GUIDs"""
    interfaces = []
    interface_details = []
    
    # Try using netifaces first if available (cross-platform solution)
    if has_netifaces:
        try:
            for iface in netifaces.interfaces():
                # Get readable addresses if available
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:  # Has IPv4 address
                    ip = addrs[netifaces.AF_INET][0].get('addr')
                    if ip and ip != '127.0.0.1':  # Skip loopback
                        interface_details.append({
                            'name': iface,
                            'ip': ip,
                            'description': f"Interface {iface}",
                            'friendly_name': f"Interface: {iface} ({ip})"
                        })
            if interface_details:
                # Convert to friendly names for display
                interfaces = [d['friendly_name'] for d in interface_details]
                return interfaces, interface_details
        except Exception as e:
            print(f"Error using netifaces: {e}")
    
    # Initialize details list
    interface_details = []
    
    # Windows-specific approach
    if os.name == 'nt':
        try:
            import subprocess
            import re
            
            # Get Scapy interfaces first (these have the correct format for capture)
            scapy_interfaces = []
            scapy_if_names = []
            if has_scapy:
                try:
                    scapy_if_names = scapy.get_if_list()
                    if hasattr(scapy, 'get_windows_if_list'):
                        scapy_interfaces = scapy.get_windows_if_list()
                except Exception as e:
                    print(f"Warning: Couldn't get Scapy interface list: {e}")
            
            # Dictionary to collect interface info
            interface_info = defaultdict(dict)
            
            # Get wireless interfaces
            try:
                wifi_output = subprocess.check_output("netsh wlan show interfaces", shell=True, stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore')
                if "There is no wireless interface on the system" not in wifi_output:
                    for line in wifi_output.split('\n'):
                        line = line.strip()
                        if line.startswith('Name'):
                            wifi_name = line.split(':', 1)[1].strip()
                            interface_info[wifi_name]['type'] = 'WiFi'
            except subprocess.CalledProcessError:
                pass  # Command might fail if no WiFi
            
            # Use ipconfig to get all interfaces
            ipconfig_output = subprocess.check_output("ipconfig /all", shell=True).decode('utf-8', errors='ignore')
            
            # Parse the output more efficiently
            current_interface = None
            
            for line in ipconfig_output.split('\n'):
                line = line.strip()
                
                # Start of a new adapter section
                if "adapter" in line.lower() and line.endswith(':'):
                    current_interface = line.split("adapter")[1].strip().rstrip(':')
                    continue
                
                if current_interface:
                    # Look for description
                    if "description" in line.lower() and ':' in line:
                        interface_info[current_interface]['description'] = line.split(':', 1)[1].strip()
                    
                    # Look for MAC address
                    elif "physical address" in line.lower() and ':' in line:
                        mac = line.split(':', 1)[1].strip()
                        if mac != "00-00-00-00-00-00":
                            interface_info[current_interface]['mac'] = mac
                    
                    # Look for IPv4 address
                    elif "ipv4 address" in line.lower() and ':' in line:
                        ip = line.split(':', 1)[1].strip()
                        if '(' in ip:
                            ip = ip.split('(')[0].strip()
                        interface_info[current_interface]['ip'] = ip
                    
                    # Try to extract the GUID which is needed by Scapy
                    elif "network adapter local" in line.lower() or "adapter guid" in line.lower():
                        match = re.search(r'\{([\w-]+)\}', line)
                        if match:
                            guid = match.group(0)  # This includes the braces
                            interface_info[current_interface]['guid'] = guid
            
            # Create friendly names for interfaces and detailed info
            for name, info in interface_info.items():
                if 'description' in info:
                    description = info['description']
                    # Determine type if not already known
                    if 'type' not in info:
                        if any(keyword in description.lower() for keyword in ['wi-fi', 'wireless', 'wlan']):
                            info['type'] = 'WiFi'
                        elif any(keyword in description.lower() for keyword in ['ethernet', 'local area connection']):
                            info['type'] = 'Ethernet'
                        else:
                            info['type'] = 'Other'
                    
                    # Create friendly name for display
                    interface_str = f"{info['type']}: {description}"
                    if 'ip' in info:
                        interface_str += f" ({info['ip']})"
                    
                    # Add GUID to the friendly name if available
                    if 'guid' in info:
                        info['guid_str'] = info['guid']  # Store the original GUID string
                    
                    # Find matching Scapy interface by GUID
                    scapy_name = None
                    guid = info.get('guid', '')
                    
                    if guid:
                        # Look for the Windows device path containing this GUID
                        for if_name in scapy_if_names:
                            if guid in if_name:
                                scapy_name = if_name
                                break
                    
                    # If not found by GUID, try to match by description
                    if not scapy_name and scapy_interfaces:
                        for scapy_if in scapy_interfaces:
                            if description == scapy_if.get('description', ''):
                                scapy_name = scapy_if.get('name')
                                break
                    
                    # Create detailed info dictionary
                    detail = {
                        'description': description,
                        'friendly_name': interface_str,
                        'type': info.get('type', 'Unknown'),
                        'ip': info.get('ip', 'N/A'),
                        'mac': info.get('mac', 'N/A'),
                        'guid': info.get('guid', ''),
                        'name': scapy_name or name,  # Use Scapy name if found, otherwise adapter name
                        'guid_with_npf': f"\\Device\\NPF_{info.get('guid', '')}" if info.get('guid') else ''
                    }
                    
                    interface_details.append(detail)
                    interfaces.append(interface_str)
        
        except Exception as e:
            print(f"Error getting Windows interfaces: {e}")
    
    # Try scapy if Windows methods failed
    if not interfaces and has_scapy:
        try:
            all_interfaces = scapy.get_if_list()
            scapy_interfaces = scapy.get_windows_if_list() if os.name == 'nt' else []
            
            for iface in all_interfaces:
                if iface != 'lo' and iface != 'any':  # Skip loopback and 'any' interface
                    # Try to get IP
                    ip = scapy.get_if_addr(iface)
                    
                    # Try to find description for Windows interfaces
                    description = iface
                    guid = ""
                    if os.name == 'nt' and scapy_interfaces:
                        for scapy_if in scapy_interfaces:
                            if scapy_if.get('name') == iface:
                                description = scapy_if.get('description', iface)
                                guid = scapy_if.get('guid', '')
                                break
                    
                    if ip != '127.0.0.1':
                        friendly_name = f"Network Interface: {description} ({ip})"
                    else:
                        friendly_name = f"Network Interface: {description}"
                    
                    # Add to lists
                    interfaces.append(friendly_name)
                    interface_details.append({
                        'name': iface,
                        'description': description,
                        'friendly_name': friendly_name,
                        'ip': ip,
                        'type': 'Network',
                        'guid': guid,
                        'guid_with_npf': f"\\Device\\NPF_{guid}" if guid else ''
                    })
        except Exception as e:
            print(f"Error using scapy for interface detection: {e}")
    
    # Last resort: basic socket approach
    if not interfaces:
        try:
            hostname = socket.gethostname()
            ip_addresses = socket.gethostbyname_ex(hostname)[2]
            for i, ip in enumerate(ip_addresses):
                if ip != '127.0.0.1':  # Skip loopback
                    friendly_name = f"Network Interface {i+1}: {ip}"
                    interfaces.append(friendly_name)
                    interface_details.append({
                        'name': f"socket_{i}",
                        'description': f"Network Interface {i+1}",
                        'friendly_name': friendly_name,
                        'ip': ip,
                        'type': 'Socket',
                        'guid': '',
                        'guid_with_npf': ''
                    })
        except Exception as e:
            print(f"Error getting interfaces via socket: {e}")
    
    # Provide at least a fallback option if nothing else worked
    if not interfaces:
        interfaces.append("Default Interface")
        interface_details.append({
            'name': 'default',
            'description': 'Default Interface',
            'friendly_name': 'Default Interface',
            'ip': 'N/A',
            'type': 'Default',
            'guid': '',
            'guid_with_npf': ''
        })
    
    # Store interface details in a global variable for easy lookup
    global _INTERFACE_DETAILS
    _INTERFACE_DETAILS = interface_details
        
    return interfaces, interface_details

def get_available_interfaces():
    """Get list of available network interfaces.
    
    Returns:
        List of interface names (user-friendly display names)
    """
    # Return both the friendly names and the actual interface details
    interfaces, details = get_windows_if_list()
    
    # Store the mapping between friendly names and interface objects globally
    global _INTERFACE_DETAILS
    _INTERFACE_DETAILS = details
    
    return interfaces

def get_interface_by_name(friendly_name):
    """Get the actual interface ID to use with scapy based on a friendly name.
    
    Args:
        friendly_name: The user-friendly interface name
        
    Returns:
        The actual interface ID to use with scapy, or None if not found
    """
    global _INTERFACE_DETAILS
    
    for iface_detail in _INTERFACE_DETAILS:
        if iface_detail.get('friendly_name') == friendly_name:
            # Try to get the right format for Windows scapy
            if os.name == 'nt':
                # Extract the GUID from the friendly name if available
                import re
                guid_match = re.search(r'\{([0-9A-F-]+)\}', friendly_name, re.IGNORECASE)
                if guid_match:
                    # Format 1: NPF-prefixed format
                    npf_format = f"\\Device\\NPF_{{{guid_match.group(1)}}}"
                    return npf_format
                
                # If GUID can't be extracted from friendly name, try other formats
                if iface_detail.get('guid_with_npf'):
                    return iface_detail.get('guid_with_npf')
                
                # Try direct name
                if iface_detail.get('name'):
                    return iface_detail.get('name')
            
            # For non-Windows, or as a fallback
            if iface_detail.get('name'):
                return iface_detail.get('name')
    
    # If for some reason we can't find the interface, return a modified version
    # of the friendly name that might work with Scapy
    if os.name == 'nt' and friendly_name:
        # Try to extract the guid part for Windows
        import re
        guid_match = re.search(r'\{([0-9A-F-]+)\}', friendly_name, re.IGNORECASE)
        if guid_match:
            return f"\\Device\\NPF_{{{guid_match.group(1)}}}"
    
    return friendly_name

def get_default_interface(interfaces):
    """Get the default network interface.
    
    Args:
        interfaces: List of available interfaces
        
    Returns:
        Default interface name or None if no interfaces available
    """
    if not interfaces:
        return None
    
    # Return the first non-loopback interface
    for iface in interfaces:
        if "loopback" not in iface.lower() and "lo" != iface.lower():
            return iface
    
    # If no suitable interface found, return the first one
    return interfaces[0] if interfaces else None

def get_mac_address(bytes_addr):
    """Convert a byte sequence into a MAC address string."""
    return ':'.join(format(b, '02x') for b in bytes_addr)

def get_next_available_filename(prefix='all_packets', extension='.csv', directory=None):
    """Get the next available filename in sequence (all_packets1.csv, all_packets2.csv, etc.)
    
    Args:
        prefix: Base filename prefix
        extension: File extension
        directory: Optional directory path
        
    Returns:
        Full path to the next available filename
    """
    # Create directory if it doesn't exist and was specified
    if directory and not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)
    
    base_path = os.path.join(directory or '', prefix)
    index = 1
    
    # Optimization: Check for existence of higher numbered files first
    # This speeds up finding the next available filename when many files exist
    jump_size = 10
    while os.path.exists(f"{base_path}{index}{extension}"):
        index += jump_size
        
    # Once we find a gap, step back and find the exact next available
    if index > 1:
        # Binary search to find the first non-existent file
        lower = max(1, index - jump_size)
        upper = index
        
        while lower < upper:
            mid = (lower + upper) // 2
            if os.path.exists(f"{base_path}{mid}{extension}"):
                lower = mid + 1
            else:
                upper = mid
        
        index = lower
    
    return f"{base_path}{index}{extension}"

# Create a more efficient protocol lookup function
# Store protocol data in a more efficient structure
_PROTOCOL_CACHE = {}

def get_protocol_name(proto):
    """Return the protocol name based on the protocol number.
    
    Uses a cache for better performance on repeated lookups.
    
    Args:
        proto: Protocol number
    
    Returns:
        Protocol name and RFC info
    """
    # Use cached value if available
    if proto in _PROTOCOL_CACHE:
        return _PROTOCOL_CACHE[proto]
    
    # Protocol mapping
    protocols = {
        0: "HOPOPT (IPv6 Hop-by-Hop Option)",
        1: "ICMP",
        2: "IGMP",
        6: "TCP",
        17: "UDP",
        47: "GRE",
        50: "ESP",
        51: "AH",
        58: "IPv6-ICMP",
        89: "OSPF",
        132: "SCTP",
        0x0806: "ARP",
    }
    
    # Check for common protocols first (optimization)
    result = protocols.get(proto, None)
    
    # If not in the common list, check the full list for completeness
    if result is None:
        # Only load the full list if needed
        full_protocols = {
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
            0x0806: "ARP (Address Resolution Protocol) - No RFC",
        }
        
        # Add any protocol values from 146-252, 253-254, and 255 if needed
        result = full_protocols.get(proto, f"Unknown Protocol ({proto})")
    
    # Cache the result
    _PROTOCOL_CACHE[proto] = result
    return result

def capture_network_details(interface=None, packet_count=0, timeout=0, output_format='csv', output_dir='capture'):
    """Capture network details using scapy or tcpdump.
    
    Args:
        interface: Network interface to use for capture
        packet_count: Number of packets to capture (0 for unlimited)
        timeout: Timeout in seconds (0 for no timeout)
        output_format: Output format ('csv', 'json')
        output_dir: Directory to save output files
    
    Returns:
        bool: True if capture was successful, False otherwise
    """
    print(green("Starting network traffic capture..."))
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate base output filename
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    output_base = os.path.join(output_dir, f"capture_{timestamp}")
    
    # Get available network interfaces
    existing_ifaces = get_available_interfaces()
    
    if interface is None and len(existing_ifaces) > 0:
        # Auto-select default interface
        interface = existing_ifaces[0]
        print(f"No interface specified. Using first available interface: {interface}")
    
    # Check capture method availability
    capture_method = 'scapy'
    if not _check_scapy_available():
        capture_method = 'tcpdump'
        if not _check_tcpdump_available():
            print("ERROR: No capture methods available. Please install scapy or tcpdump.")
            return False
    
    result = None
    
    try:
        # Start the actual capture based on the method
        if capture_method == 'scapy':
            result = _capture_with_scapy(interface, packet_count, timeout, output_base, existing_ifaces)
        elif capture_method == 'tcpdump':
            result = _capture_with_tcpdump(interface, packet_count, timeout, output_base, existing_ifaces)
    
        if result is None:
            return False
        
        stats, csv_file = result
        
        # Print capture summary
        print_capture_summary(stats)
        
        print(green("\nCapture completed successfully!"))
        print(f"Output file: {csv_file}")
        
        return True
    
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
        if result:
            stats, csv_file = result
            print_capture_summary(stats)
            print(f"Partial results saved to: {csv_file}")
        return False
    except Exception as e:
        print(f"ERROR: An unexpected error occurred: {e}")
        import traceback
        traceback.print_exc()
        return False

def _check_scapy_available():
    """Check if scapy is available for packet capture.
    
    Returns:
        bool: True if scapy is available, False otherwise
    """
    return has_scapy

def _check_tcpdump_available():
    """Check if tcpdump is available for packet capture.
    
    Returns:
        bool: True if tcpdump is available, False otherwise
    """
    try:
        # Check if tcpdump is available in the system path
        subprocess_result = subprocess.run(
            ["tcpdump", "--version"], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            check=False
        )
        return subprocess_result.returncode == 0
    except (FileNotFoundError, PermissionError):
        return False

def _capture_with_tcpdump(interface, packet_count, timeout, output_base, existing_ifaces):
    """Capture network traffic using tcpdump.
    
    Args:
        interface: Network interface to capture on
        packet_count: Number of packets to capture (0 for unlimited)
        timeout: Timeout value for packet capture (0 for no timeout)
        output_base: Base filename for output (without extension)
        existing_ifaces: List of available network interfaces
        
    Returns:
        tuple: (stats dict, CSV filepath) if successful, None if failed
    """
    # Check if tcpdump is installed
    if not _check_tcpdump_available():
        print("ERROR: tcpdump is not available.")
        return None
    
    # Initialize file paths and stats
    pcap_file = f"{output_base}.pcap"
    csv_file = f"{output_base}.csv"
    
    # Initialize statistics
    stats = {
        'total_packets': 0,
        'start_time': time.time(),
        'end_time': None,
        'duration': 0,
        'tcp_packets': 0,
        'udp_packets': 0,
        'icmp_packets': 0,
        'other_packets': 0,
        'top_ips': {},
        'top_destinations': {},
        'top_ports': {}
    }
    
    try:
        # Build tcpdump command
        command = ["tcpdump", "-i", interface, "-w", pcap_file, "-n"]
        
        # Add packet count limit if specified
        if packet_count > 0:
            command.extend(["-c", str(packet_count)])
        
        print(f"Starting tcpdump capture on interface '{interface}'...")
        print(f"Press Ctrl+C to stop the capture")
        
        # Start tcpdump process
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Wait for timeout if specified
        if timeout > 0:
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait()
        else:
            # Wait for user to interrupt
            try:
                process.wait()
            except KeyboardInterrupt:
                process.terminate()
                process.wait()
        
        # Record end time
        stats['end_time'] = time.time()
        stats['duration'] = stats['end_time'] - stats['start_time']
        
        # Check if the capture was successful
        if process.returncode != 0 and process.returncode != -15:  # -15 is SIGTERM
            error_output = process.stderr.read().decode()
            print(f"ERROR: tcpdump capture failed: {error_output}")
            return None
        
        print(f"tcpdump capture completed. Processing pcap file...")
        
        # Convert pcap to CSV using tshark if available
        try:
            # Check if we can use tshark for conversion
            subprocess.run(
                ["tshark", "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True
            )
            
            # Use tshark to convert pcap to CSV
            subprocess.run(
                [
                    "tshark", "-r", pcap_file, "-T", "fields",
                    "-e", "frame.time_epoch", "-e", "eth.src", "-e", "eth.dst",
                    "-e", "ip.src", "-e", "ip.dst", "-e", "ip.proto",
                    "-e", "frame.len", "-e", "tcp.srcport", "-e", "tcp.dstport",
                    "-e", "tcp.flags", "-e", "ip.ttl", "-e", "ip.id",
                    "-E", "header=y", "-E", "separator=,", "-E", "quote=d",
                    "-E", "occurrence=f", ">", csv_file
                ],
                shell=True,
                check=True
            )
        except (subprocess.SubprocessError, FileNotFoundError):
            print("Warning: tshark not available. Extracting limited information from pcap.")
            # Minimal processing with basic tools
            # This would require a more complex implementation
            # For now, just create a minimal CSV file
            with open(csv_file, 'w', newline='') as csvfile:
                csv_writer = csv.writer(csvfile)
                csv_writer.writerow([
                    'timestamp', 'source_mac', 'destination_mac', 'source_ip', 'destination_ip',
                    'protocol', 'length', 'source_port', 'destination_port', 'tcp_flags',
                    'packet_direction', 'ttl', 'identification'
                ])
                csv_writer.writerow([
                    time.strftime("%Y-%m-%d %H:%M:%S"), "N/A", "N/A", "N/A", "N/A",
                    "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A"
                ])
        
        # Set a default value for total packets
        with open(pcap_file, 'rb') as f:
            # Read the first 24 bytes of the pcap file
            pcap_header = f.read(24)
            if len(pcap_header) == 24:
                # Get the file size
                f.seek(0, 2)  # Go to the end of the file
                file_size = f.tell()
                # Estimate number of packets (very rough estimate)
                stats['total_packets'] = max(1, (file_size - 24) // 64)
        
        return stats, csv_file
    
    except PermissionError:
        print("ERROR: Permission denied. Try running with administrator/root privileges.")
        return None
    except Exception as e:
        print(f"ERROR: An unexpected error occurred: {e}")
        return None

def _capture_with_scapy(interface, packet_count, timeout, output_base, existing_ifaces):
    """Capture network traffic using scapy.
    
    Args:
        interface: Network interface to capture on (friendly name)
        packet_count: Number of packets to capture (0 for unlimited)
        timeout: Timeout value for packet capture (0 for no timeout)
        output_base: Base filename for output (without extension)
        existing_ifaces: List of available interfaces (friendly names)
        
    Returns:
        tuple: (stats dict, CSV filepath) if successful, None if failed
    """
    # Check if interface exists in our list of friendly names
    if interface not in existing_ifaces:
        print(f"ERROR: Interface '{interface}' not found.")
        print("Available interfaces:")
        for iface in existing_ifaces:
            print(f"  - {iface}")
        return None
    
    # Get the actual interface ID to use with scapy
    scapy_interface = get_interface_by_name(interface)
    if not scapy_interface:
        print(f"ERROR: Could not find a valid interface ID for '{interface}'.")
        return None
    
    # Initialize statistics and file paths
    stats = {
        'total_packets': 0,
        'start_time': time.time(),
        'end_time': None,
        'duration': 0,
        'tcp_packets': 0,
        'udp_packets': 0,
        'icmp_packets': 0,
        'other_packets': 0,
        'top_ips': {},
        'top_destinations': {},
        'top_ports': {}
    }
    
    csv_file = f"{output_base}.csv"
    
    # Create a buffer for packets and a lock for thread safety
    packet_buffer = []
    buffer_lock = threading.Lock()
    stop_event = threading.Event()
    
    try:
        print(f"Starting packet capture on interface '{interface}'...")
        print(f"Press Ctrl+C to stop the capture")
        
        # Define packet callback function
        def packet_callback(packet):
            nonlocal stats
            
            # Update basic stats
            stats['total_packets'] += 1
            
            # Extract source and destination IP if available
            src_ip = None
            dst_ip = None
            dst_port = None
            
            # IP layer processing
            if packet.haslayer(scapy.IP):
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                
                # Update top IPs counters
                if src_ip in stats['top_ips']:
                    stats['top_ips'][src_ip] += 1
                else:
                    stats['top_ips'][src_ip] = 1
                
                if dst_ip in stats['top_destinations']:
                    stats['top_destinations'][dst_ip] += 1
                else:
                    stats['top_destinations'][dst_ip] = 1
            
            # Update protocol-specific stats
            if packet.haslayer(scapy.TCP):
                stats['tcp_packets'] += 1
                if packet.haslayer(scapy.TCP):
                    dst_port = packet[scapy.TCP].dport
                    
                    # Update top ports counter
                    if dst_port in stats['top_ports']:
                        stats['top_ports'][dst_port] += 1
                    else:
                        stats['top_ports'][dst_port] = 1
            elif packet.haslayer(scapy.UDP):
                stats['udp_packets'] += 1
                if packet.haslayer(scapy.UDP):
                    dst_port = packet[scapy.UDP].dport
                    
                    # Update top ports counter
                    if dst_port in stats['top_ports']:
                        stats['top_ports'][dst_port] += 1
                    else:
                        stats['top_ports'][dst_port] = 1
            elif packet.haslayer(scapy.ICMP):
                stats['icmp_packets'] += 1
            else:
                stats['other_packets'] += 1
            
            # Add to buffer with lock protection
            with buffer_lock:
                packet_buffer.append(packet)
        
        # Create and start the background thread for processing
        with open(csv_file, 'w', newline='') as csvfile:
            csv_writer = csv.writer(csvfile)
            # Write CSV header
            csv_writer.writerow([
                'timestamp', 'source_mac', 'destination_mac', 'source_ip', 'destination_ip', 
                'source_port', 'destination_port', 'protocol', 'length', 'ttl',
                'tcp_flags', 'tcp_window', 'icmp_type', 'icmp_code', 'dns_query',
                'http_method', 'http_host', 'http_path', 'packet_direction'
            ])
            
            # Start background processing thread
            processor = threading.Thread(
                target=_process_packet_buffer, 
                args=(packet_buffer, buffer_lock, csv_writer, stop_event, stats)
            )
            processor.daemon = True
            processor.start()
            
            try:
                # Start sniffing with the actual interface ID
                scapy.sniff(
                    iface=scapy_interface,
                    prn=packet_callback,
                    count=packet_count,
                    timeout=timeout if timeout > 0 else None
                )
            except KeyboardInterrupt:
                print("\nCapture stopped by user.")
            finally:
                # Record end time
                stats['end_time'] = time.time()
                stats['duration'] = stats['end_time'] - stats['start_time']
                
                # Signal thread to stop and wait for it
                stop_event.set()
                processor.join(timeout=2.0)
                
                # Process any remaining packets in the buffer
                with buffer_lock:
                    remaining_packets = packet_buffer.copy()
                    packet_buffer.clear()
                
                for packet in remaining_packets:
                    _extract_and_write_packet_data(packet, csv_writer, stats)
        
        # Sort the top IPs, destinations, and ports by frequency
        stats['top_ips'] = dict(sorted(stats['top_ips'].items(), key=lambda x: x[1], reverse=True))
        stats['top_destinations'] = dict(sorted(stats['top_destinations'].items(), key=lambda x: x[1], reverse=True))
        stats['top_ports'] = dict(sorted(stats['top_ports'].items(), key=lambda x: x[1], reverse=True))
        
        return stats, csv_file
    
    except PermissionError:
        print("ERROR: Permission denied. Try running with administrator/root privileges.")
        return None
    except Exception as e:
        print(f"ERROR: An unexpected error occurred: {e}")
        return None

def _process_packet_buffer(packet_buffer, buffer_lock, csv_writer, stop_event, stats, process_interval=0.1):
    """Background thread function to process packets from buffer to CSV.
    
    Args:
        packet_buffer: List buffer to pull packets from
        buffer_lock: Threading lock for buffer access
        csv_writer: CSV writer object
        stop_event: Event to signal thread termination
        stats: Dictionary to collect packet statistics
        process_interval: How often to process buffer (seconds)
    """
    while not stop_event.is_set():
        # Process any available packets
        packets_to_process = []
        
        # Get packets from buffer with the lock
        with buffer_lock:
            if packet_buffer:
                packets_to_process = packet_buffer.copy()
                packet_buffer.clear()
        
        # Process packets outside the lock
        for packet in packets_to_process:
            _extract_and_write_packet_data(packet, csv_writer, stats)
        
        # Sleep briefly to avoid CPU hogging
        time.sleep(process_interval)

def _process_packets_to_csv(packets, csv_file, stats):
    """Process a list of packets into CSV format.
    
    Args:
        packets: List of scapy packets
        csv_file: Path to CSV output file
        stats: Dictionary to collect packet statistics
    """
    with open(csv_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        # Write CSV header
        writer.writerow([
            'timestamp', 'source_mac', 'destination_mac', 'source_ip', 'destination_ip', 
            'source_port', 'destination_port', 'protocol', 'length', 'ttl',
            'tcp_flags', 'tcp_window', 'icmp_type', 'icmp_code', 'dns_query',
            'http_method', 'http_host', 'http_path', 'packet_direction'
        ])
        
        # Process each packet
        for packet in packets:
            _extract_and_write_packet_data(packet, writer, stats)

def _extract_and_write_packet_data(packet, csv_writer, stats):
    """Extract data from a packet and write it to CSV.
    
    Args:
        packet: Scapy packet object
        csv_writer: CSV writer object to write data to
        stats: Dictionary to collect packet statistics
    """
    try:
        # Ensure stats has required keys
        if 'source_ips' not in stats:
            stats['source_ips'] = set()
        if 'dest_ips' not in stats:
            stats['dest_ips'] = set()
        if 'source_ports' not in stats:
            stats['source_ports'] = set()
        if 'dest_ports' not in stats:
            stats['dest_ports'] = set()
        if 'protocols' not in stats:
            stats['protocols'] = set()
        if 'inbound_packets' not in stats:
            stats['inbound_packets'] = 0
        if 'outbound_packets' not in stats:
            stats['outbound_packets'] = 0
        if 'local_packets' not in stats:
            stats['local_packets'] = 0
        if 'external_packets' not in stats:
            stats['external_packets'] = 0
        if 'http_packets' not in stats:
            stats['http_packets'] = 0
        if 'dns_packets' not in stats:
            stats['dns_packets'] = 0
            
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
            
            # Update stats
            stats['source_ips'].add(src_ip)
            stats['dest_ips'].add(dst_ip)
            
            # Determine packet direction
            packet_direction = _determine_packet_direction(src_ip, dst_ip)
            
            # Update direction stats
            if packet_direction == "Inbound":
                stats['inbound_packets'] += 1
            elif packet_direction == "Outbound":
                stats['outbound_packets'] += 1
            elif packet_direction == "Local":
                stats['local_packets'] += 1
            elif packet_direction == "External":
                stats['external_packets'] += 1
            
            # TCP layer
            if packet.haslayer(scapy.TCP):
                tcp_layer = packet[scapy.TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                protocol = "TCP"
                tcp_window = tcp_layer.window
                
                # Update port stats
                stats['source_ports'].add(src_port)
                stats['dest_ports'].add(dst_port)
                stats['protocols'].add("TCP")
                
                # TCP Flags
                tcp_flags = _get_tcp_flags(tcp_layer)
                
                # HTTP layer
                if packet.haslayer(http.HTTPRequest):
                    http_layer = packet[http.HTTPRequest]
                    protocol = "HTTP"
                    http_host = http_layer.Host.decode() if http_layer.Host else "N/A"
                    http_path = http_layer.Path.decode() if http_layer.Path else "N/A"
                    http_method = http_layer.Method.decode() if http_layer.Method else "N/A"
                    
                    # Update stats
                    stats['http_packets'] += 1
                    stats['protocols'].add("HTTP")
            
            # UDP layer
            elif packet.haslayer(scapy.UDP):
                udp_layer = packet[scapy.UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                protocol = "UDP"
                
                # Update port stats
                stats['source_ports'].add(src_port)
                stats['dest_ports'].add(dst_port)
                stats['protocols'].add("UDP")
                
                # DNS layer
                if packet.haslayer(scapy.DNS):
                    dns_layer = packet[scapy.DNS]
                    protocol = "DNS"
                    if dns_layer.qr == 0:  # Query
                        if dns_layer.qd and dns_layer.qd.qname:
                            dns_query = dns_layer.qd.qname.decode()
                    
                    # Update stats
                    stats['dns_packets'] += 1
                    stats['protocols'].add("DNS")
            
            # ICMP layer
            elif packet.haslayer(scapy.ICMP):
                icmp_layer = packet[scapy.ICMP]
                protocol = "ICMP"
                icmp_type = icmp_layer.type
                icmp_code = icmp_layer.code
                
                # Update stats
                stats['protocols'].add("ICMP")
        
        # ARP layer
        elif packet.haslayer(scapy.ARP):
            arp_layer = packet[scapy.ARP]
            protocol = "ARP"
            src_ip = arp_layer.psrc
            dst_ip = arp_layer.pdst
            packet_direction = "Broadcast" if dst_ip == "255.255.255.255" else "Local"
            
            # Update stats
            stats['protocols'].add("ARP")
            stats['source_ips'].add(src_ip)
            stats['dest_ips'].add(dst_ip)
            
            if packet_direction == "Local":
                stats['local_packets'] += 1
        
        # Update the protocol stats
        if protocol != "Unknown":
            stats['protocols'].add(protocol)
        
        # Write the row to CSV
        csv_writer.writerow([
            timestamp, src_mac, dst_mac, src_ip, dst_ip, 
            src_port, dst_port, protocol, length, ttl,
            tcp_flags, tcp_window, icmp_type, icmp_code, dns_query,
            http_method, http_host, http_path, packet_direction
        ])
    except Exception as e:
        print(f"Error processing packet: {e}")

def _get_tcp_flags(tcp_layer):
    """Get TCP flags as a readable string.
    
    Args:
        tcp_layer: Scapy TCP layer
        
    Returns:
        String representation of TCP flags
    """
    flags = []
    if hasattr(tcp_layer.flags, 'F') and tcp_layer.flags.F: flags.append("FIN")
    if hasattr(tcp_layer.flags, 'S') and tcp_layer.flags.S: flags.append("SYN")
    if hasattr(tcp_layer.flags, 'R') and tcp_layer.flags.R: flags.append("RST")
    if hasattr(tcp_layer.flags, 'P') and tcp_layer.flags.P: flags.append("PSH")
    if hasattr(tcp_layer.flags, 'A') and tcp_layer.flags.A: flags.append("ACK")
    if hasattr(tcp_layer.flags, 'U') and tcp_layer.flags.U: flags.append("URG")
    if hasattr(tcp_layer.flags, 'E') and tcp_layer.flags.E: flags.append("ECE")
    if hasattr(tcp_layer.flags, 'C') and tcp_layer.flags.C: flags.append("CWR")
    return " ".join(flags) if flags else "None"

def _determine_packet_direction(src_ip, dst_ip):
    """Determine packet direction based on IP addresses.
    
    Args:
        src_ip: Source IP address
        dst_ip: Destination IP address
        
    Returns:
        Direction classification: Outbound, Inbound, Local, External, or Unknown
    """
    private_prefixes = ('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', 
                       '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', 
                       '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '127.')
    
    src_private = any(src_ip.startswith(prefix) for prefix in private_prefixes)
    dst_private = any(dst_ip.startswith(prefix) for prefix in private_prefixes)
    
    if src_private and not dst_private:
        return "Outbound"
    elif not src_private and dst_private:
        return "Inbound"
    elif src_private and dst_private:
        return "Local"
    else:
        return "External"

def capture_with_socket(interface, capture_time=5, packet_limit=10000, buffer_size=65535):
    """Use raw sockets for packet capture on Linux/Unix/Windows without Scapy.
    
    Args:
        interface: Network interface to capture from
        capture_time: Time in seconds to capture
        packet_limit: Maximum number of packets to capture (safety limit)
        buffer_size: Socket buffer size
        
    Returns:
        Path to CSV file with captured data or None on error
    """
    # Create a timestamp-based directory for output
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    capture_dir = f"capture_raw_{timestamp}"
    os.makedirs(capture_dir, exist_ok=True)
    csv_file = os.path.join(capture_dir, "packets.csv")
    
    try:
        # Create a raw socket and bind to the specified interface
        if os.name == 'nt':  # Windows
            print("Warning: Windows raw socket capture has limited functionality.")
            print("For better results, please install scapy: pip install scapy")
            print("and npcap: https://npcap.com/")
            
            try:
                # Create a raw socket on Windows (requires admin privileges)
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                s.bind((interface, 0))
                # Enable promiscuous mode on Windows
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            except socket.error as e:
                print(f"Socket error: {e}")
                print("Make sure you're running as Administrator")
                return None
        else:  # Linux/Unix
            try:
                # Create a raw socket, receive at ethernet level
                s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
                s.bind((interface, 0))
            except socket.error as e:
                print(f"Socket bind error: {e}")
                if "Operation not permitted" in str(e):
                    print("This operation requires root privileges. Run with 'sudo'.")
                return None
        
        # Set timeout to 1 second to allow clean exit
        s.settimeout(1)
        
        # Initialize counters and start time
        total_packets = 0
        arp_count = 0
        tcp_count = 0
        udp_count = 0
        icmp_count = 0
        other_count = 0
        start_time = time.time()
        
        # Create the CSV file for writing and write the header
        with open(csv_file, 'w', newline='') as csv_file_handle:
            csv_writer = csv.writer(csv_file_handle)
            # Write a comprehensive header including all fields we might capture
            csv_writer.writerow(['timestamp', 'source_mac', 'dest_mac', 'source_ip', 'dest_ip', 
                              'protocol', 'length', 'source_port', 'destination_port', 
                              'tcp_flags', 'packet_direction', 'ttl', 'identification'])
            
            # Main capture loop
            print(f"Starting raw socket packet capture for {capture_time} seconds...")
            while (time.time() - start_time) < capture_time and total_packets < packet_limit:
                try:
                    # Receive a packet
                    raw_data = s.recv(buffer_size)
                    total_packets += 1
                    
                    # Get timestamp for this packet
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                    
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
                    ttl = "N/A"
                    identification = "N/A"
                    
                    # Parse Ethernet header for MAC addresses (Linux/Unix only)
                    eth_header_parsed = False
                    if os.name != 'nt':  # Linux/Unix
                        try:
                            dest_mac = raw_data[0:6]
                            src_mac = raw_data[6:12]
                            dest_mac_str = get_mac_address(dest_mac)
                            src_mac_str = get_mac_address(src_mac)
                            eth_protocol = raw_data[12:14]
                            protocol_type = struct.unpack("!H", eth_protocol)[0]
                            eth_header_parsed = True
                        except Exception as e:
                            print(f"Error parsing Ethernet header: {e}")
                    
                    # Parse IP header
                    if os.name == 'nt' or (eth_header_parsed and protocol_type == 0x0800):  # IPv4
                        try:
                            # Get IP header (after Ethernet header on Linux/Unix)
                            ip_header_start = 0 if os.name == 'nt' else ETH_FRAME_LEN
                            ip_header = raw_data[ip_header_start:ip_header_start + 20]
                            
                            # Unpack the IP header
                            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                            
                            # Extract IP header fields
                            version_ihl = iph[0]
                            version = version_ihl >> 4
                            ihl = version_ihl & 0xF
                            iph_length = ihl * 4
                            ttl = iph[5]
                            protocol_num = iph[6]
                            identification = iph[3]
                            src_ip = socket.inet_ntoa(iph[8])
                            dest_ip = socket.inet_ntoa(iph[9])
                            
                            # Get protocol
                            protocol = get_protocol_name(protocol_num).split(' ')[0]  # Just get short name
                            
                            # Handle TCP packet
                            if protocol_num == 6:  # TCP
                                tcp_count += 1
                                tcp_header_start = ip_header_start + iph_length
                                
                                if len(raw_data) >= tcp_header_start + 20:  # Need at least 20 bytes for TCP header
                                    tcp_header = raw_data[tcp_header_start:tcp_header_start + 20]
                                    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                                    
                                    src_port = tcph[0]
                                    dest_port = tcph[1]
                                    sequence = tcph[2]
                                    ack = tcph[3]
                                    doff_reserved = tcph[4]
                                    flags = tcph[5]
                                    
                                    # Extract TCP flags
                                    flag_names = []
                                    if flags & 0x01: flag_names.append("FIN")
                                    if flags & 0x02: flag_names.append("SYN")
                                    if flags & 0x04: flag_names.append("RST")
                                    if flags & 0x08: flag_names.append("PSH")
                                    if flags & 0x10: flag_names.append("ACK")
                                    if flags & 0x20: flag_names.append("URG")
                                    
                                    if flag_names:
                                        tcp_flags = " ".join(flag_names)
                            
                            # Handle UDP packet
                            elif protocol_num == 17:  # UDP
                                udp_count += 1
                                udp_header_start = ip_header_start + iph_length
                                
                                if len(raw_data) >= udp_header_start + 8:  # Need 8 bytes for UDP header
                                    udp_header = raw_data[udp_header_start:udp_header_start + 8]
                                    udph = struct.unpack('!HHHH', udp_header)
                                    
                                    src_port = udph[0]
                                    dest_port = udph[1]
                            
                            # Handle ICMP packet
                            elif protocol_num == 1:  # ICMP
                                icmp_count += 1
                            
                            # Determine packet direction based on IPs
                            packet_direction = _determine_packet_direction(src_ip, dest_ip)
                        
                        except Exception as e:
                            print(f"Error parsing IP packet: {e}")
                    
                    # Handle ARP packet (Linux/Unix only)
                    elif os.name != 'nt' and eth_header_parsed and protocol_type == 0x0806:  # ARP
                        try:
                            arp_count += 1
                            protocol = "ARP"
                            
                            # Parse ARP header
                            arp_header = raw_data[ETH_FRAME_LEN:ETH_FRAME_LEN + 28]
                            arph = struct.unpack("!HHBBH6s4s6s4s", arp_header)
                            
                            # Extract sender and target IP addresses
                            sender_mac = arph[5]
                            sender_ip = socket.inet_ntoa(arph[6])
                            target_mac = arph[7]
                            target_ip = socket.inet_ntoa(arph[8])
                            
                            src_ip = sender_ip
                            dest_ip = target_ip
                            
                            # Determine if this is a request or reply
                            operation = arph[4]  # 1 for request, 2 for reply
                            
                            # Set packet direction
                            if operation == 1:
                                packet_direction = "Request"
                            elif operation == 2:
                                packet_direction = "Reply"
                            else:
                                packet_direction = "Unknown"
                        
                        except Exception as e:
                            print(f"Error parsing ARP packet: {e}")
                    
                    else:
                        # Other packet types
                        other_count += 1
                        
                        # For unknown protocols, use MAC address patterns to guess direction
                        if dest_mac_str.startswith("ff:ff:ff"):
                            packet_direction = "Broadcast"
                    
                    # Write packet data to CSV
                    csv_writer.writerow([
                        timestamp, src_mac_str, dest_mac_str, src_ip, dest_ip,
                        protocol, packet_length, src_port, dest_port,
                        tcp_flags, packet_direction, ttl, identification
                    ])
                    
                    # Periodically flush to ensure data is written to disk
                    if total_packets % 100 == 0:
                        csv_file_handle.flush()
                
                except socket.timeout:
                    # Just continue on timeout
                    continue
                except Exception as e:
                    print(f"Error capturing packet: {str(e)}")
        
        # Disable promiscuous mode on Windows
        if os.name == 'nt':
            try:
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except:
                pass
        
        # Always close the socket
        try:
            s.close()
        except:
            pass
        
        # Output statistics
        print(f"Packet capture complete. Captured {total_packets} packets total:")
        print(f"- TCP: {tcp_count}")
        print(f"- UDP: {udp_count}")
        print(f"- ICMP: {icmp_count}")
        print(f"- ARP: {arp_count}")
        print(f"- Other: {other_count}")
        print(f"Data saved to: {csv_file}")
        
        return csv_file
    
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

def format_time(seconds):
    """Convert seconds to a human-readable time format."""
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    
    minutes = seconds / 60
    if minutes < 60:
        return f"{int(minutes)} minutes {int(seconds % 60)} seconds"
    
    hours = minutes / 60
    minutes = minutes % 60
    return f"{int(hours)} hours {int(minutes)} minutes"

def _parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Network traffic capture and analysis tool")
    
    # Interface selection
    parser.add_argument("-i", "--interface", help="Network interface to capture from")
    
    # Capture limits
    parser.add_argument("-c", "--count", type=int, default=0, 
                        help="Number of packets to capture (0 for unlimited)")
    parser.add_argument("-t", "--timeout", type=int, default=0,
                        help="Stop capture after this many seconds (0 for no timeout)")
    
    # Output options
    parser.add_argument("-o", "--output", help="Base filename for output files")
    
    # Capture method
    parser.add_argument("-m", "--method", choices=["scapy", "socket", "tcpdump"],
                        default="scapy", help="Packet capture method to use")
    
    # Detection mode
    parser.add_argument("-d", "--detection", action="store_true",
                        help="Enable threat detection mode")
    
    return parser.parse_args()

def print_capture_summary(stats):
    """Print a formatted summary of the capture statistics.
    
    Args:
        stats: Dictionary containing capture statistics
    """
    print("\n" + "="*60)
    print(yellow('CAPTURE SESSION SUMMARY'))
    print("="*60)
    
    # Print basic statistics
    print(f"Total packets captured: {stats.get('total_packets', 0)}")
    print(f"Capture duration: {stats.get('duration', 0):.2f} seconds")
    
    # Print protocol breakdown
    print("\n" + "-"*30)
    print(green('PROTOCOL BREAKDOWN'))
    print("-"*30)
    print(f"TCP packets:  {stats.get('tcp_packets', 0)} ({stats.get('tcp_packets', 0)/max(stats.get('total_packets', 1), 1)*100:.1f}%)")
    print(f"UDP packets:  {stats.get('udp_packets', 0)} ({stats.get('udp_packets', 0)/max(stats.get('total_packets', 1), 1)*100:.1f}%)")
    print(f"ICMP packets: {stats.get('icmp_packets', 0)} ({stats.get('icmp_packets', 0)/max(stats.get('total_packets', 1), 1)*100:.1f}%)")
    print(f"Other:        {stats.get('other_packets', 0)} ({stats.get('other_packets', 0)/max(stats.get('total_packets', 1), 1)*100:.1f}%)")
    
    # Print top source IPs
    if stats.get('top_ips'):
        print("\n" + "-"*30)
        print(green('TOP SOURCE IPs'))
        print("-"*30)
        for ip, count in stats.get('top_ips', {}).items():
            print(f"{ip}: {count} ({count/max(stats.get('total_packets', 1), 1)*100:.1f}%)")
    
    # Print top destination IPs
    if stats.get('top_destinations'):
        print("\n" + "-"*30)
        print(green('TOP DESTINATION IPs'))
        print("-"*30)
        for ip, count in stats.get('top_destinations', {}).items():
            print(f"{ip}: {count} ({count/max(stats.get('total_packets', 1), 1)*100:.1f}%)")
    
    # Print top ports
    if stats.get('top_ports'):
        print("\n" + "-"*30)
        print(green('TOP PORTS'))
        print("-"*30)
        for port, count in stats.get('top_ports', {}).items():
            print(f"{port}: {count} ({count/max(stats.get('total_packets', 1), 1)*100:.1f}%)")
    
    print("="*60)

def main():
    """Main function to parse arguments and control program flow."""
    args = _parse_args()
    
    # Check for interactive mode (no interface specified and no input/output redirection)
    interactive_mode = args.interface is None and sys.stdin.isatty() and sys.stdout.isatty()
    
    # Get list of interfaces (these are friendly names)
    interfaces = get_available_interfaces()
    
    # Determine interface to use
    interface = args.interface
    
    if interactive_mode:
        # Interactive interface selection
        print(green("\n===== Network Traffic Capture Tool ====="))
        interface = interactive_interface_selection()
        if interface is None:
            print("Capture canceled.")
            return
    elif not interface:
        # Non-interactive default selection
        interface = get_default_interface(interfaces)
        print(f"No interface specified. Using default interface: {interface}")
    
    # If the user provided a raw interface name rather than a friendly name,
    # use it directly (advanced usage)
    if interface and interface not in interfaces:
        # This could be a direct interface ID or GUID, so we'll use it as-is
        print(f"Warning: Using custom interface: {interface}")
    
    # Determine capture parameters
    if interactive_mode:
        # Interactive duration selection
        packet_count, timeout = interactive_duration_selection()
    else:
        # Use command line arguments
        packet_count = args.count
        timeout = args.timeout
    
    # Generate output base filename
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    if args.output:
        output_base = args.output
    else:
        output_base = f"capture_{timestamp}"
    
    # Handle detection mode
    if args.detection:
        print("Detection mode not yet implemented")
        return
    
    # Start the capture
    print(f"\nStarting capture on {interface}")
    if packet_count > 0:
        print(f"Capturing {packet_count} packets")
    if timeout > 0:
        print(f"Capture will timeout after {timeout} seconds")
    
    # Capture packets with the appropriate method
    if args.method == "scapy":
        result = _capture_with_scapy(
            interface,
            packet_count,
            timeout,
            output_base,
            interfaces
        )
        if result:
            stats, csv_file = result
            print(f"\nCapture completed. CSV data saved to {csv_file}")
            
            # Print capture summary
            print_capture_summary(stats)
    else:
        print(f"Capture method '{args.method}' not supported")

def interactive_interface_selection():
    """Display an interactive menu for selecting a network interface.
    
    Returns:
        The selected interface friendly name
    """
    # Get available interfaces
    interfaces = get_available_interfaces()
    
    if not interfaces:
        print("No network interfaces found.")
        return None
    
    # Print the menu
    print(yellow("\nAvailable Network Interfaces:"))
    print("="*50)
    for i, iface in enumerate(interfaces, 1):
        print(f"{i}. {iface}")
    print("="*50)
    
    # Get user selection
    while True:
        try:
            selection = input("\nSelect interface number (q to quit): ")
            if selection.lower() == 'q':
                return None
                
            idx = int(selection) - 1
            if 0 <= idx < len(interfaces):
                return interfaces[idx]
            else:
                print(f"Please enter a number between 1 and {len(interfaces)}")
        except ValueError:
            print("Please enter a valid number")

def interactive_duration_selection():
    """Prompt the user to input the capture duration.
    
    Returns:
        tuple: (packet_count, timeout) where packet_count is an integer and timeout is in seconds
    """
    # Get capture duration
    while True:
        try:
            mode = input("\nSelect capture mode:\n1. Time-based (seconds)\n2. Packet count\nChoice: ")
            
            if mode == "1":
                duration = input("Enter capture duration in seconds (default: 30): ")
                duration = int(duration) if duration.strip() else 30
                return 0, duration  # Zero packet_count means unlimited
            elif mode == "2":
                count = input("Enter number of packets to capture (default: 100): ")
                count = int(count) if count.strip() else 100
                return count, 0  # Zero timeout means no timeout
            else:
                print("Please enter 1 or 2")
        except ValueError:
            print("Please enter a valid number")

if __name__ == "__main__":
    main() 