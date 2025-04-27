import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
import os
import sys
import queue  # For thread-safe communication between capture and UI
import random
from datetime import datetime, timedelta
import csv

# Try importing matplotlib for visualization
try:
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    has_matplotlib = True
except ImportError:
    has_matplotlib = False

# Import sniffer functionality
import sniffer

# Set up real-time capture functionality
def _setup_realtime_capture():
    """Set up real-time packet capture by adding necessary functions to the sniffer module"""
    # Only add the function if it doesn't already exist
    if not hasattr(sniffer, '_capture_with_scapy_realtime'):
        # Add the real-time capture function to the sniffer module
        def _capture_with_scapy_realtime(interface, packet_count, timeout, output_base, existing_ifaces,
                                        packet_callback=None, stop_event=None):
            """
            Capture network packets in real-time using scapy and process them via callback
            
            Args:
                interface: Network interface to capture from
                packet_count: Number of packets to capture (0 for unlimited)
                timeout: Duration in seconds to capture (0 for unlimited)
                output_base: Base filename for output files
                existing_ifaces: List of available interfaces
                packet_callback: Function to call for each packet
                stop_event: Threading event to signal when to stop capture
                
            Returns:
                tuple: (stats_dict, csv_filename)
            """
            # Import built-in modules
            import time
            import datetime
            import csv
            import os
            import threading
            import sys
            from collections import defaultdict
            
            # Check if scapy is available
            try:
                from scapy.all import sniff, wrpcap, Ether, IP, TCP, UDP, ICMP, ARP, DNS, Raw, conf, get_windows_if_list
                HAS_SCAPY = True
            except ImportError:
                return None, None
            
            # Initialize statistics
            stats = {
                'start_time': time.time(),
                'end_time': None,
                'duration': 0,
                'total_packets': 0,
                'tcp_packets': 0,
                'udp_packets': 0,
                'icmp_packets': 0,
                'arp_packets': 0,
                'other_packets': 0,
                'top_ips': {},
                'top_destinations': {},
                'top_ports': {}
            }
            
            # Create output directories if they don't exist
            os.makedirs(os.path.dirname(output_base) or '.', exist_ok=True)
            
            # Create a CSV file for output
            csv_file = f"{output_base}.csv"
            with open(csv_file, 'w', newline='') as f:
                writer = csv.writer(f)
                # Write header
                writer.writerow([
                    'timestamp', 'source_mac', 'destination_mac', 'source_ip', 'destination_ip',
                    'protocol', 'length', 'source_port', 'destination_port', 'ttl',
                    'tcp_flags', 'tcp_window', 'icmp_type', 'icmp_code', 'dns_query',
                    'http_method', 'http_host', 'http_path', 'packet_direction', 'raw_data'
                ])
                
            # Define packet processing function
            def process_packet(packet):
                # Check if we should stop
                if stop_event and stop_event.is_set():
                    return None
                
                # Extract packet data
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                
                # Initialize packet metadata
                metadata = {
                    'timestamp': timestamp,
                    'src_mac': "",
                    'dst_mac': "",
                    'src_ip': "",
                    'dst_ip': "",
                    'protocol': "UNKNOWN",
                    'length': len(packet),
                    'src_port': "",
                    'dst_port': "",
                    'ttl': "",
                    'tcp_flags': "",
                    'tcp_window': "",
                    'icmp_type': "",
                    'icmp_code': "",
                    'dns_query': "",
                    'http_method': "",
                    'http_host': "",
                    'http_path': "",
                    'packet_direction': "",
                    'raw': []
                }
                
                # Extract Ethernet layer info if present
                if Ether in packet:
                    metadata['src_mac'] = packet[Ether].src
                    metadata['dst_mac'] = packet[Ether].dst
                
                # Extract IP layer info if present
                if IP in packet:
                    metadata['src_ip'] = packet[IP].src
                    metadata['dst_ip'] = packet[IP].dst
                    metadata['ttl'] = str(packet[IP].ttl)
                    
                    # Determine protocol
                    if TCP in packet:
                        metadata['protocol'] = "TCP"
                        metadata['src_port'] = str(packet[TCP].sport)
                        metadata['dst_port'] = str(packet[TCP].dport)
                        metadata['tcp_flags'] = str(packet[TCP].flags)
                        metadata['tcp_window'] = str(packet[TCP].window)
                        
                        # Check for HTTP
                        if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                            if Raw in packet:
                                try:
                                    payload = str(packet[Raw].load)
                                    if "HTTP/" in payload or "GET " in payload or "POST " in payload:
                                        metadata['protocol'] = "HTTP"
                                        
                                        # Extract HTTP method
                                        if "GET " in payload:
                                            metadata['http_method'] = "GET"
                                        elif "POST " in payload:
                                            metadata['http_method'] = "POST"
                                        elif "PUT " in payload:
                                            metadata['http_method'] = "PUT"
                                        elif "DELETE " in payload:
                                            metadata['http_method'] = "DELETE"
                                        
                                        # Extract host and path (simplified)
                                        if "Host: " in payload:
                                            host_start = payload.find("Host: ") + 6
                                            host_end = payload.find("\\r\\n", host_start)
                                            if host_end > host_start:
                                                metadata['http_host'] = payload[host_start:host_end]
                                        
                                        if metadata['http_method'] and " /" in payload:
                                            path_start = payload.find(" /") + 1
                                            path_end = payload.find(" HTTP", path_start)
                                            if path_end > path_start:
                                                metadata['http_path'] = payload[path_start:path_end]
                                except:
                                    pass  # Ignore errors in HTTP parsing
                    
                    elif UDP in packet:
                        metadata['protocol'] = "UDP"
                        metadata['src_port'] = str(packet[UDP].sport)
                        metadata['dst_port'] = str(packet[UDP].dport)
                        
                        # Check for DNS
                        if DNS in packet:
                            metadata['protocol'] = "DNS"
                            try:
                                if packet[DNS].qd:
                                    metadata['dns_query'] = packet[DNS].qd.qname.decode()
                            except:
                                pass  # Ignore errors in DNS parsing
                    
                    elif ICMP in packet:
                        metadata['protocol'] = "ICMP"
                        metadata['icmp_type'] = str(packet[ICMP].type)
                        metadata['icmp_code'] = str(packet[ICMP].code)
                
                # Check for ARP
                elif ARP in packet:
                    metadata['protocol'] = "ARP"
                    metadata['src_ip'] = packet[ARP].psrc
                    metadata['dst_ip'] = packet[ARP].pdst
                
                # Determine packet direction
                if metadata['src_ip'] and metadata['dst_ip']:
                    if metadata['src_ip'].startswith(('192.168.', '10.', '172.16.')):
                        if metadata['dst_ip'].startswith(('192.168.', '10.', '172.16.')):
                            metadata['packet_direction'] = "Local"
                        else:
                            metadata['packet_direction'] = "Outgoing"
                    else:
                        metadata['packet_direction'] = "Incoming"
                
                # Add raw data for hex view (simplified)
                try:
                    metadata['raw'] = [b for b in bytes(packet)][:100]  # First 100 bytes only
                except:
                    metadata['raw'] = []  # If bytes conversion fails
                
                # Update statistics
                stats['total_packets'] += 1
                
                if metadata['protocol'] == "TCP":
                    stats['tcp_packets'] += 1
                elif metadata['protocol'] == "UDP":
                    stats['udp_packets'] += 1
                elif metadata['protocol'] == "ICMP":
                    stats['icmp_packets'] += 1
                elif metadata['protocol'] == "ARP":
                    stats['arp_packets'] += 1
                else:
                    stats['other_packets'] += 1
                
                # Update IP stats
                if metadata['src_ip']:
                    stats['top_ips'][metadata['src_ip']] = stats['top_ips'].get(metadata['src_ip'], 0) + 1
                
                if metadata['dst_ip']:
                    stats['top_destinations'][metadata['dst_ip']] = stats['top_destinations'].get(metadata['dst_ip'], 0) + 1
                
                # Update port stats
                if metadata['src_port']:
                    stats['top_ports'][metadata['src_port']] = stats['top_ports'].get(metadata['src_port'], 0) + 1
                
                if metadata['dst_port']:
                    stats['top_ports'][metadata['dst_port']] = stats['top_ports'].get(metadata['dst_port'], 0) + 1
                
                # Write to CSV
                with open(csv_file, 'a', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        metadata['timestamp'],
                        metadata['src_mac'],
                        metadata['dst_mac'],
                        metadata['src_ip'],
                        metadata['dst_ip'],
                        metadata['protocol'],
                        metadata['length'],
                        metadata['src_port'],
                        metadata['dst_port'],
                        metadata['ttl'],
                        metadata['tcp_flags'],
                        metadata['tcp_window'],
                        metadata['icmp_type'],
                        metadata['icmp_code'],
                        metadata['dns_query'],
                        metadata['http_method'],
                        metadata['http_host'],
                        metadata['http_path'],
                        metadata['packet_direction'],
                        str(metadata['raw'])
                    ])
                
                # Call the callback with the packet and metadata
                if packet_callback:
                    packet_callback(packet, metadata)
                
                return packet
            
            # Try to resolve the interface name
            actual_interface = interface
            if sys.platform == 'win32':
                # On Windows, try several approaches to find the correct interface
                try:
                    # Get list of Windows interfaces
                    win_interfaces = get_windows_if_list()
                    
                    print(f"Available interfaces: {win_interfaces}")
                    
                    # Try to match by GUID
                    if '{' in interface and '}' in interface:
                        guid = interface[interface.find('{'):interface.find('}')+1]
                        for iface in win_interfaces:
                            if guid in str(iface.get('guid', '')):
                                actual_interface = iface.get('name') or iface.get('description') or interface
                                break
                    
                    # If no match by GUID, try by IP
                    elif '(' in interface and ')' in interface:
                        ip = interface[interface.find('(')+1:interface.find(')')]
                        for iface in win_interfaces:
                            if ip in str(iface.get('ips', [])):
                                actual_interface = iface.get('name') or iface.get('description') or interface
                                break
                    
                    # Last resort: try to find first valid interface
                    if actual_interface == interface and not interface.startswith('\\Device\\'):
                        if win_interfaces:
                            # Just use the first one
                            actual_interface = win_interfaces[0].get('name') or win_interfaces[0].get('description')
                            print(f"Falling back to first available interface: {actual_interface}")
                except Exception as e:
                    print(f"Error resolving Windows interface: {e}")
            
            # Start packet capture
            try:
                print(f"Starting capture on interface: {actual_interface}")
                
                # Create stop filter function
                def stop_filter(packet):
                    elapsed = time.time() - stats['start_time']
                    if stop_event and stop_event.is_set():
                        return True
                    if packet_count > 0 and stats['total_packets'] >= packet_count:
                        return True
                    if timeout > 0 and elapsed >= timeout:
                        return True
                    return False
                
                # Try to start sniffing with the resolved interface
                sniff(
                    iface=actual_interface,
                    prn=process_packet,
                    store=False,
                    stop_filter=stop_filter
                )
                
            except Exception as e:
                print(f"Error during packet capture: {e}")
                
                # Try with default interface as fallback
                try:
                    print("Trying with default interface...")
                    sniff(
                        prn=process_packet,
                        store=False,
                        stop_filter=stop_filter
                    )
                except Exception as e2:
                    print(f"Error during fallback capture: {e2}")
            finally:
                # Update statistics
                stats['end_time'] = time.time()
                stats['duration'] = stats['end_time'] - stats['start_time']
            
            return stats, csv_file
        
        # Add the function to the sniffer module
        setattr(sniffer, '_capture_with_scapy_realtime', _capture_with_scapy_realtime)

# Call the setup function to add real-time capture support
_setup_realtime_capture()

class SnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Sniffer")
        self.root.geometry("1200x800")
        self.root.minsize(800, 600)
        
        self.capture_in_progress = False
        self.capture_thread = None
        self.stats = None
        self.csv_file = None
        self.all_packets = []  # Initialize the list for storing all packets
        
        # Real-time capture settings
        self.packet_queue = queue.Queue()  # Thread-safe queue for packets
        self.update_interval = 1000  # Update UI every 1 second (in milliseconds)
        self.max_display_packets = 1000  # Maximum packets to display at once
        self.packet_count = 0  # Counter for displayed packets
        
        # Debug mode for troubleshooting
        self.debug_mode = True  # Set to True to see debug info
        
        # Initialize simple default stats for UI before capture
        self.init_default_stats()
        
        # Theme settings
        self.current_theme = "light"
        self.themes = {
            "light": {
                "bg": "#f0f0f0",
                "fg": "#000000",
                "text_bg": "#ffffff",
                "text_fg": "#000000",
                "highlight_bg": "#e0e0e0",
                "highlight_fg": "#000000",
                "button_bg": "#e0e0e0",
                "button_fg": "#000000",
                "header_bg": "#d0d0d0",
                "header_fg": "#000000"
            },
            "dark": {
                "bg": "#000000",
                "fg": "#ffffff",
                "text_bg": "#000000",
                "text_fg": "#ffffff",
                "highlight_bg": "#333333",
                "highlight_fg": "#ffffff",
                "button_bg": "#000000",
                "button_fg": "#ffffff",
                "header_bg": "#000000",
                "header_fg": "#ffffff"
            }
        }
        
        # Protocol colors for Wireshark-like color coding
        self.protocol_colors = {
            "TCP": {"light": "#e7e6ff", "dark": "#000066"},
            "UDP": {"light": "#e7ffff", "dark": "#006666"},
            "ICMP": {"light": "#ffe0e0", "dark": "#660000"},
            "ARP": {"light": "#e6ffca", "dark": "#336600"},
            "DNS": {"light": "#e6e0ff", "dark": "#330066"},
            "HTTP": {"light": "#ffe0cc", "dark": "#663300"},
            "HTTPS": {"light": "#ffd9cc", "dark": "#662200"},
            "TLS": {"light": "#ccffe6", "dark": "#006633"},
            "SSH": {"light": "#ffe6cc", "dark": "#663300"},
            "FTP": {"light": "#ffe6f2", "dark": "#660033"},
            "DHCP": {"light": "#e6f2ff", "dark": "#003366"},
            "SMB": {"light": "#f2e6ff", "dark": "#330066"},
            "NTP": {"light": "#fff2e6", "dark": "#663300"},
            "SNMP": {"light": "#e6fff2", "dark": "#006633"}
        }
        
        # Create the main framework
        self._create_menu()
        self._create_toolbar()
        self._create_main_content()
        self._create_statusbar()
        
        # Initialize interfaces list
        self._load_interfaces()
        
        # Apply the default theme
        self._apply_theme()
    
    def _create_menu(self):
        """Create the menu bar"""
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Open Capture File...", command=self._open_capture)
        file_menu.add_command(label="Save Capture As...", command=self._save_capture)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Capture menu
        capture_menu = tk.Menu(menubar, tearoff=0)
        capture_menu.add_command(label="Start", command=self.start_capture)
        capture_menu.add_command(label="Stop", command=self.stop_capture)
        menubar.add_cascade(label="Capture", menu=capture_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def _create_toolbar(self):
        """Create the toolbar with common actions"""
        toolbar_frame = ttk.Frame(self.root)
        toolbar_frame.pack(side=tk.TOP, fill=tk.X)
        
        # Interface selection
        ttk.Label(toolbar_frame, text="Interface:").pack(side=tk.LEFT, padx=5, pady=5)
        self.interface_var = tk.StringVar()
        self.interface_dropdown = ttk.Combobox(toolbar_frame, textvariable=self.interface_var, width=40)
        self.interface_dropdown.pack(side=tk.LEFT, padx=5, pady=5)
        
        # Capture mode selection
        self.capture_mode = tk.StringVar(value="time")
        ttk.Radiobutton(toolbar_frame, text="Time:", variable=self.capture_mode, value="time").pack(side=tk.LEFT, padx=5, pady=5)
        
        # Time entry
        self.time_var = tk.StringVar(value="30")
        time_entry = ttk.Entry(toolbar_frame, textvariable=self.time_var, width=5)
        time_entry.pack(side=tk.LEFT, padx=0, pady=5)
        ttk.Label(toolbar_frame, text="seconds").pack(side=tk.LEFT, padx=5, pady=5)
        
        # Packet count option
        ttk.Radiobutton(toolbar_frame, text="Packets:", variable=self.capture_mode, value="packets").pack(side=tk.LEFT, padx=5, pady=5)
        
        # Packet count entry
        self.packets_var = tk.StringVar(value="100")
        packets_entry = ttk.Entry(toolbar_frame, textvariable=self.packets_var, width=5)
        packets_entry.pack(side=tk.LEFT, padx=0, pady=5)
        
        # Start/Stop buttons
        self.start_button = ttk.Button(toolbar_frame, text="Start Capture", command=self.start_capture)
        self.start_button.pack(side=tk.LEFT, padx=20, pady=5)
        
        self.stop_button = ttk.Button(toolbar_frame, text="Stop", command=self.stop_capture, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5, pady=5)
        
        # Theme toggle button
        self.theme_var = tk.StringVar(value="Dark Mode")
        self.theme_button = ttk.Button(toolbar_frame, textvariable=self.theme_var, command=self.toggle_theme)
        self.theme_button.pack(side=tk.RIGHT, padx=10, pady=5)
    
    def _create_main_content(self):
        """Create the main content area with tabs"""
        main_frame = ttk.Frame(self.root)
        main_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        
        # Create notebook (tabbed interface)
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Packets tab
        self.packets_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.packets_frame, text="Packets")
        
        # Create a frame for the packet list
        packet_list_frame = ttk.Frame(self.packets_frame)
        packet_list_frame.pack(fill=tk.BOTH, expand=True)
        
        # Column headers - removed icmp_type, icmp_code, dns_query, http_method, http_host, http_path
        columns = (
            "no", "timestamp", "src_mac", "dst_mac", "src_ip", "dst_ip", 
            "src_port", "dst_port", "protocol", "length", "ttl", 
            "tcp_flags", "tcp_window", "packet_direction", "info"
        )
        self.packet_tree = ttk.Treeview(packet_list_frame, columns=columns, show="headings")
        
        # Define column headings
        self.packet_tree.heading("no", text="#")
        self.packet_tree.heading("timestamp", text="Time")
        self.packet_tree.heading("src_mac", text="Source MAC")
        self.packet_tree.heading("dst_mac", text="Destination MAC")
        self.packet_tree.heading("src_ip", text="Source IP")
        self.packet_tree.heading("dst_ip", text="Destination IP")
        self.packet_tree.heading("src_port", text="Source Port")
        self.packet_tree.heading("dst_port", text="Destination Port")
        self.packet_tree.heading("protocol", text="Protocol")
        self.packet_tree.heading("length", text="Length")
        self.packet_tree.heading("ttl", text="TTL")
        self.packet_tree.heading("tcp_flags", text="TCP Flags")
        self.packet_tree.heading("tcp_window", text="TCP Window")
        self.packet_tree.heading("packet_direction", text="Direction")
        self.packet_tree.heading("info", text="Info")
        
        # Set column widths
        self.packet_tree.column("no", width=50)
        self.packet_tree.column("timestamp", width=150)
        self.packet_tree.column("src_mac", width=150)
        self.packet_tree.column("dst_mac", width=150)
        self.packet_tree.column("src_ip", width=120)
        self.packet_tree.column("dst_ip", width=120)
        self.packet_tree.column("src_port", width=80)
        self.packet_tree.column("dst_port", width=80)
        self.packet_tree.column("protocol", width=80)
        self.packet_tree.column("length", width=60)
        self.packet_tree.column("ttl", width=50)
        self.packet_tree.column("tcp_flags", width=100)
        self.packet_tree.column("tcp_window", width=80)
        self.packet_tree.column("packet_direction", width=80)
        self.packet_tree.column("info", width=200)
        
        # Add a scrollbar
        scrollbar = ttk.Scrollbar(packet_list_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        self.packet_tree.configure(yscroll=scrollbar.set)
        
        # Pack the treeview and scrollbar
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind selection event to display packet details
        self.packet_tree.bind("<<TreeviewSelect>>", self._on_packet_select)
        
        # Packet details frame
        self.packet_details = ttk.LabelFrame(self.packets_frame, text="Packet Details")
        self.packet_details.pack(fill=tk.X, expand=False, padx=5, pady=5)
        
        # Text area for packet details
        self.details_text = scrolledtext.ScrolledText(self.packet_details, height=10)
        self.details_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Analytics tab
        self.analytics_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.analytics_frame, text="Analytics")
        
        # Create main analytics layout with two frames
        analytics_main_frame = ttk.Frame(self.analytics_frame)
        analytics_main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Traffic Summary section - now takes 70% of height
        summary_frame = ttk.LabelFrame(analytics_main_frame, text="Traffic Summary")
        summary_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.summary_text = scrolledtext.ScrolledText(summary_frame, height=15)
        self.summary_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Protocol Distribution section - now takes 30% of height and is fixed size
        protocol_container = ttk.Frame(analytics_main_frame)
        protocol_container.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        
        protocol_frame = ttk.LabelFrame(protocol_container, text="Protocol Distribution")
        protocol_frame.pack(side=tk.LEFT, fill=tk.BOTH, padx=5, pady=5)
        
        # Add a canvas for charts with fixed size
        self.protocol_canvas = tk.Canvas(protocol_frame, bg="white", height=200, width=400)
        self.protocol_canvas.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Raw Data tab
        self.raw_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.raw_frame, text="Raw Data")
        
        self.raw_text = scrolledtext.ScrolledText(self.raw_frame)
        self.raw_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Hex View tab
        self.hex_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.hex_frame, text="Hex View")
        
        # Add hex view controls
        hex_controls_frame = ttk.Frame(self.hex_frame)
        hex_controls_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(hex_controls_frame, text="Packet:").pack(side=tk.LEFT, padx=5, pady=5)
        self.hex_packet_var = tk.StringVar()
        self.hex_packet_dropdown = ttk.Combobox(hex_controls_frame, textvariable=self.hex_packet_var, width=10)
        self.hex_packet_dropdown.pack(side=tk.LEFT, padx=5, pady=5)
        
        ttk.Button(hex_controls_frame, text="View", command=self._display_hex_view).pack(side=tk.LEFT, padx=5, pady=5)
        
        # Hex view text area
        self.hex_text = scrolledtext.ScrolledText(self.hex_frame, font=("Courier", 10))
        self.hex_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Debug tab for troubleshooting
        if self.debug_mode:
            self.debug_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.debug_frame, text="Debug")
            
            # Create controls for testing
            controls_frame = ttk.Frame(self.debug_frame)
            controls_frame.pack(fill=tk.X, padx=5, pady=5)
            
            ttk.Label(controls_frame, text="Debug Tools:").pack(side=tk.LEFT, padx=5, pady=5)
            
            # Button to generate test packets
            test_btn = ttk.Button(controls_frame, text="Generate Test Packets", 
                                command=self._generate_test_packets)
            test_btn.pack(side=tk.LEFT, padx=5, pady=5)
            
            # Button to show interfaces
            ifaces_btn = ttk.Button(controls_frame, text="Show Available Interfaces", 
                                  command=self._show_interfaces)
            ifaces_btn.pack(side=tk.LEFT, padx=5, pady=5)
            
            # Debug log
            log_frame = ttk.LabelFrame(self.debug_frame, text="Debug Log")
            log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            self.debug_text = scrolledtext.ScrolledText(log_frame)
            self.debug_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            # Add initial debug info
            self._log_debug("Debug mode enabled")
            self._log_debug(f"System platform: {sys.platform}")
    
    def _log_debug(self, message):
        """Add a message to the debug log"""
        if not hasattr(self, 'debug_text'):
            print(f"DEBUG: {message}")  # Fall back to console if no debug text widget
            return
            
        timestamp = time.strftime("%H:%M:%S")
        self.debug_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.debug_text.see(tk.END)  # Scroll to the bottom
    
    def _generate_test_packets(self):
        """Generate test packet data when real capture fails"""
        if self.debug_mode:
            self._log_debug("Generating test packets")
        
        try:
            # Initialize packet storage
            self.all_packets = []
            
            # Create default statistics
            self.init_default_stats()
            
            # Generate random test packets
            protocols = ["TCP", "UDP", "ICMP", "DNS", "HTTP", "ARP", "DHCP"]
            local_ips = ["192.168.1.100", "192.168.1.101", "192.168.1.102", "10.0.0.15"]
            remote_ips = ["8.8.8.8", "1.1.1.1", "142.250.190.78", "151.101.193.69", "13.107.42.16"]
            local_mac = "00:11:22:33:44:55"
            remote_macs = ["AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66", "AA:11:BB:22:CC:33"]
            http_methods = ["GET", "POST", "PUT", "DELETE"]
            http_hosts = ["www.example.com", "api.github.com", "google.com", "microsoft.com"]
            
            # Calculate how many packets to generate
            num_packets = min(int(self.capture_value) if self.capture_mode == "packet" else 50, 100)
            
            # Generate statistics dictionary
            self.stats = {
                "protocol_counts": {"TCP": 0, "UDP": 0, "ICMP": 0, "DNS": 0, "HTTP": 0, "ARP": 0, "DHCP": 0, "Other": 0},
                "total_packets": num_packets,
                "total_bytes": 0,
                "start_time": time.time() - 10,  # Started 10 seconds ago
                "end_time": time.time(),
                "duration": 10,  # 10 seconds capture
                "packet_rate": num_packets / 10,
                "byte_rate": 0,
            }
            
            # Generate packets
            for i in range(num_packets):
                # Randomly choose packet attributes
                protocol = random.choice(protocols)
                is_outbound = random.choice([True, False])
                src_ip = random.choice(local_ips) if is_outbound else random.choice(remote_ips)
                dst_ip = random.choice(remote_ips) if is_outbound else random.choice(local_ips)
                src_port = random.randint(49152, 65535) if is_outbound else random.choice([80, 443, 53, 22])
                dst_port = random.choice([80, 443, 53, 22]) if is_outbound else random.randint(49152, 65535)
                src_mac = local_mac if is_outbound else random.choice(remote_macs)
                dst_mac = random.choice(remote_macs) if is_outbound else local_mac
                timestamp = datetime.now() - timedelta(seconds=random.randint(0, 10))
                timestamp_str = timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                
                # Generate protocol-specific fields
                length = random.randint(64, 1500)
                ttl = random.randint(32, 128)
                tcp_flags = "ACK" if random.random() > 0.5 else "SYN" if random.random() > 0.7 else "FIN"
                tcp_window = random.choice([8192, 16384, 65535])
                icmp_type = random.randint(0, 8) if protocol == "ICMP" else ""
                icmp_code = random.randint(0, 3) if protocol == "ICMP" else ""
                dns_query = f"{random.choice(['www', 'mail', 'api'])}.{random.choice(['example.com', 'google.com', 'microsoft.com'])}" if protocol == "DNS" else ""
                http_method = random.choice(http_methods) if protocol == "HTTP" else ""
                http_host = random.choice(http_hosts) if protocol == "HTTP" else ""
                http_path = f"/{random.choice(['index.html', 'api/v1/users', 'login', 'images/logo.png'])}" if protocol == "HTTP" else ""
                
                # Generate packet info string
                if protocol == "TCP" or protocol == "UDP":
                    info = f"{src_ip}:{src_port} → {dst_ip}:{dst_port}"
                elif protocol == "ICMP":
                    info = f"Echo {'request' if icmp_type == 8 else 'reply'} {src_ip} → {dst_ip}"
                elif protocol == "DNS":
                    info = f"Query: {dns_query}" if random.random() > 0.5 else f"Response: {dns_query}"
                elif protocol == "HTTP":
                    info = f"{http_method} {http_path} Host: {http_host}"
                elif protocol == "ARP":
                    info = f"Who has {dst_ip}? Tell {src_ip}"
                else:
                    info = f"{src_ip} → {dst_ip}"
                
                # Create packet dictionary
                packet_data = {
                    'id': i + 1,
                    'timestamp': timestamp_str,
                    'src_mac': src_mac,
                    'dst_mac': dst_mac,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': str(src_port) if src_port else "",
                    'dst_port': str(dst_port) if dst_port else "",
                    'protocol': protocol,
                    'length': str(length),
                    'ttl': str(ttl),
                    'tcp_flags': tcp_flags if protocol == "TCP" else "",
                    'tcp_window': str(tcp_window) if protocol == "TCP" else "",
                    'icmp_type': str(icmp_type) if protocol == "ICMP" else "",
                    'icmp_code': str(icmp_code) if protocol == "ICMP" else "",
                    'dns_query': dns_query,
                    'http_method': http_method,
                    'http_host': http_host,
                    'http_path': http_path,
                    'packet_direction': "outbound" if is_outbound else "inbound",
                    'info': info
                }
                self.all_packets.append(packet_data)
                
                # Add to treeview with protocol tag
                protocol_tag = self._get_protocol_tag(protocol)
                item_id = self.packet_tree.insert("", tk.END, values=(
                    i+1, timestamp_str, src_mac, dst_mac, src_ip, dst_ip, 
                    src_port, dst_port, protocol, length, ttl, 
                    tcp_flags, tcp_window, packet_data['packet_direction'], info
                ), tags=(protocol_tag,))
                
                # Update raw data tab with the first 1000 packets
                if i <= 1000:
                    # Create a simulated raw data string from packet values
                    raw_values = [
                        packet_data['timestamp'], packet_data['src_mac'], packet_data['dst_mac'],
                        packet_data['src_ip'], packet_data['dst_ip'], packet_data['protocol'],
                        packet_data['length'], packet_data['src_port'], packet_data['dst_port']
                    ]
                    raw_data = ", ".join(str(val) for val in raw_values)
                    self.raw_text.insert(tk.END, f"{i+1}: {raw_data}\n")
            
        except Exception as e:
            raise Exception(f"Error loading CSV: {str(e)}")
    
    def _open_capture(self):
        """Open a saved capture file"""
        # To be implemented
        messagebox.showinfo("Info", "Open capture file functionality will be available in a future update")
    
    def _save_capture(self):
        """Save the current capture to a file"""
        # To be implemented
        messagebox.showinfo("Info", "Save capture functionality will be available in a future update")
    
    def _show_about(self):
        """Show the about dialog"""
        messagebox.showinfo("About", "Network Sniffer\nVersion 1.0\n\nA network packet capture and analysis tool")

    def _on_packet_select(self, event):
        """Handle packet selection event"""
        selected = self.packet_tree.selection()
        if not selected:
            return
        
        # Get selected item values
        item_id = selected[0]
        values = self.packet_tree.item(item_id, "values")
        
        # Find the packet in our all_packets list to access all fields
        packet_id = int(values[0])
        packet = None
        for p in self.all_packets:
            if p['id'] == packet_id:
                packet = p
                break
        
        if not packet:
            return
        
        # Display packet details
        self.details_text.delete(1.0, tk.END)
        
        # Format details with syntax highlighting using tags
        self.details_text.tag_configure("header", foreground="blue", font=("Courier", 10, "bold"))
        self.details_text.tag_configure("field", foreground="green")
        self.details_text.tag_configure("value", foreground="black")
        
        # Frame details
        self.details_text.insert(tk.END, "FRAME INFO\n", "header")
        self.details_text.insert(tk.END, f"  {'Packet Number:':<20}", "field")
        self.details_text.insert(tk.END, f"{packet['id']}\n", "value")
        self.details_text.insert(tk.END, f"  {'Timestamp:':<20}", "field")
        self.details_text.insert(tk.END, f"{packet['timestamp']}\n", "value")
        self.details_text.insert(tk.END, f"  {'Frame Length:':<20}", "field")
        self.details_text.insert(tk.END, f"{packet['length']} bytes\n\n", "value")
        
        # MAC addresses
        self.details_text.insert(tk.END, "ETHERNET LAYER\n", "header")
        self.details_text.insert(tk.END, f"  {'Source MAC:':<20}", "field")
        self.details_text.insert(tk.END, f"{packet['src_mac']}\n", "value")
        self.details_text.insert(tk.END, f"  {'Destination MAC:':<20}", "field")
        self.details_text.insert(tk.END, f"{packet['dst_mac']}\n\n", "value")
        
        # Protocol
        protocol = packet['protocol'].upper()
        self.details_text.insert(tk.END, f"{protocol} PROTOCOL\n", "header")
        
        # IP Layer
        self.details_text.insert(tk.END, f"  {'Source IP:':<20}", "field")
        self.details_text.insert(tk.END, f"{packet['src_ip']}\n", "value")
        self.details_text.insert(tk.END, f"  {'Destination IP:':<20}", "field")
        self.details_text.insert(tk.END, f"{packet['dst_ip']}\n", "value")
        
        # TTL if available
        if packet['ttl']:
            self.details_text.insert(tk.END, f"  {'TTL:':<20}", "field")
            self.details_text.insert(tk.END, f"{packet['ttl']}\n", "value")
        
        # Direction if available
        if packet['packet_direction']:
            self.details_text.insert(tk.END, f"  {'Direction:':<20}", "field")
            self.details_text.insert(tk.END, f"{packet['packet_direction']}\n", "value")
        
        # Additional protocol-specific info
        if protocol == "TCP":
            self._add_tcp_details(packet)
        elif protocol == "UDP":
            self._add_udp_details(packet)
        elif protocol == "ICMP":
            self._add_icmp_details(packet)
        elif "DNS" in protocol or packet['dns_query']:
            self._add_dns_details(packet)
        elif "HTTP" in protocol or packet['http_method'] or packet['http_host'] or packet['http_path']:
            self._add_http_details(packet)
        
        # Add info field
        self.details_text.insert(tk.END, "\nINFO\n", "header")
        self.details_text.insert(tk.END, f"  {packet['info']}\n", "value")
        
        # Also display the hex view for this packet
        try:
            self.hex_packet_var.set(str(packet_id))
            self._display_hex_view()
        except:
            pass

    def _add_tcp_details(self, packet):
        """Add TCP-specific details to packet details"""
        # Add TCP ports
        self.details_text.insert(tk.END, "\nTCP DETAILS\n", "header")
        
        if packet['src_port']:
            self.details_text.insert(tk.END, f"  {'Source Port:':<20}", "field")
            self.details_text.insert(tk.END, f"{packet['src_port']}\n", "value")
        
        if packet['dst_port']:
            self.details_text.insert(tk.END, f"  {'Destination Port:':<20}", "field")
            self.details_text.insert(tk.END, f"{packet['dst_port']}\n", "value")
        
        # TCP flags if available
        if packet['tcp_flags']:
            self.details_text.insert(tk.END, f"  {'TCP Flags:':<20}", "field")
            self.details_text.insert(tk.END, f"{packet['tcp_flags']}\n", "value")
        
        # TCP window if available
        if packet['tcp_window']:
            self.details_text.insert(tk.END, f"  {'TCP Window Size:':<20}", "field")
            self.details_text.insert(tk.END, f"{packet['tcp_window']}\n", "value")

    def _add_udp_details(self, packet):
        """Add UDP-specific details to packet details"""
        self.details_text.insert(tk.END, "\nUDP DETAILS\n", "header")
        
        if packet['src_port']:
            self.details_text.insert(tk.END, f"  {'Source Port:':<20}", "field")
            self.details_text.insert(tk.END, f"{packet['src_port']}\n", "value")
        
        if packet['dst_port']:
            self.details_text.insert(tk.END, f"  {'Destination Port:':<20}", "field")
            self.details_text.insert(tk.END, f"{packet['dst_port']}\n", "value")

    def _add_icmp_details(self, packet):
        """Add ICMP-specific details to packet details"""
        self.details_text.insert(tk.END, "\nICMP DETAILS\n", "header")
        
        if packet['icmp_type']:
            self.details_text.insert(tk.END, f"  {'ICMP Type:':<20}", "field")
            self.details_text.insert(tk.END, f"{packet['icmp_type']}\n", "value")
        else:
            self.details_text.insert(tk.END, f"  {'ICMP Type:':<20}", "field")
            self.details_text.insert(tk.END, "Unknown\n", "value")
        
        if packet['icmp_code']:
            self.details_text.insert(tk.END, f"  {'ICMP Code:':<20}", "field")
            self.details_text.insert(tk.END, f"{packet['icmp_code']}\n", "value")
        else:
            self.details_text.insert(tk.END, f"  {'ICMP Code:':<20}", "field")
            self.details_text.insert(tk.END, "Unknown\n", "value")

    def _add_dns_details(self, packet):
        """Add DNS-specific details to packet details"""
        self.details_text.insert(tk.END, "\nDNS DETAILS\n", "header")
        
        if packet['dns_query']:
            self.details_text.insert(tk.END, f"  {'DNS Query:':<20}", "field")
            self.details_text.insert(tk.END, f"{packet['dns_query']}\n", "value")

    def _add_http_details(self, packet):
        """Add HTTP-specific details to packet details"""
        self.details_text.insert(tk.END, "\nHTTP DETAILS\n", "header")
        
        if packet['http_method']:
            self.details_text.insert(tk.END, f"  {'HTTP Method:':<20}", "field")
            self.details_text.insert(tk.END, f"{packet['http_method']}\n", "value")
        
        if packet['http_host']:
            self.details_text.insert(tk.END, f"  {'HTTP Host:':<20}", "field")
            self.details_text.insert(tk.END, f"{packet['http_host']}\n", "value")
        
        if packet['http_path']:
            self.details_text.insert(tk.END, f"  {'HTTP Path:':<20}", "field")
            self.details_text.insert(tk.END, f"{packet['http_path']}\n", "value")

    def _display_hex_view(self):
        """Display hexadecimal view of the selected packet"""
        try:
            packet_id = int(self.hex_packet_var.get())
            
            # Find the packet in the all_packets list
            packet = None
            for p in self.all_packets:
                if p['id'] == packet_id:
                    packet = p
                    break
            
            if not packet:
                self.hex_text.delete(1.0, tk.END)
                self.hex_text.insert(tk.END, f"Packet {packet_id} not found")
                return
            
            # Set hex view colors based on theme
            if self.current_theme == "dark":
                self.hex_text.config(background="#000000", foreground="#ffffff")
                header_color = "#66b3ff"
                offset_color = "#99ff99"
                hex_color = "#ffffff"
                ascii_color = "#ffcc66"
            else:
                self.hex_text.config(background="#ffffff", foreground="#000000")
                header_color = "#0066cc"
                offset_color = "#007700"
                hex_color = "#000000"
                ascii_color = "#cc6600"
            
            # Configure hex view tags
            self.hex_text.tag_configure("header", foreground=header_color, font=("Courier", 10, "bold"))
            self.hex_text.tag_configure("offset", foreground=offset_color)
            self.hex_text.tag_configure("hex", foreground=hex_color)
            self.hex_text.tag_configure("ascii", foreground=ascii_color)
            
            # Format the packet data as hex
            self.hex_text.delete(1.0, tk.END)
            
            # Display header
            self.hex_text.insert(tk.END, f"Packet #{packet_id} - {packet['protocol']} - {packet['length']} bytes\n\n", "header")
            
            # Get the raw data from the packet
            raw_data = packet['raw']
            
            # Create a simulated hex dump since we don't have the actual binary data
            # This is just for demonstration purposes
            offset = 0
            hex_data = ""
            
            # Convert each field to bytes and display as hex
            for field in raw_data:
                try:
                    field_bytes = field.encode('utf-8')
                    
                    # Format in groups of 16 bytes
                    line_offset = f"{offset:04x}:  "
                    self.hex_text.insert(tk.END, line_offset, "offset")
                    
                    ascii_repr = ""
                    
                    for i, byte in enumerate(field_bytes):
                        if i % 16 == 0 and i > 0:
                            self.hex_text.insert(tk.END, "  " + ascii_repr + "\n", "ascii")
                            
                            line_offset = f"{offset+i:04x}:  "
                            self.hex_text.insert(tk.END, line_offset, "offset")
                            ascii_repr = ""
                        
                        self.hex_text.insert(tk.END, f"{byte:02x} ", "hex")
                        
                        # ASCII representation
                        if 32 <= byte <= 126:  # Printable ASCII
                            ascii_repr += chr(byte)
                        else:
                            ascii_repr += "."
                    
                    # Pad the last line
                    if len(field_bytes) % 16 != 0:
                        padding = 16 - (len(field_bytes) % 16)
                        self.hex_text.insert(tk.END, "   " * padding)
                    
                    self.hex_text.insert(tk.END, "  " + ascii_repr + "\n\n", "ascii")
                    
                    offset += len(field_bytes)
                except:
                    continue
            
        except Exception as e:
            self.hex_text.delete(1.0, tk.END)
            self.hex_text.insert(tk.END, f"Error displaying hex view: {str(e)}")

    def _apply_theme(self):
        """Apply the current theme to the UI"""
        theme = self.themes[self.current_theme]
        
        # Configure root and common styles
        self.root.config(bg=theme["bg"])
        
        # Create a custom ttk style
        style = ttk.Style()
        
        # Configure ttk themes
        if self.current_theme == "dark":
            # Try to use a pre-defined dark theme if available
            try:
                style.theme_use("clam")  # "clam" is more customizable
            except:
                pass
        else:
            # Try to use default theme for light mode
            try:
                style.theme_use("vista" if sys.platform == "win32" else "clam")
            except:
                pass
        
        # Configure ttk styles
        style.configure("TFrame", background=theme["bg"])
        style.configure("TLabel", background=theme["bg"], foreground=theme["fg"])
        style.configure("TButton", background=theme["button_bg"], foreground=theme["button_fg"])
        style.configure("TEntry", fieldbackground=theme["text_bg"], foreground=theme["text_fg"])
        style.configure("TCombobox", fieldbackground=theme["text_bg"], foreground=theme["text_fg"])
        style.configure("TNotebook", background=theme["bg"], tabmargins=[2, 5, 2, 0])
        style.configure("TNotebook.Tab", background=theme["button_bg"], foreground=theme["button_fg"], padding=[10, 2])
        
        # Prevent hover color change by setting the same colors for all states
        style.map("TButton",
                 background=[("active", theme["button_bg"]), 
                            ("pressed", theme["button_bg"]),
                            ("hover", theme["button_bg"])],
                 foreground=[("active", theme["button_fg"]),
                            ("pressed", theme["button_fg"]),
                            ("hover", theme["button_fg"])])
        
        style.map("TNotebook.Tab", 
                  background=[("selected", theme["highlight_bg"]),
                             ("active", theme["highlight_bg"])],
                  foreground=[("selected", theme["highlight_fg"]),
                             ("active", theme["highlight_fg"])])
        
        # Configure Treeview (packet list)
        style.configure("Treeview", 
                       background=theme["text_bg"], 
                       foreground=theme["text_fg"],
                       fieldbackground=theme["text_bg"])
        style.configure("Treeview.Heading", 
                       background=theme["header_bg"], 
                       foreground=theme["header_fg"])
        
        # Prevent hover color change in Treeview
        style.map("Treeview", 
                 background=[("selected", theme["highlight_bg"]),
                            ("active", theme["text_bg"])],
                 foreground=[("selected", theme["highlight_fg"]),
                            ("active", theme["text_fg"])])
        
        # Configure text widgets
        text_widgets = [self.details_text, self.summary_text, self.raw_text, self.hex_text]
        for widget in text_widgets:
            widget.config(
                background=theme["text_bg"],
                foreground=theme["text_fg"],
                insertbackground=theme["text_fg"]
            )
        
        # Configure the canvas background
        if hasattr(self, 'protocol_canvas'):
            self.protocol_canvas.config(bg=theme["text_bg"])
        
        # Update text display colors
        self.details_text.tag_configure("header", foreground="#0066cc" if self.current_theme == "light" else "#66b3ff")
        self.details_text.tag_configure("field", foreground="#007700" if self.current_theme == "light" else "#99ff99")
        self.details_text.tag_configure("value", foreground=theme["text_fg"])
        
        # Configure protocol tags only if packet_tree exists
        if hasattr(self, 'packet_tree'):
            self._configure_protocol_tags()

    def toggle_theme(self):
        """Toggle between light and dark theme"""
        if self.current_theme == "light":
            self.current_theme = "dark"
            self.theme_var.set("Light Mode")  # Shows what mode will be activated on next click
        else:
            self.current_theme = "light"
            self.theme_var.set("Dark Mode")   # Shows what mode will be activated on next click
        
        self._apply_theme()

    def _load_interfaces(self):
        """Load available network interfaces into the dropdown"""
        try:
            # Get list of interfaces
            interfaces = sniffer.get_available_interfaces()
            
            # Format interface names for display
            if interfaces:
                formatted_interfaces = []
                for iface in interfaces:
                    # Try to extract IP from interface description
                    ip_match = ""
                    if "(" in iface and ")" in iface:
                        ip_start = iface.find("(") + 1
                        ip_end = iface.find(")")
                        if ip_end > ip_start:
                            ip_match = iface[ip_start:ip_end]
                    
                    # Format display string
                    if ip_match:
                        formatted_interfaces.append(f"{iface}")
                    else:
                        formatted_interfaces.append(iface)
                
                # Update dropdown values
                self.interface_dropdown['values'] = formatted_interfaces
                
                # Select first interface
                if formatted_interfaces:
                    self.interface_var.set(formatted_interfaces[0])
            
            if self.debug_mode:
                self._log_debug(f"Loaded {len(interfaces)} interfaces")
                
        except Exception as e:
            if self.debug_mode:
                self._log_debug(f"Error loading interfaces: {str(e)}")
            messagebox.showwarning("Interface Error", f"Could not load network interfaces: {str(e)}")

    def _show_interfaces(self):
        """Show available interfaces in the debug log"""
        interfaces = sniffer.get_available_interfaces()
        self._log_debug(f"Available interfaces: {interfaces}")

    def _get_protocol_tag(self, protocol):
        """Get the tag name for a specific protocol to apply colors"""
        protocol = protocol.upper() if protocol else "UNKNOWN"
        
        if protocol in ["TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "HTTPS", "TLS", "SSH", "FTP", "DHCP", "SMB", "NTP", "SNMP"]:
            return protocol
        return "OTHER"
    
    def _configure_protocol_tags(self):
        """Configure colors for different protocol tags in the packet tree"""
        for protocol, colors in self.protocol_colors.items():
            color = colors["dark"] if self.current_theme == "dark" else colors["light"]
            self.packet_tree.tag_configure(protocol, background=color)
        
        # Configure default "OTHER" tag
        if self.current_theme == "dark":
            self.packet_tree.tag_configure("OTHER", background="#333333")
        else:
            self.packet_tree.tag_configure("OTHER", background="#f5f5f5")

    def init_default_stats(self):
        """Initialize default statistics"""
        self.stats = {
            "protocol_counts": {"TCP": 0, "UDP": 0, "ICMP": 0, "DNS": 0, "HTTP": 0, "ARP": 0, "Other": 0},
            "total_packets": 0,
            "total_bytes": 0,
            "start_time": time.time(),
            "end_time": time.time(),
            "duration": 0,
            "packet_rate": 0,
            "byte_rate": 0,
            "top_ips": {},
            "top_destinations": {},
            "top_ports": {}
        }

    def start_capture(self):
        """Start packet capture"""
        if self.capture_in_progress:
            return
        
        # Get interface
        interface = self.interface_var.get()
        if not interface:
            messagebox.showerror("Error", "Please select a network interface")
            return
        
        # Get capture parameters
        try:
            # Determine mode and value
            capture_mode = self.capture_mode.get() if hasattr(self.capture_mode, 'get') else "time"
            self.capture_mode = capture_mode  # Store as instance variable
            
            if capture_mode == "time":
                timeout = int(self.time_var.get()) if self.time_var.get() else 30
                packet_count = 0  # Unlimited
                self.capture_value = timeout
            else:  # packet mode
                packet_count = int(self.packets_var.get()) if self.packets_var.get() else 100
                timeout = 0  # Unlimited
                self.capture_value = packet_count
                
            if self.debug_mode:
                mode_str = f"{timeout} seconds" if capture_mode == "time" else f"{packet_count} packets"
                self._log_debug(f"Starting capture on {interface}, mode: {mode_str}")
        except ValueError:
            messagebox.showerror("Error", "Invalid capture parameters. Please enter numeric values.")
            return
        
        # Initialize capture state
        self.capture_in_progress = True
        self.stop_button.config(state=tk.NORMAL)
        self.start_button.config(state=tk.DISABLED)
        
        # Clear previous data
        self.packet_tree.delete(*self.packet_tree.get_children())
        self.details_text.delete(1.0, tk.END)
        self.summary_text.delete(1.0, tk.END)
        self.raw_text.delete(1.0, tk.END)
        self.hex_text.delete(1.0, tk.END)
        
        # Initialize packet queue and counter
        self.packet_queue = queue.Queue()
        self.packet_count = 0
        self.all_packets = []
        
        # Set output filename
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        output_base = f"capture_{timestamp}"
        
        # Create and start the capture thread
        self.stop_capture_event = threading.Event()
        self.capture_thread = threading.Thread(
            target=self._run_capture,
            args=(interface, packet_count, timeout, output_base)
        )
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
        # Schedule the first display update
        self.root.after(500, self._update_display)
        
        # Update status
        self.status_label.config(text=f"Starting capture on {interface}...")
    
    def _update_display(self):
        """Update display with captured packets from the queue"""
        if not self.capture_in_progress:
            return
        
        # Process packets waiting in the queue
        try:
            packets_processed = 0
            start_time = time.time()
            
            # Process a batch of packets (up to 100 per update to avoid UI freezing)
            while not self.packet_queue.empty() and packets_processed < 100:
                packet_data = self.packet_queue.get_nowait()
                packets_processed += 1
                
                # Add packet to our list
                self.all_packets.append(packet_data)
                packet_id = packet_data['id']
                
                # Add to treeview with protocol tag
                protocol_tag = self._get_protocol_tag(packet_data['protocol'])
                self.packet_tree.insert("", tk.END, values=(
                    packet_id,
                    packet_data['timestamp'], 
                    packet_data['src_mac'], 
                    packet_data['dst_mac'], 
                    packet_data['src_ip'], 
                    packet_data['dst_ip'], 
                    packet_data['src_port'], 
                    packet_data['dst_port'], 
                    packet_data['protocol'], 
                    packet_data['length'], 
                    packet_data['ttl'], 
                    packet_data['tcp_flags'], 
                    packet_data['tcp_window'], 
                    packet_data['packet_direction'], 
                    packet_data['info']
                ), tags=(protocol_tag,))
                
                # Update raw data tab (only for first 1000 packets to avoid memory issues)
                if len(self.all_packets) <= 1000:
                    raw_data = ", ".join(str(val) for val in packet_data['raw'] if val)
                    self.raw_text.insert(tk.END, f"{packet_id}: {raw_data}\n")
                    # Auto-scroll raw data to bottom
                    self.raw_text.see(tk.END)
            
            # Auto-scroll packet list to most recent entry
            if packets_processed > 0:
                self.packet_tree.see(self.packet_tree.get_children()[-1])
                
                # Update dropdown for hex viewer
                packet_ids = [str(p['id']) for p in self.all_packets[-100:]]  # Last 100 packets
                self.hex_packet_var.set(packet_ids[-1] if packet_ids else "")
                self.hex_packet_dropdown['values'] = packet_ids
            
            # Update status
            total_packets = len(self.all_packets)
            queue_size = self.packet_queue.qsize()
            elapsed = time.time() - getattr(self, 'capture_start_time', time.time())
            packet_rate = total_packets / elapsed if elapsed > 0 else 0
            
            self.status_label.config(text=f"Capturing... {total_packets} packets ({packet_rate:.1f}/sec) - Queue: {queue_size}")
            
            if self.debug_mode and packets_processed > 0:
                self._log_debug(f"Processed {packets_processed} packets in {(time.time()-start_time)*1000:.1f}ms, queue size: {queue_size}")
                
        except Exception as e:
            self.status_label.config(text=f"Error updating display: {str(e)}")
            if self.debug_mode:
                self._log_debug(f"Display error: {str(e)}")
        
        # Schedule the next update if capture is still in progress
        if self.capture_in_progress:
            # Schedule next update - use shorter interval when packets are available
            update_interval = 200 if not self.packet_queue.empty() else 1000
            self.root.after(update_interval, self._update_display)
    
    def _run_capture(self, interface, packet_count, timeout, output_base):
        """Run the packet capture in a separate thread"""
        try:
            # Track start time
            self.capture_start_time = time.time()
            
            # Create a callback function to process packets as they arrive
            def packet_callback(packet, metadata):
                # Assign ID to new packets
                self.packet_count += 1
                metadata['id'] = self.packet_count
                
                # Add raw data for hex view if not present
                if 'raw' not in metadata:
                    metadata['raw'] = []
                
                # Ensure all required fields exist
                for field in ['src_mac', 'dst_mac', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 
                            'protocol', 'length', 'ttl', 'tcp_flags', 'tcp_window', 'icmp_type', 
                            'icmp_code', 'dns_query', 'http_method', 'http_host', 'http_path', 
                            'packet_direction']:
                    if field not in metadata:
                        metadata[field] = ""
                
                # Generate default info field if not present
                if 'info' not in metadata or not metadata['info']:
                    if metadata['protocol'] == 'TCP' or metadata['protocol'] == 'UDP':
                        metadata['info'] = f"{metadata['src_ip']}:{metadata['src_port']} → {metadata['dst_ip']}:{metadata['dst_port']}"
                    else:
                        metadata['info'] = f"{metadata['src_ip']} → {metadata['dst_ip']}"
                
                # Add to queue for GUI thread to process
                self.packet_queue.put(metadata)
                
                # Force an immediate update if this is the first packet
                if self.packet_count == 1:
                    self.root.after(10, self._update_display)
            
            if self.debug_mode:
                self._log_debug(f"Starting capture on interface: {interface}")
                
            # Start capture with callback
            self.stats, self.csv_file = sniffer._capture_with_scapy_realtime(
                interface, 
                packet_count, 
                timeout, 
                output_base,
                [],  # existing_ifaces - not used with callback
                packet_callback,
                self.stop_capture_event
            )
            
            # Capture completed
            self.root.after(0, self._update_capture_status)
            
        except Exception as e:
            error_msg = f"Error during capture: {str(e)}"
            if self.debug_mode:
                self._log_debug(error_msg)
            messagebox.showerror("Capture Error", error_msg)
            self.root.after(0, self.stop_capture)
    
    def _update_capture_status(self):
        """Update the UI after capture is complete"""
        if self.stats and self.csv_file:
            # Load the packets from csv
            self._load_packets_from_csv(self.csv_file)
            
            # Update analytics
            self._display_capture_results()
        
        # Reset UI state
        self.stop_capture()
    
    def stop_capture(self):
        """Stop the current packet capture"""
        if not self.capture_in_progress:
            return
            
        if self.debug_mode:
            self._log_debug("Stopping capture...")
            
        # Set the stop flag for the capture thread
        if hasattr(self, 'stop_capture_event'):
            self.stop_capture_event.set()
            
        # Give the capture thread a moment to react to the stop event
        self.root.after(100, self._finalize_capture)
        
        # Update UI
        self.status_label.config(text="Stopping capture...")
    
    def _finalize_capture(self):
        """Finalize the capture process after stopping it"""
        # Update UI state
        self.capture_in_progress = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        
        # Process any remaining packets in the queue
        remaining = self.packet_queue.qsize()
        if remaining > 0 and self.debug_mode:
            self._log_debug(f"Processing {remaining} remaining packets in queue")
            
        # Force one final display update
        self._update_display()
            
        # Wait for capture thread to finish if it's still running
        if self.capture_thread and self.capture_thread.is_alive():
            try:
                self.capture_thread.join(timeout=1.0)  # Wait up to 1 second
            except:
                pass  # Ignore any thread joining errors
                
        # Update stats and display results
        if self.stats and self.csv_file:
            packets_count = len(self.all_packets)
            elapsed = self.stats.get('duration', 0)
            rate = packets_count / elapsed if elapsed > 0 else 0
            
            # Update status
            self.status_label.config(text=f"Capture complete: {packets_count} packets in {elapsed:.1f} seconds ({rate:.1f} packets/sec)")
            
            if self.debug_mode:
                self._log_debug(f"Capture complete: {packets_count} packets in {elapsed:.1f} seconds")
                
            # Display capture results
            self._display_capture_results()
    
    def _display_capture_results(self):
        """Display capture results in the UI"""
        try:
            # Update analytics
            if not self.stats:
                return
                
            # Process statistics
            total_packets = self.stats.get('total_packets', 0)
            if total_packets == 0:
                return
                
            # Get the top N items from each category
            top_limit = 5  # Show top 5 items in each category
            
            # Sort dictionaries by value (count)
            top_ips = sorted(self.stats.get('top_ips', {}).items(), key=lambda x: x[1], reverse=True)[:top_limit]
            top_destinations = sorted(self.stats.get('top_destinations', {}).items(), key=lambda x: x[1], reverse=True)[:top_limit]
            top_ports = sorted(self.stats.get('top_ports', {}).items(), key=lambda x: x[1], reverse=True)[:top_limit]
            
            # Display summary
            summary = f"Total packets: {total_packets}\n"
            summary += f"Duration: {self.stats.get('duration', 0):.2f} seconds\n\n"
            summary += f"TCP packets: {self.stats.get('tcp_packets', 0)}\n"
            summary += f"UDP packets: {self.stats.get('udp_packets', 0)}\n"
            summary += f"ICMP packets: {self.stats.get('icmp_packets', 0)}\n"
            summary += f"Other packets: {self.stats.get('other_packets', 0)}\n\n"
            
            # Add top sources
            summary += "Top Source IPs:\n"
            for ip, count in top_ips:
                summary += f"  {ip}: {count}\n"
            
            # Add top destinations
            summary += "\nTop Destination IPs:\n"
            for ip, count in top_destinations:
                summary += f"  {ip}: {count}\n"
            
            # Add top ports
            summary += "\nTop Ports:\n"
            for port, count in top_ports:
                summary += f"  {port}: {count}\n"
            
            self.summary_text.delete(1.0, tk.END)
            self.summary_text.insert(tk.END, summary)
            
            # Create protocol distribution chart if matplotlib is available
            self._create_protocol_chart()
                
        except Exception as e:
            if self.debug_mode:
                self._log_debug(f"Error displaying results: {str(e)}")
    
    def _create_protocol_chart(self):
        """Create a chart showing protocol distribution"""
        # Check if matplotlib is available
        if not has_matplotlib:
            return
            
        try:
            # Clear previous chart
            self.protocol_canvas.delete("all")
            
            # Create figure and axis
            fig = plt.Figure(figsize=(4, 3), dpi=100)
            ax = fig.add_subplot(111)
            
            # Extract protocol data
            protocols = ['TCP', 'UDP', 'ICMP', 'Other']
            counts = [
                self.stats.get('tcp_packets', 0),
                self.stats.get('udp_packets', 0),
                self.stats.get('icmp_packets', 0),
                self.stats.get('other_packets', 0)
            ]
            
            # Remove zeros to avoid empty wedges
            non_zero_protocols = []
            non_zero_counts = []
            for i, count in enumerate(counts):
                if count > 0:
                    non_zero_protocols.append(protocols[i])
                    non_zero_counts.append(count)
            
            if not non_zero_counts:
                return  # No data to display
                
            # Set colors based on theme
            colors = []
            for protocol in non_zero_protocols:
                if protocol == 'TCP' and 'TCP' in self.protocol_colors:
                    colors.append(self.protocol_colors['TCP']['light' if self.current_theme == 'light' else 'dark'])
                elif protocol == 'UDP' and 'UDP' in self.protocol_colors:
                    colors.append(self.protocol_colors['UDP']['light' if self.current_theme == 'light' else 'dark'])
                elif protocol == 'ICMP' and 'ICMP' in self.protocol_colors:
                    colors.append(self.protocol_colors['ICMP']['light' if self.current_theme == 'light' else 'dark'])
                else:
                    colors.append('#cccccc' if self.current_theme == 'light' else '#333333')
            
            # Create pie chart
            wedges, texts, autotexts = ax.pie(
                non_zero_counts, 
                labels=non_zero_protocols, 
                autopct='%1.1f%%',
                colors=colors,
                startangle=90
            )
            
            # Set text color based on theme
            for text in texts + autotexts:
                text.set_color('#000000' if self.current_theme == 'light' else '#ffffff')
            
            # Equal aspect ratio ensures that pie is drawn as a circle
            ax.axis('equal')
            ax.set_title('Protocol Distribution', color='#000000' if self.current_theme == 'light' else '#ffffff')
            fig.patch.set_facecolor(self.themes[self.current_theme]['text_bg'])
            ax.set_facecolor(self.themes[self.current_theme]['text_bg'])
            
            # Embed the figure in the tkinter canvas
            canvas = FigureCanvasTkAgg(fig, master=self.protocol_canvas)
            canvas.draw()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            
        except Exception as e:
            if self.debug_mode:
                self._log_debug(f"Error creating chart: {str(e)}")
            # Create a label instead of the chart
            self.protocol_canvas.create_text(
                200, 100,
                text=f"Could not create chart: {str(e)}",
                fill="#000000" if self.current_theme == "light" else "#ffffff"
            )

    def _create_statusbar(self):
        """Create the status bar at the bottom of the window"""
        self.status_frame = ttk.Frame(self.root, relief=tk.SUNKEN, border=1)
        self.status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.status_label = ttk.Label(self.status_frame, text="Ready", anchor=tk.W)
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=2)
        
        self.packet_count_label = ttk.Label(self.status_frame, text="Packets: 0", anchor=tk.E)
        self.packet_count_label.pack(side=tk.RIGHT, padx=5, pady=2)

if __name__ == "__main__":
    root = tk.Tk()
    app = SnifferGUI(root)
    root.mainloop() 