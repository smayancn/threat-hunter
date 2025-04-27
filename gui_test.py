import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
import os
import sys
import queue
import re
import random
from datetime import datetime
import csv

# Try importing matplotlib for visualization
try:
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    has_matplotlib = True
except ImportError:
    has_matplotlib = False

# Try importing Scapy at the module level with better error handling
try:
    import scapy.all as scapy
    from scapy.all import sniff, wrpcap, Ether, IP, TCP, UDP, ICMP, ARP, DNS, Raw, conf
    
    # Try to import get_windows_if_list, but provide a fallback if it's not available
    try:
        from scapy.all import get_windows_if_list
    except ImportError:
        print("get_windows_if_list not available in scapy.all, using custom implementation")
        # Custom implementation for get_windows_if_list if not available in Scapy
        def get_windows_if_list():
            """Custom implementation of get_windows_if_list for Windows"""
            import subprocess
            import re
            import json
            
            # Use Windows CLI to get available interfaces
            try:
                # Use netsh to get interface information
                netsh_output = subprocess.check_output(
                    "netsh interface ip show interfaces",
                    shell=True, 
                    universal_newlines=True
                )
                
                # Parse netsh output to extract interface information
                interfaces = []
                lines = netsh_output.strip().split('\n')
                headers = [h.strip() for h in lines[0].split() if h.strip()]
                
                for line in lines[2:]:  # Skip header and separator
                    if not line.strip():
                        continue
                    
                    # Extract interface name (usually the last part)
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        name = ' '.join(parts[3:])  # Interface name is usually after the first 3 fields
                        idx = parts[0]  # First field is usually the index
                        
                        # Get the IP address for this interface using ipconfig
                        ip_addresses = []
                        try:
                            ipconfig = subprocess.check_output(
                                f"ipconfig /all", 
                                shell=True, 
                                universal_newlines=True
                            )
                            
                            # Find section for this interface and extract IP
                            sections = ipconfig.split('\n\n')
                            for section in sections:
                                if name in section:
                                    ip_match = re.search(r'IPv4 Address[^:]*:\s*([0-9.]+)', section)
                                    if ip_match:
                                        ip_addresses.append(ip_match.group(1))
                        except:
                            pass
                        
                        # Create interface info
                        iface = {
                            'name': name,
                            'description': name,
                            'win_index': idx,
                            'guid': f"Interface_{idx}",  # Use index as a fake GUID
                            'ips': ip_addresses
                        }
                        interfaces.append(iface)
                
                return interfaces
            except Exception as e:
                print(f"Error getting Windows interfaces: {e}")
                # Return at least a minimal localhost interface
                return [{'name': 'Local Interface', 'description': 'Localhost', 'win_index': '1', 'guid': '{00000000-0000-0000-0000-000000000000}', 'ips': ['127.0.0.1']}]
    
    HAS_SCAPY = True
    print("Successfully imported Scapy at module level")
except ImportError as e:
    print(f"ImportError when importing Scapy: {str(e)}")
    HAS_SCAPY = False
    print("WARNING: Failed to import Scapy. Installing scapy with 'pip install scapy' may be required for capture.")
except Exception as e:
    print(f"Unexpected error when importing Scapy: {str(e)}")
    HAS_SCAPY = False
    print("WARNING: Failed to import Scapy due to an unexpected error. This may be a permissions issue.")

# Import sniffer functionality
import sniffer

class SnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Sniffer")
        self.root.geometry("1200x800")
        self.root.minsize(800, 600)
        
        # Debug mode for troubleshooting
        self.debug_mode = True  # Set to True to see debug info
        
        self.capture_in_progress = False
        self.capture_thread = None
        self.stats = None
        self.csv_file = None
        self.all_packets = []  # Initialize the list for storing all packets
        
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
        
        # Create a second toolbar for filters
        filter_frame = ttk.Frame(self.root)
        filter_frame.pack(side=tk.TOP, fill=tk.X)
        
        # Filter options
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT, padx=5, pady=5)
        
        # Protocol filter
        ttk.Label(filter_frame, text="Protocol:").pack(side=tk.LEFT, padx=5, pady=5)
        self.protocol_filter = ttk.Combobox(filter_frame, values=["All", "TCP", "UDP", "ICMP", "ARP", "Other"], width=10)
        self.protocol_filter.current(0)
        self.protocol_filter.pack(side=tk.LEFT, padx=5, pady=5)
        
        # IP filter
        ttk.Label(filter_frame, text="IP:").pack(side=tk.LEFT, padx=5, pady=5)
        self.ip_filter = ttk.Entry(filter_frame, width=15)
        self.ip_filter.pack(side=tk.LEFT, padx=5, pady=5)
        
        # Port filter
        ttk.Label(filter_frame, text="Port:").pack(side=tk.LEFT, padx=5, pady=5)
        self.port_filter = ttk.Entry(filter_frame, width=5)
        self.port_filter.pack(side=tk.LEFT, padx=5, pady=5)
        
        # Apply filter button
        self.filter_button = ttk.Button(filter_frame, text="Apply Filter", command=self._apply_filters)
        self.filter_button.pack(side=tk.LEFT, padx=5, pady=5)
        
        # Clear filter button
        self.clear_filter_button = ttk.Button(filter_frame, text="Clear Filter", command=self._clear_filters)
        self.clear_filter_button.pack(side=tk.LEFT, padx=5, pady=5)
    
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
        
        # Create a paned window for hex view to split content
        hex_pane = ttk.PanedWindow(self.hex_frame, orient=tk.VERTICAL)
        hex_pane.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Top frame for hex display
        hex_top_frame = ttk.Frame(hex_pane)
        hex_pane.add(hex_top_frame, weight=3)
        
        # Hex view text area
        self.hex_text = scrolledtext.ScrolledText(hex_top_frame, font=("Courier", 10))
        self.hex_text.pack(fill=tk.BOTH, expand=True)
        
        # Bottom frame split into technical and layman explanations
        hex_bottom_frame = ttk.Frame(hex_pane)
        hex_pane.add(hex_bottom_frame, weight=2)
        
        # Create horizontal paned window for technical and user-friendly views
        hex_bottom_pane = ttk.PanedWindow(hex_bottom_frame, orient=tk.HORIZONTAL)
        hex_bottom_pane.pack(fill=tk.BOTH, expand=True)
        
        # Technical details frame
        tech_frame = ttk.LabelFrame(hex_bottom_pane, text="Technical Details")
        hex_bottom_pane.add(tech_frame, weight=1)
        
        self.tech_details_text = scrolledtext.ScrolledText(tech_frame, font=("Consolas", 9))
        self.tech_details_text.pack(fill=tk.BOTH, expand=True)
        
        # User-friendly explanation frame
        user_frame = ttk.LabelFrame(hex_bottom_pane, text="Explained Simply")
        hex_bottom_pane.add(user_frame, weight=1)
        
        self.user_friendly_text = scrolledtext.ScrolledText(user_frame, font=("Segoe UI", 10), wrap=tk.WORD)
        self.user_friendly_text.pack(fill=tk.BOTH, expand=True)
        # Enable hyperlink functionality for the user-friendly text
        self.user_friendly_text.tag_configure("hyperlink", foreground="blue", underline=1)
        self.user_friendly_text.bind("<Button-1>", self._handle_hyperlink_click)
    
    def _create_statusbar(self):
        """Create the status bar at the bottom of the window"""
        self.status_frame = ttk.Frame(self.root, relief=tk.SUNKEN, border=1)
        self.status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.status_label = ttk.Label(self.status_frame, text="Ready")
        self.status_label.pack(side=tk.LEFT, padx=5, pady=2)
        
        self.packet_count_label = ttk.Label(self.status_frame, text="Packets: 0")
        self.packet_count_label.pack(side=tk.RIGHT, padx=5, pady=2)
    
    def _log_debug(self, message):
        """Add a message to the debug log"""
        timestamp = time.strftime("%H:%M:%S")
        print(f"DEBUG: [{timestamp}] {message}")
        
        # If debug text widget exists, also log there
        if hasattr(self, 'debug_text'):
            self.debug_text.insert(tk.END, f"[{timestamp}] {message}\n")
            self.debug_text.see(tk.END)  # Scroll to the bottom
    
    def _load_interfaces(self):
        """Load available network interfaces into the dropdown"""
        try:
            interfaces = sniffer.get_available_interfaces()
            self.interface_dropdown['values'] = interfaces
            if interfaces:
                self.interface_dropdown.current(0)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load network interfaces: {str(e)}")
    
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
        """Run the packet capture with the given parameters"""
        try:
            # Create a temporary directory for captures if needed
            os.makedirs(os.path.dirname(output_base) or '.', exist_ok=True)
            
            # Update UI state
            self.status_label.config(text=f"Capturing packets on {interface}...")
            
            # Check if Scapy is available
            if not HAS_SCAPY:
                error_msg = "Scapy is installed but could not be imported properly. This may be due to permissions issues."
                error_details = "Try running this application as administrator or with elevated privileges."
                
                if sys.platform == 'win32':
                    error_details += "\nOn Windows, you may need to run with administrator privileges and have Npcap installed."
                
                self.status_label.config(text="Scapy import failed - permissions issue?")
                messagebox.showerror("Scapy Error", f"{error_msg}\n\n{error_details}")
                
                self.capture_in_progress = False
                self.start_button.config(state=tk.NORMAL)
                self.stop_button.config(state=tk.DISABLED)
                return
                
            # Try importing Scapy again at runtime (sometimes this works when the module level import fails)
            try:
                import scapy.all as scapy_runtime
                if self.debug_mode:
                    self._log_debug("Successfully imported Scapy at runtime")
            except Exception as e:
                if self.debug_mode:
                    self._log_debug(f"Runtime Scapy import failed: {str(e)}")
            
            # Set up for packet capture
            self.capture_start_time = time.time()
            
            # Run capture using sniffer module's standard method
            if self.debug_mode:
                self._log_debug(f"Calling sniffer.capture_network_details with: interface={interface}, packet_count={packet_count}, timeout={timeout}")
            
            # Get the output filenames
            csv_file = f"{output_base}.csv"
            pcap_file = f"{output_base}.pcap"
            
            # Call sniffer.capture_network_details with the correct parameters
            # Inspect the function signature to see what parameters it expects
            try:
                # First try the form with output_csv and output_pcap as parameters
                stats = sniffer.capture_network_details(
                    interface=interface,
                    packet_count=packet_count,
                    timeout=timeout,
                    output_csv=csv_file,
                    output_pcap=pcap_file
                )
                # If successful, this function might return just stats
                self.csv_file = csv_file
            except TypeError:
                # If that fails, try the form with just output_file
                try:
                    stats = sniffer.capture_network_details(
                        interface=interface,
                        packet_count=packet_count,
                        timeout=timeout,
                        output_file=csv_file
                    )
                    self.csv_file = csv_file
                except TypeError:
                    # If that also fails, try with just the basic parameters
                    stats = sniffer.capture_network_details(
                        interface=interface,
                        packet_count=packet_count,
                        timeout=timeout
                    )
                    # In this case, we may need to determine csv_file from the return value
                    self.csv_file = getattr(stats, 'csv_file', csv_file)
            
            # Store results
            self.stats = stats
            
            # Check if the CSV file exists and log its path and contents
            if os.path.exists(self.csv_file):
                if self.debug_mode:
                    self._log_debug(f"CSV file exists at: {self.csv_file}")
                    with open(self.csv_file, 'r') as f:
                        line_count = sum(1 for _ in f)
                    self._log_debug(f"CSV file contains {line_count} lines (including header)")
            else:
                if self.debug_mode:
                    self._log_debug(f"CSV file not found at: {self.csv_file}")
                # Look for csv files in the output directory
                csv_files = [f for f in os.listdir(os.path.dirname(output_base) or '.') if f.endswith('.csv')]
                if csv_files:
                    if self.debug_mode:
                        self._log_debug(f"Found CSV files in directory: {csv_files}")
                    # Use the most recent csv file
                    most_recent = max(csv_files, key=lambda f: os.path.getmtime(os.path.join(os.path.dirname(output_base) or '.', f)))
                    self.csv_file = os.path.join(os.path.dirname(output_base) or '.', most_recent)
                    if self.debug_mode:
                        self._log_debug(f"Using most recent CSV file: {self.csv_file}")
            
            # Create a manual lookup for the CSV file based on terminal output
            # The sniffer module might print the output file path to the terminal
            if self.debug_mode:
                self._log_debug("Looking for CSV file in working directory")
                all_files = os.listdir('.')
                csv_files = [f for f in all_files if f.endswith('.csv')]
                if csv_files:
                    self._log_debug(f"Found CSV files in working directory: {csv_files}")
                
                capture_dir = os.path.join('.', 'capture')
                if os.path.exists(capture_dir) and os.path.isdir(capture_dir):
                    capture_files = os.listdir(capture_dir)
                    csv_capture_files = [os.path.join(capture_dir, f) for f in capture_files if f.endswith('.csv')]
                    if csv_capture_files:
                        self._log_debug(f"Found CSV files in capture directory: {csv_capture_files}")
                        # Use the most recent csv file from the capture directory
                        most_recent = max(csv_capture_files, key=os.path.getmtime)
                        self.csv_file = most_recent
                        self._log_debug(f"Using most recent CSV file from capture directory: {self.csv_file}")
            
            # Update the UI after capture
            self._update_capture_status()
            
            if self.debug_mode:
                self._log_debug(f"Capture completed: {getattr(stats, 'total_packets', 0)} packets")
                
        except Exception as e:
            error_message = str(e)
            if "permission" in error_message.lower() or "access" in error_message.lower():
                error_message = "Permission denied. Try running as administrator."
                if sys.platform == 'win32':
                    error_message += "\nOn Windows, you need administrator privileges and Npcap installed."
            
            self.status_label.config(text=f"Error during capture: {error_message}")
            self.capture_in_progress = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            messagebox.showerror("Capture Error", f"Failed to capture packets: {error_message}")
            
            if self.debug_mode:
                self._log_debug(f"Capture error: {str(e)}")
                import traceback
                self._log_debug(traceback.format_exc())

    def _update_capture_status(self):
        """Update the UI after capture is complete"""
        try:
            if self.stats:
                # Check if stats is a dictionary or an object
                if isinstance(self.stats, dict):
                    total_packets = self.stats.get('total_packets', 0)
                else:
                    # Try to access as an attribute
                    total_packets = getattr(self.stats, 'total_packets', 0)
                
                # Load the packets from csv if it exists
                if self.csv_file and os.path.exists(self.csv_file):
                    self._load_packets_from_csv(self.csv_file)
                    
                    # Create stats from the packet list if they don't exist
                    if total_packets == 0 and self.all_packets:
                        total_packets = len(self.all_packets)
                        if isinstance(self.stats, dict):
                            self.stats['total_packets'] = total_packets
                
                # Update analytics
                self._display_capture_results()
                
                # Update status with packet count
                self.status_label.config(text=f"Capture complete: {total_packets} packets captured")
            else:
                # If no stats but we have packets, create stats from the packet list
                if self.all_packets:
                    total_packets = len(self.all_packets)
                    if self.debug_mode:
                        self._log_debug(f"Creating stats from {total_packets} loaded packets")
                    self._display_capture_results()
                    self.status_label.config(text=f"Capture complete: {total_packets} packets captured")
                else:
                    self.status_label.config(text="Capture complete: No stats available")
        except Exception as e:
            if self.debug_mode:
                self._log_debug(f"Error in _update_capture_status: {str(e)}")
                import traceback
                self._log_debug(traceback.format_exc())
            self.status_label.config(text="Capture complete")
        
        # Reset UI state
        self.capture_in_progress = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def _on_capture_complete(self):
        """Called when the capture is complete."""
        self.status_var.set(f"Capture complete: {len(self.all_packets)} packets captured")
        self.capture_btn.config(text="Start Capture", command=self._run_capture)
        
        # Update the filter dropdown with available protocols
        protocols = sorted(list(set(p.get('protocol', 'Unknown') for p in self.all_packets if p.get('protocol'))))
        # Add "All" and "Other" options
        self.protocol_filter_combo['values'] = ["All"] + protocols + ["Other"]
        self.protocol_filter_combo.current(0)
        
        # Update visualizations with final data
        self._update_visualizations()

    def _stop_capture(self):
        """Stop the current capture."""
        if hasattr(self, 'stop_capture_event'):
            self.stop_capture_event.set()
        
        self.status_var.set("Stopping capture...")
        self.capture_btn.config(state=tk.DISABLED)
        
        # Process any remaining packets in the queue
        self._process_packet_queue()

    def _apply_filters(self):
        """Apply filters to the packet display"""
        # Get filter values
        protocol_filter = self.protocol_filter.get()
        ip_filter = self.ip_filter.get().strip()
        port_filter = self.port_filter.get().strip()
        
        # Clear current display
        self.packet_tree.delete(*self.packet_tree.get_children())
        
        # Apply filters
        filtered_packets = []
        for packet in self.all_packets:
            # Protocol filter
            if protocol_filter != "All" and packet['protocol'].upper() != protocol_filter.upper():
                if protocol_filter == "Other" and packet['protocol'].upper() in ["TCP", "UDP", "ICMP", "ARP"]:
                    continue
                elif protocol_filter != "Other":
                    continue
            
            # IP filter
            if ip_filter and ip_filter not in packet['src_ip'] and ip_filter not in packet['dst_ip']:
                continue
            
            # Port filter
            if port_filter and port_filter not in packet['src_port'] and port_filter not in packet['dst_port']:
                continue
            
            # Packet passed all filters
            filtered_packets.append(packet)
        
        # Display filtered packets
        for i, packet in enumerate(filtered_packets, 1):
            protocol_tag = self._get_protocol_tag(packet['protocol'])
            
            self.packet_tree.insert("", tk.END, values=(
                packet['id'],
                packet['timestamp'],
                packet['src_mac'],
                packet['dst_mac'],
                packet['src_ip'],
                packet['dst_ip'],
                packet['src_port'],
                packet['dst_port'],
                packet['protocol'],
                packet['length'],
                packet['ttl'],
                packet['tcp_flags'],
                packet['tcp_window'],
                packet['packet_direction'],
                packet['info']
            ), tags=(protocol_tag,))
        
        # Update status
        self.status_label.config(text=f"Filtered: {len(filtered_packets)} packets")

    def _clear_filters(self):
        """Clear all filters and show all packets"""
        # Reset filter values
        self.protocol_filter.current(0)
        self.ip_filter.delete(0, tk.END)
        self.port_filter.delete(0, tk.END)
        
        # Clear current display
        self.packet_tree.delete(*self.packet_tree.get_children())
        
        # Show all packets
        for packet in self.all_packets:
            protocol_tag = self._get_protocol_tag(packet['protocol'])
            
            self.packet_tree.insert("", tk.END, values=(
                packet['id'],
                packet['timestamp'],
                packet['src_mac'],
                packet['dst_mac'],
                packet['src_ip'],
                packet['dst_ip'],
                packet['src_port'],
                packet['dst_port'],
                packet['protocol'],
                packet['length'],
                packet['ttl'],
                packet['tcp_flags'],
                packet['tcp_window'],
                packet['packet_direction'],
                packet['info']
            ), tags=(protocol_tag,))
        
        # Update status
        self.status_label.config(text=f"Showing all {len(self.all_packets)} packets")

    def _display_hex_view(self):
        """Display hexadecimal view of the selected packet in Wireshark style"""
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
                self.tech_details_text.delete(1.0, tk.END)
                self.user_friendly_text.delete(1.0, tk.END)
                return
            
            # Debug: log the keys in the packet to help diagnose
            if self.debug_mode:
                self._log_debug(f"Packet keys: {packet.keys()}")
                if 'raw' in packet:
                    self._log_debug(f"Raw data type: {type(packet['raw'])}, content preview: {str(packet['raw'])[:100]}")
                else:
                    self._log_debug("No 'raw' key found in the packet")
            
            # Set color scheme based on theme
            if self.current_theme == "dark":
                self.hex_text.config(background="#0f0f0f", foreground="#ffffff")
                offset_color = "#66cdaa"    # Light seafoam for offsets
                hex_color = "#ffffff"       # White for hex values
                ascii_color = "#add8e6"     # Light blue for ASCII
                separator_color = "#808080" # Gray for separators
                highlight_color = "#3a3a3a" # Dark gray for highlighting
                
                self.tech_details_text.config(background="#0f0f0f", foreground="#ffffff")
                self.user_friendly_text.config(background="#0f0f0f", foreground="#ffffff")
                link_color = "#00ffff"      # Cyan for hyperlinks in dark mode
            else:
                self.hex_text.config(background="#ffffff", foreground="#000000")
                offset_color = "#0000a0"    # Dark blue for offsets
                hex_color = "#000000"       # Black for hex values
                ascii_color = "#8b0000"     # Dark red for ASCII
                separator_color = "#a9a9a9" # Dark gray for separators
                highlight_color = "#f0f0f0" # Light gray for highlighting
                
                self.tech_details_text.config(background="#ffffff", foreground="#000000")
                self.user_friendly_text.config(background="#ffffff", foreground="#000000")
                link_color = "#0000ff"      # Blue for hyperlinks in light mode
            
            # Configure text tags
            self.hex_text.tag_configure("offset", foreground=offset_color)
            self.hex_text.tag_configure("hex", foreground=hex_color)
            self.hex_text.tag_configure("ascii", foreground=ascii_color)
            self.hex_text.tag_configure("separator", foreground=separator_color)
            self.hex_text.tag_configure("highlight", background=highlight_color)
            
            # Configure hyperlink tag
            self.user_friendly_text.tag_configure("hyperlink", foreground=link_color, underline=1)
            
            # Clear existing content and set a fixed-width font
            self.hex_text.delete(1.0, tk.END)
            self.hex_text.config(font=("Courier New", 10))
            
            # Clear technical and user-friendly text areas
            self.tech_details_text.delete(1.0, tk.END)
            self.user_friendly_text.delete(1.0, tk.END)
            
            # Get raw data from different possible sources to handle various packet formats
            raw_data = None
            
            # Try multiple ways to get raw data
            if 'raw' in packet and packet['raw']:
                raw_data = packet['raw']
            elif 'raw_data' in packet and packet['raw_data']:
                raw_data = packet['raw_data']
            elif 'bytes' in packet and packet['bytes']:
                raw_data = packet['bytes']
            elif 'protocol' in packet:
                # Generate dummy data based on packet headers for common protocols
                dummy_data = []
                protocol = packet['protocol'].upper()
                
                # Generate a basic dummy header based on protocol
                if protocol == 'TCP':
                    # Create TCP-like header with SYN/ACK flags, ports, etc.
                    src_ip = packet.get('src_ip', '192.168.1.1')
                    dst_ip = packet.get('dst_ip', '192.168.1.2')
                    src_port = packet.get('src_port', '80')
                    dst_port = packet.get('dst_port', '12345')
                    tcp_flags = packet.get('tcp_flags', 'ACK')
                    
                    # IP version 4, header length 5, TOS 0
                    dummy_data.append(0x45)  # Version 4, header length 5
                    dummy_data.append(0x00)  # TOS
                    dummy_data.append(0x00)  # Total length high byte
                    dummy_data.append(0x28)  # Total length low byte (40 bytes)
                    
                    # ID, flags, fragment offset
                    dummy_data.extend([0x00, 0x01, 0x40, 0x00])
                    
                    # TTL, Protocol (TCP=6), Header checksum
                    ttl = int(packet.get('ttl', 64))
                    dummy_data.extend([ttl, 0x06, 0x00, 0x00])
                    
                    # Source IP (convert to bytes)
                    try:
                        src_ip_parts = [int(p) for p in src_ip.split('.')]
                        dummy_data.extend(src_ip_parts[:4])
                    except:
                        dummy_data.extend([192, 168, 1, 1])
                    
                    # Destination IP (convert to bytes)
                    try:
                        dst_ip_parts = [int(p) for p in dst_ip.split('.')]
                        dummy_data.extend(dst_ip_parts[:4])
                    except:
                        dummy_data.extend([192, 168, 1, 2])
                    
                    # Source and destination ports
                    try:
                        src_port_int = int(src_port)
                        dummy_data.append((src_port_int >> 8) & 0xFF)
                        dummy_data.append(src_port_int & 0xFF)
                    except:
                        dummy_data.extend([0x00, 0x50])  # Default to port 80
                        
                    try:
                        dst_port_int = int(dst_port)
                        dummy_data.append((dst_port_int >> 8) & 0xFF)
                        dummy_data.append(dst_port_int & 0xFF)
                    except:
                        dummy_data.extend([0x30, 0x39])  # Default to port 12345
                    
                    # Sequence and ack numbers
                    dummy_data.extend([0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01])
                    
                    # TCP header length and flags
                    dummy_data.append(0x50)  # Header length 5 * 4 = 20 bytes
                    if 'SYN' in tcp_flags:
                        dummy_data.append(0x02)  # SYN flag
                    elif 'FIN' in tcp_flags:
                        dummy_data.append(0x01)  # FIN flag
                    else:
                        dummy_data.append(0x10)  # ACK flag
                    
                    # Window size, checksum, urgent pointer
                    dummy_data.extend([0x72, 0x10, 0x00, 0x00, 0x00, 0x00])
                    
                    # Add some data bytes for padding
                    dummy_data.extend([0x44, 0x41, 0x54, 0x41])  # "DATA" in ASCII
                
                elif protocol == 'UDP':
                    # Create UDP-like header
                    src_ip = packet.get('src_ip', '192.168.1.1')
                    dst_ip = packet.get('dst_ip', '192.168.1.2')
                    src_port = packet.get('src_port', '53')
                    dst_port = packet.get('dst_port', '12345')
                    
                    # IP header
                    dummy_data.append(0x45)  # Version 4, header length 5
                    dummy_data.append(0x00)  # TOS
                    dummy_data.append(0x00)  # Total length high byte
                    dummy_data.append(0x21)  # Total length low byte
                    
                    # Rest of IP header
                    dummy_data.extend([0x00, 0x01, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00])
                    
                    # Source and destination IP
                    try:
                        src_ip_parts = [int(p) for p in src_ip.split('.')]
                        dummy_data.extend(src_ip_parts[:4])
                    except:
                        dummy_data.extend([192, 168, 1, 1])
                    
                    try:
                        dst_ip_parts = [int(p) for p in dst_ip.split('.')]
                        dummy_data.extend(dst_ip_parts[:4])
                    except:
                        dummy_data.extend([192, 168, 1, 2])
                    
                    # UDP header
                    try:
                        src_port_int = int(src_port)
                        dummy_data.append((src_port_int >> 8) & 0xFF)
                        dummy_data.append(src_port_int & 0xFF)
                    except:
                        dummy_data.extend([0x00, 0x35])  # Default to port 53
                        
                    try:
                        dst_port_int = int(dst_port)
                        dummy_data.append((dst_port_int >> 8) & 0xFF)
                        dummy_data.append(dst_port_int & 0xFF)
                    except:
                        dummy_data.extend([0x30, 0x39])  # Default to port 12345
                    
                    # Length and checksum
                    dummy_data.extend([0x00, 0x0d, 0x00, 0x00])
                    
                    # Data
                    dummy_data.extend([0x44, 0x41, 0x54, 0x41])  # "DATA" in ASCII
                
                elif protocol == 'ICMP':
                    # Create ICMP-like header
                    src_ip = packet.get('src_ip', '192.168.1.1')
                    dst_ip = packet.get('dst_ip', '192.168.1.2')
                    icmp_type = packet.get('icmp_type', '8')  # Echo request
                    
                    # IP header
                    dummy_data.append(0x45)  # Version 4, header length 5
                    dummy_data.append(0x00)  # TOS
                    dummy_data.append(0x00)  # Total length high byte
                    dummy_data.append(0x3c)  # Total length low byte
                    
                    # Rest of IP header
                    dummy_data.extend([0x00, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00])
                    
                    # Source and destination IP
                    try:
                        src_ip_parts = [int(p) for p in src_ip.split('.')]
                        dummy_data.extend(src_ip_parts[:4])
                    except:
                        dummy_data.extend([192, 168, 1, 1])
                    
                    try:
                        dst_ip_parts = [int(p) for p in dst_ip.split('.')]
                        dummy_data.extend(dst_ip_parts[:4])
                    except:
                        dummy_data.extend([192, 168, 1, 2])
                    
                    # ICMP header
                    try:
                        icmp_type_int = int(icmp_type)
                        dummy_data.append(icmp_type_int)
                    except:
                        dummy_data.append(0x08)  # Echo request
                    
                    dummy_data.append(0x00)  # Code
                    dummy_data.extend([0x00, 0x00])  # Checksum
                    dummy_data.extend([0x00, 0x01, 0x00, 0x01])  # Identifier and sequence
                    
                    # Data
                    for i in range(32):
                        dummy_data.append((i % 26) + 97)  # Data pattern (a-z)
                
                else:
                    # Generic dummy data with header pattern
                    for i in range(64):
                        dummy_data.append(i)
                
                raw_data = dummy_data
            
            # Generate sample data if nothing is available
            if not raw_data:
                # Create sample data that shows packet structure
                if self.debug_mode:
                    self._log_debug("No raw data available, generating sample data")
                
                # Create a sample of 128 bytes with a recognizable pattern
                raw_data = []
                
                # Ethernet header (14 bytes)
                raw_data.extend([0xff, 0xff, 0xff, 0xff, 0xff, 0xff])  # Destination MAC
                raw_data.extend([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])  # Source MAC
                raw_data.extend([0x08, 0x00])  # EtherType (IPv4)
                
                # IP header (20 bytes)
                raw_data.append(0x45)  # Version 4, header length 5
                raw_data.append(0x00)  # TOS
                raw_data.extend([0x00, 0x73])  # Total length
                raw_data.extend([0x00, 0x00])  # Identification
                raw_data.extend([0x40, 0x00])  # Flags, fragment offset
                raw_data.append(0x40)  # TTL
                raw_data.append(0x06)  # Protocol (TCP)
                raw_data.extend([0x00, 0x00])  # Header checksum
                raw_data.extend([192, 168, 1, 1])  # Source IP
                raw_data.extend([192, 168, 1, 2])  # Destination IP
                
                # TCP header (20 bytes)
                raw_data.extend([0x00, 0x50])  # Source port (80)
                raw_data.extend([0x12, 0x34])  # Destination port (4660)
                raw_data.extend([0x00, 0x00, 0x00, 0x01])  # Sequence number
                raw_data.extend([0x00, 0x00, 0x00, 0x00])  # Acknowledgment number
                raw_data.append(0x50)  # Data offset, reserved
                raw_data.append(0x18)  # Flags (PSH, ACK)
                raw_data.extend([0x01, 0x00])  # Window size
                raw_data.extend([0x00, 0x00])  # Checksum
                raw_data.extend([0x00, 0x00])  # Urgent pointer
                
                # Payload - sample HTTP request
                http_request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
                for c in http_request:
                    raw_data.append(ord(c))
                
                # Pad to at least 64 bytes
                while len(raw_data) < 64:
                    raw_data.append(0x00)
            
            if not raw_data:
                self.hex_text.insert(tk.END, "No raw data available for this packet\n")
                self.hex_text.insert(tk.END, "This is likely because the packet was generated without raw data capture enabled.\n")
                self.hex_text.insert(tk.END, "Try capturing new packets with the latest version of the application.")
                return
            
            # Convert to bytes if needed
            try:
                if isinstance(raw_data, list):
                    # Use the list directly
                    raw_bytes = raw_data
                elif isinstance(raw_data, str):
                    # Try to parse the string
                    if raw_data.startswith('[') and raw_data.endswith(']'):
                        # It might be a string representation of a list
                        try:
                            import ast
                            raw_bytes = ast.literal_eval(raw_data)
                            if not isinstance(raw_bytes, list):
                                raw_bytes = [ord(c) for c in raw_data]
                        except:
                            raw_bytes = [ord(c) for c in raw_data]
                    else:
                        # Treat as a regular string
                        raw_bytes = [ord(c) for c in raw_data]
                elif hasattr(raw_data, '__iter__') and not isinstance(raw_data, (str, dict)):
                    # It's some other iterable, convert to list
                    raw_bytes = list(raw_data)
                else:
                    # Unknown format, try string representation
                    raw_bytes = [ord(c) for c in str(raw_data)]
                    
                if not raw_bytes:
                    self.hex_text.insert(tk.END, "Unable to parse raw data for this packet")
                    return
                
                # Add a header row (Wireshark-style)
                header = "    "
                for i in range(16):
                    header += f"{i:02x} "
                    if i == 7:
                        header += " "
                header += "  "
                ascii_header = "0123456789abcdef"
                self.hex_text.insert(tk.END, f"{header}|{ascii_header}|\n", "separator")
                self.hex_text.insert(tk.END, f"{'-'*70}\n", "separator")
                
                # Display the hex dump in 16-byte rows
                offset = 0
                while offset < len(raw_bytes):
                    # Get current line bytes (up to 16)
                    line_bytes = raw_bytes[offset:offset+16]
                    
                    # Format the line with offset
                    line_offset = f"{offset:04x}  "
                    self.hex_text.insert(tk.END, line_offset, "offset")
                    
                    # Format hex display with middle separator
                    hex_display = ""
                    for i, b in enumerate(line_bytes):
                        if isinstance(b, int):
                            hex_display += f"{b:02x} "
                        else:
                            try:
                                hex_display += f"{ord(b):02x} "
                            except:
                                hex_display += "?? "
                        
                        # Add extra space after 8 bytes
                        if i == 7:
                            hex_display += " "
                    
                    # Pad if less than 16 bytes
                    padding = 16 - len(line_bytes)
                    hex_display += "   " * padding
                    if padding > 8:
                        hex_display += " "  # Extra space for the middle divider
                        
                    self.hex_text.insert(tk.END, hex_display, "hex")
                    
                    # Add separator between hex and ASCII
                    self.hex_text.insert(tk.END, " |", "separator")
                    
                    # Format ASCII display
                    for b in line_bytes:
                        if isinstance(b, int) and 32 <= b <= 126:
                            char = chr(b)
                            self.hex_text.insert(tk.END, char, "ascii")
                        elif not isinstance(b, int) and isinstance(b, str) and len(b) == 1:
                            ord_val = ord(b)
                            if 32 <= ord_val <= 126:
                                self.hex_text.insert(tk.END, b, "ascii")
                            else:
                                self.hex_text.insert(tk.END, ".", "ascii")
                        else:
                            self.hex_text.insert(tk.END, ".", "ascii")
                    
                    # Add padding for incomplete lines
                    if len(line_bytes) < 16:
                        self.hex_text.insert(tk.END, " " * (16 - len(line_bytes)), "ascii")
                    
                    # Close ASCII section
                    self.hex_text.insert(tk.END, "|\n", "separator")
                    
                    # Move to next line
                    offset += 16
                    
            except Exception as e:
                self.hex_text.insert(tk.END, f"Error parsing raw data: {str(e)}")
                if self.debug_mode:
                    self._log_debug(f"Error parsing packet raw data: {str(e)}")
                    import traceback
                    self._log_debug(traceback.format_exc())
            
            # After displaying the hex dump, add technical details and user-friendly explanations
            self._display_technical_details(packet, raw_bytes)
            self._display_user_friendly_explanation(packet, raw_bytes)
            
        except Exception as e:
            self.hex_text.delete(1.0, tk.END)
            self.hex_text.insert(tk.END, f"Error displaying hex view: {str(e)}")
            self.tech_details_text.delete(1.0, tk.END)
            self.user_friendly_text.delete(1.0, tk.END)
            if self.debug_mode:
                import traceback
                self._log_debug(f"Error in _display_hex_view: {str(e)}")
                self._log_debug(traceback.format_exc())
                
    def _display_technical_details(self, packet, raw_bytes):
        """Display detailed technical information about the packet"""
        protocol = packet.get('protocol', '').upper()
        
        details = []
        details.append("---- PACKET TECHNICAL DETAILS ----\n")
        
        # Header info
        details.append(f"Packet ID: {packet.get('id', 'N/A')}")
        details.append(f"Timestamp: {packet.get('timestamp', 'N/A')}")
        details.append(f"Protocol: {protocol}")
        details.append(f"Length: {packet.get('length', 'N/A')} bytes")
        details.append("")
        
        # MAC Layer details
        details.append("=== LAYER 2 (Data Link) ===")
        details.append(f"Source MAC: {packet.get('src_mac', 'N/A')}")
        details.append(f"Destination MAC: {packet.get('dst_mac', 'N/A')}")
        if packet.get('eth_type'):
            details.append(f"EtherType: 0x{packet.get('eth_type'):04x}")
        details.append("")
        
        # IP Layer details (if applicable)
        if packet.get('src_ip') or packet.get('dst_ip'):
            details.append("=== LAYER 3 (Network) ===")
            details.append(f"Source IP: {packet.get('src_ip', 'N/A')}")
            details.append(f"Destination IP: {packet.get('dst_ip', 'N/A')}")
            details.append(f"TTL: {packet.get('ttl', 'N/A')}")
            details.append(f"IP Flags: {packet.get('ip_flags', 'N/A')}")
            details.append("")
        
        # Transport Layer details
        if protocol in ['TCP', 'UDP', 'ICMP']:
            details.append("=== LAYER 4 (Transport) ===")
            if protocol == 'TCP':
                details.append(f"Source Port: {packet.get('src_port', 'N/A')}")
                details.append(f"Destination Port: {packet.get('dst_port', 'N/A')}")
                details.append(f"TCP Flags: {packet.get('tcp_flags', 'N/A')}")
                details.append(f"Sequence Number: {packet.get('tcp_seq', 'N/A')}")
                details.append(f"Acknowledgment Number: {packet.get('tcp_ack', 'N/A')}")
                details.append(f"Window Size: {packet.get('tcp_window', 'N/A')}")
            elif protocol == 'UDP':
                details.append(f"Source Port: {packet.get('src_port', 'N/A')}")
                details.append(f"Destination Port: {packet.get('dst_port', 'N/A')}")
                details.append(f"UDP Length: {packet.get('udp_length', 'N/A')}")
            elif protocol == 'ICMP':
                details.append(f"ICMP Type: {packet.get('icmp_type', 'N/A')}")
                details.append(f"ICMP Code: {packet.get('icmp_code', 'N/A')}")
            details.append("")
        
        # Application Layer details for known protocols
        if protocol in ['HTTP', 'DNS', 'DHCP', 'TLS', 'SSH']:
            details.append("=== LAYER 7 (Application) ===")
            if protocol == 'HTTP':
                details.append(f"HTTP Method: {packet.get('http_method', 'N/A')}")
                details.append(f"HTTP Host: {packet.get('http_host', 'N/A')}")
                details.append(f"HTTP Path: {packet.get('http_path', 'N/A')}")
                details.append(f"HTTP Version: {packet.get('http_version', 'N/A')}")
            elif protocol == 'DNS':
                details.append(f"DNS Query: {packet.get('dns_query', 'N/A')}")
                details.append(f"DNS Query Type: {packet.get('dns_qtype', 'N/A')}")
                details.append(f"DNS Response: {packet.get('dns_response', 'N/A')}")
            details.append("")
        
        # Packet binary structure
        if raw_bytes and len(raw_bytes) > 0:
            details.append("=== PACKET STRUCTURE ANALYSIS ===")
            
            # Identify Ethernet header
            if len(raw_bytes) >= 14:
                details.append("Ethernet Header (first 14 bytes):")
                details.append(f"  Destination MAC: {':'.join(f'{b:02x}' for b in raw_bytes[0:6])}")
                details.append(f"  Source MAC: {':'.join(f'{b:02x}' for b in raw_bytes[6:12])}")
                details.append(f"  EtherType: 0x{raw_bytes[12]:02x}{raw_bytes[13]:02x}")
                
                # Identify IP header if present
                if raw_bytes[12] == 0x08 and raw_bytes[13] == 0x00 and len(raw_bytes) >= 34:
                    ip_header_len = (raw_bytes[14] & 0x0F) * 4
                    details.append("")
                    details.append(f"IPv4 Header (bytes 14-{14+ip_header_len-1}):")
                    details.append(f"  Version: {raw_bytes[14] >> 4}")
                    details.append(f"  IHL: {raw_bytes[14] & 0x0F} ({ip_header_len} bytes)")
                    details.append(f"  DSCP/ECN: 0x{raw_bytes[15]:02x}")
                    details.append(f"  Total Length: {(raw_bytes[16] << 8) + raw_bytes[17]} bytes")
                    details.append(f"  Identification: 0x{raw_bytes[18]:02x}{raw_bytes[19]:02x}")
                    
                    flags = raw_bytes[20] >> 5
                    flag_details = []
                    if flags & 0x01:
                        flag_details.append("Reserved (must be 0)")
                    if flags & 0x02:
                        flag_details.append("Don't Fragment")
                    if flags & 0x04:
                        flag_details.append("More Fragments")
                    
                    details.append(f"  Flags: {flags} ({', '.join(flag_details) if flag_details else 'None'})")
                    details.append(f"  Fragment Offset: {((raw_bytes[20] & 0x1F) << 8) + raw_bytes[21]}")
                    details.append(f"  TTL: {raw_bytes[22]}")
                    
                    protocols = {1: "ICMP", 6: "TCP", 17: "UDP", 2: "IGMP"}
                    protocol_num = raw_bytes[23]
                    protocol_name = protocols.get(protocol_num, f"Unknown ({protocol_num})")
                    details.append(f"  Protocol: {protocol_name} ({protocol_num})")
                    
                    details.append(f"  Header Checksum: 0x{raw_bytes[24]:02x}{raw_bytes[25]:02x}")
                    details.append(f"  Source IP: {'.'.join(str(b) for b in raw_bytes[26:30])}")
                    details.append(f"  Destination IP: {'.'.join(str(b) for b in raw_bytes[30:34])}")
                    
                    # Additional info about transport layer if we can identify it
                    transport_offset = 14 + ip_header_len
                    
                    if protocol_num == 6 and len(raw_bytes) >= transport_offset + 20:  # TCP
                        tcp_header_len = ((raw_bytes[transport_offset + 12] >> 4) & 0x0F) * 4
                        details.append("")
                        details.append(f"TCP Header (bytes {transport_offset}-{transport_offset+tcp_header_len-1}):")
                        details.append(f"  Source Port: {(raw_bytes[transport_offset] << 8) + raw_bytes[transport_offset+1]}")
                        details.append(f"  Destination Port: {(raw_bytes[transport_offset+2] << 8) + raw_bytes[transport_offset+3]}")
                        details.append(f"  Sequence Number: 0x{raw_bytes[transport_offset+4]:02x}{raw_bytes[transport_offset+5]:02x}{raw_bytes[transport_offset+6]:02x}{raw_bytes[transport_offset+7]:02x}")
                        details.append(f"  Acknowledgment Number: 0x{raw_bytes[transport_offset+8]:02x}{raw_bytes[transport_offset+9]:02x}{raw_bytes[transport_offset+10]:02x}{raw_bytes[transport_offset+11]:02x}")
                        
                        # TCP flags
                        tcp_flags = raw_bytes[transport_offset+13]
                        flag_details = []
                        if tcp_flags & 0x01: flag_details.append("FIN")
                        if tcp_flags & 0x02: flag_details.append("SYN")
                        if tcp_flags & 0x04: flag_details.append("RST")
                        if tcp_flags & 0x08: flag_details.append("PSH")
                        if tcp_flags & 0x10: flag_details.append("ACK")
                        if tcp_flags & 0x20: flag_details.append("URG")
                        if tcp_flags & 0x40: flag_details.append("ECE")
                        if tcp_flags & 0x80: flag_details.append("CWR")
                        
                        details.append(f"  Data Offset: {(raw_bytes[transport_offset+12] >> 4) & 0x0F} ({tcp_header_len} bytes)")
                        details.append(f"  Flags: 0x{tcp_flags:02x} ({', '.join(flag_details) if flag_details else 'None'})")
                        details.append(f"  Window Size: {(raw_bytes[transport_offset+14] << 8) + raw_bytes[transport_offset+15]}")
                        details.append(f"  Checksum: 0x{raw_bytes[transport_offset+16]:02x}{raw_bytes[transport_offset+17]:02x}")
                        details.append(f"  Urgent Pointer: 0x{raw_bytes[transport_offset+18]:02x}{raw_bytes[transport_offset+19]:02x}")
                        
                        # HTTP detection (very basic)
                        payload_offset = transport_offset + tcp_header_len
                        if payload_offset < len(raw_bytes):
                            payload = raw_bytes[payload_offset:]
                            payload_text = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in payload)
                            
                            if any(method in payload_text for method in ["GET ", "POST ", "HTTP/"]):
                                details.append("")
                                details.append(f"HTTP Data Detected (bytes {payload_offset}+):")
                                details.append(f"  First line: {payload_text.split('\\r\\n')[0] if '\\r\\n' in payload_text else payload_text[:50]+'...'}")
                    
                    elif protocol_num == 17 and len(raw_bytes) >= transport_offset + 8:  # UDP
                        details.append("")
                        details.append(f"UDP Header (bytes {transport_offset}-{transport_offset+7}):")
                        details.append(f"  Source Port: {(raw_bytes[transport_offset] << 8) + raw_bytes[transport_offset+1]}")
                        details.append(f"  Destination Port: {(raw_bytes[transport_offset+2] << 8) + raw_bytes[transport_offset+3]}")
                        details.append(f"  Length: {(raw_bytes[transport_offset+4] << 8) + raw_bytes[transport_offset+5]} bytes")
                        details.append(f"  Checksum: 0x{raw_bytes[transport_offset+6]:02x}{raw_bytes[transport_offset+7]:02x}")
                        
                        # DNS detection (port 53)
                        src_port = (raw_bytes[transport_offset] << 8) + raw_bytes[transport_offset+1]
                        dst_port = (raw_bytes[transport_offset+2] << 8) + raw_bytes[transport_offset+3]
                        if src_port == 53 or dst_port == 53:
                            details.append("")
                            details.append(f"DNS Data Detected (Port 53):")
        
        # Join all details and display
        self.tech_details_text.insert(tk.END, "\n".join(details))
    
    def _display_user_friendly_explanation(self, packet, raw_bytes):
        """Display user-friendly explanations of the packet with links to more information"""
        protocol = packet.get('protocol', '').upper()
        
        explanations = []
        explanations.append(" COMPLETE PACKET EXPLANATION \n")
        
        # Basic packet info in user-friendly terms
        explanations.append(f"📦 This is packet #{packet.get('id', 'N/A')} captured at {packet.get('timestamp', 'N/A')}")
        explanations.append(f"📊 Size: {packet.get('length', 'N/A')} bytes")
        
        # Direction with visual indicator
        direction = packet.get('packet_direction', '')
        if direction == 'Inbound':
            explanations.append(f"📥 Direction: {direction} - This packet is coming into your device")
        elif direction == 'Outbound':
            explanations.append(f"📤 Direction: {direction} - This packet is going out from your device")
        else:
            explanations.append(f"🔄 Direction: {direction}")
        
        # Protocol explanation - expanded with more details
        explanations.append("\n🌐 PACKET TYPE & PURPOSE")
        if protocol == 'TCP':
            explanations.append("This is a TCP (Transmission Control Protocol) packet.")
            explanations.append("TCP provides reliable, ordered delivery of data between applications.")
            explanations.append("It's commonly used for:")
            explanations.append("• Web browsing (HTTP/HTTPS)")
            explanations.append("• Email (SMTP, IMAP, POP3)")
            explanations.append("• File transfers (FTP, SFTP)")
            explanations.append("• Remote access (SSH, Telnet)")
            
            # TCP flags explanation in simple terms
            if packet.get('tcp_flags'):
                flags = packet.get('tcp_flags')
                explanations.append("\n🚩 TCP Flags - What is this packet doing?")
                
                if 'SYN' in flags and 'ACK' in flags:
                    explanations.append("This packet is acknowledging a connection request (SYN-ACK). This is part of the 'handshake' that starts a connection.")
                elif 'SYN' in flags:
                    explanations.append("This packet is requesting to start a new connection (SYN). This is the first step in establishing communication.")
                elif 'FIN' in flags and 'ACK' in flags:
                    explanations.append("This packet is gracefully ending a connection while acknowledging data (FIN-ACK).")
                elif 'FIN' in flags:
                    explanations.append("This packet is requesting to end the connection (FIN). This is the start of a graceful shutdown.")
                elif 'RST' in flags:
                    explanations.append("⚠️ This packet is forcibly terminating a connection (RST). This usually indicates an error or unexpected behavior.")
                elif 'ACK' in flags and 'PSH' in flags:
                    explanations.append("This packet is delivering data and requesting immediate processing (PSH-ACK). Common during active data transfer.")
                elif 'ACK' in flags:
                    explanations.append("This packet is acknowledging received data (ACK). It's telling the sender 'I got your data'.")
                
                # Add suspicious flag combinations
                if 'SYN' in flags and 'FIN' in flags:
                    explanations.append("⚠️ WARNING: This packet has both SYN and FIN flags set, which is abnormal and often indicates a port scan or attack!")
                if 'SYN' in flags and 'RST' in flags:
                    explanations.append("⚠️ WARNING: This packet has both SYN and RST flags set, which is abnormal and potentially malicious!")
            
            # TCP Window size explanation
            if packet.get('tcp_window'):
                window = packet.get('tcp_window')
                if window != 'N/A' and window.isdigit():
                    window_size = int(window)
                    explanations.append(f"\nℹ️ TCP Window Size: {window}")
                    explanations.append("The window size indicates how much data can be sent before requiring acknowledgment.")
                    if window_size < 1000:
                        explanations.append("This is a small window size, possibly indicating network congestion or limited receiving capacity.")
                    elif window_size > 65000:
                        explanations.append("This is a large window size, indicating a high-capacity connection with good throughput.")
            
        elif protocol == 'UDP':
            explanations.append("This is a UDP (User Datagram Protocol) packet.")
            explanations.append("UDP is simpler than TCP and doesn't guarantee delivery, order, or error-checking.")
            explanations.append("It's commonly used for:")
            explanations.append("• Video/audio streaming (faster but can tolerate some data loss)")
            explanations.append("• Online gaming (where speed is critical)")
            explanations.append("• DNS lookups (translating domain names to IP addresses)")
            explanations.append("• VoIP calls (voice over internet)")
            
        elif protocol == 'ICMP':
            explanations.append("This is an ICMP (Internet Control Message Protocol) packet.")
            explanations.append("ICMP helps networks diagnose problems by sending error messages and operational information.")
            explanations.append("Common ICMP messages include:")
            
            icmp_type = packet.get('icmp_type', 'N/A')
            icmp_code = packet.get('icmp_code', 'N/A')
            
            if icmp_type == '0':
                explanations.append("• Echo Reply (ping response) - A device responding to a ping request")
            elif icmp_type == '8':
                explanations.append("• Echo Request (ping) - Checking if a device is reachable")
            elif icmp_type == '3':
                explanations.append("• Destination Unreachable - The target couldn't be reached")
                if icmp_code == '0':
                    explanations.append("  (Network Unreachable - The network is unreachable)")
                elif icmp_code == '1':
                    explanations.append("  (Host Unreachable - The specific device is unreachable)")
                elif icmp_code == '3':
                    explanations.append("  (Port Unreachable - The service on that device isn't available)")
            elif icmp_type == '11':
                explanations.append("• Time Exceeded - The packet took too long to reach its destination")
                
        elif protocol == 'DNS':
            explanations.append("This is a DNS (Domain Name System) packet.")
            explanations.append("DNS translates human-readable domain names (like google.com) into IP addresses computers use.")
            explanations.append("It's like the internet's phone book.")
            
            dns_query = packet.get('dns_query', '')
            if dns_query and dns_query != 'N/A':
                explanations.append(f"\nℹ️ DNS Query: {dns_query}")
                explanations.append(f"Someone is looking up the address for '{dns_query}'")
                
            dns_response = packet.get('dns_response', '')
            if dns_response and dns_response != 'N/A':
                explanations.append(f"\nℹ️ DNS Response: {dns_response}")
                explanations.append(f"The DNS server is providing the IP address for a requested domain")
                
        elif protocol == 'HTTP':
            explanations.append("This is an HTTP (Hypertext Transfer Protocol) packet.")
            explanations.append("HTTP is used for browsing websites. It transfers web page data between servers and browsers.")
            
            http_method = packet.get('http_method', '')
            http_host = packet.get('http_host', '')
            http_path = packet.get('http_path', '')
            
            if http_method and http_method != 'N/A':
                explanations.append(f"\n📄 HTTP Method: {http_method}")
                if http_method == 'GET':
                    explanations.append("This is requesting a web page or resource (like viewing a site)")
                elif http_method == 'POST':
                    explanations.append("This is submitting data to a web server (like filling out a form)")
                elif http_method == 'HEAD':
                    explanations.append("This is checking for updates to a web page without downloading all content")
                    
            if http_host and http_host != 'N/A':
                explanations.append(f"📍 Website: {http_host}")
                
            if http_path and http_path != 'N/A':
                explanations.append(f"🔍 Specific page/resource: {http_path}")
                
            explanations.append("\n⚠️ Security Note: HTTP traffic is unencrypted! Anyone in between can see this data.")
            
        elif protocol == 'HTTPS':
            explanations.append("This is an HTTPS (HTTP Secure) packet.")
            explanations.append("HTTPS is encrypted web browsing traffic, protecting your privacy and security.")
            explanations.append("The contents are encrypted, so even if someone intercepts it, they cannot read the data.")
            
        elif protocol == 'ARP':
            explanations.append("This is an ARP (Address Resolution Protocol) packet.")
            explanations.append("ARP helps devices find each other on a local network.")
            explanations.append("It translates IP addresses (like 192.168.1.1) to physical MAC addresses (like 00:1A:2B:3C:4D:5E).")
            explanations.append("Think of it as asking 'Who has this IP address?' on your local network.")
            
        else:
            explanations.append(f"This is a {protocol} packet.")
            explanations.append("This protocol is used for specialized network communication.")
        
        # Source and destination in user-friendly terms - ENHANCED
        explanations.append("\n🔄 COMMUNICATION DETAILS")
        src_ip = packet.get('src_ip', 'N/A')
        dst_ip = packet.get('dst_ip', 'N/A')
        src_mac = packet.get('src_mac', 'N/A')
        dst_mac = packet.get('dst_mac', 'N/A')
        
        explanations.append(f"Source IP: {src_ip}")
        explanations.append(f"Destination IP: {dst_ip}")
        
        # Add MAC address info with explanation
        explanations.append(f"\nSource MAC: {src_mac}")
        explanations.append(f"Destination MAC: {dst_mac}")
        explanations.append("MAC addresses are like the physical addresses of network devices, similar to a serial number.")
        
        if src_ip != 'N/A' and dst_ip != 'N/A':
            # Identify if internal or external IPs with more context
            is_internal_src = self._is_private_ip(src_ip)
            is_internal_dst = self._is_private_ip(dst_ip)
            
            explanations.append("\n📍 Network Context:")
            if is_internal_src and is_internal_dst:
                explanations.append("This is local network traffic between two devices on your network.")
                explanations.append("This is typical for file sharing, printers, or devices communicating within your home/office.")
            elif is_internal_src:
                explanations.append(f"A device on your network ({src_ip}) is sending data to an external address ({dst_ip}).")
                explanations.append("This is normal for outgoing web traffic, emails, or other internet activity.")
            elif is_internal_dst:
                explanations.append(f"An external address ({src_ip}) is sending data to a device on your network ({dst_ip}).")
                explanations.append("This could be a response to a request, incoming data, or potentially unwanted traffic.")
            else:
                explanations.append(f"This appears to be traffic between two external addresses.")
                explanations.append("Your device captured this traffic passing through the network. This is unusual unless you're monitoring network traffic.")
        
        # Add TTL explanation
        ttl = packet.get('ttl', 'N/A')
        if ttl != 'N/A' and ttl.isdigit():
            ttl_value = int(ttl)
            explanations.append(f"\n⏱️ TTL (Time To Live): {ttl}")
            explanations.append("TTL determines how many network hops (routers) a packet can travel through before being discarded.")
            if ttl_value < 64:
                explanations.append("This packet has a relatively low TTL value, indicating it may have traveled through multiple routers.")
            if ttl_value <= 30:
                explanations.append("The low TTL could indicate international traffic or a complex routing path.")
        
        # Port explanation - ENHANCED with more ports and explanations
        src_port = packet.get('src_port', 'N/A')
        dst_port = packet.get('dst_port', 'N/A')
        
        if src_port != 'N/A' or dst_port != 'N/A':
            well_known_ports = {
                '20': 'FTP data transfer',
                '21': 'File transfers (FTP control)',
                '22': 'Secure remote access (SSH)',
                '23': 'Telnet (insecure remote access)',
                '25': 'Email sending (SMTP)',
                '53': 'Domain name lookup (DNS)',
                '67': 'DHCP server (IP address assignment)',
                '68': 'DHCP client (IP address request)',
                '80': 'Web browsing (HTTP)',
                '110': 'Email receiving (POP3)',
                '123': 'Network time synchronization (NTP)',
                '143': 'Email access (IMAP)',
                '161': 'Network management (SNMP)',
                '443': 'Secure web browsing (HTTPS)',
                '465': 'Secure email sending (SMTPS)',
                '500': 'Internet Security Association (IPsec)',
                '587': 'Email submission',
                '993': 'Secure email receiving (IMAPS)',
                '995': 'Secure POP3 (POP3S)',
                '1194': 'VPN (OpenVPN)',
                '1433': 'Database (Microsoft SQL Server)',
                '1723': 'VPN (PPTP)',
                '3306': 'Database (MySQL)',
                '3389': 'Remote desktop (RDP)',
                '5060': 'Voice over IP (SIP)',
                '5432': 'Database (PostgreSQL)',
                '8080': 'Alternative web/proxy server',
                '8443': 'Alternative secure web server',
                '27017': 'Database (MongoDB)'
            }
            
            # Add explanation for high port numbers
            high_ports = []
            if src_port != 'N/A' and src_port.isdigit() and int(src_port) > 1023:
                high_ports.append(src_port)
            if dst_port != 'N/A' and dst_port.isdigit() and int(dst_port) > 1023:
                high_ports.append(dst_port)
                
            explanations.append("\n🚪 PORT INFORMATION")
            explanations.append("Ports are like specific channels or doors for different types of internet traffic.")
            explanations.append(f"Source Port: {src_port}")
            explanations.append(f"Destination Port: {dst_port}")
            
            # Add high port explanation
            if high_ports:
                explanations.append(f"\nNote: Ports above 1023 (like {', '.join(high_ports)}) are typically temporary ports used by your device for outgoing connections.")
            
            # Explain common port combinations
            if ((src_port == '80' or dst_port == '80') and protocol == 'TCP'):
                explanations.append("\nThis is standard web browsing traffic (HTTP).")
            elif ((src_port == '443' or dst_port == '443') and protocol == 'TCP'):
                explanations.append("\nThis is secure web browsing traffic (HTTPS).")
            elif ((src_port == '53' or dst_port == '53') and protocol == 'UDP'):
                explanations.append("\nThis is domain name resolution traffic (DNS).")
            
            port_explanation = []
            if src_port in well_known_ports:
                port_explanation.append(f"Source port {src_port} is used for {well_known_ports[src_port]}.")
            
            if dst_port in well_known_ports:
                port_explanation.append(f"Destination port {dst_port} is used for {well_known_ports[dst_port]}.")
            
            if port_explanation:
                for exp in port_explanation:
                    explanations.append(exp)
        
        # Security analysis - EXPANDED
        explanations.append("\n🔒 SECURITY ANALYSIS")
        security_concerns = []
        security_ok = []
        
        # Check for potential security issues
        if protocol == 'TCP' and packet.get('tcp_flags'):
            flags = packet.get('tcp_flags')
            if 'FIN' in flags and 'SYN' in flags:
                security_concerns.append("⚠️ UNUSUAL FLAG COMBINATION: This packet has both SYN and FIN flags set, which is unusual and could indicate a port scan or network attack.")
            elif 'RST' in flags and 'SYN' in flags:
                security_concerns.append("⚠️ UNUSUAL FLAG COMBINATION: This packet has both SYN and RST flags set, which is abnormal and potentially malicious.")
            elif 'NULL' in flags:
                security_concerns.append("⚠️ NULL SCAN DETECTED: This packet has no flags set, which is typically part of a stealth port scan.")
            elif 'RST' in flags and direction == 'Inbound':
                security_concerns.append("ℹ️ CONNECTION REJECTED: A remote server actively refused a connection from your device.")
            elif 'SYN' in flags and dst_port != 'N/A' and dst_port.isdigit() and int(dst_port) < 1024:
                security_concerns.append(f"ℹ️ CONNECTION REQUEST: Someone is trying to connect to a service on port {dst_port}.")
        
        # Check for unencrypted protocols
        if protocol in ['HTTP', 'TELNET', 'FTP']:
            security_concerns.append(f"⚠️ UNENCRYPTED PROTOCOL: {protocol} sends data in plain text, which is not secure.")
            
            if protocol == 'HTTP':
                security_concerns.append("Consider using HTTPS instead for sensitive browsing.")
            elif protocol == 'TELNET':
                security_concerns.append("SSH is a more secure alternative for remote access.")
            elif protocol == 'FTP':
                security_concerns.append("SFTP or FTPS provide encrypted file transfers.")
        
        # Secure protocols
        if protocol in ['HTTPS', 'SSH', 'SFTP']:
            security_ok.append(f"✅ ENCRYPTED PROTOCOL: {protocol} uses encryption to protect your data.")
        
        # Check for broadcast traffic
        if dst_ip == '255.255.255.255' or dst_mac == 'ff:ff:ff:ff:ff:ff':
            security_concerns.append("ℹ️ BROADCAST TRAFFIC: This packet is being sent to all devices on the local network.")
        
        # Add security findings to explanations
        if security_concerns:
            for concern in security_concerns:
                explanations.append(concern)
        
        if security_ok:
            for ok in security_ok:
                explanations.append(ok)
                
        if not security_concerns and not security_ok:
            explanations.append("No obvious security concerns detected in this packet.")
        
        # Add packet characteristics and patterns section
        explanations.append("\n🧩 PACKET CHARACTERISTICS")
        
        packet_length = packet.get('length', 'N/A')
        if packet_length != 'N/A' and packet_length.isdigit():
            length_value = int(packet_length)
            if length_value < 60:
                explanations.append(f"📏 SMALL PACKET: At {packet_length} bytes, this is a small packet, likely just control information without much data.")
            elif length_value > 1400:
                explanations.append(f"📏 LARGE PACKET: At {packet_length} bytes, this is a large packet carrying substantial data.")
            else:
                explanations.append(f"📏 MEDIUM PACKET: At {packet_length} bytes, this is an average-sized packet.")
        
        # Add a section about the hex view itself
        explanations.append("\n🔢 UNDERSTANDING THE HEX VIEW")
        explanations.append("The hex view shows the raw packet data in hexadecimal (base-16) format. Each byte is shown as two characters from 0-9 and a-f.")
        explanations.append("• The leftmost column shows the offset (position) in the packet")
        explanations.append("• The middle columns show the raw bytes in hexadecimal")
        explanations.append("• The rightmost column shows the ASCII representation (printable characters)")
        
        
        
        
        # Join all explanations and display
        for line in explanations:
            if line.startswith("_LINK_"):
                # Special case for hyperlinks added earlier
                continue
            self.user_friendly_text.insert(tk.END, line + "\n")
    
    def _add_hyperlink(self, text_widget, hyperlink_text, url):
        """Add a hyperlink to the text widget"""
        text_widget.insert(tk.END, "\n→ ")
        
        # Store the position where the link starts
        start_pos = text_widget.index(tk.INSERT)
        
        # Insert the link text
        text_widget.insert(tk.END, hyperlink_text, "hyperlink")
        
        # Store the position where the link ends
        end_pos = text_widget.index(tk.INSERT)
        
        # Add the URL as a tag
        text_widget.tag_add(url, start_pos, end_pos)
        
        # Add a newline after the link
        text_widget.insert(tk.END, "\n")
    
    def _handle_hyperlink_click(self, event):
        """Handle clicks on hyperlinks in the user-friendly text widget"""
        try:
            # Get the position of the click
            index = self.user_friendly_text.index(f"@{event.x},{event.y}")
            
            # Get all tags at this position
            tags = self.user_friendly_text.tag_names(index)
            
            # Find a tag that looks like a URL
            for tag in tags:
                if tag.startswith("http"):
                    # Open the URL in the default browser
                    import webbrowser
                    webbrowser.open(tag)
                    break
        except Exception as e:
            if self.debug_mode:
                self._log_debug(f"Error handling hyperlink click: {str(e)}")
    
    def _is_private_ip(self, ip):
        """Check if an IP address is private/internal"""
        try:
            # Check for loopback address
            if ip.startswith("127."):
                return True
            
            # Check for private IP ranges
            octet1, octet2, *_ = ip.split(".")
            if octet1 == "10":  # 10.0.0.0/8
                return True
            if octet1 == "172" and 16 <= int(octet2) <= 31:  # 172.16.0.0/12
                return True
            if octet1 == "192" and octet2 == "168":  # 192.168.0.0/16
                return True
            
            return False
        except:
            return False

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

    def _create_settings_content(self):
        """Create the settings tab content."""
        settings_frame = ttk.Frame(self.settings_tab)
        settings_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Network Interface Selection
        interface_frame = ttk.LabelFrame(settings_frame, text="Network Interface")
        interface_frame.pack(fill="x", padx=5, pady=5)
        
        # Get list of available interfaces
        self.interfaces = self._get_interfaces()
        interface_options = [f"{iface['name']} ({iface['description']})" for iface in self.interfaces]
        
        # Interface dropdown
        self.interface_var = tk.StringVar()
        interface_dropdown = ttk.Combobox(interface_frame, textvariable=self.interface_var)
        interface_dropdown['values'] = interface_options
        interface_dropdown.pack(fill="x", padx=5, pady=5)
        if interface_options:
            interface_dropdown.current(0)
        
        # Refresh interfaces button
        refresh_btn = ttk.Button(interface_frame, text="Refresh Interfaces", command=self._refresh_interfaces)
        refresh_btn.pack(fill="x", padx=5, pady=5)
        
        # Capture Settings
        capture_frame = ttk.LabelFrame(settings_frame, text="Capture Settings")
        capture_frame.pack(fill="x", padx=5, pady=5)
        
        # Packet count
        packet_count_frame = ttk.Frame(capture_frame)
        packet_count_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(packet_count_frame, text="Packet Count:").pack(side="left")
        self.packet_count_var = tk.StringVar(value="0")
        ttk.Entry(packet_count_frame, textvariable=self.packet_count_var).pack(side="right", expand=True, fill="x")
        
        # Timeout
        timeout_frame = ttk.Frame(capture_frame)
        timeout_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(timeout_frame, text="Timeout (seconds):").pack(side="left")
        self.timeout_var = tk.StringVar(value="60")
        ttk.Entry(timeout_frame, textvariable=self.timeout_var).pack(side="right", expand=True, fill="x")
        
        # Output directory
        output_dir_frame = ttk.Frame(capture_frame)
        output_dir_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(output_dir_frame, text="Output Directory:").pack(side="left")
        self.output_dir_var = tk.StringVar(value=os.path.join(os.path.dirname(os.path.abspath(__file__)), "captures"))
        ttk.Entry(output_dir_frame, textvariable=self.output_dir_var).pack(side="left", expand=True, fill="x")
        ttk.Button(output_dir_frame, text="Browse", command=self._browse_output_dir).pack(side="right")
        
        # Simulation mode checkbox
        simulation_frame = ttk.Frame(capture_frame)
        simulation_frame.pack(fill="x", padx=5, pady=5)
        self.simulation_mode_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(simulation_frame, text="Simulation Mode (generate test data)", variable=self.simulation_mode_var).pack(anchor="w")
        
        # Action buttons
        button_frame = ttk.Frame(settings_frame)
        button_frame.pack(fill="x", padx=5, pady=10)
        
        self.start_button = ttk.Button(button_frame, text="Start Capture", command=self._run_capture)
        self.start_button.pack(side="left", fill="x", expand=True, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="Stop Capture", command=self._stop_capture, state="disabled")
        self.stop_button.pack(side="right", fill="x", expand=True, padx=5)

    def _open_capture(self):
        """Open a saved capture file"""
        from tkinter import filedialog
        filename = filedialog.askopenfilename(
            title="Open Capture File",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if filename:
            try:
                self._load_packets_from_csv(filename)
                self.status_label.config(text=f"Loaded capture file: {os.path.basename(filename)}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open capture file: {str(e)}")
    
    def _save_capture(self):
        """Save the current capture to a file"""
        if not self.all_packets:
            messagebox.showinfo("Info", "No packets to save")
            return
            
        from tkinter import filedialog
        filename = filedialog.asksaveasfilename(
            title="Save Capture As",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if not filename:
            return
            
        try:
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                # Write header
                writer.writerow([
                    'timestamp', 'source_mac', 'destination_mac', 'source_ip', 'destination_ip',
                    'protocol', 'length', 'source_port', 'destination_port', 'ttl',
                    'tcp_flags', 'tcp_window', 'icmp_type', 'icmp_code', 'dns_query',
                    'http_method', 'http_host', 'http_path', 'packet_direction', 'raw_data'
                ])
                
                # Write packet data
                for packet in self.all_packets:
                    writer.writerow([
                        packet.get('timestamp', ''),
                        packet.get('src_mac', ''),
                        packet.get('dst_mac', ''),
                        packet.get('src_ip', ''),
                        packet.get('dst_ip', ''),
                        packet.get('protocol', ''),
                        packet.get('length', ''),
                        packet.get('src_port', ''),
                        packet.get('dst_port', ''),
                        packet.get('ttl', ''),
                        packet.get('tcp_flags', ''),
                        packet.get('tcp_window', ''),
                        packet.get('icmp_type', ''),
                        packet.get('icmp_code', ''),
                        packet.get('dns_query', ''),
                        packet.get('http_method', ''),
                        packet.get('http_host', ''),
                        packet.get('http_path', ''),
                        packet.get('packet_direction', ''),
                        str(packet.get('raw', ''))
                    ])
                
            self.status_label.config(text=f"Saved capture to: {os.path.basename(filename)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save capture file: {str(e)}")

    def _load_packets_from_csv(self, csv_file):
        """Load packets from a CSV file into the GUI"""
        if not os.path.exists(csv_file):
            if self.debug_mode:
                self._log_debug(f"CSV file not found: {csv_file}")
            raise FileNotFoundError(f"CSV file not found: {csv_file}")
            
        try:
            if self.debug_mode:
                self._log_debug(f"Loading packets from CSV file: {csv_file}")
                
            # Clear existing packets
            self.all_packets = []
            self.packet_tree.delete(*self.packet_tree.get_children())
            self.details_text.delete(1.0, tk.END)
            self.raw_text.delete(1.0, tk.END)
            self.hex_text.delete(1.0, tk.END)
            
            # Configure protocol tags
            self._configure_protocol_tags()
            
            # Read CSV file
            with open(csv_file, 'r', newline='', encoding='utf-8') as f:
                reader = csv.reader(f)
                
                # Read header row
                try:
                    header = next(reader, None)
                    if self.debug_mode:
                        self._log_debug(f"CSV header: {header}")
                except Exception as e:
                    if self.debug_mode:
                        self._log_debug(f"Error reading CSV header: {str(e)}")
                    header = []
                
                if not header:
                    if self.debug_mode:
                        self._log_debug("CSV file is empty or has no header row")
                    raise ValueError("CSV file is empty or has no header row")
                    
                # Create mapping of column names to indices
                col_idx = {}
                # Standard field mappings with fallbacks for different naming conventions
                field_mappings = {
                    'timestamp': ['timestamp', 'time', 'Timestamp', 'Time'],
                    'src_mac': ['source_mac', 'src_mac', 'source mac', 'Source MAC', 'source_MAC'],
                    'dst_mac': ['destination_mac', 'dst_mac', 'destination mac', 'Destination MAC', 'destination_MAC'],
                    'src_ip': ['source_ip', 'src_ip', 'source ip', 'Source IP', 'src_IP'],
                    'dst_ip': ['destination_ip', 'dst_ip', 'destination ip', 'Destination IP', 'dst_IP'],
                    'src_port': ['source_port', 'src_port', 'source port', 'Source Port'],
                    'dst_port': ['destination_port', 'dst_port', 'destination port', 'Destination Port'],
                    'protocol': ['protocol', 'Protocol', 'proto', 'Proto'],
                    'length': ['length', 'len', 'size', 'Length', 'Size'],
                    'ttl': ['ttl', 'time to live', 'TTL', 'Time to Live'],
                    'tcp_flags': ['tcp_flags', 'flags', 'TCP Flags', 'Flags'],
                    'tcp_window': ['tcp_window', 'window', 'TCP Window', 'Window Size'],
                    'icmp_type': ['icmp_type', 'ICMP Type', 'icmp type'],
                    'icmp_code': ['icmp_code', 'ICMP Code', 'icmp code'],
                    'dns_query': ['dns_query', 'DNS Query', 'dns query', 'query'],
                    'http_method': ['http_method', 'HTTP Method', 'http method', 'method'],
                    'http_host': ['http_host', 'HTTP Host', 'http host', 'host'],
                    'http_path': ['http_path', 'HTTP Path', 'http path', 'path'],
                    'packet_direction': ['packet_direction', 'direction', 'Direction'],
                    'raw_data': ['raw_data', 'raw', 'Raw Data', 'Raw']
                }
                
                # Determine actual column indices for each field
                for field, possible_names in field_mappings.items():
                    for name in possible_names:
                        if name in header:
                            col_idx[field] = header.index(name)
                            break
                
                if self.debug_mode:
                    self._log_debug(f"Column index mapping: {col_idx}")
                
                # Helper function to safely get column value
                def get_col_value(row, field):
                    if field in col_idx and col_idx[field] < len(row):
                        return row[col_idx[field]]
                    return ""
                
                # Count of packets in the CSV
                packet_count = 0
                
                # Load each row
                for row_idx, row in enumerate(reader, 1):
                    if not row:
                        continue
                    
                    if self.debug_mode and row_idx == 1:
                        self._log_debug(f"First row of data: {row}")
                        
                    # Extract packet data from CSV
                    packet_data = {
                        'id': row_idx,
                        'timestamp': get_col_value(row, 'timestamp'),
                        'src_mac': get_col_value(row, 'src_mac'),
                        'dst_mac': get_col_value(row, 'dst_mac'),
                        'src_ip': get_col_value(row, 'src_ip'),
                        'dst_ip': get_col_value(row, 'dst_ip'),
                        'src_port': get_col_value(row, 'src_port'),
                        'dst_port': get_col_value(row, 'dst_port'),
                        'protocol': get_col_value(row, 'protocol'),
                        'length': get_col_value(row, 'length'),
                        'ttl': get_col_value(row, 'ttl'),
                        'tcp_flags': get_col_value(row, 'tcp_flags'),
                        'tcp_window': get_col_value(row, 'tcp_window'),
                        'icmp_type': get_col_value(row, 'icmp_type'),
                        'icmp_code': get_col_value(row, 'icmp_code'),
                        'dns_query': get_col_value(row, 'dns_query'),
                        'http_method': get_col_value(row, 'http_method'),
                        'http_host': get_col_value(row, 'http_host'),
                        'http_path': get_col_value(row, 'http_path'),
                        'packet_direction': get_col_value(row, 'packet_direction'),
                        'raw': get_col_value(row, 'raw_data')
                    }
                    
                    # Construct info field if not present
                    packet_data['info'] = ''
                    if packet_data['protocol'] == 'TCP' or packet_data['protocol'] == 'UDP':
                        if packet_data['src_ip'] and packet_data['dst_ip']:
                            packet_data['info'] = f"{packet_data['src_ip']}:{packet_data['src_port']} → {packet_data['dst_ip']}:{packet_data['dst_port']}"
                    elif packet_data['protocol'] == 'ICMP':
                        if packet_data['src_ip'] and packet_data['dst_ip']:
                            packet_data['info'] = f"ICMP {packet_data['src_ip']} → {packet_data['dst_ip']}"
                    elif packet_data['protocol'] == 'ARP':
                        if packet_data['src_ip'] and packet_data['dst_ip']:
                            packet_data['info'] = f"Who has {packet_data['dst_ip']}? Tell {packet_data['src_ip']}"
                    elif packet_data['protocol'] == 'DNS':
                        if packet_data['dns_query']:
                            packet_data['info'] = f"Query: {packet_data['dns_query']}"
                    elif packet_data['protocol'] == 'HTTP':
                        if packet_data['http_method'] and packet_data['http_path']:
                            packet_data['info'] = f"{packet_data['http_method']} {packet_data['http_path']}"
                            if packet_data['http_host']:
                                packet_data['info'] += f" Host: {packet_data['http_host']}"
                    elif packet_data['src_ip'] and packet_data['dst_ip']:
                        packet_data['info'] = f"{packet_data['src_ip']} → {packet_data['dst_ip']}"
                    
                    # Add to packet list
                    self.all_packets.append(packet_data)
                    
                    # Add to tree view
                    protocol_tag = self._get_protocol_tag(packet_data['protocol'])
                    self.packet_tree.insert("", tk.END, values=(
                        packet_data['id'],
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
                    
                    # Update raw data tab (only for first 1000 packets)
                    if row_idx <= 1000:
                        # Create a simulated raw data string from packet values
                        raw_data = ", ".join([
                            packet_data['timestamp'], packet_data['src_mac'], packet_data['dst_mac'],
                            packet_data['src_ip'], packet_data['dst_ip'], packet_data['protocol'],
                            packet_data['length'], packet_data['src_port'], packet_data['dst_port']
                        ])
                        self.raw_text.insert(tk.END, f"{row_idx}: {raw_data}\n")
                    
                    packet_count += 1
                
                if self.debug_mode:
                    self._log_debug(f"Loaded {packet_count} packets from CSV file")
                
                # Update hex view dropdown
                packet_ids = [str(p['id']) for p in self.all_packets[-100:]]  # Last 100 packets
                self.hex_packet_var.set(packet_ids[-1] if packet_ids else "")
                self.hex_packet_dropdown['values'] = packet_ids
                
                # Update status
                self.status_label.config(text=f"Loaded {len(self.all_packets)} packets from {os.path.basename(csv_file)}")
                
                # Manual creation of stats object if we don't have one
                if not self.stats or not isinstance(self.stats, dict) or not self.stats.get('total_packets'):
                    # Create stats based on the loaded packets
                    self.stats = {
                        'total_packets': len(self.all_packets),
                        'tcp_packets': sum(1 for p in self.all_packets if p['protocol'] == 'TCP'),
                        'udp_packets': sum(1 for p in self.all_packets if p['protocol'] == 'UDP'),
                        'icmp_packets': sum(1 for p in self.all_packets if p['protocol'] == 'ICMP'),
                        'other_packets': sum(1 for p in self.all_packets if p['protocol'] not in ['TCP', 'UDP', 'ICMP']),
                        'duration': 0,
                        'top_ips': {},
                        'top_destinations': {},
                        'top_ports': {}
                    }
                    
                    # Calculate top IPs, destinations, and ports
                    for p in self.all_packets:
                        if p['src_ip']:
                            self.stats['top_ips'][p['src_ip']] = self.stats['top_ips'].get(p['src_ip'], 0) + 1
                        if p['dst_ip']:
                            self.stats['top_destinations'][p['dst_ip']] = self.stats['top_destinations'].get(p['dst_ip'], 0) + 1
                        if p['src_port']:
                            self.stats['top_ports'][p['src_port']] = self.stats['top_ports'].get(p['src_port'], 0) + 1
                        if p['dst_port']:
                            self.stats['top_ports'][p['dst_port']] = self.stats['top_ports'].get(p['dst_port'], 0) + 1
                
                return True
                
        except Exception as e:
            if self.debug_mode:
                self._log_debug(f"Error loading CSV: {str(e)}")
                import traceback
                self._log_debug(traceback.format_exc())
            raise Exception(f"Error loading CSV: {str(e)}")

    def stop_capture(self):
        """Stop the current packet capture"""
        if not self.capture_in_progress:
            return
            
        if self.debug_mode:
            self._log_debug("Stopping capture...")
            
        # Set the stop flag for the capture thread
        if hasattr(self, 'stop_capture_event'):
            self.stop_capture_event.set()
            
        # Update UI state
        self.status_label.config(text="Stopping capture...")
        self.capture_in_progress = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        
        # Wait for capture thread to finish if it's still running
        if self.capture_thread and self.capture_thread.is_alive():
            try:
                # Give the capture thread a moment to react to the stop event
                time.sleep(0.5)
                self.capture_thread.join(timeout=1.0)  # Wait up to 1 second
            except:
                pass  # Ignore any thread joining errors

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
        if packet.get('packet_direction'):
            self.details_text.insert(tk.END, f"  {'Direction:':<20}", "field")
            self.details_text.insert(tk.END, f"{packet['packet_direction']}\n", "value")
        
        # Additional protocol-specific info
        if protocol == "TCP":
            self._add_tcp_details(packet)
        elif protocol == "UDP":
            self._add_udp_details(packet)
        elif protocol == "ICMP":
            self._add_icmp_details(packet)
        elif "DNS" in protocol or packet.get('dns_query'):
            self._add_dns_details(packet)
        elif "HTTP" in protocol or packet.get('http_method') or packet.get('http_host') or packet.get('http_path'):
            self._add_http_details(packet)
        
        # Add info field
        self.details_text.insert(tk.END, "\nINFO\n", "header")
        self.details_text.insert(tk.END, f"  {packet.get('info', '')}\n", "value")
        
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
        
        if packet.get('src_port'):
            self.details_text.insert(tk.END, f"  {'Source Port:':<20}", "field")
            self.details_text.insert(tk.END, f"{packet['src_port']}\n", "value")
        
        if packet.get('dst_port'):
            self.details_text.insert(tk.END, f"  {'Destination Port:':<20}", "field")
            self.details_text.insert(tk.END, f"{packet['dst_port']}\n", "value")
        
        # TCP flags if available
        if packet.get('tcp_flags'):
            self.details_text.insert(tk.END, f"  {'TCP Flags:':<20}", "field")
            self.details_text.insert(tk.END, f"{packet['tcp_flags']}\n", "value")
        
        # TCP window if available
        if packet.get('tcp_window'):
            self.details_text.insert(tk.END, f"  {'TCP Window Size:':<20}", "field")
            self.details_text.insert(tk.END, f"{packet['tcp_window']}\n", "value")

    def _add_udp_details(self, packet):
        """Add UDP-specific details to packet details"""
        self.details_text.insert(tk.END, "\nUDP DETAILS\n", "header")
        
        if packet.get('src_port'):
            self.details_text.insert(tk.END, f"  {'Source Port:':<20}", "field")
            self.details_text.insert(tk.END, f"{packet['src_port']}\n", "value")
        
        if packet.get('dst_port'):
            self.details_text.insert(tk.END, f"  {'Destination Port:':<20}", "field")
            self.details_text.insert(tk.END, f"{packet['dst_port']}\n", "value")

    def _add_icmp_details(self, packet):
        """Add ICMP-specific details to packet details"""
        self.details_text.insert(tk.END, "\nICMP DETAILS\n", "header")
        
        if packet.get('icmp_type'):
            self.details_text.insert(tk.END, f"  {'ICMP Type:':<20}", "field")
            self.details_text.insert(tk.END, f"{packet['icmp_type']}\n", "value")
        else:
            self.details_text.insert(tk.END, f"  {'ICMP Type:':<20}", "field")
            self.details_text.insert(tk.END, "Unknown\n", "value")
        
        if packet.get('icmp_code'):
            self.details_text.insert(tk.END, f"  {'ICMP Code:':<20}", "field")
            self.details_text.insert(tk.END, f"{packet['icmp_code']}\n", "value")
        else:
            self.details_text.insert(tk.END, f"  {'ICMP Code:':<20}", "field")
            self.details_text.insert(tk.END, "Unknown\n", "value")

    def _add_dns_details(self, packet):
        """Add DNS-specific details to packet details"""
        self.details_text.insert(tk.END, "\nDNS DETAILS\n", "header")
        
        if packet.get('dns_query'):
            self.details_text.insert(tk.END, f"  {'DNS Query:':<20}", "field")
            self.details_text.insert(tk.END, f"{packet['dns_query']}\n", "value")

    def _add_http_details(self, packet):
        """Add HTTP-specific details to packet details"""
        self.details_text.insert(tk.END, "\nHTTP DETAILS\n", "header")
        
        if packet.get('http_method'):
            self.details_text.insert(tk.END, f"  {'HTTP Method:':<20}", "field")
            self.details_text.insert(tk.END, f"{packet['http_method']}\n", "value")
        
        if packet.get('http_host'):
            self.details_text.insert(tk.END, f"  {'HTTP Host:':<20}", "field")
            self.details_text.insert(tk.END, f"{packet['http_host']}\n", "value")
        
        if packet.get('http_path'):
            self.details_text.insert(tk.END, f"  {'HTTP Path:':<20}", "field")
            self.details_text.insert(tk.END, f"{packet['http_path']}\n", "value")

    def _get_protocol_tag(self, protocol):
        """Get the tag for the protocol for styling in the treeview"""
        protocol = protocol.upper() if protocol else ""
        
        if "TCP" in protocol:
            return "tcp"
        elif "UDP" in protocol:
            return "udp"
        elif "ICMP" in protocol:
            return "icmp"
        elif "ARP" in protocol:
            return "arp"
        elif "DNS" in protocol:
            return "dns"
        elif "HTTP" in protocol:
            return "http"
        elif "HTTPS" in protocol or "TLS" in protocol or "SSL" in protocol:
            return "tls"
        else:
            return "other"
    
    def _configure_protocol_tags(self):
        """Configure tags for protocols to color rows in treeview"""
        # Configure tags using Wireshark-like colors
        if self.current_theme == "light":
            self.packet_tree.tag_configure("tcp", background=self.protocol_colors["TCP"]["light"])
            self.packet_tree.tag_configure("udp", background=self.protocol_colors["UDP"]["light"])
            self.packet_tree.tag_configure("icmp", background=self.protocol_colors["ICMP"]["light"])
            self.packet_tree.tag_configure("arp", background=self.protocol_colors["ARP"]["light"])
            self.packet_tree.tag_configure("dns", background=self.protocol_colors["DNS"]["light"])
            self.packet_tree.tag_configure("http", background=self.protocol_colors["HTTP"]["light"])
            self.packet_tree.tag_configure("tls", background=self.protocol_colors["TLS"]["light"])
            self.packet_tree.tag_configure("other", background="#f0f0f0")
        else:
            self.packet_tree.tag_configure("tcp", background=self.protocol_colors["TCP"]["dark"])
            self.packet_tree.tag_configure("udp", background=self.protocol_colors["UDP"]["dark"])
            self.packet_tree.tag_configure("icmp", background=self.protocol_colors["ICMP"]["dark"])
            self.packet_tree.tag_configure("arp", background=self.protocol_colors["ARP"]["dark"])
            self.packet_tree.tag_configure("dns", background=self.protocol_colors["DNS"]["dark"])
            self.packet_tree.tag_configure("http", background=self.protocol_colors["HTTP"]["dark"])
            self.packet_tree.tag_configure("tls", background=self.protocol_colors["TLS"]["dark"])
            self.packet_tree.tag_configure("other", background="#333333")

    def _display_capture_results(self):
        """Display capture results in the UI"""
        try:
            # Use packet list if available, even if stats aren't present
            if not self.stats and self.all_packets:
                # Create stats from packet list
                if self.debug_mode:
                    self._log_debug(f"Creating stats from {len(self.all_packets)} loaded packets")
                
                self.stats = {
                    'total_packets': len(self.all_packets),
                    'tcp_packets': sum(1 for p in self.all_packets if p['protocol'] == 'TCP'),
                    'udp_packets': sum(1 for p in self.all_packets if p['protocol'] == 'UDP'),
                    'icmp_packets': sum(1 for p in self.all_packets if p['protocol'] == 'ICMP'),
                    'other_packets': sum(1 for p in self.all_packets if p['protocol'] not in ['TCP', 'UDP', 'ICMP']),
                    'duration': 0,
                    'top_ips': {},
                    'top_destinations': {},
                    'top_ports': {}
                }
                
                # Calculate top IPs, destinations, and ports
                for p in self.all_packets:
                    if p['src_ip']:
                        self.stats['top_ips'][p['src_ip']] = self.stats['top_ips'].get(p['src_ip'], 0) + 1
                    if p['dst_ip']:
                        self.stats['top_destinations'][p['dst_ip']] = self.stats['top_destinations'].get(p['dst_ip'], 0) + 1
                    if p['src_port']:
                        self.stats['top_ports'][p['src_port']] = self.stats['top_ports'].get(p['src_port'], 0) + 1
                    if p['dst_port']:
                        self.stats['top_ports'][p['dst_port']] = self.stats['top_ports'].get(p['dst_port'], 0) + 1
            
            # Update analytics
            if not self.stats:
                if self.debug_mode:
                    self._log_debug("No stats available to display")
                return
                
            # Extract stats based on object type (dict or object with attributes)
            if isinstance(self.stats, dict):
                # Direct dictionary access
                total_packets = self.stats.get('total_packets', 0)
                duration = self.stats.get('duration', 0)
                tcp_packets = self.stats.get('tcp_packets', 0)
                udp_packets = self.stats.get('udp_packets', 0)
                icmp_packets = self.stats.get('icmp_packets', 0)
                other_packets = self.stats.get('other_packets', 0)
                top_ips = self.stats.get('top_ips', {})
                top_destinations = self.stats.get('top_destinations', {})
                top_ports = self.stats.get('top_ports', {})
            else:
                # Object attribute access
                total_packets = getattr(self.stats, 'total_packets', 0)
                duration = getattr(self.stats, 'duration', 0)
                tcp_packets = getattr(self.stats, 'tcp_packets', 0)
                udp_packets = getattr(self.stats, 'udp_packets', 0)
                icmp_packets = getattr(self.stats, 'icmp_packets', 0)
                other_packets = getattr(self.stats, 'other_packets', 0)
                top_ips = getattr(self.stats, 'top_ips', {})
                top_destinations = getattr(self.stats, 'top_destinations', {})
                top_ports = getattr(self.stats, 'top_ports', {})
                
            if total_packets == 0 and self.all_packets:
                # If stats show 0 packets but we have loaded packets, use the packet count
                total_packets = len(self.all_packets)
                if self.debug_mode:
                    self._log_debug(f"Stats show 0 packets but {total_packets} packets are loaded")
                
            if total_packets == 0:
                if self.debug_mode:
                    self._log_debug("No packets to display in results")
                return
                
            # Get the top N items from each category
            top_limit = 5  # Show top 5 items in each category
            
            # Sort dictionaries by value (count)
            if hasattr(top_ips, 'items'):
                top_ips = sorted(top_ips.items(), key=lambda x: x[1], reverse=True)[:top_limit]
            else:
                top_ips = []
                
            if hasattr(top_destinations, 'items'):
                top_destinations = sorted(top_destinations.items(), key=lambda x: x[1], reverse=True)[:top_limit]
            else:
                top_destinations = []
                
            if hasattr(top_ports, 'items'):
                top_ports = sorted(top_ports.items(), key=lambda x: x[1], reverse=True)[:top_limit]
            else:
                top_ports = []
            
            # Display summary
            summary = f"Total packets: {total_packets}\n"
            summary += f"Duration: {duration:.2f} seconds\n\n"
            summary += f"TCP packets: {tcp_packets}\n"
            summary += f"UDP packets: {udp_packets}\n"
            summary += f"ICMP packets: {icmp_packets}\n"
            summary += f"Other packets: {other_packets}\n\n"
            
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
            self._create_protocol_chart(tcp_packets, udp_packets, icmp_packets, other_packets)
                
        except Exception as e:
            if self.debug_mode:
                self._log_debug(f"Error displaying results: {str(e)}")
                import traceback
                self._log_debug(traceback.format_exc())

    def _create_protocol_chart(self, tcp_packets, udp_packets, icmp_packets, other_packets):
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
            counts = [tcp_packets, udp_packets, icmp_packets, other_packets]
            
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

    def _update_raw_data_tab(self):
        """Update the raw data tab with the first 1000 packets"""
        try:
            if not hasattr(self, 'all_packets') or not self.all_packets:
                if self.debug_mode:
                    self._log_debug("No packets to display in raw data tab")
                return
                
            # Clear existing content
            self.raw_data_text.delete(1.0, tk.END)
            
            # Add header row
            if self.all_packets and len(self.all_packets) > 0:
                # Get column names from first packet
                header = list(self.all_packets[0].keys())
                self.raw_data_text.insert(tk.END, "# " + ", ".join(header) + "\n")
                
                # Add packet data (first 1000 packets to avoid performance issues)
                display_limit = min(1000, len(self.all_packets))
                for i in range(display_limit):
                    packet = self.all_packets[i]
                    # Convert all values to strings and join with commas
                    values = [str(packet.get(col, '')) for col in header]
                    self.raw_data_text.insert(tk.END, ", ".join(values) + "\n")
                
                if display_limit < len(self.all_packets):
                    self.raw_data_text.insert(tk.END, f"\n# Note: Only showing {display_limit} of {len(self.all_packets)} packets")
            
            if self.debug_mode:
                self._log_debug(f"Updated raw data tab with {len(self.all_packets)} packets")
                
        except Exception as e:
            if self.debug_mode:
                self._log_debug(f"Error updating raw data tab: {str(e)}")
                import traceback
                self._log_debug(traceback.format_exc())

    def _on_capture_packet(self, packet_data):
        """Handle a newly captured packet"""
        try:
            if self.debug_mode:
                self._log_debug(f"Received packet: {packet_data.get('protocol', 'Unknown')}")
            
            # Add to all_packets list
            if not hasattr(self, 'all_packets'):
                self.all_packets = []
            self.all_packets.append(packet_data)
            
            # Add to tree view
            values = []
            for col in self.columns:
                values.append(packet_data.get(col, ''))
            
            self.packet_tree.insert('', 'end', values=values, tags=(packet_data.get('protocol', 'other').lower(),))
            
            # Update packet count
            self.status_label.config(text=f"Packets: {len(self.all_packets)}")
            
            # Keep the most recent packet visible by scrolling to the bottom
            self.packet_tree.yview_moveto(1.0)
            
            # Update raw data tab periodically (every 10 packets)
            if len(self.all_packets) % 10 == 0:
                self._update_raw_data_tab()
                
        except Exception as e:
            if self.debug_mode:
                self._log_debug(f"Error processing packet: {str(e)}")
                import traceback
                self._log_debug(traceback.format_exc())

if __name__ == "__main__":
    root = tk.Tk()
    app = SnifferGUI(root)
    root.mainloop() 