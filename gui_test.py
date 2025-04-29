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
import json
from tkinter import filedialog

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
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)  # Handle window close
        self.master.title("Threat Hunter - Network Traffic Analyzer")
        self.create_widgets()
        self.packets = []
        self.packet_tree = None
        
        self.protocol_stats = {}
        self.ip_stats = {}
        self.port_stats = {}
        
        self.selected_packet = None
        self.capture_active = False
        self.stop_capture_event = threading.Event()
        self.capture_thread = None
        self.capture_file = None
        
        # New properties for security analysis
        self.security_findings = []
        self.security_summary = {}
        self.debug_mode = True  # Set to False in production
        
        # Create a debug log file
        if self.debug_mode:
            self.debug_log = os.path.join(os.path.dirname(os.path.abspath(__file__)), "debug.log")
            with open(self.debug_log, "w") as f:
                f.write(f"Debug log started at {datetime.now()}\n")

    def create_widgets(self):
        # Configure grid weight to allow resizing
        self.master.grid_rowconfigure(0, weight=1)
        self.master.grid_columnconfigure(0, weight=1)
        
        # Create main frame
        self.mainframe = ttk.Frame(self.master)
        self.mainframe.grid(sticky="nsew")
        
        # Configure frame grid weight
        self.mainframe.grid_rowconfigure(1, weight=1)
        self.mainframe.grid_columnconfigure(0, weight=1)
        
        # Create menubar
        self.create_menu()
        
        # Create toolbar for common actions
        self.create_toolbar()
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.mainframe)
        self.notebook.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        
        # Create packets tab
        self.packets_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.packets_frame, text="Packets")
        
        # Create analytics tab
        self.analytics_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.analytics_frame, text="Analytics")
        
        # Create raw data tab
        self.raw_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.raw_frame, text="Raw Data")
        
        # Create hex view tab
        self.hex_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.hex_frame, text="Hex View")
        
        # Create security tab
        self.security_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.security_frame, text="Security")
        
        # Setup the tab contents
        self.setup_packets_tab()
        self.setup_analytics_tab()
        self.setup_raw_tab()
        self.setup_hex_tab()
        self.setup_security_tab()
        
        # Create status bar
        self.statusbar = ttk.Frame(self.mainframe, relief=tk.SUNKEN, padding=(2, 2))
        self.statusbar.grid(row=2, column=0, sticky="ew")
        
        self.status_label = ttk.Label(self.statusbar, text="Ready")
        self.status_label.pack(side=tk.LEFT)
        
        self.packet_count_label = ttk.Label(self.statusbar, text="Packets: 0")
        self.packet_count_label.pack(side=tk.RIGHT)

    def setup_security_tab(self):
        """Setup the security analysis tab"""
        # Configure grid weights
        self.security_frame.grid_rowconfigure(1, weight=1)
        self.security_frame.grid_columnconfigure(0, weight=1)
        
        # Control bar with buttons
        control_frame = ttk.Frame(self.security_frame)
        control_frame.grid(row=0, column=0, sticky="ew", pady=5)
        
        ttk.Button(control_frame, text="Run Security Analysis", 
                  command=self.run_security_analysis).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(control_frame, text="Export Findings", 
                  command=self.export_security_findings).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(control_frame, text="Severity Filter:").pack(side=tk.LEFT, padx=(15, 5))
        
        self.severity_filter = ttk.Combobox(control_frame, values=["All", "Critical", "High", "Medium", "Low", "Info"], 
                                           width=10, state="readonly")
        self.severity_filter.current(0)  # Set to "All" by default
        self.severity_filter.pack(side=tk.LEFT, padx=5)
        self.severity_filter.bind("<<ComboboxSelected>>", self.filter_security_findings)
        
        # Create paned window to split the security tab
        security_paned = ttk.PanedWindow(self.security_frame, orient=tk.HORIZONTAL)
        security_paned.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        
        # Left panel for findings list
        findings_frame = ttk.Frame(security_paned)
        security_paned.add(findings_frame, weight=40)
        
        # Configure findings frame
        findings_frame.grid_rowconfigure(1, weight=1)
        findings_frame.grid_columnconfigure(0, weight=1)
        
        # Create summary frame for security metrics
        summary_frame = ttk.LabelFrame(findings_frame, text="Security Summary")
        summary_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        
        # Summary metrics
        metrics_frame = ttk.Frame(summary_frame)
        metrics_frame.pack(fill=tk.X, expand=True, padx=10, pady=5)
        
        # Create metric labels with default values
        self.metrics = {
            'findings_count': ttk.Label(metrics_frame, text="Total Findings: 0"),
            'critical_count': ttk.Label(metrics_frame, text="Critical: 0", foreground="red"),
            'high_count': ttk.Label(metrics_frame, text="High: 0", foreground="orange"),
            'medium_count': ttk.Label(metrics_frame, text="Medium: 0", foreground="blue"),
            'low_count': ttk.Label(metrics_frame, text="Low: 0"),
            'security_status': ttk.Label(metrics_frame, text="Status: No issues detected", 
                                       foreground="green", font=("", 10, "bold"))
        }
        
        # Position metric labels
        self.metrics['findings_count'].grid(row=0, column=0, padx=5, pady=2, sticky="w")
        self.metrics['critical_count'].grid(row=0, column=1, padx=5, pady=2, sticky="w")
        self.metrics['high_count'].grid(row=0, column=2, padx=5, pady=2, sticky="w")
        self.metrics['medium_count'].grid(row=0, column=3, padx=5, pady=2, sticky="w")
        self.metrics['low_count'].grid(row=0, column=4, padx=5, pady=2, sticky="w")
        self.metrics['security_status'].grid(row=1, column=0, columnspan=5, padx=5, pady=2, sticky="w")
        
        # Create findings treeview
        findings_label = ttk.Label(findings_frame, text="Security Findings:")
        findings_label.grid(row=2, column=0, sticky="w", padx=5)
        
        # Create a frame for the treeview and scrollbar
        findings_tree_frame = ttk.Frame(findings_frame)
        findings_tree_frame.grid(row=3, column=0, sticky="nsew", padx=5, pady=5)
        findings_tree_frame.grid_rowconfigure(0, weight=1)
        findings_tree_frame.grid_columnconfigure(0, weight=1)
        
        # Create scrollbar
        findings_scrollbar = ttk.Scrollbar(findings_tree_frame)
        findings_scrollbar.grid(row=0, column=1, sticky="ns")
        
        # Create treeview
        self.findings_tree = ttk.Treeview(findings_tree_frame, 
                                         columns=("severity", "type", "summary"),
                                         show="headings",
                                         yscrollcommand=findings_scrollbar.set)
        self.findings_tree.grid(row=0, column=0, sticky="nsew")
        findings_scrollbar.config(command=self.findings_tree.yview)
        
        # Define column headings
        self.findings_tree.heading("severity", text="Severity")
        self.findings_tree.heading("type", text="Type")
        self.findings_tree.heading("summary", text="Summary")
        
        # Define column widths
        self.findings_tree.column("severity", width=80, anchor="center")
        self.findings_tree.column("type", width=150)
        self.findings_tree.column("summary", width=350)
        
        # Bind selection event
        self.findings_tree.bind("<<TreeviewSelect>>", self.on_finding_select)
        
        # Right panel for finding details
        details_frame = ttk.Frame(security_paned)
        security_paned.add(details_frame, weight=60)
        
        # Configure details frame
        details_frame.grid_rowconfigure(1, weight=1)
        details_frame.grid_columnconfigure(0, weight=1)
        
        # Create detail view label
        details_label = ttk.Label(details_frame, text="Finding Details:")
        details_label.grid(row=0, column=0, sticky="w", padx=5, pady=5)
        
        # Create notebook for details tabs
        details_notebook = ttk.Notebook(details_frame)
        details_notebook.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        
        # Overview tab
        overview_frame = ttk.Frame(details_notebook)
        details_notebook.add(overview_frame, text="Overview")
        
        # Technical details tab
        technical_frame = ttk.Frame(details_notebook)
        details_notebook.add(technical_frame, text="Technical Details")
        
        # Recommendations tab
        recommendations_frame = ttk.Frame(details_notebook)
        details_notebook.add(recommendations_frame, text="Recommendations")
        
        # Configure overview frame
        overview_frame.grid_rowconfigure(0, weight=1)
        overview_frame.grid_columnconfigure(0, weight=1)
        
        # Create overview text widget
        self.overview_text = tk.Text(overview_frame, wrap=tk.WORD, padx=10, pady=10, 
                                    height=20, width=50)
        self.overview_text.grid(row=0, column=0, sticky="nsew")
        self.overview_text.config(state=tk.DISABLED)
        
        # Configure technical frame
        technical_frame.grid_rowconfigure(0, weight=1)
        technical_frame.grid_columnconfigure(0, weight=1)
        
        # Create technical details text widget
        self.technical_text = tk.Text(technical_frame, wrap=tk.WORD, padx=10, pady=10,
                                     height=20, width=50)
        self.technical_text.grid(row=0, column=0, sticky="nsew")
        self.technical_text.config(state=tk.DISABLED)
        
        # Configure recommendations frame
        recommendations_frame.grid_rowconfigure(0, weight=1)
        recommendations_frame.grid_columnconfigure(0, weight=1)
        
        # Create recommendations text widget
        self.recommendations_text = tk.Text(recommendations_frame, wrap=tk.WORD, padx=10, pady=10,
                                          height=20, width=50)
        self.recommendations_text.grid(row=0, column=0, sticky="nsew")
        self.recommendations_text.config(state=tk.DISABLED)

    def run_security_analysis(self):
        """Run security analysis on the captured packets"""
        if not self.packets:
            messagebox.showinfo("Security Analysis", "No packets to analyze. Please capture or load some traffic first.")
            return
        
        self.status_label.config(text="Running security analysis...")
        self.master.update_idletasks()
        
        # Clear previous findings
        self.security_findings = []
        
        # Run analysis in a thread to avoid freezing the GUI
        def analysis_thread():
            # Perform the security analysis
            self.security_findings = self.perform_security_analysis()
            
            # Generate summary
            self.security_summary = self._generate_security_summary(self.security_findings)
            
            # Update the GUI in the main thread
            self.master.after(0, lambda: self.update_security_display())
            
            # Update the dashboard variables directly
            if hasattr(self, 'suspicious_count_var'):
                # Count suspicious packets
                suspicious_count = sum(1 for f in self.security_findings if f.get('severity', '') in ['medium', 'high', 'critical'])
                self.suspicious_count_var.set(str(suspicious_count))
                self._log_debug(f"Setting dashboard suspicious_count to {suspicious_count}")
                
                # Count potential attacks
                attack_types = ['brute force', 'port scan', 'data exfiltration', 'malware', 'suspicious']
                attack_count = sum(1 for f in self.security_findings 
                                if any(attack_type in f.get('type', '').lower() for attack_type in attack_types))
                self.attack_count_var.set(str(attack_count))
                self._log_debug(f"Setting dashboard attack_count to {attack_count}")
                
                # Count unique suspicious IPs
                suspicious_ips = set()
                for finding in self.security_findings:
                    if 'related_ips' in finding and finding['related_ips']:
                        suspicious_ips.update(finding['related_ips'])
                self.malicious_ip_count_var.set(str(len(suspicious_ips)))
                self._log_debug(f"Setting dashboard malicious_ip_count to {len(suspicious_ips)}")
            
            # Update the security tree with new findings
            if hasattr(self, 'security_tree'):
                # Clear existing items
                for item in self.security_tree.get_children():
                    self.security_tree.delete(item)
                
                # Add new findings
                for finding in self.security_findings:
                    self.security_tree.insert("", "end", values=(
                        finding.get('id', 'Unknown'),
                        finding.get('timestamp', 'Unknown'),
                        finding.get('severity', 'Unknown').upper(),
                        finding.get('type', 'Unknown'),
                        finding.get('summary', 'No summary')
                    ))
                self._log_debug(f"Updated security_tree with {len(self.security_findings)} findings")
            
            # Update threat level indicator
            if hasattr(self, 'threat_level_var') and hasattr(self, 'threat_canvas'):
                self._update_threat_level_from_findings()
            
            # Make sure the security tab is displayed
            self.notebook.select(self.security_frame)
            
            # Update status
            self.status_label.config(text="Security analysis complete")
        
        thread = threading.Thread(target=analysis_thread)
        thread.daemon = True
        thread.start()

    def update_security_display(self):
        """Update security tab displays with analysis results"""
        # Clear existing items
        for item in self.findings_tree.get_children():
            self.findings_tree.delete(item)
        
        # Update metrics display
        counts = self.security_summary['severity_counts']
        self.metrics['findings_count'].config(text=f"Total Findings: {self.security_summary['total_findings']}")
        self.metrics['critical_count'].config(text=f"Critical: {counts['critical']}")
        self.metrics['high_count'].config(text=f"High: {counts['high']}")
        self.metrics['medium_count'].config(text=f"Medium: {counts['medium']}")
        self.metrics['low_count'].config(text=f"Low: {counts['low']}")
        
        # Update security status
        if self.security_summary['total_findings'] == 0:
            status_text = "Status: No issues detected"
            status_color = "green"
        else:
            highest = self.security_summary['highest_severity']
            status_map = {
                'critical': ("Status: CRITICAL issues detected", "red"),
                'high': ("Status: HIGH severity issues detected", "orange"),
                'medium': ("Status: MEDIUM severity issues detected", "blue"),
                'low': ("Status: LOW severity issues detected", "green"),
                'info': ("Status: Informational findings only", "green")
            }
            status_text, status_color = status_map.get(highest, ("Status: Unknown", "black"))
        
        self.metrics['security_status'].config(text=status_text, foreground=status_color)
        
        # Update main security dashboard metrics
        # (These are the ones shown in the screenshot)
        if hasattr(self, 'suspicious_count_var'):
            # Count suspicious packets
            suspicious_count = sum(1 for f in self.security_findings if f['severity'] in ['medium', 'high', 'critical'])
            self.suspicious_count_var.set(str(suspicious_count))
            self._log_debug(f"Setting suspicious_count to {suspicious_count}")
            
            # Count potential attacks
            attack_types = ['brute force', 'port scan', 'data exfiltration', 'malware', 'suspicious']
            attack_count = sum(1 for f in self.security_findings 
                            if any(attack_type in f.get('type', '').lower() for attack_type in attack_types))
            self.attack_count_var.set(str(attack_count))
            self._log_debug(f"Setting attack_count to {attack_count}")
            
            # Count unique suspicious IPs
            suspicious_ips = set()
            for finding in self.security_findings:
                if 'related_ips' in finding and finding['related_ips']:
                    suspicious_ips.update(finding['related_ips'])
            self.malicious_ip_count_var.set(str(len(suspicious_ips)))
            self._log_debug(f"Setting malicious_ip_count to {len(suspicious_ips)}")
        
        # Populate findings tree
        current_filter = self.severity_filter.get().lower()
        
        # Ensure security_findings is not None
        if not self.security_findings:
            self.security_findings = []
            
        # Debug log
        self._log_debug(f"Updating security display with {len(self.security_findings)} findings")
        for finding in self.security_findings:
            self._log_debug(f"Processing finding: {finding.get('type', 'Unknown')} - {finding.get('severity', 'Unknown')}")
            
            severity = finding.get('severity', 'info').lower()
            
            # Apply filter
            if current_filter != 'all' and severity != current_filter.lower():
                continue
            
            # Add to tree with appropriate colors
            severity_colors = {
                'critical': '#FF0000',  # Red
                'high': '#FF8C00',      # Dark Orange
                'medium': '#0066CC',    # Blue
                'low': '#008000',       # Green
                'info': '#808080'       # Gray
            }
            
            # Create item in tree
            item_id = self.findings_tree.insert("", tk.END, 
                                              values=(finding.get('severity', 'Unknown').upper(), 
                                                     finding.get('type', 'Unknown'), 
                                                     finding.get('summary', 'No summary provided')),
                                              tags=(severity,))
            
            # Apply tag for color
            self.findings_tree.tag_configure(severity, 
                                           foreground=severity_colors.get(severity, 'black'))
        
        # Clear details pane
        self.clear_finding_details()
        
        # Update status
        self.status_label.config(text="Security analysis complete")
        
        # Force UI update
        self.master.update_idletasks()
    
    def _update_threat_level_from_findings(self):
        """Update the threat level indicator based on findings"""
        try:
            # Count findings by severity
            critical_count = sum(1 for f in self.security_findings if f.get('severity', '').lower() == 'critical')
            high_count = sum(1 for f in self.security_findings if f.get('severity', '').lower() == 'high')
            medium_count = sum(1 for f in self.security_findings if f.get('severity', '').lower() == 'medium')
            low_count = sum(1 for f in self.security_findings if f.get('severity', '').lower() == 'low')
            
            # Determine overall threat level
            if critical_count > 0:
                threat_level = "Critical"
                color = "#ff0000"  # Red
            elif high_count > 0:
                threat_level = "High"
                color = "#ff4500"  # OrangeRed
            elif medium_count > 0:
                threat_level = "Medium"
                color = "#ffa500"  # Orange
            elif low_count > 0:
                threat_level = "Low"
                color = "#ffff00"  # Yellow
            else:
                threat_level = "Low"
                color = "#00ff00"  # Green
            
            # Update the threat level label
            if hasattr(self, 'threat_level_var'):
                self.threat_level_var.set(threat_level)
                self._log_debug(f"Setting threat_level to {threat_level}")
            
            # Update threat indicator on canvas
            if hasattr(self, 'threat_canvas'):
                self.threat_canvas.delete("all")
                self.threat_canvas.create_rectangle(0, 0, 100, 30, fill=color, outline="")
            
        except Exception as e:
            self._log_debug(f"Error updating threat level: {str(e)}")
            import traceback
            self._log_debug(traceback.format_exc())

    def on_finding_select(self, event):
        """Handle selection of a finding in the tree"""
        selection = self.findings_tree.selection()
        if not selection:
            return
        
        # Get the finding data
        item_id = selection[0]
        item_index = self.findings_tree.index(item_id)
        
        # Apply the current filter to get the correct index
        current_filter = self.severity_filter.get().lower()
        filtered_findings = [f for f in self.security_findings 
                           if current_filter == 'all' or 
                           f.get('severity', '').lower() == current_filter]
        
        if item_index >= len(filtered_findings):
            return
        
        finding = filtered_findings[item_index]
        
        # Update overview text
        self.overview_text.config(state=tk.NORMAL)
        self.overview_text.delete(1.0, tk.END)
        
        overview = f"""
        Finding ID: {finding.get('id', 'N/A')}
        
        Timestamp: {finding.get('timestamp', 'N/A')}
        
        Severity: {finding.get('severity', 'N/A').upper()}
        
        Type: {finding.get('type', 'N/A')}
        
        Summary:
        {finding.get('summary', 'N/A')}
        
        Description:
        {finding.get('description', 'N/A')}
        """
        
        self.overview_text.insert(tk.END, overview)
        self.overview_text.config(state=tk.DISABLED)
        
        # Update technical details text
        self.technical_text.config(state=tk.NORMAL)
        self.technical_text.delete(1.0, tk.END)
        
        technical = f"""
        Technical Details:
        {finding.get('technical_details', 'N/A')}
        
        Affected Packets:
        {', '.join(map(str, finding.get('affected_packets', ['N/A'])))}
        
        Related IPs:
        {', '.join(finding.get('related_ips', ['N/A']))}
        """
        
        # Add references if available
        if 'references' in finding and finding['references']:
            technical += "\n\nReferences:\n"
            for ref in finding['references']:
                technical += f"- {ref.get('title', 'N/A')}: {ref.get('url', 'N/A')}\n"
        
        self.technical_text.insert(tk.END, technical)
        self.technical_text.config(state=tk.DISABLED)
        
        # Update recommendations text
        self.recommendations_text.config(state=tk.NORMAL)
        self.recommendations_text.delete(1.0, tk.END)
        
        recommendations = "Recommendations:\n\n"
        
        if 'recommendations' in finding and finding['recommendations']:
            for i, rec in enumerate(finding['recommendations'], 1):
                recommendations += f"{i}. {rec}\n\n"
        else:
            recommendations += "No specific recommendations available."
        
        self.recommendations_text.insert(tk.END, recommendations)
        self.recommendations_text.config(state=tk.DISABLED)

    def clear_finding_details(self):
        """Clear the finding details panes"""
        for text_widget in [self.overview_text, self.technical_text, self.recommendations_text]:
            text_widget.config(state=tk.NORMAL)
            text_widget.delete(1.0, tk.END)
            text_widget.config(state=tk.DISABLED)

    def filter_security_findings(self, event=None):
        """Filter security findings by severity"""
        self.update_security_display()

    def export_security_findings(self):
        """Export security findings to a file"""
        if not self.security_findings:
            messagebox.showinfo("Export", "No security findings to export.")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
            title="Export Security Findings"
        )
        
        if not filename:
            return
        
        try:
            with open(filename, "w") as f:
                # Create export data with metadata
                export_data = {
                    "export_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "total_findings": self.security_summary['total_findings'],
                    "severity_counts": self.security_summary['severity_counts'],
                    "findings": self.security_findings
                }
                
                # Convert sets to lists for JSON serialization
                if 'affected_ips' in self.security_summary:
                    export_data['affected_ips'] = list(self.security_summary['affected_ips'])
                
                json.dump(export_data, f, indent=2)
            
            messagebox.showinfo("Export", f"Security findings exported to {filename}")
        
        except Exception as e:
            messagebox.showerror("Export Error", f"Error exporting findings: {str(e)}")

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
        
        # Security Dashboard tab
        self.security_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.security_frame, text="Security Dashboard")
        
        # Create main security layout with multiple panes
        security_main_pane = ttk.PanedWindow(self.security_frame, orient=tk.VERTICAL)
        security_main_pane.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Security Overview Frame (top)
        security_overview_frame = ttk.LabelFrame(security_main_pane, text="Security Overview")
        security_main_pane.add(security_overview_frame, weight=1)
        
        # Statistics row (threat level indicators)
        security_stats_frame = ttk.Frame(security_overview_frame)
        security_stats_frame.pack(fill=tk.X, expand=False, padx=5, pady=5)
        
        # Create statistics indicators
        self.security_stats = {}
        
        # Threat Level indicator
        threat_frame = ttk.LabelFrame(security_stats_frame, text="Threat Level")
        threat_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.threat_level_var = tk.StringVar(value="Low")
        self.threat_level_label = ttk.Label(threat_frame, textvariable=self.threat_level_var, 
                                           font=("Segoe UI", 12, "bold"))
        self.threat_level_label.pack(side=tk.TOP, pady=5)
        
        self.threat_canvas = tk.Canvas(threat_frame, height=30, width=100)
        self.threat_canvas.pack(side=tk.TOP, pady=5)
        
        # Suspicious Packets indicator
        suspicious_frame = ttk.LabelFrame(security_stats_frame, text="Suspicious Packets")
        suspicious_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.suspicious_count_var = tk.StringVar(value="0")
        self.suspicious_count_label = ttk.Label(suspicious_frame, textvariable=self.suspicious_count_var, 
                                              font=("Segoe UI", 12, "bold"))
        self.suspicious_count_label.pack(side=tk.TOP, pady=5)
        
        # Potential Attacks indicator
        attacks_frame = ttk.LabelFrame(security_stats_frame, text="Potential Attacks")
        attacks_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.attack_count_var = tk.StringVar(value="0")
        self.attack_count_label = ttk.Label(attacks_frame, textvariable=self.attack_count_var, 
                                          font=("Segoe UI", 12, "bold"))
        self.attack_count_label.pack(side=tk.TOP, pady=5)
        
        # Malicious IPs indicator
        malicious_ip_frame = ttk.LabelFrame(security_stats_frame, text="Suspicious IPs")
        malicious_ip_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.malicious_ip_count_var = tk.StringVar(value="0")
        self.malicious_ip_label = ttk.Label(malicious_ip_frame, textvariable=self.malicious_ip_count_var, 
                                          font=("Segoe UI", 12, "bold"))
        self.malicious_ip_label.pack(side=tk.TOP, pady=5)
        
        # Bottom pane containing security findings
        security_findings_pane = ttk.PanedWindow(security_main_pane, orient=tk.HORIZONTAL)
        security_main_pane.add(security_findings_pane, weight=4)
        
        # Left side: Security findings tree
        security_findings_frame = ttk.LabelFrame(security_findings_pane, text="Security Findings")
        security_findings_pane.add(security_findings_frame, weight=1)
        
        # Create a treeview for security findings
        findings_columns = ("id", "timestamp", "severity", "type", "summary")
        self.security_tree = ttk.Treeview(security_findings_frame, columns=findings_columns, show="headings")
        
        # Define findings column headings
        self.security_tree.heading("id", text="#")
        self.security_tree.heading("timestamp", text="Time")
        self.security_tree.heading("severity", text="Severity")
        self.security_tree.heading("type", text="Type")
        self.security_tree.heading("summary", text="Summary")
        
        # Set findings column widths
        self.security_tree.column("id", width=50)
        self.security_tree.column("timestamp", width=150)
        self.security_tree.column("severity", width=80)
        self.security_tree.column("type", width=120)
        self.security_tree.column("summary", width=300)
        
        # Add a scrollbar for findings
        findings_scrollbar = ttk.Scrollbar(security_findings_frame, orient=tk.VERTICAL, 
                                          command=self.security_tree.yview)
        self.security_tree.configure(yscroll=findings_scrollbar.set)
        
        # Pack the findings treeview and scrollbar
        self.security_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        findings_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind selection event to display finding details
        self.security_tree.bind("<<TreeviewSelect>>", self._on_security_finding_select)
        
        # Right side: Finding details explanation
        finding_details_frame = ttk.LabelFrame(security_findings_pane, text="Finding Details & Recommendations")
        security_findings_pane.add(finding_details_frame, weight=1)
        
        # Text area for finding details with hyperlink support
        self.finding_details_text = scrolledtext.ScrolledText(finding_details_frame, 
                                                           font=("Segoe UI", 10), wrap=tk.WORD)
        self.finding_details_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.finding_details_text.tag_configure("heading", font=("Segoe UI", 11, "bold"))
        self.finding_details_text.tag_configure("severity_high", foreground="red", font=("Segoe UI", 10, "bold"))
        self.finding_details_text.tag_configure("severity_medium", foreground="orange", font=("Segoe UI", 10, "bold"))
        self.finding_details_text.tag_configure("severity_low", foreground="blue", font=("Segoe UI", 10, "bold"))
        self.finding_details_text.tag_configure("severity_info", foreground="green", font=("Segoe UI", 10))
        self.finding_details_text.tag_configure("hyperlink", foreground="blue", underline=1)
        
        # Bind click event for finding details hyperlinks
        self.finding_details_text.bind("<Button-1>", self._handle_finding_hyperlink_click)
    
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

    def _handle_finding_hyperlink_click(self, event):
        """Handle clicks on hyperlinks in the finding details text widget"""
        try:
            # Get the position of the click
            index = self.finding_details_text.index(f"@{event.x},{event.y}")
            
            # Get all tags at this position
            tags = self.finding_details_text.tag_names(index)
            
            # Find a tag that looks like a URL
            for tag in tags:
                if tag.startswith("http"):
                    # Open the URL in the default browser
                    import webbrowser
                    webbrowser.open(tag)
                    break
        except Exception as e:
            if self.debug_mode:
                self._log_debug(f"Error handling finding hyperlink click: {str(e)}")
    
    def _on_security_finding_select(self, event):
        """Display details about the selected security finding"""
        try:
            # Get the selected item
            selection = self.security_tree.selection()
            if not selection:
                return
                
            # Get the finding ID
            item_id = self.security_tree.item(selection[0], "values")[0]
            
            # Find the finding in the findings list
            finding = None
            for f in self.security_findings:
                if f['id'] == int(item_id):
                    finding = f
                    break
                    
            if not finding:
                return
                
            # Display finding details
            self._display_finding_details(finding)
            
        except Exception as e:
            if self.debug_mode:
                self._log_debug(f"Error displaying security finding: {str(e)}")
    
    def _display_finding_details(self, finding):
        """Display detailed information about a security finding"""
        try:
            # Clear existing content
            self.finding_details_text.delete(1.0, tk.END)
            
            # Get severity tag
            severity = finding.get('severity', 'info').lower()
            severity_tag = f"severity_{severity}"
            
            # Add title
            self.finding_details_text.insert(tk.END, f"{finding.get('summary', 'Unknown Finding')}\n\n", "heading")
            
            # Add severity
            self.finding_details_text.insert(tk.END, f"Severity: ", "bold")
            self.finding_details_text.insert(tk.END, f"{finding.get('severity', 'Unknown').upper()}\n", severity_tag)
            
            # Add timestamp
            self.finding_details_text.insert(tk.END, f"Detected at: {finding.get('timestamp', 'Unknown')}\n")
            
            # Add type
            self.finding_details_text.insert(tk.END, f"Finding Type: {finding.get('type', 'Unknown')}\n")
            
            # Add description
            self.finding_details_text.insert(tk.END, "\nDescription:\n", "bold")
            self.finding_details_text.insert(tk.END, f"{finding.get('description', 'No description available.')}\n\n")
            
            # Add technical details if available
            if 'technical_details' in finding:
                self.finding_details_text.insert(tk.END, "Technical Details:\n", "bold")
                self.finding_details_text.insert(tk.END, f"{finding['technical_details']}\n\n")
            
            # Add affected packets if available
            if 'affected_packets' in finding and finding['affected_packets']:
                self.finding_details_text.insert(tk.END, "Affected Packets:\n", "bold")
                for packet_id in finding['affected_packets']:
                    self.finding_details_text.insert(tk.END, f"• Packet #{packet_id}\n")
                self.finding_details_text.insert(tk.END, "\n")
            
            # Add IPs or hosts if available
            if 'related_ips' in finding and finding['related_ips']:
                self.finding_details_text.insert(tk.END, "Related IP Addresses:\n", "bold")
                for ip in finding['related_ips']:
                    self.finding_details_text.insert(tk.END, f"• {ip}\n")
                self.finding_details_text.insert(tk.END, "\n")
            
            # Add recommendations
            self.finding_details_text.insert(tk.END, "Recommendations:\n", "bold")
            if 'recommendations' in finding and finding['recommendations']:
                for rec in finding['recommendations']:
                    self.finding_details_text.insert(tk.END, f"• {rec}\n")
            else:
                self.finding_details_text.insert(tk.END, "No specific recommendations available.\n")
            
            # Add reference links if available
            if 'references' in finding and finding['references']:
                self.finding_details_text.insert(tk.END, "\nReferences:\n", "bold")
                for ref in finding['references']:
                    if isinstance(ref, dict) and 'title' in ref and 'url' in ref:
                        self._add_finding_hyperlink(ref['title'], ref['url'])
                    elif isinstance(ref, str) and ref.startswith('http'):
                        self._add_finding_hyperlink(ref, ref)
            
        except Exception as e:
            self.finding_details_text.delete(1.0, tk.END)
            self.finding_details_text.insert(tk.END, f"Error displaying finding details: {str(e)}")
            if self.debug_mode:
                self._log_debug(f"Error in _display_finding_details: {str(e)}")
    
    def _add_finding_hyperlink(self, hyperlink_text, url):
        """Add a hyperlink to the finding details text widget"""
        self.finding_details_text.insert(tk.END, "• ")
        
        # Store the position where the link starts
        start_pos = self.finding_details_text.index(tk.INSERT)
        
        # Insert the link text
        self.finding_details_text.insert(tk.END, hyperlink_text, "hyperlink")
        
        # Store the position where the link ends
        end_pos = self.finding_details_text.index(tk.INSERT)
        
        # Add the URL as a tag
        self.finding_details_text.tag_add(url, start_pos, end_pos)
        
        # Add a newline after the link
        self.finding_details_text.insert(tk.END, "\n")
    
    def _update_security_dashboard(self):
        """Update the security dashboard with current findings"""
        try:
            # Skip if no packets captured yet
            if not hasattr(self, 'all_packets') or not self.all_packets:
                return
                
            # Initialize security findings list if not exists
            if not hasattr(self, 'security_findings'):
                self.security_findings = []
            
            # Analyze current packets for security issues
            new_findings = self._analyze_security_issues()
            
            # Add any new findings to the list
            if new_findings:
                self.security_findings.extend(new_findings)
                
                # Update the security tree with new findings
                for finding in new_findings:
                    self.security_tree.insert("", "end", values=(
                        finding['id'],
                        finding['timestamp'],
                        finding['severity'],
                        finding['type'],
                        finding['summary']
                    ))
            
            # Update security statistics
            self._update_security_stats()
            
            # Update threat level indicator
            self._update_threat_level()
            
        except Exception as e:
            if self.debug_mode:
                self._log_debug(f"Error updating security dashboard: {str(e)}")
                import traceback
                self._log_debug(traceback.format_exc())
    
    def _update_security_stats(self):
        """Update the security statistics indicators"""
        try:
            # Count suspicious packets
            suspicious_count = sum(1 for f in self.security_findings if f['severity'] in ['low', 'medium', 'high'])
            self.suspicious_count_var.set(str(suspicious_count))
            
            # Count potential attacks
            attack_count = sum(1 for f in self.security_findings if 'attack' in f['type'].lower())
            self.attack_count_var.set(str(attack_count))
            
            # Count unique suspicious IPs
            suspicious_ips = set()
            for finding in self.security_findings:
                if 'related_ips' in finding:
                    suspicious_ips.update(finding['related_ips'])
            self.malicious_ip_count_var.set(str(len(suspicious_ips)))
            
        except Exception as e:
            if self.debug_mode:
                self._log_debug(f"Error updating security stats: {str(e)}")
    
    def _update_threat_level(self):
        """Update the threat level indicator based on findings"""
        try:
            # Count findings by severity
            high_count = sum(1 for f in self.security_findings if f['severity'] == 'high')
            medium_count = sum(1 for f in self.security_findings if f['severity'] == 'medium')
            low_count = sum(1 for f in self.security_findings if f['severity'] == 'low')
            
            # Determine overall threat level
            if high_count > 0:
                threat_level = "High"
                color = "#ff0000"  # Red
            elif medium_count > 2:
                threat_level = "Medium"
                color = "#ffa500"  # Orange
            elif medium_count > 0 or low_count > 5:
                threat_level = "Low"
                color = "#ffff00"  # Yellow
            else:
                threat_level = "Minimal"
                color = "#00ff00"  # Green
            
            # Update the threat level label
            self.threat_level_var.set(threat_level)
            
            # Update threat indicator on canvas
            self.threat_canvas.delete("all")
            self.threat_canvas.create_rectangle(0, 0, 100, 30, fill=color, outline="")
            
        except Exception as e:
            if self.debug_mode:
                self._log_debug(f"Error updating threat level: {str(e)}")
    
    def _analyze_security_issues(self):
        """Analyze packets for security issues and return new findings"""
        try:
            # Return early if no packets
            if not self.all_packets:
                return []
                
            # Get the highest finding ID so far
            next_id = 1
            if self.security_findings:
                next_id = max(f['id'] for f in self.security_findings) + 1
                
            # Get timestamp for new findings
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Track which packets we've already analyzed
            if not hasattr(self, 'analyzed_packet_ids'):
                self.analyzed_packet_ids = set()
                
            # Find packets we haven't analyzed yet
            new_packet_ids = set(p['id'] for p in self.all_packets) - self.analyzed_packet_ids
            if not new_packet_ids:
                return []  # No new packets to analyze
                
            # Get new packets
            new_packets = [p for p in self.all_packets if p['id'] in new_packet_ids]
            
            # Add these packets to the analyzed set
            self.analyzed_packet_ids.update(new_packet_ids)
            
            # List to hold new findings
            new_findings = []
            
            # Run detection modules
            self._detect_port_scans(new_packets, new_findings, next_id, timestamp)
            next_id += len(new_findings)
            
            self._detect_suspicious_flags(new_packets, new_findings, next_id, timestamp)
            next_id += len(new_findings)
            
            self._detect_malware_communication(new_packets, new_findings, next_id, timestamp)
            next_id += len(new_findings)
            
            self._detect_data_exfiltration(new_packets, new_findings, next_id, timestamp)
            next_id += len(new_findings)
            
            self._detect_brute_force(new_packets, new_findings, next_id, timestamp)
            
            return new_findings
            
        except Exception as e:
            if self.debug_mode:
                self._log_debug(f"Error analyzing security issues: {str(e)}")
                import traceback
                self._log_debug(traceback.format_exc())
            return []

    def _detect_port_scans(self, packets, findings, next_id, timestamp):
        """
        Detect port scanning activity in the packet capture
        """
        self._log_debug("Detecting port scanning activity")
        
        # Track connections by source IP to destination IP:port
        scan_tracking = {}
        packet_indices = {}
        
        # Define scan thresholds
        PORT_SCAN_THRESHOLD = 10  # Number of unique ports to trigger detection
        TIME_WINDOW = 10          # Time window in seconds to consider for port scans
        
        # First pass - collect data about port access patterns
        for i, packet in enumerate(packets):
            if 'IP' in packet and ('TCP' in packet or 'UDP' in packet):
                src_ip = packet['IP'].src
                dst_ip = packet['IP'].dst
                
                if 'TCP' in packet:
                    dst_port = packet['TCP'].dport
                    flags = packet['TCP'].flags
                    proto = 'TCP'
                    # Only count SYN packets for TCP (typical for scans)
                    if flags != 2:  # SYN flag value is 2
                        continue
                elif 'UDP' in packet:
                    dst_port = packet['UDP'].dport
                    proto = 'UDP'
                else:
                    continue
                
                # Create a key for this source IP
                src_key = src_ip
                
                # Initialize tracking for this source if needed
                if src_key not in scan_tracking:
                    scan_tracking[src_key] = {
                        'targets': {},
                        'packet_time': packet.time,
                        'packets': []
                    }
                
                # Update time to the most recent packet
                scan_tracking[src_key]['packet_time'] = packet.time
                
                # Add to packet indices
                scan_tracking[src_key]['packets'].append(i)
                
                # Create target key
                target_key = f"{dst_ip}:{proto}"
                
                # Initialize target tracking if needed
                if target_key not in scan_tracking[src_key]['targets']:
                    scan_tracking[src_key]['targets'][target_key] = {
                        'ports': set(),
                        'ip': dst_ip,
                        'proto': proto
                    }
                
                # Add the port to the set
                scan_tracking[src_key]['targets'][target_key]['ports'].add(dst_port)
        
        # Second pass - analyze for port scanning patterns
        for src_ip, data in scan_tracking.items():
            for target_key, target_data in data['targets'].items():
                # If enough unique ports were scanned, flag as port scan
                if len(target_data['ports']) >= PORT_SCAN_THRESHOLD:
                    # Create a finding ID
                    finding_id = f"PORTSCAN-{next_id}"
                    next_id += 1
                    
                    # Sort ports for better display
                    sorted_ports = sorted(target_data['ports'])
                    
                    # Determine if this is a specific type of scan
                    common_ports = [20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
                    common_ports_count = sum(1 for port in target_data['ports'] if port in common_ports)
                    common_ports_ratio = common_ports_count / len(target_data['ports']) if target_data['ports'] else 0
                    
                    is_sequential = self._is_sequential_scan(sorted_ports)
                    scan_types = []
                    
                    if common_ports_ratio > 0.8:
                        scan_types.append("common services scan")
                    elif is_sequential:
                        scan_types.append("sequential port scan")
                    else:
                        port_ranges = self._identify_port_ranges(sorted_ports)
                        if len(port_ranges) == 1 and port_ranges[0][1] - port_ranges[0][0] > 200:
                            scan_types.append(f"range scan ({port_ranges[0][0]}-{port_ranges[0][1]})")
                        else:
                            scan_types.append("randomized port scan")
                    
                    scan_type_str = ", ".join(scan_types)
                    
                    # Determine severity based on scan type and scale
                    if len(target_data['ports']) > 100:
                        severity = 'high'  # Large-scale scan
                    elif common_ports_ratio > 0.8:
                        severity = 'medium'  # Targeted at common services
                    else:
                        severity = 'low'  # Smaller scan
                    
                    # Create a meaningful summary
                    summary = f"Port scan detected from {src_ip} to {target_data['ip']} ({len(target_data['ports'])} ports)"
                    
                    # Construct detailed description
                    description = f"Detected a {scan_type_str} from {src_ip} targeting {target_data['ip']} using {target_data['proto']}. The scan covered {len(target_data['ports'])} unique ports."
                    
                    # Add port range information
                    port_ranges = self._identify_port_ranges(sorted_ports)
                    if port_ranges:
                        range_str = ", ".join([f"{start}-{end}" for start, end in port_ranges])
                        description += f"\n\nThe scan covered the following port ranges: {range_str}"
                    else:
                        port_list = ", ".join(str(p) for p in sorted(list(target_data['ports']))[:20])
                        if len(target_data['ports']) > 20:
                            port_list += f", ... ({len(target_data['ports']) - 20} more)"
                        description += f"\n\nSample of scanned ports: {port_list}"
                    
                    # Technical details
                    technical_details = f"Scan details:\n"
                    technical_details += f"- Source IP: {src_ip}\n"
                    technical_details += f"- Target IP: {target_data['ip']}\n"
                    technical_details += f"- Protocol: {target_data['proto']}\n"
                    technical_details += f"- Unique ports scanned: {len(target_data['ports'])}\n"
                    technical_details += f"- Scan type: {scan_type_str}\n\n"
                    
                    # Add information about port distribution
                    port_categories = {
                        'well_known': sum(1 for p in target_data['ports'] if p < 1024),
                        'registered': sum(1 for p in target_data['ports'] if 1024 <= p < 49152),
                        'dynamic': sum(1 for p in target_data['ports'] if p >= 49152)
                    }
                    
                    technical_details += "Port distribution:\n"
                    technical_details += f"- Well-known ports (0-1023): {port_categories['well_known']}\n"
                    technical_details += f"- Registered ports (1024-49151): {port_categories['registered']}\n"
                    technical_details += f"- Dynamic ports (49152-65535): {port_categories['dynamic']}\n\n"
                    
                    # Add common service ports if they were scanned
                    common_scanned = [p for p in common_ports if p in target_data['ports']]
                    if common_scanned:
                        service_map = {
                            20: 'FTP Data', 21: 'FTP Control', 22: 'SSH', 23: 'Telnet',
                            25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
                            111: 'RPC', 135: 'MS RPC', 139: 'NetBIOS', 143: 'IMAP',
                            443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
                            1723: 'PPTP', 3306: 'MySQL', 3389: 'RDP', 5900: 'VNC',
                            8080: 'HTTP Proxy'
                        }
                        
                        technical_details += "Common services scanned:\n"
                        for port in common_scanned:
                            service = service_map.get(port, 'Unknown Service')
                            technical_details += f"- Port {port}: {service}\n"
                    
                    # Recommendations based on finding
                    recommendations = [
                        "Review your firewall rules to ensure unnecessary ports are closed.",
                        "Investigate the source IP to determine if this is a legitimate scan (e.g., from security team) or potential reconnaissance activity.",
                        "Consider implementing rate limiting or other protective measures against port scans.",
                        "Ensure all services running on scanned ports have up-to-date security patches."
                    ]
                    
                    # References for further information
                    references = [
                        {
                            "title": "MITRE ATT&CK: Network Service Scanning (T1046)",
                            "url": "https://attack.mitre.org/techniques/T1046/"
                        },
                        {
                            "title": "Understanding Port Scanning",
                            "url": "https://nmap.org/book/man-port-scanning-basics.html"
                        }
                    ]
                    
                    # Create the finding
                    finding = {
                        'id': finding_id,
                        'timestamp': timestamp,
                        'severity': severity,
                        'type': 'Port Scan',
                        'summary': summary,
                        'description': description,
                        'technical_details': technical_details,
                        'recommendations': recommendations,
                        'affected_packets': data['packets'],
                        'related_ips': [src_ip, target_data['ip']],
                        'references': references
                    }
                    
                    findings.append(finding)
        
        return next_id
    
    def _is_sequential_scan(self, ports):
        """Check if ports are mostly sequential"""
        if not ports or len(ports) < 5:
            return False
        
        # Check if at least 80% of ports are sequential
        sequential_count = 0
        for i in range(1, len(ports)):
            if ports[i] == ports[i-1] + 1:
                sequential_count += 1
        
        return sequential_count >= 0.8 * (len(ports) - 1)
    
    def _identify_port_ranges(self, ports):
        """
        Identify contiguous port ranges from a list of ports
        Returns a list of tuples (start_port, end_port)
        """
        if not ports:
            return []
        
        # Sort ports first
        sorted_ports = sorted(ports)
        
        ranges = []
        range_start = sorted_ports[0]
        prev_port = sorted_ports[0]
        
        for port in sorted_ports[1:]:
            # If there's a gap larger than 1, end the current range
            if port > prev_port + 1:
                ranges.append((range_start, prev_port))
                range_start = port
            prev_port = port
        
        # Add the last range
        ranges.append((range_start, prev_port))
        
        # Consolidate small ranges (less than 5 ports) into individual ports
        consolidated = []
        for start, end in ranges:
            if end - start >= 4:  # Range has at least 5 ports
                consolidated.append((start, end))
        
        return consolidated

    def _detect_suspicious_flags(self, packets, findings, next_id, timestamp):
        """
        Detect suspicious TCP flag combinations that may indicate scanning or evasion techniques
        """
        self._log_debug("Detecting suspicious TCP flags")
        
        # Define suspicious flag combinations
        suspicious_flags = {
            'null_scan': 0,                        # No flags (NULL scan)
            'fin_scan': 0x01,                      # FIN scan
            'xmas_scan': 0x29,                     # FIN, PSH, URG (XMAS scan)
            'maimon_scan': 0x05,                   # FIN, ACK (Maimon scan)
            'syn_fin': 0x03,                       # SYN, FIN (invalid combination)
            'all_flags': 0x3F,                     # All flags set (invalid in normal traffic)
            'ack_scan': 0x10,                      # ACK scan
            'urg_psh_scan': 0x28,                  # URG, PSH (uncommon)
            'urg_fin_scan': 0x21,                  # URG, FIN (uncommon)
            'rst_scan': 0x04                       # RST scan
        }
        
        # Track suspicious packets by source IP
        suspicious_packets = {}
        
        # Analyze each packet for suspicious flags
        for i, packet in enumerate(packets):
            if 'IP' in packet and 'TCP' in packet:
                src_ip = packet['IP'].src
                dst_ip = packet['IP'].dst
                dst_port = packet['TCP'].dport
                flags = packet['TCP'].flags
                
                # Check for suspicious flag combinations
                scan_type = None
                for scan_name, flag_value in suspicious_flags.items():
                    if flags == flag_value:
                        scan_type = scan_name
                        break
                
                if scan_type:
                    # Track by source IP
                    if src_ip not in suspicious_packets:
                        suspicious_packets[src_ip] = {
                            'packets': [],
                            'targets': set(),
                            'scan_types': set(),
                            'ports': set()
                        }
                    
                    # Add to tracking
                    suspicious_packets[src_ip]['packets'].append(i)
                    suspicious_packets[src_ip]['targets'].add(dst_ip)
                    suspicious_packets[src_ip]['scan_types'].add(scan_type)
                    suspicious_packets[src_ip]['ports'].add(dst_port)
        
        # Generate findings for sources with suspicious packets
        for src_ip, data in suspicious_packets.items():
            # Only create a finding if there are enough suspicious packets
            if len(data['packets']) >= 3:
                # Create a finding ID
                finding_id = f"SCANFLAG-{next_id}"
                next_id += 1
                
                # Convert sets to sorted lists for display
                target_ips = sorted(list(data['targets']))
                scan_types = sorted(list(data['scan_types']))
                ports = sorted(list(data['ports']))
                
                # Format scan types for display
                scan_names = {
                    'null_scan': "NULL scan (no flags)",
                    'fin_scan': "FIN scan",
                    'xmas_scan': "XMAS scan (FIN, PSH, URG)",
                    'maimon_scan': "Maimon scan (FIN, ACK)",
                    'syn_fin': "SYN-FIN scan (invalid flags)",
                    'all_flags': "All flags set scan",
                    'ack_scan': "ACK scan",
                    'urg_psh_scan': "URG-PSH scan",
                    'urg_fin_scan': "URG-FIN scan",
                    'rst_scan': "RST scan"
                }
                
                scan_types_display = [scan_names.get(st, st) for st in scan_types]
                
                # Determine severity based on scan type and scale
                if 'xmas_scan' in scan_types or 'null_scan' in scan_types or 'syn_fin' in scan_types:
                    severity = 'high'  # More sophisticated scan techniques
                elif len(data['packets']) > 10:
                    severity = 'medium'  # Multiple suspicious packets
                else:
                    severity = 'low'  # Few suspicious packets
                
                # Create a meaningful summary
                if len(scan_types) == 1:
                    summary = f"Detected {scan_names.get(scan_types[0], scan_types[0])} from {src_ip}"
                else:
                    summary = f"Multiple suspicious scan techniques detected from {src_ip}"
                
                # Construct detailed description
                description = f"Detected {len(data['packets'])} packets with suspicious TCP flag combinations sent from {src_ip} to {len(target_ips)} unique target IPs."
                
                if len(scan_types) == 1:
                    description += f"\n\nThe scan technique appears to be a {scan_names.get(scan_types[0], scan_types[0])}, which is often used for stealth scanning to evade detection by simple firewall rules."
                else:
                    description += f"\n\nMultiple scanning techniques were detected: {', '.join(scan_types_display)}. This suggests a deliberate port scanning activity using advanced techniques."
                
                # Add target information
                if len(target_ips) <= 5:
                    description += f"\n\nTarget IPs: {', '.join(target_ips)}"
                else:
                    description += f"\n\nTarget IPs include: {', '.join(target_ips[:5])} and {len(target_ips) - 5} more."
                
                # Technical details
                technical_details = f"Scan details:\n"
                technical_details += f"- Source IP: {src_ip}\n"
                technical_details += f"- Suspicious packets: {len(data['packets'])}\n"
                technical_details += f"- Unique targets: {len(target_ips)}\n"
                technical_details += f"- Scan techniques: {', '.join(scan_types_display)}\n\n"
                
                # Add explanation of the techniques
                technical_details += "Technique explanations:\n"
                for st in scan_types:
                    if st == 'null_scan':
                        technical_details += "- NULL scan: No TCP flags set. This can bypass simple firewall rules that filter based on specific flags.\n"
                    elif st == 'fin_scan':
                        technical_details += "- FIN scan: Only the FIN flag is set. Closed ports often respond to these with RST packets, while open ports may drop them.\n"
                    elif st == 'xmas_scan':
                        technical_details += "- XMAS scan: FIN, PSH, and URG flags are set, making the packet 'lit up like a Christmas tree'. Used for stealth scanning.\n"
                    elif st == 'maimon_scan':
                        technical_details += "- Maimon scan: FIN and ACK flags set. A specialized technique named after its discoverer.\n"
                    elif st == 'syn_fin':
                        technical_details += "- SYN-FIN scan: Both SYN and FIN flags set, which is invalid in normal TCP. May bypass certain filters.\n"
                    elif st == 'all_flags':
                        technical_details += "- All flags scan: All TCP flags set at once, which is highly unusual in legitimate traffic.\n"
                    elif st == 'ack_scan':
                        technical_details += "- ACK scan: Only the ACK flag is set. Used to map firewall rulesets and identify filtering behavior.\n"
                    elif st == 'urg_psh_scan':
                        technical_details += "- URG-PSH scan: URG and PSH flags set. Uncommon in normal traffic and may indicate scanning activity.\n"
                    elif st == 'urg_fin_scan':
                        technical_details += "- URG-FIN scan: URG and FIN flags set. Another uncommon combination used in stealth scanning.\n"
                    elif st == 'rst_scan':
                        technical_details += "- RST scan: Only the RST flag is set. Unusual as a first packet in a connection and may indicate scanning.\n"
                
                # Add port information
                if ports:
                    port_ranges = self._identify_port_ranges(ports)
                    if port_ranges:
                        range_str = ", ".join([f"{start}-{end}" for start, end in port_ranges])
                        technical_details += f"\nPort ranges scanned: {range_str}\n"
                    else:
                        port_list = ", ".join(str(p) for p in ports[:20])
                        if len(ports) > 20:
                            port_list += f", ... ({len(ports) - 20} more)"
                        technical_details += f"\nPorts scanned: {port_list}\n"
                
                # Recommendations based on finding
                recommendations = [
                    "Configure your firewall to detect and block these types of scans.",
                    "Monitor the source IP for further suspicious activity.",
                    "Consider implementing IDS/IPS systems that can detect advanced scanning techniques.",
                    "Use a stateful firewall that can properly track TCP connection states."
                ]
                
                # References for further information
                references = [
                    {
                        "title": "MITRE ATT&CK: Network Service Scanning (T1046)",
                        "url": "https://attack.mitre.org/techniques/T1046/"
                    },
                    {
                        "title": "TCP Flag Scans and Their Detection",
                        "url": "https://nmap.org/book/man-port-scanning-techniques.html"
                    },
                    {
                        "title": "Stealth Port Scanning Methods",
                        "url": "https://www.sans.org/reading-room/whitepapers/testing/stealth-port-scanning-methods-32514"
                    }
                ]
                
                # Create the finding
                finding = {
                    'id': finding_id,
                    'timestamp': timestamp,
                    'severity': severity,
                    'type': 'Suspicious TCP Flags',
                    'summary': summary,
                    'description': description,
                    'technical_details': technical_details,
                    'recommendations': recommendations,
                    'affected_packets': data['packets'],
                    'related_ips': [src_ip] + target_ips[:5],  # Include source and up to 5 targets
                    'references': references
                }
                
                findings.append(finding)
        
        return next_id

    def _detect_malware_communication(self, packets, findings, next_id, timestamp):
        """
        Detect potential malware communication patterns in packets
        """
        self._log_debug("Detecting malware communication patterns")
        
        # Known malicious IP ranges and domains (for demonstration purposes)
        # In a real tool, this would be regularly updated from threat intelligence feeds
        malicious_ips = [
            '185.147.14.0/24',   # Example range - not necessarily real malicious IPs  
            '103.35.74.0/24',    # Example range
            '91.92.136.0/24',    # Example range
            '192.0.2.1',         # Documentation example IP
            '198.51.100.23',     # Documentation example IP  
            '203.0.113.42'       # Documentation example IP
        ]
        
        malicious_domains = [
            'evil-malware.example',
            'ransomware.test',
            'malicious.local',
            'badware.invalid'
        ]
        
        # Common C2 ports
        c2_ports = [
            4444,  # Metasploit
            1080,  # SOCKS proxy
            8080,  # Alternative HTTP
            8443,  # Alternative HTTPS
            6666,  # IRC alternative
            4343,  # Common trojan port
            31337, # Elite port used by backdoors
        ]
        
        # Malicious patterns in payloads
        malicious_patterns = [
            rb'(?i)\\x00CMD\\x00',             # Command injection marker
            rb'(?i)(eval|system|exec)\s*\([\'"]', # PHP shell command execution  
            rb'(?i)<script>.*?<\/script>',     # Suspicious script tags
            rb'(?i)(?:fromcharcode|eval\(|\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2})', # Obfuscation
            rb'(?i)(?:powershell|cmd\.exe|bash|\/bin\/sh)\s+-[ce]', # Command line execution
        ]
        
        # Create IP network objects for CIDR notation
        ip_networks = []
        for ip in malicious_ips:
            try:
                if '/' in ip:
                    # This is a network range in CIDR notation
                    ip_networks.append(ip)
                else:
                    # Single IP address
                    ip_networks.append(ip)
            except Exception as e:
                self._log_debug(f"Error processing malicious IP {ip}: {str(e)}")
        
        # Track suspicious connections
        suspicious_connections = {}
        packet_indices = {}
        
        # Analyze each packet
        for i, packet in enumerate(packets):
            if 'IP' in packet and ('TCP' in packet or 'UDP' in packet):
                src_ip = packet['IP'].src
                dst_ip = packet['IP'].dst
                
                # Check if destination IP matches any malicious IP or network
                is_malicious_ip = False
                for network in ip_networks:
                    if '/' in network:
                        # Check if the IP falls within this network range
                        # A proper implementation would use ipaddress module for this check
                        network_base = network.split('/')[0]
                        if dst_ip.startswith(network_base.rsplit('.', 1)[0]):
                            is_malicious_ip = True
                            break
                    elif dst_ip == network:
                        is_malicious_ip = True
                        break
                
                # Extract protocol specific information
                if 'TCP' in packet:
                    src_port = packet['TCP'].sport
                    dst_port = packet['TCP'].dport
                    proto = 'TCP'
                elif 'UDP' in packet:
                    src_port = packet['UDP'].sport
                    dst_port = packet['UDP'].dport
                    proto = 'UDP'
                else:
                    continue
                
                # Check for suspicious port usage
                is_c2_port = dst_port in c2_ports
                
                # Check for malicious DNS lookups
                is_malicious_domain = False
                domain_requested = None
                if 'DNS' in packet and hasattr(packet['DNS'], 'qd') and packet['DNS'].qd:
                    for query in packet['DNS'].qd:
                        if hasattr(query, 'qname'):
                            domain = query.qname.decode('utf-8', errors='ignore').lower().rstrip('.')
                            domain_requested = domain
                            for bad_domain in malicious_domains:
                                if bad_domain in domain:
                                    is_malicious_domain = True
                                    break
                            if is_malicious_domain:
                                break
                
                # Check for malicious payload patterns
                has_malicious_pattern = False
                matched_pattern = None
                if Raw in packet:
                    payload = bytes(packet[Raw].load)
                    for pattern in malicious_patterns:
                        if re.search(pattern, payload):
                            has_malicious_pattern = True
                            matched_pattern = pattern
                            break
                
                # Flag the connection if any suspicious indicator is found
                if is_malicious_ip or is_c2_port or is_malicious_domain or has_malicious_pattern:
                    conn_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
                    
                    if conn_key not in suspicious_connections:
                        suspicious_connections[conn_key] = {
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'src_port': src_port,
                            'dst_port': dst_port,
                            'protocol': proto,
                            'first_seen': timestamp,
                            'packet_count': 1,
                            'reasons': set(),
                            'domain': domain_requested,
                            'pattern': matched_pattern,
                            'packets': [i]
                        }
                    else:
                        suspicious_connections[conn_key]['packet_count'] += 1
                        suspicious_connections[conn_key]['packets'].append(i)
                    
                    # Add reasons for flagging
                    reasons = suspicious_connections[conn_key]['reasons']
                    if is_malicious_ip:
                        reasons.add('malicious_ip')
                    if is_c2_port:
                        reasons.add('c2_port')
                    if is_malicious_domain:
                        reasons.add('malicious_domain')
                    if has_malicious_pattern:
                        reasons.add('malicious_pattern')
        
        # Generate findings for suspicious connections
        for conn_key, conn_info in suspicious_connections.items():
            # Create a finding ID
            finding_id = f"MALWARE-{next_id}"
            next_id += 1
            
            # Determine severity based on evidence
            reasons = conn_info['reasons']
            if 'malicious_pattern' in reasons or len(reasons) > 1:
                severity = 'critical'
            elif 'malicious_ip' in reasons or 'malicious_domain' in reasons:
                severity = 'high'
            else:
                severity = 'medium'
            
            # Create a meaningful summary
            if 'malicious_domain' in reasons:
                summary = f"Potential malware communication to malicious domain: {conn_info['domain']}"
            elif 'malicious_ip' in reasons:
                summary = f"Communication with known malicious IP address: {conn_info['dst_ip']}"
            elif 'malicious_pattern' in reasons:
                summary = f"Malicious payload detected in communication"
            else:
                summary = f"Suspicious communication using potential C2 port {conn_info['dst_port']}"
            
            # Construct detailed description
            description = f"Detected potentially malicious network traffic between {conn_info['src_ip']}:{conn_info['src_port']} and {conn_info['dst_ip']}:{conn_info['dst_port']} using {conn_info['protocol']}."
            
            # Add specific details based on the reasons
            if 'malicious_ip' in reasons:
                description += f"\n\nThe destination IP address {conn_info['dst_ip']} matches a known malicious IP address or range."
            
            if 'c2_port' in reasons:
                description += f"\n\nThe destination port {conn_info['dst_port']} is commonly used for command and control (C2) communication."
            
            if 'malicious_domain' in reasons:
                description += f"\n\nThe DNS query for domain {conn_info['domain']} matches a known malicious domain pattern."
            
            if 'malicious_pattern' in reasons:
                description += f"\n\nThe packet payload contains patterns indicative of malicious activity or exploitation attempts."
            
            # Technical details
            technical_details = f"Connection details:\n"
            technical_details += f"- Source IP: {conn_info['src_ip']}\n"
            technical_details += f"- Source Port: {conn_info['src_port']}\n"
            technical_details += f"- Destination IP: {conn_info['dst_ip']}\n"
            technical_details += f"- Destination Port: {conn_info['dst_port']}\n"
            technical_details += f"- Protocol: {conn_info['protocol']}\n"
            technical_details += f"- First seen: {conn_info['first_seen']}\n"
            technical_details += f"- Packet count: {conn_info['packet_count']}\n\n"
            
            technical_details += "Detection reasons:\n"
            for reason in reasons:
                technical_details += f"- {reason.replace('_', ' ').title()}\n"
            
            if conn_info['domain']:
                technical_details += f"\nDomain requested: {conn_info['domain']}\n"
            
            if conn_info['pattern']:
                technical_details += f"\nMatched pattern: {str(conn_info['pattern'])}\n"
            
            # Recommendations based on finding
            recommendations = [
                "Block communication with the identified IP address or domain at your firewall or security gateway.",
                "Scan the source system for malware using an up-to-date antivirus scanner.",
                "Check system logs for signs of compromise or unusual activity.",
                "If communication was from a critical system, consider isolating it for further investigation."
            ]
            
            # References for further information
            references = [
                {
                    "title": "MITRE ATT&CK: Command and Control",
                    "url": "https://attack.mitre.org/tactics/TA0011/"
                },
                {
                    "title": "Understanding Malware Command and Control Channels",
                    "url": "https://www.sans.org/reading-room/whitepapers/detection/understanding-command-control-channels-malware-detection-32969"
                }
            ]
            
            # Create the finding
            finding = {
                'id': finding_id,
                'timestamp': timestamp,
                'severity': severity,
                'type': 'Malware Communication',
                'summary': summary,
                'description': description,
                'technical_details': technical_details,
                'recommendations': recommendations,
                'affected_packets': conn_info['packets'],
                'related_ips': [conn_info['src_ip'], conn_info['dst_ip']],
                'references': references
            }
            
            findings.append(finding)
        
        return next_id

    def _detect_data_exfiltration(self, packets, findings, next_id, timestamp):
        """
        Detect potential data exfiltration by analyzing outbound data volumes and patterns
        """
        self._log_debug("Detecting data exfiltration patterns")
        
        # Define thresholds and detection parameters
        VOLUME_THRESHOLD = 1000000  # 1MB in bytes 
        DNS_QUERY_LENGTH_THRESHOLD = 50  # Suspicious DNS query length
        DNS_TXT_THRESHOLD = 5  # Number of DNS TXT queries to flag
        ICMP_DATA_THRESHOLD = 500  # Bytes of ICMP data
        HTTP_POST_THRESHOLD = 500000  # 500KB HTTP POST
        
        # Unusual destination ports that could indicate tunneling
        unusual_ports = [53, 123, 1900, 67, 68, 5353, 137, 161, 162]
        
        # Track data flows by connection
        data_flows = {}
        dns_queries = {}
        icmp_data = {}
        
        # Track local subnets to identify outbound traffic
        local_subnets = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]
        
        # Analyze each packet
        for i, packet in enumerate(packets):
            if 'IP' in packet:
                src_ip = packet['IP'].src
                dst_ip = packet['IP'].dst
                
                # Check if source is local and destination is external
                is_src_local = any(self._ip_in_subnet(src_ip, subnet) for subnet in local_subnets)
                is_dst_local = any(self._ip_in_subnet(dst_ip, subnet) for subnet in local_subnets)
                
                if is_src_local and not is_dst_local:
                    # Track TCP/UDP data flows
                    if 'TCP' in packet or 'UDP' in packet:
                        proto = 'TCP' if 'TCP' in packet else 'UDP'
                        src_port = packet[proto].sport
                        dst_port = packet[proto].dport
                        
                        # Create connection key
                        conn_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
                        
                        # Initialize connection tracking
                        if conn_key not in data_flows:
                            data_flows[conn_key] = {
                                'src_ip': src_ip,
                                'dst_ip': dst_ip,
                                'src_port': src_port,
                                'dst_port': dst_port,
                                'protocol': proto,
                                'bytes_out': 0,
                                'packet_count': 0,
                                'start_time': packet.time,
                                'last_time': packet.time,
                                'packets': []
                            }
                        
                        # Calculate payload size
                        payload_size = 0
                        if Raw in packet:
                            payload_size = len(packet[Raw].load)
                        
                        # Update flow statistics
                        data_flows[conn_key]['bytes_out'] += payload_size
                        data_flows[conn_key]['packet_count'] += 1
                        data_flows[conn_key]['last_time'] = packet.time
                        data_flows[conn_key]['packets'].append(i)
                    
                    # Track ICMP data
                    elif 'ICMP' in packet and Raw in packet:
                        icmp_payload = packet[Raw].load
                        
                        if src_ip not in icmp_data:
                            icmp_data[src_ip] = {
                                'destinations': {},
                                'total_bytes': 0,
                                'packets': []
                            }
                        
                        icmp_data[src_ip]['packets'].append(i)
                        icmp_data[src_ip]['total_bytes'] += len(icmp_payload)
        
        # Create findings for large data transfers
        for conn_key, flow in data_flows.items():
            if flow['bytes_out'] > VOLUME_THRESHOLD:
                # Create a finding ID
                finding_id = f"EXFIL-{next_id}"
                next_id += 1
                
                # Calculate flow duration and rate
                duration = flow['last_time'] - flow['start_time']
                rate_bytes_per_sec = flow['bytes_out'] / duration if duration > 0 else flow['bytes_out']
                
                # Determine severity based on volume
                severity = 'low'
                if flow['bytes_out'] > VOLUME_THRESHOLD * 10:  # 10MB+
                    severity = 'high'
                elif flow['bytes_out'] > VOLUME_THRESHOLD * 5:  # 5MB+
                    severity = 'medium'
                
                # Create a meaningful summary
                summary = f"Large data transfer: {flow['bytes_out'] / 1000000:.2f} MB sent from {flow['src_ip']} to {flow['dst_ip']}"
                
                # Construct detailed description
                description = f"Detected a large outbound data transfer of {flow['bytes_out'] / 1000000:.2f} MB from {flow['src_ip']} to {flow['dst_ip']}:{flow['dst_port']} using {flow['protocol']}."
                description += f"\n\nThe transfer occurred over {duration:.2f} seconds at a rate of {rate_bytes_per_sec / 1000:.2f} KB/s."
                
                # Technical details
                technical_details = f"Data Flow Details:\n"
                technical_details += f"- Source IP: {flow['src_ip']}\n"
                technical_details += f"- Source Port: {flow['src_port']}\n"
                technical_details += f"- Destination IP: {flow['dst_ip']}\n"
                technical_details += f"- Destination Port: {flow['dst_port']}\n"
                technical_details += f"- Protocol: {flow['protocol']}\n"
                technical_details += f"- Total Bytes Sent: {flow['bytes_out']} ({flow['bytes_out'] / 1000000:.2f} MB)\n"
                technical_details += f"- Duration: {duration:.2f} seconds\n"
                technical_details += f"- Rate: {rate_bytes_per_sec / 1000:.2f} KB/s\n"
                technical_details += f"- Packet Count: {flow['packet_count']}\n"
                
                # Recommendations
                recommendations = [
                    "Investigate the source system to identify what application is sending this data.",
                    "Review the destination to ensure it is a legitimate service or destination.",
                    "If this is not an expected data transfer, isolate the source system for further analysis.",
                    "Consider implementing data loss prevention (DLP) controls to monitor and restrict large outbound transfers."
                ]
                
                # References
                references = [
                    {
                        "title": "MITRE ATT&CK: Exfiltration Over Other Network Medium (T1011)",
                        "url": "https://attack.mitre.org/techniques/T1011/"
                    },
                    {
                        "title": "Data Exfiltration Detection and Prevention",
                        "url": "https://www.sans.org/reading-room/whitepapers/detection/detecting-preventing-data-exfiltration-unauthorized-data-copying-35447"
                    }
                ]
                
                # Create the finding
                finding = {
                    'id': finding_id,
                    'timestamp': timestamp,
                    'severity': severity,
                    'type': 'Potential Data Exfiltration',
                    'summary': summary,
                    'description': description,
                    'technical_details': technical_details,
                    'recommendations': recommendations,
                    'affected_packets': flow['packets'],
                    'related_ips': [flow['src_ip'], flow['dst_ip']],
                    'references': references
                }
                
                findings.append(finding)
        
        # Check for ICMP tunneling (simplified)
        for src_ip, data in icmp_data.items():
            if data['total_bytes'] > ICMP_DATA_THRESHOLD:
                finding_id = f"EXFIL-ICMP-{next_id}"
                next_id += 1
                
                severity = 'medium'
                
                finding = {
                    'id': finding_id,
                    'timestamp': timestamp,
                    'severity': severity,
                    'type': 'ICMP Tunneling',
                    'summary': f"Potential ICMP tunneling detected from {src_ip}",
                    'description': f"Detected abnormal amount of ICMP data ({data['total_bytes']} bytes) from {src_ip}.",
                    'technical_details': f"Source IP: {src_ip}\nICMP data bytes: {data['total_bytes']}\nPacket count: {len(data['packets'])}",
                    'recommendations': [
                        "Investigate the source system for signs of compromise.",
                        "Consider restricting ICMP traffic if not required."
                    ],
                    'affected_packets': data['packets'],
                    'related_ips': [src_ip],
                    'references': [
                        {
                            "title": "ICMP Tunneling Techniques",
                            "url": "https://attack.mitre.org/techniques/T1048/"
                        }
                    ]
                }
                
                findings.append(finding)
        
        return next_id

    def _detect_brute_force(self, packets, findings, next_id, timestamp):
        """Detect potential brute force password attacks"""
        try:
            # Track authentication attempts by source/destination/service
            auth_attempts = {}
            
            # Common authentication service ports
            auth_services = {
                '22': 'SSH',
                '23': 'Telnet',
                '3389': 'RDP',
                '21': 'FTP',
                '25': 'SMTP',
                '110': 'POP3',
                '143': 'IMAP',
                '445': 'SMB',
                '1433': 'MSSQL',
                '3306': 'MySQL',
                '5432': 'PostgreSQL',
                '5900': 'VNC'
            }
            
            # Analyze packets for potential authentication attempts
            for packet in packets:
                protocol = packet.get('protocol', '').upper()
                src_ip = packet.get('src_ip', 'Unknown')
                dst_ip = packet.get('dst_ip', 'Unknown')
                dst_port = packet.get('dst_port', 'Unknown')
                tcp_flags = packet.get('tcp_flags', '')
                
                # Skip if essential fields are missing
                if src_ip == 'Unknown' or dst_ip == 'Unknown' or dst_port == 'Unknown':
                    continue
                
                # Skip non-TCP packets for most services (could add UDP for some)
                if protocol != 'TCP':
                    continue
                
                # Check if this is a known authentication service
                if dst_port in auth_services:
                    service = auth_services[dst_port]
                    
                    # Create key for this src-dst-service combo
                    key = f"{src_ip}_{dst_ip}_{dst_port}"
                    
                    # Initialize tracking for this key
                    if key not in auth_attempts:
                        auth_attempts[key] = {
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'dst_port': dst_port,
                            'service': service,
                            'syn_count': 0,
                            'packet_ids': set(),
                            'connection_attempts': 0
                        }
                    
                    # Count SYN packets as potential new connection attempts
                    if 'SYN' in tcp_flags and 'ACK' not in tcp_flags:
                        auth_attempts[key]['syn_count'] += 1
                        auth_attempts[key]['connection_attempts'] += 1
                    
                    # Count certain packet size combinations for intelligent guessing
                    # This is a simplification - real detection would be protocol-specific
                    auth_attempts[key]['packet_ids'].add(packet['id'])
            
            # Define thresholds for brute force detection
            # These would ideally be configurable
            connection_threshold = {
                'SSH': 10,
                'Telnet': 10,
                'RDP': 10,
                'FTP': 15,
                'SMTP': 20,
                'POP3': 15,
                'IMAP': 15,
                'SMB': 10,
                'MSSQL': 10,
                'MySQL': 10,
                'PostgreSQL': 10,
                'VNC': 10,
                'default': 15
            }
            
            # Check for potential brute force attacks
            for key, data in auth_attempts.items():
                service = data['service']
                threshold = connection_threshold.get(service, connection_threshold['default'])
                
                # Check if connection attempts exceed threshold
                if data['connection_attempts'] >= threshold:
                    finding = {
                        'id': next_id,
                        'timestamp': timestamp,
                        'severity': 'high',
                        'type': 'Potential Brute Force',
                        'summary': f"Potential {service} brute force from {data['src_ip']}",
                        'description': (f"Detected {data['connection_attempts']} connection attempts "
                                      f"from {data['src_ip']} to {service} service on {data['dst_ip']}. "
                                      f"This pattern is consistent with a brute force password attack."),
                        'technical_details': (f"Source IP: {data['src_ip']}\n"
                                           f"Target IP: {data['dst_ip']}\n"
                                           f"Target Port: {data['dst_port']} ({service})\n"
                                           f"Connection Attempts: {data['connection_attempts']}\n"
                                           f"SYN Packets: {data['syn_count']}"),
                        'affected_packets': list(data['packet_ids'])[:100] + (['...'] if len(data['packet_ids']) > 100 else []),
                        'related_ips': [data['src_ip'], data['dst_ip']],
                        'recommendations': [
                            f"Temporarily block {data['src_ip']} at your firewall.",
                            f"Check {service} logs on {data['dst_ip']} for failed login attempts.",
                            "Implement account lockout policies if not already in place.",
                            "Consider rate limiting authentication attempts.",
                            "Implement multi-factor authentication if possible."
                        ],
                        'references': [
                            {'title': 'MITRE ATT&CK - Brute Force', 'url': 'https://attack.mitre.org/techniques/T1110/'},
                            {'title': 'Password Attack Prevention', 'url': 'https://www.sans.org/security-resources/passwords'}
                        ]
                    }
                    findings.append(finding)
                    next_id += 1
            
            return findings
            
        except Exception as e:
            if self.debug_mode:
                self._log_debug(f"Error in brute force detection: {str(e)}")
                import traceback
                self._log_debug(traceback.format_exc())
            return findings

    def perform_security_analysis(self):
        """
        Main function to orchestrate security analysis on captured packets.
        Returns a list of security findings.
        """
        self._log_debug("Starting security analysis")
        
        # Initialize findings list
        findings = []
        
        # Create a timestamp for the analysis
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Initialize finding ID counter
        next_id = 1
        
        try:
            # Make sure we have packets to analyze
            if not self.packets:
                self._log_debug("No packets to analyze")
                return []
                
            self._log_debug(f"Analyzing {len(self.packets)} packets")
            
            # Execute various detection modules
            self._log_debug("Running port scan detection")
            next_id = self._detect_port_scans(self.packets, findings, next_id, timestamp)
            self._log_debug(f"After port scan detection: {len(findings)} findings")
            
            self._log_debug("Running suspicious flags detection")
            next_id = self._detect_suspicious_flags(self.packets, findings, next_id, timestamp)
            self._log_debug(f"After suspicious flags detection: {len(findings)} findings")
            
            self._log_debug("Running malware communication detection")
            next_id = self._detect_malware_communication(self.packets, findings, next_id, timestamp)
            self._log_debug(f"After malware communication detection: {len(findings)} findings")
            
            self._log_debug("Running data exfiltration detection")
            next_id = self._detect_data_exfiltration(self.packets, findings, next_id, timestamp)
            self._log_debug(f"After data exfiltration detection: {len(findings)} findings")
            
            self._log_debug("Running brute force detection")
            next_id = self._detect_brute_force(self.packets, findings, next_id, timestamp)
            self._log_debug(f"After brute force detection: {len(findings)} findings")
            
            # Sort findings by severity
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
            findings.sort(key=lambda x: severity_order.get(x.get('severity', 'info').lower(), 5))
            
            # Generate a test finding if no findings were detected
            if not findings and self.debug_mode:
                self._log_debug("No findings detected, generating a test finding")
                test_finding = {
                    'id': f"TEST-1",
                    'timestamp': timestamp,
                    'severity': 'medium',
                    'type': 'Test Finding',
                    'summary': "Test security finding",
                    'description': "This is a test security finding to verify the dashboard is working correctly.",
                    'technical_details': "No technical details for test finding",
                    'recommendations': ["This is just a test", "No real actions needed"],
                    'affected_packets': [],
                    'related_ips': []
                }
                findings.append(test_finding)
            
            self._log_debug(f"Security analysis complete. Found {len(findings)} issues.")
            
            return findings
            
        except Exception as e:
            self._log_debug(f"Error in security analysis: {str(e)}")
            import traceback
            self._log_debug(traceback.format_exc())
            
            # Create an error finding
            error_finding = {
                'id': f"ERROR-{next_id}",
                'timestamp': timestamp,
                'severity': 'info',
                'type': 'Analysis Error',
                'summary': f"Error during security analysis: {str(e)}",
                'description': f"An error occurred during the security analysis process. Some results may be incomplete.\n\nError details: {str(e)}",
                'technical_details': traceback.format_exc(),
                'recommendations': [
                    "Check the application logs for more details.",
                    "Ensure the packets were captured correctly.",
                    "Try analyzing a smaller subset of packets if the dataset is large."
                ],
                'affected_packets': [],
                'related_ips': []
            }
            
            findings.append(error_finding)
            return findings
    
    def _generate_security_summary(self, findings):
        """
        Generate a summary of security findings for dashboard display
        """
        self._log_debug("Generating security summary")
        
        # Initialize summary data
        summary = {
            'total_findings': len(findings),
            'severity_counts': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            },
            'finding_types': {},
            'affected_ips': set(),
            'highest_severity': 'info'
        }
        
        # Severity ranking for determining highest severity
        severity_rank = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1,
            'info': 0
        }
        
        highest_severity_rank = -1
        
        # Process each finding
        for finding in findings:
            # Count by severity
            severity = finding.get('severity', 'info').lower()
            summary['severity_counts'][severity] += 1
            
            # Update highest severity
            current_rank = severity_rank.get(severity, 0)
            if current_rank > highest_severity_rank:
                highest_severity_rank = current_rank
                summary['highest_severity'] = severity
            
            # Count by type
            finding_type = finding.get('type', 'Unknown')
            if finding_type not in summary['finding_types']:
                summary['finding_types'][finding_type] = 0
            summary['finding_types'][finding_type] += 1
            
            # Collect affected IPs
            if 'related_ips' in finding:
                for ip in finding['related_ips']:
                    summary['affected_ips'].add(ip)
        
        # Convert sets to lists for easier handling
        # (This will be done during export to avoid modifying the original data)
        
        return summary

    def _ip_in_subnet(self, ip, subnet):
        """Check if an IP address is within a CIDR subnet"""
        # Simple string-based prefix check for demonstration
        # A proper implementation would use ipaddress module
        net_parts = subnet.split('/')
        net_prefix = net_parts[0].rsplit('.', 1)[0]  # Get network prefix
        
        return ip.startswith(net_prefix)

if __name__ == "__main__":
    root = tk.Tk()
    app = SnifferGUI(root)
    root.mainloop()