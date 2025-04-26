import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import os
import sys
import pandas as pd
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import subprocess
import csv
import time

# Import the sniffer functionality
from sniffer import get_windows_if_list, capture_network_details, get_next_available_filename

# Add ThreadedSniffer class
class ThreadedSniffer(threading.Thread):
    """Thread class for running packet capture in the background"""
    def __init__(self, interface, output_file, callback=None, capture_time=30):
        threading.Thread.__init__(self)
        self.interface = interface
        self.output_file = os.path.abspath(output_file)  # Ensure we have absolute path
        self.callback = callback
        self.capture_time = capture_time
        self.daemon = True  # Thread will exit when main program exits
        
    def run(self):
        """Main execution method for the thread"""
        try:
            # Pass a positive integer for capture duration
            capture_duration = self.capture_time if self.capture_time is not None else 3600  # Use 1 hour as default
            
            # Wait until previous file operations complete
            time.sleep(0.5)
            
            # Ensure output directory exists
            output_dir = os.path.dirname(self.output_file)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            print(f"Starting capture to file: {self.output_file}")
            
            # Call the capture function
            result = capture_network_details(self.interface, capture_duration)
            
            # Handle the result correctly
            if result:
                csv_path, _ = result if isinstance(result, tuple) else (result, None)
                
                # Print detailed outcome for debugging
                print(f"Capture completed. CSV file: {csv_path}")
                
                if self.callback:
                    # Make sure we're passing the absolute path to the callback
                    abs_path = os.path.abspath(csv_path)
                    self.callback(f"Capture completed: {abs_path}")
            else:
                # If capture returns None but our output file exists, use that instead
                if os.path.exists(self.output_file):
                    print(f"Capture function returned None, but output file exists: {self.output_file}")
                    if self.callback:
                        self.callback(f"Capture completed: {self.output_file}")
                else:
                    # No file was created
                    print("Capture failed: No results returned and no output file exists")
                    if self.callback:
                        self.callback("Capture failed: No results returned")
                
        except Exception as e:
            print(f"Error in ThreadedSniffer: {str(e)}")
            if self.callback:
                self.callback(f"Error in capture: {str(e)}")

class SnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Threat Hunter")
        self.root.geometry("1200x800")
        self.root.minsize(800, 600)
        
        # Interface and capture variables
        self.interface_var = tk.StringVar()
        self.capture_time_var = tk.StringVar(value="30")
        self.is_capturing = False
        self.capture_thread = None
        self.current_csv = None
        
        # Real-time capture is now default
        self.realtime_var = tk.BooleanVar(value=True)
        self.passive_var = tk.BooleanVar(value=False)
        
        # Create main frame
        main_frame = ttk.Frame(root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Create header with app title
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(header_frame, text="Network Threat Hunter", 
                 font=("Segoe UI", 18, "bold")).pack(side=tk.LEFT)
        
        # Create upper frame for controls
        control_frame = ttk.LabelFrame(main_frame, text="Capture Controls")
        control_frame.pack(fill=tk.X, pady=10, padx=5, ipadx=10, ipady=10)
        
        # Interface selection with better layout
        interface_frame = ttk.Frame(control_frame)
        interface_frame.pack(fill=tk.X, pady=(10, 5), padx=10)
        
        ttk.Label(interface_frame, text="Network Interface:", 
                 font=("Segoe UI", 10)).pack(side=tk.LEFT, padx=(0, 10))
        
        self.interface_combo = ttk.Combobox(interface_frame, textvariable=self.interface_var, width=50)
        self.interface_combo.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        refresh_button = ttk.Button(interface_frame, text="Refresh", command=self.refresh_interfaces)
        refresh_button.pack(side=tk.LEFT, padx=5)
        
        # Capture mode selection
        mode_frame = ttk.Frame(control_frame)
        mode_frame.pack(fill=tk.X, pady=5, padx=10)
        
        ttk.Label(mode_frame, text="Capture Mode:", 
                 font=("Segoe UI", 10)).pack(side=tk.LEFT, padx=(0, 10))
                 
        # Add radio buttons for capture mode
        realtime_radio = ttk.Radiobutton(mode_frame, text="Real-time Capture", 
                                        variable=self.realtime_var, value=True,
                                        command=self.toggle_capture_mode)
        realtime_radio.pack(side=tk.LEFT, padx=5)
        
        passive_radio = ttk.Radiobutton(mode_frame, text="Passive Capture", 
                                       variable=self.realtime_var, value=False,
                                       command=self.toggle_capture_mode)
        passive_radio.pack(side=tk.LEFT, padx=5)
        
        # Capture time with better layout
        time_frame = ttk.Frame(control_frame)
        time_frame.pack(fill=tk.X, pady=10, padx=10)
        
        ttk.Label(time_frame, text="Capture Duration (seconds):", 
                 font=("Segoe UI", 10)).pack(side=tk.LEFT, padx=(0, 10))
        
        # Default capture time entry should be disabled because real-time is default
        self.capture_time_entry = ttk.Entry(time_frame, textvariable=self.capture_time_var, width=10, state='disabled')
        self.capture_time_entry.pack(side=tk.LEFT, padx=5)
        
        # Capture control buttons - WITH FILE MANAGEMENT
        button_frame = ttk.Frame(control_frame)
        button_frame.pack(pady=10, padx=10, fill=tk.X)
        
        # Create capture button frame on the left
        capture_btn_frame = ttk.Frame(button_frame)
        capture_btn_frame.pack(side=tk.LEFT, fill=tk.Y)
        
        self.start_button = ttk.Button(capture_btn_frame, text="Start Real-time Capture", command=self.start_capture, width=20)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        # Add a separate button for passive capture
        passive_capture_btn = ttk.Button(capture_btn_frame, text="Start Passive Capture", 
                                       command=self.start_passive_capture, width=20)
        passive_capture_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(capture_btn_frame, text="Stop Capture", command=self.stop_capture, state=tk.DISABLED, width=15)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        # Create CSV file management sections in the control frame
        file_buttons_frame = ttk.Frame(button_frame)
        file_buttons_frame.pack(side=tk.RIGHT, fill=tk.Y)
        
        # CSV file management buttons - moved next to capture controls
        ttk.Button(file_buttons_frame, text="Open CSV", 
                  command=self.open_csv, width=12).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(file_buttons_frame, text="Export", 
                  command=self.export_results, width=10).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(file_buttons_frame, text="View Files", 
                  command=self.list_all_captures, width=12).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(file_buttons_frame, text="Load External", 
                  command=self.load_external_csv, width=12).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(file_buttons_frame, text="Open Directory", 
                  command=self.open_csv_directory, width=12).pack(side=tk.LEFT, padx=5)
        
        # Create tabs for different views
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Live capture tab
        self.live_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.live_tab, text="Live Capture")
        
        # Create header frame for title and controls
        live_header_frame = ttk.Frame(self.live_tab, padding=5)
        live_header_frame.pack(fill=tk.X)
        
        ttk.Label(live_header_frame, text="Live Network Packet Capture", 
                 font=("Segoe UI", 12, "bold")).pack(side=tk.LEFT, padx=5)
                 
        # Create packet counter display
        self.packet_counter_var = tk.StringVar(value="Packets: 0")
        ttk.Label(live_header_frame, textvariable=self.packet_counter_var,
                font=("Segoe UI", 10)).pack(side=tk.RIGHT, padx=10)
        
        # Create live display frame
        live_frame = ttk.Frame(self.live_tab, padding=10)
        live_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create text widget with a better monospace font for packet display
        self.live_text = scrolledtext.ScrolledText(
            live_frame, 
            wrap=tk.WORD, 
            background="white", 
            foreground="black",
            font=("Consolas", 10)  # Use monospace font
        )
        self.live_text.pack(fill=tk.BOTH, expand=True)
        
        # Add a header to the live capture
        header_text = "=== Network Packet Capture ===\n"
        header_text += "Timestamp | Protocol | Source → Destination | Info\n"
        header_text += "-----------------------------------------------------\n"
        self.live_text.insert(tk.END, header_text, "header")
        
        # Statistics tab with visualizations
        self.stats_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.stats_tab, text="Analytics")
        
        # Create a frame for text stats and visualizations
        self.stats_frame = ttk.Frame(self.stats_tab, padding=10)
        self.stats_frame.pack(fill=tk.BOTH, expand=True)
        
        # Left side for text stats
        stats_left = ttk.Frame(self.stats_frame)
        stats_left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # Add a label for stats
        ttk.Label(stats_left, text="Capture Statistics", 
                 font=("Segoe UI", 12, "bold")).pack(side=tk.TOP, anchor=tk.W, pady=(0, 5))
        
        self.stats_text = scrolledtext.ScrolledText(stats_left, wrap=tk.WORD, background="white", foreground="black")
        self.stats_text.pack(fill=tk.BOTH, expand=True)
        
        # Right side for visualizations
        self.stats_right = ttk.Frame(self.stats_frame)
        self.stats_right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        # Add a label for visualizations
        ttk.Label(self.stats_right, text="Visualizations", 
                 font=("Segoe UI", 12, "bold")).pack(side=tk.TOP, anchor=tk.W, pady=(0, 5))
        
        # Visualization tabs
        self.viz_notebook = ttk.Notebook(self.stats_right)
        self.viz_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create visualization tabs
        self.protocol_tab = ttk.Frame(self.viz_notebook, padding=5)
        self.viz_notebook.add(self.protocol_tab, text="Protocols")
        
        self.ip_tab = ttk.Frame(self.viz_notebook, padding=5)
        self.viz_notebook.add(self.ip_tab, text="IP Analysis")
        
        self.traffic_tab = ttk.Frame(self.viz_notebook, padding=5)
        self.viz_notebook.add(self.traffic_tab, text="Traffic Flow")
        
        # Network Data tab (for viewing CSV data)
        self.data_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.data_tab, text="Network Data")
        
        # Create a frame for the data table
        data_frame = ttk.Frame(self.data_tab, padding=10)
        data_frame.pack(fill=tk.BOTH, expand=True)
        
        # Add a Treeview widget for the data with styled appearance
        tree_frame = ttk.Frame(data_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        # Add a scrollbar for horizontal scrolling
        h_scrollbar = ttk.Scrollbar(tree_frame, orient="horizontal")
        h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Add a scrollbar for vertical scrolling
        v_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical")
        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Configure the treeview with scrollbars
        self.tree = ttk.Treeview(tree_frame, 
                                xscrollcommand=h_scrollbar.set,
                                yscrollcommand=v_scrollbar.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Configure the scrollbars
        h_scrollbar.config(command=self.tree.xview)
        v_scrollbar.config(command=self.tree.yview)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(main_frame, textvariable=self.status_var, 
                                   relief=tk.SUNKEN, anchor=tk.W, padding=(10, 5))
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM, pady=5)
        
        # Initialize packet buffer for real-time capturing
        self.packet_buffer = []
        self.realtime_capturing = False
        self.realtime_update_id = None
        self.max_display_packets = 10000  # Maximum number of packets to store in memory
        
        # Initialize interface list
        self.refresh_interfaces()
        
        # Set up real-time display by default
        self.setup_realtime_display()
        
        # Create or reset the temp capture file
        self.create_temp_capture_file()
    
    def refresh_interfaces(self):
        """Refresh the list of network interfaces"""
        self.status_var.set("Refreshing network interfaces...")
        interfaces = get_windows_if_list()
        
        if interfaces:
            self.interface_combo['values'] = interfaces
            self.interface_combo.current(0)
            self.status_var.set(f"Found {len(interfaces)} network interfaces")
        else:
            self.status_var.set("No network interfaces found")
            messagebox.showwarning("Warning", "No network interfaces found")
    
    def toggle_capture_mode(self):
        """Toggle between real-time and passive capture modes"""
        if self.realtime_var.get():
            # Real-time mode selected
            self.passive_var.set(False)
            self.capture_time_entry.config(state='disabled')
            self.start_button.configure(text="Start Real-time Capture")
        else:
            # Passive mode selected
            self.passive_var.set(True)
            self.capture_time_entry.config(state='normal')
            self.start_button.configure(text="Start Passive Capture")
    
    def start_realtime_default(self):
        """Start real-time capture by default when the app launches"""
        if self.interface_var.get() and not self.is_capturing:
            # Only auto-start if an interface is selected and we're not already capturing
            self.toggle_capture_mode()  # Make sure UI is consistent
            self.start_capture()
    
    def start_passive_capture(self):
        """Start a passive (non-real-time) capture"""
        # Set capture mode to passive
        self.passive_var.set(True)
        self.realtime_var.set(False)
        
        # Enable capture time entry
        self.capture_time_entry.config(state='normal')
        
        # Don't immediately start the capture - let the user edit the duration first
        # Just update UI and wait for the user to press the Start button
        self.status_var.set("Passive capture mode - set duration and press Start")
        
        # Change start button text
        self.start_button.configure(text="Start Passive Capture")
    
    def start_capture(self):
        """Start packet capture"""
        if not self.interface_var.get():
            messagebox.showerror("Error", "Please select a network interface")
            return
        
        try:
            # Determine capture mode based on passive checkbox
            if self.passive_var.get():
                # Passive (time-limited) capture
                capture_time = int(self.capture_time_var.get())
                if capture_time <= 0:
                    raise ValueError("Capture time must be positive")
                self.realtime_capturing = False
            else:
                # Real-time capture (default)
                capture_time = 0  # Continuous capture
                self.realtime_capturing = True
            
            # Clear displays
            self.live_text.delete(1.0, tk.END)
            self.stats_text.delete(1.0, tk.END)
            
            # Clear visualizations
            for widget in self.protocol_tab.winfo_children():
                widget.destroy()
            for widget in self.ip_tab.winfo_children():
                widget.destroy()
            for widget in self.traffic_tab.winfo_children():
                widget.destroy()
            
            # Clear packet buffer for real-time mode
            self.packet_buffer = []
            
            # Clear treeview for real-time mode
            for item in self.tree.get_children():
                self.tree.delete(item)
            
            # Update UI state
            self.is_capturing = True
            self.start_button.configure(state=tk.DISABLED)
            self.stop_button.configure(state=tk.NORMAL)
            
            # For real-time mode, set up the display before starting the capture
            if self.realtime_capturing:
                # Set up columns for real-time display
                self.setup_realtime_display()
                # Switch to the data tab to show real-time updates
                self.notebook.select(self.data_tab)
            
            # Start capture in a thread
            self.status_var.set(f"Starting capture on {self.interface_var.get()}...")
            self.capture_thread = threading.Thread(
                target=self.run_capture,
                args=(self.interface_var.get(), capture_time)
            )
            self.capture_thread.daemon = True
            self.capture_thread.start()
            
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid capture time: {str(e)}")
            return
    
    def setup_realtime_display(self):
        """Set up the treeview columns for real-time packet display"""
        # Configure columns for the treeview
        columns = [
            'timestamp', 'source_ip', 'destination_ip', 'protocol', 
            'length', 'source_port', 'destination_port', 'packet_direction'
        ]
        self.tree["columns"] = columns
        
        # Configure column headings
        self.tree.column("#0", width=0, stretch=tk.NO)  # Hide the first column
        
        # Configure column widths
        column_widths = {
            'timestamp': 150,
            'source_ip': 120,
            'destination_ip': 120,
            'protocol': 80,
            'length': 60,
            'source_port': 80,
            'destination_port': 80,
            'packet_direction': 100
        }
        
        # Set up columns
        for col in columns:
            width = column_widths.get(col, 100)
            self.tree.column(col, anchor=tk.W, width=width)
            self.tree.heading(col, text=col.replace('_', ' ').title(), anchor=tk.W)
        
        # Configure row colors
        self.tree.tag_configure('inbound', background='#EF9A9A')  # Red for inbound
        self.tree.tag_configure('outbound', background='#A5D6A7')  # Green for outbound
        
        # Configure text colors for live_text widget
        self.live_text.tag_configure('header', foreground='#000080', font=("Consolas", 10, "bold"))
        self.live_text.tag_configure('inbound', foreground='#B71C1C')  # Dark red for inbound
        self.live_text.tag_configure('outbound', foreground='#1B5E20')  # Dark green for outbound
    
    def update_realtime_display(self):
        """Update the display with new packets in real-time mode"""
        if not self.realtime_capturing:
            print("Real-time capturing is disabled, not updating display")
            return
        
        # Print status for debugging
        print(f"Updating real-time display. Current CSV: {self.current_csv}")
        
        # Check if the current CSV file exists
        csv_file_to_use = None
        
        # Try the expected path first
        if self.current_csv and os.path.exists(self.current_csv):
            csv_file_to_use = self.current_csv
            print(f"Using existing CSV file at path: {csv_file_to_use}")
        else:
            print(f"Primary CSV path not found: {self.current_csv}")
            print("Searching for CSV files in multiple locations...")
            
            # Search in current directory first
            print("Looking in current directory...")
            potential_files = [f for f in os.listdir('.') if f.endswith('.csv')]
            
            # If no files found, also check the workspace root directory
            if not potential_files:
                try:
                    # Get the absolute path to determine workspace root
                    current_dir = os.path.abspath('.')
                    parent_dir = os.path.dirname(current_dir)
                    
                    print(f"Looking in parent directory: {parent_dir}")
                    if os.path.exists(parent_dir):
                        potential_files.extend([os.path.join(parent_dir, f) 
                                              for f in os.listdir(parent_dir) 
                                              if f.endswith('.csv')])
                except Exception as e:
                    print(f"Error checking parent directory: {e}")
            
            # If still no files, check common subdirectories
            common_dirs = ['output', 'data', 'captures', 'temp']
            for directory in common_dirs:
                if not potential_files and os.path.exists(directory):
                    print(f"Looking in {directory} directory...")
                    potential_files.extend([os.path.join(directory, f) 
                                          for f in os.listdir(directory) 
                                          if f.endswith('.csv')])
            
            # Filter for all_packets files if multiple CSVs found
            all_packets_files = [f for f in potential_files if 'all_packets' in os.path.basename(f)]
            if all_packets_files:
                potential_files = all_packets_files
            
            # If we found files, sort by modification time and use the most recent
            if potential_files:
                print(f"Found {len(potential_files)} potential CSV files:")
                for i, file in enumerate(potential_files):
                    try:
                        size = os.path.getsize(file)
                        mod_time = os.path.getmtime(file)
                        print(f"  {i+1}. {file} - Size: {size} bytes, Modified: {datetime.fromtimestamp(mod_time)}")
                    except:
                        print(f"  {i+1}. {file} - Error getting details")
                
                # Sort by modification time to get the most recent
                try:
                    potential_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
                    csv_file_to_use = potential_files[0]
                    print(f"Selected most recent CSV file: {csv_file_to_use}")
                    # Update current_csv to use this file in future
                    self.current_csv = csv_file_to_use
                except Exception as e:
                    print(f"Error sorting files by modification time: {e}")
            else:
                print("No CSV files found in any location")
        
        # If we found a file to use, try to read it
        if csv_file_to_use:
            try:
                # Read the CSV file
                print(f"Reading CSV file: {csv_file_to_use}")
                # Wrap in try/except to handle file access issues
                try:
                    with open(csv_file_to_use, 'r') as f:
                        # Just checking if we can open the file
                        pass
                    
                    # If we can open the file, read it with pandas
                    df = pd.read_csv(csv_file_to_use)
                    
                    if not df.empty:
                        print(f"CSV contains {len(df)} rows")
                        # Get count of currently displayed packets
                        current_count = len(self.tree.get_children())
                        print(f"Currently displaying {current_count} packets")
                        
                        # If there are new rows to display
                        if len(df) > current_count:
                            # Get only the new rows
                            new_rows = df.iloc[current_count:]
                            print(f"Adding {len(new_rows)} new rows to display")
                            
                            # Add the new rows to the display
                            self.add_rows_to_treeview(new_rows)
                            
                            # Also add to live capture text
                            self.update_live_text(new_rows)
                            
                            # Update status
                            self.status_var.set(f"Capturing packets in real-time. Total: {len(df)}")
                    else:
                        print("CSV file is empty")
                except PermissionError:
                    print(f"Permission denied accessing file: {csv_file_to_use}")
                except FileNotFoundError:
                    print(f"File not found during read: {csv_file_to_use}")
            except Exception as e:
                # Print errors from reading incomplete files
                print(f"Error reading CSV during real-time update: {e}")
        else:
            print(f"No suitable CSV file found")
        
        # Schedule the next update if still capturing
        if self.realtime_capturing:
            print("Scheduling next update in 1 second")
            self.realtime_update_id = self.root.after(1000, self.update_realtime_display)
    
    def update_live_text(self, new_rows):
        """Update the live capture text widget with new packet data"""
        # Format each row into a readable string and add to the live text widget
        for _, row in new_rows.iterrows():
            try:
                # Format packet information
                packet_info = f"[{row.get('timestamp', 'unknown')}] "
                
                # Add protocol info
                if 'protocol' in row:
                    packet_info += f"{str(row['protocol']).upper()} "
                
                # Add IP info
                if 'source_ip' in row and 'destination_ip' in row:
                    src_ip = row['source_ip'] if row['source_ip'] != 'N/A' else '-'
                    dst_ip = row['destination_ip'] if row['destination_ip'] != 'N/A' else '-'
                    packet_info += f"{src_ip} → {dst_ip} "
                
                # Add port info
                if 'source_port' in row and 'destination_port' in row:
                    if row['source_port'] != 'N/A' and row['destination_port'] != 'N/A':
                        packet_info += f"(Port {row['source_port']} → {row['destination_port']}) "
                
                # Add packet length
                if 'length' in row:
                    packet_info += f"Size: {row['length']} bytes "
                
                # Add direction
                if 'packet_direction' in row:
                    packet_info += f"[{row['packet_direction']}]"
                
                # Add new line and insert into text widget
                packet_info += "\n"
                
                # Set text color based on direction
                if 'packet_direction' in row:
                    direction = str(row['packet_direction']).lower()
                    if 'inbound' in direction:
                        self.live_text.insert(tk.END, packet_info, "inbound")
                    elif 'outbound' in direction:
                        self.live_text.insert(tk.END, packet_info, "outbound")
                    else:
                        self.live_text.insert(tk.END, packet_info)
                else:
                    self.live_text.insert(tk.END, packet_info)
                
                # Auto-scroll to the latest entry
                self.live_text.see(tk.END)
                
            except Exception as e:
                print(f"Error formatting packet for live display: {e}")
                # Add a simple fallback format
                self.live_text.insert(tk.END, f"Packet: {dict(row)}\n")
                self.live_text.see(tk.END)
                
        # Update the packet counter
        current_packet_count = len(self.tree.get_children())
        self.packet_counter_var.set(f"Packets: {current_packet_count}")
    
    def stop_capture(self):
        """Stop packet capture"""
        if self.is_capturing:
            self.is_capturing = False
            self.realtime_capturing = False
            self.status_var.set("Stopping capture...")
            self.stop_button.configure(state=tk.DISABLED)
            
            # Cancel any pending real-time updates
            if self.realtime_update_id:
                self.root.after_cancel(self.realtime_update_id)
                self.realtime_update_id = None
    
    def update_status(self, message):
        """Update status bar with message from capture thread"""
        # Update the status bar
        self.status_var.set(message)
        
        # Log the message for debugging
        print(f"Status update: {message}")
        
        # Check if we need to refresh the display for capture completion
        if "completed" in message.lower():
            # Extract the CSV filename from the message if present
            csv_path = None
            if ":" in message:
                csv_path = message.split(":", 1)[1].strip()
                
                # Verify the path exists
                if os.path.exists(csv_path):
                    print(f"Found capture CSV file: {csv_path}")
                    self.current_csv = csv_path
                else:
                    print(f"Warning: CSV file not found at path: {csv_path}")
                    # Try to find the file in the current directory or output directory
                    if os.path.exists(os.path.basename(csv_path)):
                        self.current_csv = os.path.basename(csv_path)
                        print(f"Found CSV file in current directory: {self.current_csv}")
                    elif os.path.exists(os.path.join("output", os.path.basename(csv_path))):
                        self.current_csv = os.path.join("output", os.path.basename(csv_path))
                        print(f"Found CSV file in output directory: {self.current_csv}")
            
            # Check if we have a valid CSV file - either the one specified in the message
            # or the one we were monitoring for real-time updates
            if self.current_csv and os.path.exists(self.current_csv):
                # Reset the UI and show results
                self.reset_ui()
                self.show_capture_results()
                self.view_csv_data()
            else:
                # Look for any recently created CSV files
                try:
                    # First look for all_packets files
                    csv_files = [f for f in os.listdir('.') if f.endswith('.csv') and f.startswith('all_packets')]
                    if not csv_files:
                        # Then look in the output directory
                        if os.path.exists('output'):
                            csv_files = [os.path.join('output', f) for f in os.listdir('output') 
                                       if f.endswith('.csv') and f.startswith('capture_')]
                        # Last resort, look for any CSV files
                        if not csv_files:
                            csv_files = [f for f in os.listdir('.') if f.endswith('.csv')]
                    
                    if csv_files:
                        # Sort by modification time (newest first)
                        csv_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
                        self.current_csv = csv_files[0]
                        print(f"Found most recent CSV file: {self.current_csv}")
                        
                        # Reset the UI and show results
                        self.reset_ui()
                        self.show_capture_results()
                        self.view_csv_data()
                        return
                except Exception as e:
                    print(f"Error searching for CSV files: {e}")
                
                # If we still have no file, show error
                self.reset_ui()
                self.status_var.set("Capture completed, but no data file was created")
                messagebox.showwarning("No Data", "Capture completed, but no data file was created")
    
    def complete_capture(self):
        """Called when timed capture completes"""
        if self.is_capturing:
            self.stop_capture()
            print("Capture completed, looking for CSV files...")
            
            # Check if we already have a valid CSV file
            if self.current_csv and os.path.exists(self.current_csv):
                print(f"Using existing CSV file: {self.current_csv}")
                self.reset_ui()
                self.show_capture_results()
                self.view_csv_data()
                return
            
            # If not, look for CSV files
            try:
                # First look for all_packets files
                csv_files = [f for f in os.listdir('.') if f.endswith('.csv') and f.startswith('all_packets')]
                if not csv_files:
                    # Then look in the output directory
                    if os.path.exists('output'):
                        csv_files = [os.path.join('output', f) for f in os.listdir('output') 
                                   if f.endswith('.csv')]
                
                if csv_files:
                    # Sort by modification time (newest first)
                    csv_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
                    self.current_csv = csv_files[0]
                    print(f"Found most recent CSV file: {self.current_csv}")
                    
                    self.reset_ui()
                    self.show_capture_results()
                    self.view_csv_data()
                else:
                    # No CSV file found
                    self.reset_ui()
                    self.status_var.set("Capture completed, but no data file was created")
                    messagebox.showwarning("No Data", "Capture completed, but no data file was created")
            except Exception as e:
                print(f"Error searching for CSV files: {e}")
                self.reset_ui()
                self.status_var.set(f"Error: {str(e)}")
        else:
            # Not capturing, just reset UI
            self.reset_ui()
    
    def schedule_updates(self):
        """Schedule periodic UI updates for real-time capture"""
        if self.is_capturing:
            # Update display if we have data
            if os.path.exists(self.current_csv):
                try:
                    # Try to read the CSV file that's being written to
                    df = pd.read_csv(self.current_csv)
                    if not df.empty:
                        self.status_var.set(f"Capturing packets in real-time. Total: {len(df)}")
                        # Just reload the last few rows if there's new data
                        current_count = len(self.tree.get_children())
                        if len(df) > current_count:
                            # There are new rows to display
                            new_rows = df.iloc[current_count:]
                            self.add_rows_to_treeview(new_rows)
                except Exception as e:
                    # Ignore errors from reading incomplete files
                    pass
                
            # Check again in 1 second
            self.root.after(1000, self.schedule_updates)
    
    def add_rows_to_treeview(self, df):
        """Add dataframe rows to the treeview"""
        if df.empty:
            print("No rows to add to treeview - dataframe is empty")
            return
            
        print(f"Adding {len(df)} rows to treeview")
        # Replace NaN values with "N/A" for better display
        df = df.fillna("N/A")
        
        # Format special columns
        if 'protocol' in df.columns:
            df['protocol'] = df['protocol'].astype(str).str.upper()
            
        if 'packet_direction' in df.columns:
            df['packet_direction'] = df['packet_direction'].astype(str).str.capitalize()
        
        # Add the rows to the treeview
        for _, row in df.iterrows():
            values = row.tolist()
            # Convert all values to strings with proper formatting
            values = [str(val).strip() for val in values]
            
            # Apply row color based on packet direction if that column exists
            tag = ""
            if 'packet_direction' in df.columns:
                packet_direction_index = df.columns.get_loc('packet_direction')
                direction = values[packet_direction_index].lower()
                
                # Add with tags for coloring
                if 'inbound' in direction:
                    tag = 'inbound'
                elif 'outbound' in direction:
                    tag = 'outbound'
            
            # Insert at beginning to show newest first
            self.tree.insert("", 0, values=values, tags=(tag,))
            
        # Limit the number of displayed packets
        while len(self.tree.get_children()) > self.max_display_packets:
            # Remove oldest packets (at the end)
            last_item = self.tree.get_children()[-1]
            self.tree.delete(last_item)
            
        print(f"Now displaying {len(self.tree.get_children())} rows in treeview")
    
    def run_capture(self, interface, capture_time):
        """Execute the capture process"""
        try:
            # Create a redirector for stdout to capture live output
            class StdoutRedirector:
                def __init__(self, text_widget):
                    self.text_widget = text_widget
                    self.original_stdout = sys.stdout
                
                def write(self, string):
                    self.original_stdout.write(string)
                    self.text_widget.insert(tk.END, string)
                    self.text_widget.see(tk.END)
                    
                    # Check if the string contains a path to a CSV file we should be monitoring
                    if '.csv' in string and 'Full path to CSV file:' in string:
                        try:
                            # Extract the path
                            path = string.split('Full path to CSV file:')[1].strip()
                            # Update the current_csv
                            self.text_widget.master.master.master.current_csv = path
                            print(f"Detected CSV file path from output: {path}")
                        except Exception as e:
                            print(f"Error parsing CSV path from output: {e}")
                
                def flush(self):
                    self.original_stdout.flush()
            
            # Clear previous output
            self.live_text.delete(1.0, tk.END)
            
            # Add a header to the live capture
            header_text = "=== Network Packet Capture ===\n"
            header_text += "Timestamp | Protocol | Source → Destination | Info\n"
            header_text += "-----------------------------------------------------\n"
            self.live_text.insert(tk.END, header_text, "header")
            
            # Redirect stdout to the text widget
            stdout_redirector = StdoutRedirector(self.live_text)
            original_stdout = sys.stdout
            sys.stdout = stdout_redirector
            
            # Get selected interface name
            interface_name = interface
            
            if not interface_name:
                messagebox.showerror("Error", "Please select a network interface")
                return
            
            # Create the output directory if it doesn't exist
            if not os.path.exists("output"):
                os.makedirs("output")
            
            # Create a fresh temp capture file that we'll initially monitor
            self.create_temp_capture_file()
            
            # First, let's check for existing CSV files that might be useful
            print("Preparing for capture, checking for existing CSV files...")
            try:
                # Look for all_packets files in the current directory
                old_csv_files = [f for f in os.listdir('.') if f.endswith('.csv') and f.startswith('all_packets')]
                for file in old_csv_files:
                    try:
                        # Check if the file is a valid CSV and has some rows
                        try:
                            df = pd.read_csv(file)
                            if len(df) > 0:
                                print(f"Found existing file with {len(df)} rows: {file}")
                            else:
                                print(f"Found empty CSV file: {file}")
                        except:
                            print(f"Invalid CSV file: {file} - will be ignored")
                    except:
                        pass
            except Exception as e:
                print(f"Error checking existing CSV files: {e}")
            
            print(f"Starting capture process. Will search for CSV files as they're created.")
            
            # If passive is selected, use timed capture, otherwise use real-time mode
            if self.passive_var.get():
                # Get the capture time
                try:
                    capture_time = int(self.capture_time_var.get())
                    if capture_time <= 0:
                        raise ValueError("Capture time must be positive")
                except ValueError as e:
                    messagebox.showerror("Error", str(e))
                    return
                
                print(f"Starting passive capture for {capture_time} seconds")
                
                # Update button text back to normal
                self.start_button.configure(text="Start Real-time Capture")
                
                # Make sure we set the notebook to display the live capture output
                self.notebook.select(self.live_tab)
                
                # Start the sniffer with a time limit
                self.sniffer = ThreadedSniffer(
                    interface_name, 
                    "output/ignored_filename.csv",  # This won't be used by the sniffer module
                    callback=self.update_status,
                    capture_time=capture_time
                )
                self.sniffer.start()
                
                # Schedule the capture to complete
                self.root.after(capture_time * 1000 + 1000, self.complete_capture)
            else:
                # Start real-time sniffer
                print("Starting real-time capture")
                
                # For real-time, we'll use a shorter duration and continuously restart 
                # to ensure we get regular updates (30 minutes at a time)
                self.sniffer = ThreadedSniffer(
                    interface_name, 
                    "output/ignored_filename.csv",  # This won't be used by the sniffer module
                    callback=self.update_status,
                    capture_time=1800  # 30 minutes at a time
                )
                self.sniffer.start()
                self.status_var.set(f"Starting real-time capture on {interface_name}...")
                
                # Enable real-time updates
                self.realtime_capturing = True
                
                # Set up real-time display
                self.setup_realtime_display()
                
                # For real-time, we'll show both live capture and data tabs
                # Use a custom frame to hold buttons for switching between views
                tab_switcher = ttk.Frame(self.live_tab)
                tab_switcher.pack(fill=tk.X, pady=5)
                
                ttk.Label(tab_switcher, text="View packet data in:").pack(side=tk.LEFT, padx=5)
                
                ttk.Button(tab_switcher, text="Live View", 
                          command=lambda: self.notebook.select(self.live_tab)).pack(side=tk.LEFT, padx=5)
                
                ttk.Button(tab_switcher, text="Data Table", 
                          command=lambda: self.notebook.select(self.data_tab)).pack(side=tk.LEFT, padx=5)
                
                # Start with the live capture tab visible
                self.notebook.select(self.live_tab)
                
                # Wait a bit longer before starting updates to ensure file is created
                print("Scheduling first real-time display update in 5 seconds")
                self.root.after(5000, self.update_realtime_display)
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start capture: {str(e)}")
            self.status_var.set(f"Error: {str(e)}")
            
        finally:
            # Restore the original stdout
            sys.stdout = original_stdout
    
    def reset_ui(self):
        """Reset UI state after capture"""
        self.is_capturing = False
        self.start_button.configure(state=tk.NORMAL)
        self.stop_button.configure(state=tk.DISABLED)
    
    def show_capture_results(self):
        """Display capture statistics and visualizations"""
        if self.current_csv and os.path.exists(self.current_csv):
            try:
                # Read the CSV file and generate statistics
                df = pd.read_csv(self.current_csv)
                
                stats = []
                stats.append(f"=== Capture Statistics ===")
                stats.append(f"Capture time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                stats.append(f"Total packets: {len(df)}")
                stats.append(f"CSV File: {self.current_csv}")
                stats.append("")
                
                # Protocol distribution
                protocol_data = None
                if 'protocol' in df.columns:
                    stats.append("Protocol Distribution:")
                    protocol_counts = df['protocol'].value_counts()
                    protocol_data = protocol_counts
                    for protocol, count in protocol_counts.items():
                        stats.append(f"  {protocol}: {count} ({count/len(df)*100:.2f}%)")
                
                # Source IP distribution
                source_data = None
                if 'source_ip' in df.columns:
                    stats.append("\nTop Source IPs:")
                    source_counts = df['source_ip'].value_counts().head(10)
                    source_data = source_counts
                    for ip, count in source_counts.items():
                        stats.append(f"  {ip}: {count}")
                
                # Destination IP distribution
                dest_data = None
                if 'destination_ip' in df.columns:
                    stats.append("\nTop Destination IPs:")
                    dest_counts = df['destination_ip'].value_counts().head(10)
                    dest_data = dest_counts
                    for ip, count in dest_counts.items():
                        stats.append(f"  {ip}: {count}")
                
                # Traffic direction
                direction_data = None
                if 'packet_direction' in df.columns:
                    stats.append("\nTraffic Direction:")
                    direction_counts = df['packet_direction'].value_counts()
                    direction_data = direction_counts
                    for direction, count in direction_counts.items():
                        stats.append(f"  {direction}: {count} ({count/len(df)*100:.2f}%)")
                
                # TCP Flags (if present)
                tcp_flags_data = None
                if 'tcp_flags' in df.columns:
                    tcp_data = df[df['protocol'] == 'TCP']
                    if not tcp_data.empty:
                        stats.append("\nTCP Flags Distribution:")
                        flag_counts = tcp_data['tcp_flags'].value_counts().head(10)
                        tcp_flags_data = flag_counts
                        for flags, count in flag_counts.items():
                            stats.append(f"  {flags}: {count}")
                
                # HTTP specific stats
                http_data = None
                if 'http_host' in df.columns:
                    http_hosts = df[df['http_host'] != 'N/A']['http_host'].value_counts()
                    if not http_hosts.empty:
                        stats.append("\nTop HTTP Hosts:")
                        http_data = http_hosts.head(10)
                        for host, count in http_data.items():
                            stats.append(f"  {host}: {count}")
                
                # Display text results
                self.stats_text.delete(1.0, tk.END)
                self.stats_text.insert(tk.END, "\n".join(stats))
                
                # Create visualizations with light theme
                # Set matplotlib style for light theme
                plt.style.use('default')
                
                # Protocol Distribution Pie Chart
                if protocol_data is not None and len(protocol_data) > 0:
                    self.create_pie_chart(
                        self.protocol_tab, 
                        protocol_data, 
                        "Network Protocol Distribution",
                        colors=['#4285F4', '#EA4335', '#FBBC05', '#34A853', '#8334A8', '#F77234', '#3AAEE1']
                    )
                
                # IP Analysis Charts
                if source_data is not None and dest_data is not None:
                    # Create a frame to hold two charts side by side
                    ip_frame = ttk.Frame(self.ip_tab)
                    ip_frame.pack(fill=tk.BOTH, expand=True)
                    
                    # Source IPs
                    source_frame = ttk.Frame(ip_frame)
                    source_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
                    self.create_bar_chart(
                        source_frame,
                        source_data,
                        "Top Source IPs",
                        x_label="IP Address",
                        y_label="Packet Count",
                        color='#4285F4'
                    )
                    
                    # Destination IPs
                    dest_frame = ttk.Frame(ip_frame)
                    dest_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
                    self.create_bar_chart(
                        dest_frame,
                        dest_data,
                        "Top Destination IPs",
                        x_label="IP Address",
                        y_label="Packet Count",
                        color='#EA4335'
                    )
                
                # Traffic Direction Chart
                if direction_data is not None:
                    self.create_pie_chart(
                        self.traffic_tab,
                        direction_data,
                        "Traffic Direction",
                        colors=['#34A853', '#EA4335', '#4285F4']
                    )
                
                # Update status
                self.status_var.set(f"Capture completed: {len(df)} packets captured")
                
                # Switch to the statistics tab
                self.notebook.select(self.stats_tab)
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to analyze results: {str(e)}")
                self.status_var.set("Error analyzing capture results")
        else:
            self.status_var.set("No capture results available")
    
    def create_pie_chart(self, parent, data, title, colors=None):
        """Create a pie chart visualization"""
        try:
            # Create figure and axis with white background
            fig, ax = plt.subplots(figsize=(6, 4), dpi=100, facecolor='white')
            
            # Plot pie chart
            wedges, texts, autotexts = ax.pie(
                data.values, 
                labels=data.index,
                autopct='%1.1f%%',
                startangle=90,
                colors=colors
            )
            
            # Make text more visible
            for text in texts:
                text.set_fontsize(9)
                text.set_color('black')  # Black text for visibility
            for autotext in autotexts:
                autotext.set_fontsize(9)
                autotext.set_color('white')
            
            # Equal aspect ratio ensures pie is circular
            ax.axis('equal')
            ax.set_title(title, color='black')  # Black title for visibility
            
            # Create canvas and add to parent
            canvas = FigureCanvasTkAgg(fig, master=parent)
            canvas.draw()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        except Exception as e:
            print(f"Error creating pie chart: {e}")
            ttk.Label(parent, text=f"Could not create chart: {str(e)}").pack(pady=20)
    
    def create_bar_chart(self, parent, data, title, x_label="", y_label="", color='#4285F4'):
        """Create a bar chart visualization"""
        try:
            # Create figure and axis with white background
            fig, ax = plt.subplots(figsize=(6, 4), dpi=100, facecolor='white')
            
            # Set background color
            ax.set_facecolor('white')
            
            # For empty data, show placeholder
            if len(data) == 0:
                ax.text(0.5, 0.5, "No data available", 
                       ha='center', va='center', fontsize=12, color='black')
                ax.set_title(title, color='black')
                canvas = FigureCanvasTkAgg(fig, master=parent)
                canvas.draw()
                canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
                return
                
            # Plot bar chart (horizontal)
            bars = ax.barh(data.index, data.values, color=color)
            
            # Add value labels
            for bar in bars:
                width = bar.get_width()
                ax.text(width + (width * 0.02), 
                       bar.get_y() + bar.get_height()/2, 
                       f'{int(width)}',
                       va='center', fontsize=8, color='black')  # Black text for visibility
            
            # Set labels and title with black text
            ax.set_xlabel(x_label, color='black')
            ax.set_ylabel(y_label, color='black')
            ax.set_title(title, color='black')
            
            # Set tick colors to black for visibility
            ax.tick_params(colors='black')
            
            # Adjust layout for better display
            plt.tight_layout()
            
            # Create canvas and add to parent
            canvas = FigureCanvasTkAgg(fig, master=parent)
            canvas.draw()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        except Exception as e:
            print(f"Error creating bar chart: {e}")
            ttk.Label(parent, text=f"Could not create chart: {str(e)}").pack(pady=20)
    
    def view_csv_data(self):
        """Display CSV data in the treeview"""
        if not self.current_csv:
            print("No current CSV file set")
            messagebox.showinfo("Info", "No CSV file available")
            return
            
        if not os.path.exists(self.current_csv):
            print(f"CSV file does not exist at path: {self.current_csv}")
            # Try to find the file in current directory or output directory
            basename = os.path.basename(self.current_csv)
            if os.path.exists(basename):
                self.current_csv = basename
                print(f"Found file in current directory: {self.current_csv}")
            elif os.path.exists(os.path.join("output", basename)):
                self.current_csv = os.path.join("output", basename)
                print(f"Found file in output directory: {self.current_csv}")
            else:
                messagebox.showinfo("Info", f"CSV file not found: {self.current_csv}")
                return
        
        try:
            # Read the CSV file
            print(f"Reading CSV file for display: {self.current_csv}")
            df = pd.read_csv(self.current_csv)
            print(f"CSV file contains {len(df)} rows")
            
            # Replace NaN values with "N/A" for better display
            df = df.fillna("N/A")
            
            # Clear the treeview
            for item in self.tree.get_children():
                self.tree.delete(item)
                
            # Configure columns
            columns = list(df.columns)
            self.tree["columns"] = columns
            
            # Configure column headings
            self.tree.column("#0", width=0, stretch=tk.NO)  # Hide the first column
            
            # Configure column widths based on content type
            column_widths = {
                'timestamp': 150,
                'source_mac': 150, 
                'destination_mac': 150,
                'source_ip': 120,
                'destination_ip': 120,
                'source_port': 80,
                'destination_port': 80,
                'protocol': 80,
                'length': 60,
                'ttl': 50,
                'tcp_flags': 100,
                'tcp_window': 80,
                'icmp_type': 80,
                'icmp_code': 80,
                'dns_query': 200,
                'http_method': 80,
                'http_host': 200,
                'http_path': 200,
                'packet_direction': 100
            }
            
            # Apply specific formatting for each column
            for col in columns:
                # Get optimal width or use default
                width = column_widths.get(col.lower(), 100)
                self.tree.column(col, anchor=tk.W, width=width)
                self.tree.heading(col, text=col.replace('_', ' ').title(), anchor=tk.W)
            
            # Add data to the treeview (limit to 1000 rows for performance)
            max_rows = 1000
            display_rows = min(len(df), max_rows)
            
            # Format special columns
            if 'protocol' in df.columns:
                df['protocol'] = df['protocol'].astype(str).str.upper()
                
            if 'packet_direction' in df.columns:
                df['packet_direction'] = df['packet_direction'].astype(str).str.capitalize()
            
            # Add the rows to the treeview
            for i in range(display_rows):
                values = df.iloc[i].tolist()
                # Convert all values to strings with proper formatting
                values = [str(val).strip() for val in values]
                
                # Apply row color based on packet direction if that column exists
                packet_direction_index = -1
                if 'packet_direction' in df.columns:
                    packet_direction_index = df.columns.get_loc('packet_direction')
                    direction = values[packet_direction_index].lower()
                    
                    # Add with tags for coloring
                    if 'inbound' in direction:
                        self.tree.insert("", tk.END, values=values, tags=('inbound',))
                    elif 'outbound' in direction:
                        self.tree.insert("", tk.END, values=values, tags=('outbound',))
                    else:
                        self.tree.insert("", tk.END, values=values)
                else:
                    self.tree.insert("", tk.END, values=values)
            
            # Configure row colors - DARKER COLORS
            self.tree.tag_configure('inbound', background='#EF9A9A')  # Darker red for inbound
            self.tree.tag_configure('outbound', background='#A5D6A7')  # Darker green for outbound
                
            # Switch to the data tab
            self.notebook.select(self.data_tab)
            
            # Update status
            rows_count = len(self.tree.get_children())
            print(f"Added {rows_count} rows to treeview")
            if len(df) > max_rows:
                self.status_var.set(f"Displaying {max_rows} of {len(df)} rows. Open the CSV file to view all data.")
            else:
                self.status_var.set(f"Displaying all {len(df)} rows")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load CSV data: {str(e)}")
            print(f"Error details: {e}")  # Print detailed error for debugging
    
    def open_csv(self):
        """Open CSV file with system default app"""
        if self.current_csv and os.path.exists(self.current_csv):
            try:
                # Print the full path for debugging
                print(f"Opening CSV file: {os.path.abspath(self.current_csv)}")
                
                if os.name == 'nt':  # Windows
                    os.startfile(self.current_csv)
                else:
                    import subprocess
                    subprocess.call(['xdg-open', self.current_csv])
                    
                self.status_var.set(f"Opened CSV file: {self.current_csv}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open CSV file: {str(e)}")
        else:
            messagebox.showinfo("Info", "No CSV file available")
    
    def open_csv_directory(self):
        """Open the directory containing the current CSV file"""
        if self.current_csv and os.path.exists(self.current_csv):
            try:
                # Get the directory path
                dir_path = os.path.dirname(os.path.abspath(self.current_csv))
                
                # Open the directory
                if os.name == 'nt':  # Windows
                    os.startfile(dir_path)
                elif os.name == 'darwin':  # macOS
                    subprocess.call(['open', dir_path])
                else:  # Linux and other Unix
                    subprocess.call(['xdg-open', dir_path])
                
                self.status_var.set(f"Opened directory: {dir_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open directory: {str(e)}")
        else:
            # If no current CSV, open the current working directory
            try:
                current_dir = os.getcwd()
                if os.name == 'nt':  # Windows
                    os.startfile(current_dir)
                elif os.name == 'darwin':  # macOS
                    subprocess.call(['open', current_dir])
                else:  # Linux and other Unix
                    subprocess.call(['xdg-open', current_dir])
                
                self.status_var.set(f"Opened current directory: {current_dir}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open directory: {str(e)}")
    
    def load_external_csv(self):
        """Load an external CSV file"""
        file_path = filedialog.askopenfilename(
            title="Select CSV File to Load",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
        
        try:
            # Test if file can be read as CSV
            df = pd.read_csv(file_path)
            
            # Set as current CSV
            self.current_csv = file_path
            
            # Show results
            self.show_capture_results()
            self.view_csv_data()
            
            self.status_var.set(f"Loaded external CSV file: {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load CSV file: {str(e)}")
    
    def export_results(self):
        """Export capture results to a user-selected location"""
        if not self.current_csv or not os.path.exists(self.current_csv):
            messagebox.showinfo("Info", "No capture results to export")
            return
        
        # Ask user where to save the file
        default_filename = os.path.basename(self.current_csv)
        export_path = filedialog.asksaveasfilename(
            title="Export Network Data", 
            defaultextension=".csv",
            initialfile=default_filename,
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if not export_path:
            return  
        
        try:
            import shutil
            # Copy the file to the new location
            shutil.copy2(self.current_csv, export_path)
            
            messagebox.showinfo("Success", f"Exported data to:\n{export_path}")
            self.status_var.set(f"Data exported to {export_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {str(e)}")
            
    def list_all_captures(self):
        """List all available packet capture files"""
        try:
            # Find all packet capture files in the current directory
            captures = [f for f in os.listdir('.') if f.startswith('all_packets') and f.endswith('.csv')]
            
            if not captures:
                messagebox.showinfo("Info", "No capture files found")
                return
            
            # Show file selection dialog
            capture_selection = tk.Toplevel(self.root)
            capture_selection.title("Select Capture File")
            capture_selection.geometry("600x450")
            capture_selection.configure(background="white")
            
            ttk.Label(capture_selection, text="Select a capture file to load:", 
                     font=("Segoe UI", 12, "bold")).pack(pady=10)
            
            # Create a frame for the listbox
            list_frame = ttk.Frame(capture_selection)
            list_frame.pack(pady=5, padx=15, fill=tk.BOTH, expand=True)
            
            # Create a listbox with all capture files
            listbox = tk.Listbox(list_frame, width=70, height=15, 
                                font=("Segoe UI", 10),
                                background="white", foreground="black",
                                selectbackground="#0078D7", selectforeground="white")
            listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            
            # Add scrollbar
            scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=listbox.yview)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            listbox.configure(yscrollcommand=scrollbar.set)
            
            # Add files to listbox
            for capture in captures:
                # Get file size and creation time for display
                file_stat = os.stat(capture)
                file_size = file_stat.st_size / 1024  # KB
                file_time = datetime.fromtimestamp(file_stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                
                # Add to listbox
                listbox.insert(tk.END, f"{capture} ({file_size:.1f} KB, {file_time})")
            
            # Function to load the selected file
            def load_selected_file():
                selection = listbox.curselection()
                if selection:
                    # Get the filename from the selection (strip off size and time)
                    selected_text = listbox.get(selection[0])
                    selected_file = selected_text.split(' (')[0]
                    
                    # Set as current file
                    self.current_csv = selected_file
                    
                    # Update the display
                    self.show_capture_results()
                    self.view_csv_data()
                    
                    # Close the dialog
                    capture_selection.destroy()
            
            # Function to open the directory of the selected file
            def open_file_dir():
                selection = listbox.curselection()
                if selection:
                    # Get the filename from the selection
                    selected_text = listbox.get(selection[0])
                    selected_file = selected_text.split(' (')[0]
                    
                    # Get the absolute path
                    abs_path = os.path.abspath(selected_file)
                    dir_path = os.path.dirname(abs_path)
                    
                    # Open the directory
                    try:
                        if os.name == 'nt':  # Windows
                            os.startfile(dir_path)
                        elif os.name == 'darwin':  # macOS
                            subprocess.call(['open', dir_path])
                        else:  # Linux and other Unix
                            subprocess.call(['xdg-open', dir_path])
                    except Exception as e:
                        messagebox.showerror("Error", f"Failed to open directory: {str(e)}")
            
            # Function to open the selected file directly
            def open_selected_file():
                selection = listbox.curselection()
                if selection:
                    # Get the filename from the selection
                    selected_text = listbox.get(selection[0])
                    selected_file = selected_text.split(' (')[0]
                    
                    # Get the absolute path
                    abs_path = os.path.abspath(selected_file)
                    
                    # Open the file
                    try:
                        if os.name == 'nt':  # Windows
                            os.startfile(abs_path)
                        else:
                            subprocess.call(['xdg-open', abs_path])
                    except Exception as e:
                        messagebox.showerror("Error", f"Failed to open file: {str(e)}")
            
            # Add buttons
            button_frame = ttk.Frame(capture_selection)
            button_frame.pack(pady=15)
            
            ttk.Button(button_frame, text="Load Selected", 
                      command=load_selected_file, width=15).pack(side=tk.LEFT, padx=10)
            
            ttk.Button(button_frame, text="Open File", 
                      command=open_selected_file, width=15).pack(side=tk.LEFT, padx=10)
                      
            ttk.Button(button_frame, text="Open Directory", 
                      command=open_file_dir, width=15).pack(side=tk.LEFT, padx=10)
            
            ttk.Button(button_frame, text="Cancel", 
                      command=capture_selection.destroy, width=15).pack(side=tk.LEFT, padx=10)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to list capture files: {str(e)}")
    
    def create_temp_capture_file(self):
        """Create an empty capture file to ensure we have something to read from"""
        try:
            # Create a temporary capture file with headers
            temp_file = "temp_capture.csv"
            with open(temp_file, 'w', newline='') as f:
                writer = csv.writer(f)
                # Write headers that match what the sniffer.py would produce
                writer.writerow([
                    'timestamp', 'source_mac', 'destination_mac', 'source_ip', 'destination_ip', 
                    'protocol', 'length', 'source_port', 'destination_port', 'packet_direction'
                ])
            print(f"Created temporary capture file: {temp_file}")
            self.current_csv = os.path.abspath(temp_file)
        except Exception as e:
            print(f"Error creating temporary capture file: {e}")

def main():
    # Use regular Tk
    root = tk.Tk()
    
    # Set window icon
    try:
        root.iconbitmap("network.ico")  # You would need to add this icon file
    except:
        pass  # If icon not found, use default
    
    app = SnifferGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main() 