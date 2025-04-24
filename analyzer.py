import pandas as pd
import numpy as np
import os
import time
import sys
import argparse
from collections import Counter

def analyze_network_traffic(csv_file, output_file=None):
    """
    Analyze network traffic using simple rule-based detection.
    
    Parameters:
    -----------
    csv_file : str
        Path to the CSV file containing network traffic data
    output_file : str
        Path to save analysis results (optional)
    """
    print(f"Analyzing network traffic in {csv_file}...")
    start_time = time.time()
    
    # Load the data
    try:
        df = pd.read_csv(csv_file, low_memory=False)
        print(f"Successfully loaded {len(df)} rows from {csv_file}")
    except Exception as e:
        print(f"Error loading CSV file: {str(e)}")
        print("Attempting to load with different settings...")
        try:
            df = pd.read_csv(csv_file, encoding='latin1', on_bad_lines='skip', low_memory=False)
            print(f"Successfully loaded {len(df)} rows with alternative method")
        except Exception as e:
            print(f"Fatal error loading CSV: {str(e)}")
            return None
    
    # Display basic information
    print(f"Dataset shape: {df.shape}")
    print(f"Columns: {df.columns.tolist()}")
    
    # Map common column name variations
    column_mappings = {
        'SrcIP': 'Source IP',
        'Src IP': 'Source IP',
        'Source_IP': 'Source IP',
        'src': 'Source IP',
        'DstIP': 'Destination IP',
        'Dst IP': 'Destination IP',
        'Destination_IP': 'Destination IP',
        'dst': 'Destination IP',
        'Proto': 'Protocol',
        'protocol': 'Protocol',
        'Source Port': 'Source Port',
        'Src Port': 'Source Port',
        'sport': 'Source Port',
        'Destination Port': 'Destination Port', 
        'Dst Port': 'Destination Port',
        'dport': 'Destination Port',
        'Length': 'Packet Length',
        'Pkt Length': 'Packet Length',
        'len': 'Packet Length',
        'flags': 'TCP Flags',
        'tcp.flags': 'TCP Flags',
        'TCPFlags': 'TCP Flags',
        'direction': 'Packet Direction',
        'packet_direction': 'Packet Direction',
        'Direction': 'Packet Direction'
    }
    
    # Rename columns based on mappings
    df = df.rename(columns={k: v for k, v in column_mappings.items() if k in df.columns})
    
    # Fill missing values
    required_columns = ['Source IP', 'Destination IP', 'Protocol']
    for col in required_columns:
        if col not in df.columns:
            print(f"Warning: Required column {col} not found in dataset. Creating with default values.")
            df[col] = 'Unknown'
    
    # Clean and process data
    # Handle port columns
    if 'Source Port' in df.columns:
        df['Source Port'] = pd.to_numeric(df['Source Port'], errors='coerce').fillna(-1)
    else:
        df['Source Port'] = -1
    
    if 'Destination Port' in df.columns:
        df['Destination Port'] = pd.to_numeric(df['Destination Port'], errors='coerce').fillna(-1)
    else:
        df['Destination Port'] = -1
    
    # Make sure TCP Flags column exists
    if 'TCP Flags' not in df.columns:
        df['TCP Flags'] = ""
    else:
        df['TCP Flags'] = df['TCP Flags'].fillna("")
    
    # Define detection rules
    results = analyze_packets(df)
    
    # Print summary
    print_analysis_summary(results)
    
    # Save results if output file is specified
    if output_file:
        result_df = pd.concat([df, pd.DataFrame(results)], axis=1)
        result_df.to_csv(output_file, index=False)
        print(f"Analysis results saved to {output_file}")
    
    print(f"Analysis completed in {time.time() - start_time:.2f} seconds")
    return results

def analyze_packets(df):
    """
    Analyze each packet to determine if it's suspicious based on rules.
    
    Parameters:
    -----------
    df : DataFrame
        DataFrame containing packet data
    
    Returns:
    --------
    dict
        Dictionary with analysis results
    """
    total_packets = len(df)
    is_suspicious = np.zeros(total_packets, dtype=int)
    suspicion_score = np.zeros(total_packets)
    reasons = [""] * total_packets
    direction = ["Unknown"] * total_packets
    
    print("Applying detection rules...")
    
    # Determine packet directions
    if 'Packet Direction' in df.columns:
        direction = df['Packet Direction'].fillna("Unknown").tolist()
    else:
        # Try to infer direction from IPs
        private_ip_patterns = ('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', 
                              '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', 
                              '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.')
        
        for i, row in df.iterrows():
            src_ip = str(row['Source IP'])
            dst_ip = str(row['Destination IP'])
            
            if any(src_ip.startswith(p) for p in private_ip_patterns) and not any(dst_ip.startswith(p) for p in private_ip_patterns):
                direction[i] = "Outbound"
            elif not any(src_ip.startswith(p) for p in private_ip_patterns) and any(dst_ip.startswith(p) for p in private_ip_patterns):
                direction[i] = "Inbound"
            elif any(src_ip.startswith(p) for p in private_ip_patterns) and any(dst_ip.startswith(p) for p in private_ip_patterns):
                direction[i] = "Local"
            else:
                direction[i] = "External"
    
    # 1. Suspicious TCP flag combinations
    suspicious_flag_combinations = [
        {'flags': ['SYN', 'FIN'], 'description': 'SYN+FIN flags (often used in scanning)'},
        {'flags': ['SYN', 'FIN', 'PSH', 'URG'], 'description': 'XMAS scan detected'},
        {'flags': ['FIN', 'PSH', 'URG'], 'description': 'FIN+PSH+URG without SYN/ACK'},
        {'flags': ['NULL'], 'description': 'NULL scan (no flags set)'},
        {'flags': ['FIN'], 'description': 'FIN scan without ACK'}
    ]
    
    # 2. Suspicious ports
    suspicious_ports = [0, 31337, 1337, 4444, 6666, 6667, 12345, 54321, 666, 1024, 2222, 
                       5554, 27374, 27665, 31338, 20034, 1000, 1999]
    
    # 3. Common vulnerable service ports to monitor
    vulnerable_service_ports = [21, 22, 23, 25, 53, 139, 445, 1433, 3306, 3389, 5432, 5900, 8080]
    
    for i, row in df.iterrows():
        packet_reasons = []
        score = 0
        
        # Extract TCP flags
        flags = str(row['TCP Flags']).upper()
        
        # Flag-based detection for TCP traffic
        if 'Protocol' in df.columns and str(row['Protocol']).upper() == 'TCP' and flags:
            # Check for suspicious flag combinations
            for combo in suspicious_flag_combinations:
                if all(flag in flags for flag in combo['flags']):
                    packet_reasons.append(combo['description'])
                    score += 0.7
                # Special case for NULL scan (no flags set in TCP)
                elif combo['flags'] == ['NULL'] and not flags:
                    packet_reasons.append(combo['description'])
                    score += 0.7
            
            # Unusual flag frequencies
            if flags.count('SYN') > 1 or flags.count('FIN') > 1:
                packet_reasons.append('Multiple SYN or FIN flags')
                score += 0.5
            
            # RST flags without prior connection
            if 'RST' in flags and 'ACK' not in flags:
                packet_reasons.append('RST without ACK (potential scan)')
                score += 0.4
        
        # Port-based detection (for all protocols)
        src_port = int(row['Source Port']) if row['Source Port'] != -1 else 0
        dst_port = int(row['Destination Port']) if row['Destination Port'] != -1 else 0
        
        # Check for suspicious source ports
        if src_port in suspicious_ports:
            packet_reasons.append(f'Suspicious source port: {src_port}')
            score += 0.5
        
        # Check for suspicious destination ports
        if dst_port in suspicious_ports:
            packet_reasons.append(f'Suspicious destination port: {dst_port}')
            score += 0.5
        
        # Higher scrutiny for connections to vulnerable services
        if dst_port in vulnerable_service_ports:
            # Add to reasons, but with lower score unless combined with other factors
            packet_reasons.append(f'Connection to potentially vulnerable service: {dst_port}')
            score += 0.2
            
            # If this is an external connection to a vulnerable service, increase score
            if direction[i] == "Inbound":
                packet_reasons.append('External connection to vulnerable service')
                score += 0.3
        
        # Protocol-based detection for non-TCP traffic
        if 'Protocol' in df.columns:
            protocol = str(row['Protocol']).upper()
            
            # ICMP flood detection
            if protocol == 'ICMP':
                # Just note it for now, will correlate with frequency later
                packet_reasons.append('ICMP traffic')
                score += 0.1
            
            # Other potentially suspicious protocols
            if protocol in ['IGMP', 'GRE']:
                packet_reasons.append(f'Uncommon protocol: {protocol}')
                score += 0.2
        
        # Packet size analysis
        if 'Packet Length' in df.columns:
            try:
                length = float(row['Packet Length'])
                # Extremely large packets
                if length > 1500:
                    packet_reasons.append(f'Unusually large packet: {length} bytes')
                    score += 0.3
                # Zero-length TCP packets (except pure ACK)
                elif length == 0 and ('Protocol' in df.columns and str(row['Protocol']).upper() == 'TCP'):
                    if not (flags == 'ACK'):
                        packet_reasons.append('Zero-length TCP packet')
                        score += 0.4
            except:
                pass
        
        # Final decision
        if score >= 0.7:
            is_suspicious[i] = 1
        suspicion_score[i] = min(0.99, score)  # Cap at 0.99
        reasons[i] = "; ".join(packet_reasons) if packet_reasons else "Normal traffic"
    
    # Post-processing: Correlate traffic patterns
    # Detect potential port scans
    port_scan_threshold = 10
    src_dst_pairs = {}
    
    for i, row in df.iterrows():
        src_ip = str(row['Source IP'])
        src_dst_pair = (src_ip, 'multiple_destinations')
        
        if src_dst_pair not in src_dst_pairs:
            src_dst_pairs[src_dst_pair] = set()
        
        if row['Destination Port'] != -1:
            src_dst_pairs[src_dst_pair].add(int(row['Destination Port']))
    
    # Mark packets from IP addresses that connect to many different ports
    for i, row in df.iterrows():
        src_ip = str(row['Source IP'])
        src_dst_pair = (src_ip, 'multiple_destinations')
        
        if src_dst_pair in src_dst_pairs and len(src_dst_pairs[src_dst_pair]) > port_scan_threshold:
            if not is_suspicious[i]:  # Only modify if not already marked
                is_suspicious[i] = 1
                suspicion_score[i] = max(suspicion_score[i], 0.8)
                reasons[i] = f"Potential port scan: connecting to {len(src_dst_pairs[src_dst_pair])} different ports" + ("; " + reasons[i] if reasons[i] != "Normal traffic" else "")
    
    # Detect potential ICMP flood
    if 'Protocol' in df.columns:
        icmp_counts = Counter()
        icmp_indices = []
        
        for i, row in df.iterrows():
            if str(row['Protocol']).upper() == 'ICMP':
                src_ip = str(row['Source IP'])
                icmp_counts[src_ip] += 1
                icmp_indices.append(i)
        
        icmp_flood_threshold = 20
        for i in icmp_indices:
            src_ip = str(df.iloc[i]['Source IP'])
            if icmp_counts[src_ip] > icmp_flood_threshold:
                is_suspicious[i] = 1
                suspicion_score[i] = max(suspicion_score[i], 0.85)
                reasons[i] = f"Potential ICMP flood: {icmp_counts[src_ip]} packets" + ("; " + reasons[i] if reasons[i] != "Normal traffic" else "")
    
    return {
        'is_suspicious': is_suspicious,
        'suspicion_score': suspicion_score,
        'reason': reasons,
        'predicted_direction': direction
    }

def print_analysis_summary(results):
    """Print a summary of the analysis results."""
    suspicious_count = sum(results['is_suspicious'])
    total_count = len(results['is_suspicious'])
    
    print("\nAnalysis Results:")
    print(f"Total packets analyzed: {total_count}")
    print(f"Suspicious packets detected: {suspicious_count} ({100 * suspicious_count / total_count:.2f}%)")
    
    # Direction distribution
    direction_counts = Counter(results['predicted_direction'])
    print("\nDirection distribution:")
    for direction, count in direction_counts.items():
        print(f"  {direction}: {count} ({100 * count / total_count:.2f}%)")
    
    # Top suspicion reasons
    if suspicious_count > 0:
        reason_list = [reason for i, reason in enumerate(results['reason']) if results['is_suspicious'][i]]
        # Split reasons that have multiple parts
        flat_reasons = []
        for reason in reason_list:
            flat_reasons.extend([r.strip() for r in reason.split(";")])
        
        reason_counts = Counter(flat_reasons)
        print("\nTop suspicion reasons:")
        for reason, count in reason_counts.most_common(5):
            if reason != "Normal traffic":
                print(f"  {reason}: {count} ({100 * count / len(flat_reasons):.2f}%)")

def main():
    """Main function with command-line options."""
    parser = argparse.ArgumentParser(description="Simple Network Traffic Analyzer")
    parser.add_argument("--analyze", type=str, help="Analyze CSV file with network traffic")
    parser.add_argument("--output", type=str, help="Output file for analysis results")
    
    args = parser.parse_args()
    
    # If no arguments provided, show an interactive menu
    if len(sys.argv) == 1:
        print("\n===== Simple Network Traffic Analyzer =====")
        print("Please select an option:")
        print("1. Analyze network traffic")
        print("2. Exit")
        
        choice = input("\nEnter your choice (1-2): ")
        
        if choice == "1":
            print("\n--- Analyzing Network Traffic ---")
            csv_file = input("Enter CSV file path to analyze: ")
            save_output = input("Save results to CSV? (y/n): ").lower().startswith('y')
            if save_output:
                output_file = input("Enter output file path [default: analysis_results.csv]: ") or "analysis_results.csv"
            else:
                output_file = None
                
            # Process the input file
            if csv_file:
                analyze_network_traffic(csv_file, output_file)
            else:
                print("No file specified. Exiting.")
        elif choice == "2":
            print("Exiting...")
            return
        else:
            print("Invalid choice. Exiting...")
            return
    else:
        # Process command-line arguments
        if args.analyze:
            if not os.path.exists(args.analyze):
                print(f"Error: Input file {args.analyze} not found")
                return
                
            analyze_network_traffic(args.analyze, args.output)
        else:
            parser.print_help()

if __name__ == "__main__":
    main() 