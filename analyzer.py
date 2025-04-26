import os
import pandas as pd
from datetime import datetime

def analyze_network_traffic(file_path):
    """
    Analyze network traffic from a CSV file
    
    Args:
        file_path: Path to the CSV file containing captured traffic
        
    Returns:
        dict: Analysis results
    """
    try:
        # Check if file exists
        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}
            
        # Read the CSV file
        df = pd.read_csv(file_path)
        
        # Basic statistics
        total_packets = len(df)
        
        # Protocol distribution
        protocol_col = 'protocol' if 'protocol' in df.columns else 'Protocol' 
        if protocol_col in df.columns:
            protocol_dist = df[protocol_col].value_counts().to_dict()
        else:
            protocol_dist = {"N/A": total_packets}
            
        # IP statistics
        src_ip_col = 'source_ip' if 'source_ip' in df.columns else 'Source IP'
        dst_ip_col = 'destination_ip' if 'destination_ip' in df.columns else 'Destination IP'
        
        if src_ip_col in df.columns:
            top_sources = df[src_ip_col].value_counts().head(10).to_dict()
        else:
            top_sources = {"N/A": total_packets}
            
        if dst_ip_col in df.columns:
            top_destinations = df[dst_ip_col].value_counts().head(10).to_dict()
        else:
            top_destinations = {"N/A": total_packets}
            
        # HTTP analysis
        http_requests = 0
        top_hosts = {}
        
        if protocol_col in df.columns and 'HTTP' in df[protocol_col].values:
            http_df = df[df[protocol_col] == 'HTTP']
            http_requests = len(http_df)
            
            host_col = 'host' if 'host' in df.columns else 'Host'
            if host_col in df.columns:
                top_hosts = http_df[host_col].value_counts().head(10).to_dict()
        
        # Prepare results
        results = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "file_analyzed": file_path,
            "total_packets": total_packets,
            "protocol_distribution": protocol_dist,
            "top_source_ips": top_sources,
            "top_destination_ips": top_destinations,
            "http_statistics": {
                "total_requests": http_requests,
                "top_hosts": top_hosts
            }
        }
        
        return results
        
    except Exception as e:
        return {"error": f"Analysis failed: {str(e)}"}
    
def format_analysis_report(analysis_results):
    """
    Format analysis results into a human-readable report
    
    Args:
        analysis_results: Dictionary containing analysis results
        
    Returns:
        str: Formatted report
    """
    if "error" in analysis_results:
        return f"ERROR: {analysis_results['error']}"
        
    report = []
    report.append(f"=== Network Traffic Analysis Report ===")
    report.append(f"Timestamp: {analysis_results['timestamp']}")
    report.append(f"File: {analysis_results['file_analyzed']}")
    report.append(f"Total Packets: {analysis_results['total_packets']}")
    report.append("")
    
    # Protocol distribution
    report.append("Protocol Distribution:")
    for protocol, count in analysis_results['protocol_distribution'].items():
        percentage = (count / analysis_results['total_packets']) * 100
        report.append(f"  {protocol}: {count} ({percentage:.2f}%)")
    report.append("")
    
    # Top source IPs
    report.append("Top Source IPs:")
    for ip, count in analysis_results['top_source_ips'].items():
        percentage = (count / analysis_results['total_packets']) * 100
        report.append(f"  {ip}: {count} ({percentage:.2f}%)")
    report.append("")
    
    # Top destination IPs
    report.append("Top Destination IPs:")
    for ip, count in analysis_results['top_destination_ips'].items():
        percentage = (count / analysis_results['total_packets']) * 100
        report.append(f"  {ip}: {count} ({percentage:.2f}%)")
    report.append("")
    
    # HTTP statistics
    http_stats = analysis_results['http_statistics']
    report.append("HTTP Statistics:")
    report.append(f"  Total HTTP Requests: {http_stats['total_requests']}")
    
    if http_stats['total_requests'] > 0:
        report.append("  Top Hosts:")
        for host, count in http_stats['top_hosts'].items():
            percentage = (count / http_stats['total_requests']) * 100
            report.append(f"    {host}: {count} ({percentage:.2f}%)")
    
    return "\n".join(report)

if __name__ == "__main__":
    # Test the analyzer with a sample file
    import sys
    
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        results = analyze_network_traffic(file_path)
        print(format_analysis_report(results))
    else:
        print("Usage: python analyzer.py <csv_file>") 