#!/usr/bin/env python3
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
import sys, os

def preprocess_network_data(input_file, output_file=None):
    print(f"Loading {input_file}...")
    df = pd.read_csv(input_file).replace(['N/A', 'n/a', 'null', ''], np.nan)
    df = df.dropna(axis=1, thresh=len(df) * 0.1).dropna(axis=0, thresh=len(df.columns) * 0.5)
    print(f"Cleaned: {len(df)} rows, {len(df.columns)} columns")
    
    # Clean column names
    df.columns = [col.replace(' ', '_').replace('#', 'packet_num').lower() for col in df.columns]
    
    # Time features
    if 'time' in df.columns:
        df['time'] = pd.to_datetime(df['time'], errors='coerce')
        df['hour'] = df['time'].dt.hour
        df['is_weekend'] = (df['time'].dt.dayofweek >= 5).astype(int)
        df['is_business_hours'] = ((df['hour'] >= 9) & (df['hour'] <= 17)).astype(int)
        df['is_night_time'] = ((df['hour'] >= 22) | (df['hour'] <= 6)).astype(int)
        df = df.drop('time', axis=1)
    
    # Convert numeric
    numeric_cols = ['source_port', 'destination_port', 'length', 'ttl', 'udp_length', 'dns_id', 'http_status', 'icmp_type', 'icmp_code']
    for col in numeric_cols:
        if col in df.columns: df[col] = pd.to_numeric(df[col], errors='coerce')
    
    # IP features
    for ip_col in ['source_ip', 'destination_ip']:
        if ip_col in df.columns:
            prefix = ip_col.split('_')[0]
            df[f'{prefix}_is_private'] = df[ip_col].apply(lambda x: 1 if pd.notna(x) and any(str(x).startswith(p) for p in ['192.168.', '10.', '172.', '127.']) else 0)
            df = df.drop(ip_col, axis=1)
    
    # Port & protocol features
    for port_col in ['source_port', 'destination_port']:
        if port_col in df.columns:
            df[f'{port_col.split("_")[0]}_is_well_known'] = (df[port_col] <= 1023).astype(int)
    
    if 'protocol' in df.columns:
        for proto in ['TCP', 'UDP', 'ICMP']: df[f'is_{proto.lower()}'] = (df['protocol'] == proto).astype(int)
    
    # Size features
    if 'length' in df.columns: df['is_large_packet'] = (df['length'] > 1024).astype(int)
    if 'udp_length' in df.columns:
        df['is_large_udp'] = (df['udp_length'] > 512).astype(int)
        if 'length' in df.columns: df['udp_payload_ratio'] = df['udp_length'] / df['length']
    
    # TCP flags
    if 'tcp_flags' in df.columns:
        tcp_str = df['tcp_flags'].astype(str).fillna('')
        for flag in ['SYN', 'ACK', 'FIN', 'RST', 'PSH']: df[f'has_{flag.lower()}'] = tcp_str.str.contains(flag).astype(int)
        df['is_syn_flood'] = (tcp_str.str.contains('SYN') & ~tcp_str.str.contains('ACK')).astype(int)
        df['is_fin_scan'] = (tcp_str.str.contains('FIN') & ~tcp_str.str.contains('ACK')).astype(int)
    
    # HTTP features
    if 'http_method' in df.columns:
        df['has_http'] = (~df['http_method'].isna()).astype(int)
        for method in ['GET', 'POST']: df[f'is_{method.lower()}'] = (df['http_method'] == method).astype(int)
        df = df.drop('http_method', axis=1)
    
    if 'http_status' in df.columns:
        df['is_http_success'] = ((df['http_status'] >= 200) & (df['http_status'] < 300)).astype(int)
        df['is_http_error'] = (df['http_status'] >= 400).astype(int)
    
    # DNS features
    for dns_col in ['dns_qname', 'dns_query']:
        if dns_col in df.columns:
            df['has_dns'] = (~df[dns_col].isna()).astype(int)
            df['dns_query_len'] = df[dns_col].astype(str).str.len().fillna(0)
            df = df.drop(dns_col, axis=1)
            break
    
    if 'dns_qr' in df.columns: df['is_dns_query'] = (df['dns_qr'] == 0).astype(int)
    
    # Service detection
    if 'destination_port' in df.columns:
        services = {'http': [80, 8080], 'https': [443, 8443], 'dns': [53], 'ssh': [22], 'ftp': [20, 21]}
        for service, ports in services.items(): df[f'is_{service}_port'] = df['destination_port'].isin(ports).astype(int)
    
    # Cleanup
    text_cols = [col for col in df.columns if df[col].dtype == 'object' and col not in ['protocol'] and df[col].nunique() > 50]
    df = df.drop(text_cols, axis=1)
    for col in df.select_dtypes(include=['object']).columns: df[col] = LabelEncoder().fit_transform(df[col].astype(str))
    for col in df.columns: df[col] = df[col].fillna(df[col].median() if df[col].dtype != 'object' else 0)
    
    # Normalize and save
    df_scaled = pd.DataFrame(StandardScaler().fit_transform(df), columns=df.columns)
    output_file = output_file or input_file.replace('.csv', '_processed.csv')
    df_scaled.to_csv(output_file, index=False)
    print(f"Done! {len(df_scaled)} rows, {len(df_scaled.columns)} features -> {output_file}")
    return output_file

def main():
    csv_files = [f for f in os.listdir('.') if f.endswith('.csv') and not f.endswith('_processed.csv')]
    if not csv_files: print("No CSV files found!"); sys.exit(1)
    
    if len(csv_files) == 1:
        input_file = csv_files[0]
        print(f"Auto-processing: {input_file}")
    else:
        print("Multiple CSV files found:")
        for i, f in enumerate(csv_files, 1): print(f"{i}. {f}")
        try:
            choice = int(input("Select file (enter number): ")) - 1
            input_file = csv_files[choice]
        except: input_file = csv_files[0]; print("Using first file")
    
    preprocess_network_data(input_file, input_file.replace('.csv', '_processed.csv'))

if __name__ == "__main__": main()
