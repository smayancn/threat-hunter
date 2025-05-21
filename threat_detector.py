import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
import joblib
import os
import csv
import argparse
from datetime import datetime
import re
import ipaddress

# Common network threat indicators
SUSPICIOUS_PORTS = {22, 23, 25, 135, 445, 1433, 3306, 3389, 5900, 8080, 8888}
SUSPICIOUS_FLAGS = {'RST+ACK', 'FIN+RST', 'SYN+FIN'}
SUSPICIOUS_PROTOCOLS = {'BitTorrent', 'IRC'}
KNOWN_MALWARE_DOMAINS = {'malware.com', 'badsite.com', 'evil.net', 'attacker.org'}
SUSPICIOUS_HTTP_PATHS = {'/admin', '/wp-login', '/shell', '/cmd', '/exec', '/phpmyadmin'}
SUSPICIOUS_DNS_QUERIES = {'.xyz', '.top', '.pw', '.cc', '.tk'}
SUSPICIOUS_USER_AGENTS = {'sqlmap', 'nikto', 'nmap', 'masscan', 'zgrab'}

class NetworkThreatDetector:
    def __init__(self):
        self.model = None
        self.feature_columns = None
        self.preprocessor = None
        self.source_type = None
        self.label_column = 'is_threat'
        
    def load_data(self, csv_file, source_type=None):
        """
        Load packet data from CSV file
        source_type: 'basic' for sniffer.py format, 'detailed' for colab.py format
        """
        try:
            # Auto-detect file source type if not specified
            if source_type is None:
                source_type = self._detect_csv_source_type(csv_file)
                
            self.source_type = source_type
            print(f"Loading data with detected source type: {source_type}")
            
            if source_type == 'basic':
                return self._load_basic_format(csv_file)
            else:
                return self._load_detailed_format(csv_file)
                
        except Exception as e:
            print(f"Error loading data: {e}")
            return None
            
    def _detect_csv_source_type(self, csv_file):
        """
        Auto-detect if the CSV is from sniffer.py (basic) or colab.py (detailed)
        """
        try:
            with open(csv_file, 'r', newline='') as f:
                reader = csv.reader(f)
                header = next(reader)
                
                # Check for colab.py specific columns
                if any(col in header for col in ["HTTP Method", "DNS QName", "TLS Content Type"]):
                    return 'detailed'
                # Basic sniffer.py format
                else:
                    return 'basic'
        except Exception:
            # Default to basic if detection fails
            return 'basic'
    
    def _load_basic_format(self, csv_file):
        """
        Load and preprocess data from the basic sniffer.py format
        """
        df = pd.read_csv(csv_file)
        
        # Apply transformations specific to basic format
        return self._preprocess_basic_data(df)
        
    def _load_detailed_format(self, csv_file):
        """
        Load and preprocess data from the detailed colab.py format
        """
        df = pd.read_csv(csv_file)
        
        # Apply transformations specific to detailed format
        return self._preprocess_detailed_data(df)
    
    def _is_private_ip(self, ip):
        """Check if an IP address is private."""
        try:
            if pd.isna(ip) or ip == "N/A":
                return False
            return ipaddress.ip_address(ip).is_private
        except:
            return False
            
    def _extract_domain_from_dns(self, query):
        """Extract domain from a DNS query."""
        if pd.isna(query) or query == "":
            return ""
        return str(query).lower()
    
    def _port_is_suspicious(self, port):
        """Check if a port is in the suspicious list."""
        try:
            if pd.isna(port) or port == "N/A":
                return False
            return int(port) in SUSPICIOUS_PORTS
        except:
            return False
    
    def _preprocess_basic_data(self, df):
        """
        Preprocess the basic data format from sniffer.py (capture_20250521-222829.csv)
        """
        print("Preprocessing basic format data (capture_20250521-222829.csv)...")
        
        # Handle missing values - fill with empty string or 0 for numeric to avoid type errors
        for col in df.columns:
            if df[col].dtype == 'object':
                df[col] = df[col].fillna("")
            else:
                df[col] = df[col].fillna(0)

        processed_df = pd.DataFrame()
        
        # Basic packet features - using column names from capture_20250521-222829.csv
        if 'protocol' in df.columns:
            processed_df['protocol_str'] = df['protocol'].astype(str).fillna("Unknown") # Keep a string version for one-hot encoding if needed
            processed_df['is_tcp'] = df['protocol'].astype(str).str.contains("TCP", case=False, na=False).astype(int)
            processed_df['is_udp'] = df['protocol'].astype(str).str.contains("UDP", case=False, na=False).astype(int)
            processed_df['is_icmp'] = df['protocol'].astype(str).str.contains("ICMP", case=False, na=False).astype(int)
            processed_df['is_http_basic'] = df['protocol'].astype(str).str.contains("HTTP", case=False, na=False).astype(int) # Renamed to avoid clash
            processed_df['is_dns_basic'] = df['protocol'].astype(str).str.contains("DNS", case=False, na=False).astype(int) # Renamed to avoid clash
            processed_df['is_arp_basic'] = df['protocol'].astype(str).str.contains("ARP", case=False, na=False).astype(int) # Renamed to avoid clash
        
        # Source/destination features
        if 'source_ip' in df.columns:
            processed_df['src_ip_is_private'] = df['source_ip'].apply(self._is_private_ip).astype(int)
        
        if 'destination_ip' in df.columns:
            processed_df['dst_ip_is_private'] = df['destination_ip'].apply(self._is_private_ip).astype(int)
            
        # Port-based features
        if 'source_port' in df.columns:
            processed_df['src_port_suspicious'] = df['source_port'].apply(self._port_is_suspicious).astype(int)
            
        if 'destination_port' in df.columns:
            processed_df['dst_port_suspicious'] = df['destination_port'].apply(self._port_is_suspicious).astype(int)
        
        # TCP flags
        if 'tcp_flags' in df.columns:
            processed_df['has_suspicious_flags'] = df['tcp_flags'].apply(
                lambda x: 1 if isinstance(x, str) and any(flag in x for flag in SUSPICIOUS_FLAGS) else 0
            )
            processed_df['has_syn_basic'] = df['tcp_flags'].astype(str).str.contains("SYN", case=False, na=False).astype(int)
            processed_df['has_rst_basic'] = df['tcp_flags'].astype(str).str.contains("RST", case=False, na=False).astype(int)
            processed_df['has_fin_basic'] = df['tcp_flags'].astype(str).str.contains("FIN", case=False, na=False).astype(int)
            processed_df['has_ack_basic'] = df['tcp_flags'].astype(str).str.contains("ACK", case=False, na=False).astype(int)

        # Packet direction
        if 'packet_direction' in df.columns:
            processed_df['is_inbound'] = df['packet_direction'].astype(str).str.contains("Inbound", na=False).astype(int)
            processed_df['is_outbound'] = df['packet_direction'].astype(str).str.contains("Outbound", na=False).astype(int)
        
        # Packet length
        if 'length' in df.columns:
            processed_df['packet_length'] = pd.to_numeric(df['length'], errors='coerce').fillna(0)
            processed_df['is_large_packet'] = (processed_df['packet_length'] > 1500).astype(int)
        
        # TTL
        if 'ttl' in df.columns:
            processed_df['ttl'] = pd.to_numeric(df['ttl'], errors='coerce').fillna(0)
            processed_df['has_low_ttl_basic'] = (processed_df['ttl'] < 32).astype(int)


        # DNS Query (basic version from sniffer.py)
        if 'dns_query' in df.columns:
            processed_df['has_dns_query_basic'] = (df['dns_query'].astype(str) != "").astype(int)
            processed_df['has_suspicious_dns_query_basic'] = df['dns_query'].apply(
                lambda x: 1 if isinstance(x, str) and any(tld in x.lower() for tld in SUSPICIOUS_DNS_QUERIES) else 0
            )

        # HTTP Method, Host, Path (basic versions from sniffer.py)
        if 'http_method' in df.columns:
             processed_df['has_http_method_basic'] = (df['http_method'].astype(str) != "").astype(int)
        if 'http_path' in df.columns:
            processed_df['has_suspicious_http_path_basic'] = df['http_path'].apply(
                lambda x: 1 if isinstance(x, str) and any(path in x.lower() for path in SUSPICIOUS_HTTP_PATHS) else 0
            )
        if 'http_host' in df.columns:
            processed_df['has_suspicious_http_host_basic'] = df['http_host'].apply(
                lambda x: 1 if isinstance(x, str) and any(domain in x.lower() for domain in KNOWN_MALWARE_DOMAINS) else 0
            )
        
        # Ensure all expected columns are present, fill with 0 if not
        expected_cols = [
            'protocol_str', 'is_tcp', 'is_udp', 'is_icmp', 'is_http_basic', 'is_dns_basic', 'is_arp_basic',
            'src_ip_is_private', 'dst_ip_is_private', 'src_port_suspicious', 'dst_port_suspicious',
            'has_suspicious_flags', 'has_syn_basic', 'has_rst_basic', 'has_fin_basic', 'has_ack_basic',
            'is_inbound', 'is_outbound', 'packet_length', 'is_large_packet', 'ttl', 'has_low_ttl_basic',
            'has_dns_query_basic', 'has_suspicious_dns_query_basic', 'has_http_method_basic',
            'has_suspicious_http_path_basic', 'has_suspicious_http_host_basic'
        ]
        for col in expected_cols:
            if col not in processed_df.columns:
                processed_df[col] = 0
                
        # Generate labels based on basic threat indicators
        processed_df[self.label_column] = (
            (processed_df['src_port_suspicious'] > 0) | 
            (processed_df['dst_port_suspicious'] > 0) | 
            (processed_df.get('has_suspicious_flags', 0) > 0) | # Use .get for safety
            (processed_df.get('has_suspicious_dns_query_basic', 0) > 0) |
            (processed_df.get('has_suspicious_http_path_basic', 0) > 0) |
            (processed_df.get('has_suspicious_http_host_basic', 0) > 0)
        ).astype(int)
        
        # Drop original columns used for feature engineering if they were not already dropped
        # and only keep the engineered features.
        # This is to ensure that the basic model only uses features derivable from basic data.
        
        print(f"Basic preprocessed_df columns: {processed_df.columns.tolist()}")
        print(f"Generated {processed_df[self.label_column].sum()} threat labels from {len(processed_df)} basic packets")
        return processed_df
    
    def _preprocess_detailed_data(self, df):
        """
        Preprocess the detailed data format from colab.py (network_logs.csv)
        """
        print("Preprocessing detailed format data (network_logs.csv)...")
        
        # Handle missing values - fill with empty string or 0 for numeric
        for col in df.columns:
            if df[col].dtype == 'object':
                df[col] = df[col].fillna("")
            else:
                df[col] = df[col].fillna(0)

        processed_df = pd.DataFrame()
        
        # Basic protocol features (using column names from network_logs.csv)
        if 'Protocol' in df.columns:
            processed_df['protocol_str'] = df['Protocol'].astype(str).fillna("Unknown") # Keep a string version
            processed_df['is_tcp'] = df['Protocol'].astype(str).str.contains("TCP", case=False, na=False).astype(int)
            processed_df['is_udp'] = df['Protocol'].astype(str).str.contains("UDP", case=False, na=False).astype(int)
            processed_df['is_icmp'] = df['Protocol'].astype(str).str.contains("ICMP", case=False, na=False).astype(int)
            processed_df['is_http'] = df['Protocol'].astype(str).str.contains("HTTP", case=False, na=False).astype(int)
            processed_df['is_dns'] = df['Protocol'].astype(str).str.contains("DNS", case=False, na=False).astype(int)
            processed_df['is_tls'] = df['Protocol'].astype(str).str.contains("TLS", case=False, na=False).astype(int)
            processed_df['is_snmp'] = df['Protocol'].astype(str).str.contains("SNMP", case=False, na=False).astype(int)
            processed_df['is_dhcp'] = df['Protocol'].astype(str).str.contains("DHCP", case=False, na=False).astype(int)
            processed_df['is_arp'] = df['Protocol'].astype(str).str.contains("ARP", case=False, na=False).astype(int)
        
        # IP-based features
        if 'Source IP' in df.columns:
            processed_df['src_ip_is_private'] = df['Source IP'].apply(self._is_private_ip).astype(int)
        
        if 'Destination IP' in df.columns:
            processed_df['dst_ip_is_private'] = df['Destination IP'].apply(self._is_private_ip).astype(int)
            
        # Port-based features
        if 'Source Port' in df.columns:
            processed_df['src_port_suspicious'] = df['Source Port'].apply(self._port_is_suspicious).astype(int)
            
        if 'Destination Port' in df.columns:
            processed_df['dst_port_suspicious'] = df['Destination Port'].apply(self._port_is_suspicious).astype(int)
        
        # TCP flags
        if 'TCP Flags' in df.columns:
            processed_df['has_suspicious_flags'] = df['TCP Flags'].apply(
                lambda x: 1 if isinstance(x, str) and any(flag in x for flag in SUSPICIOUS_FLAGS) else 0
            )
            processed_df['has_syn'] = df['TCP Flags'].astype(str).str.contains("SYN", case=False, na=False).astype(int)
            processed_df['has_rst'] = df['TCP Flags'].astype(str).str.contains("RST", case=False, na=False).astype(int)
            processed_df['has_fin'] = df['TCP Flags'].astype(str).str.contains("FIN", case=False, na=False).astype(int)
            processed_df['has_ack'] = df['TCP Flags'].astype(str).str.contains("ACK", case=False, na=False).astype(int)
            processed_df['has_psh'] = df['TCP Flags'].astype(str).str.contains("PSH", case=False, na=False).astype(int)
            processed_df['has_urg'] = df['TCP Flags'].astype(str).str.contains("URG", case=False, na=False).astype(int)
        
        # TTL analysis
        if 'TTL' in df.columns:
            processed_df['ttl'] = pd.to_numeric(df['TTL'], errors='coerce').fillna(0)
            processed_df['has_low_ttl'] = (processed_df['ttl'] < 32).astype(int)
        
        # HTTP-specific features
        if 'HTTP Method' in df.columns:
            processed_df['has_http_method'] = (df['HTTP Method'].astype(str) != "").astype(int)
            processed_df['is_http_get'] = df['HTTP Method'].astype(str).str.contains("GET", case=False, na=False).astype(int)
            processed_df['is_http_post'] = df['HTTP Method'].astype(str).str.contains("POST", case=False, na=False).astype(int)
        
        if 'HTTP Path' in df.columns:
            processed_df['has_suspicious_http_path'] = df['HTTP Path'].apply(
                lambda x: 1 if isinstance(x, str) and any(path in x.lower() for path in SUSPICIOUS_HTTP_PATHS) else 0
            )
        
        if 'HTTP Host' in df.columns:
            processed_df['has_suspicious_http_host'] = df['HTTP Host'].apply(
                lambda x: 1 if isinstance(x, str) and any(domain in x.lower() for domain in KNOWN_MALWARE_DOMAINS) else 0
            )
        
        # DNS-specific features
        if 'DNS QName' in df.columns:
            processed_df['has_dns_query'] = (df['DNS QName'].astype(str) != "").astype(int)
            processed_df['has_suspicious_dns_query'] = df['DNS QName'].apply(
                lambda x: 1 if isinstance(x, str) and any(tld in x.lower() for tld in SUSPICIOUS_DNS_QUERIES) else 0
            )
        
        # ICMP-specific features
        if 'ICMP Type' in df.columns and 'ICMP Code' in df.columns:
            processed_df['is_icmp_scan'] = ((df['ICMP Type'].astype(str) == "8") & (df['ICMP Code'].astype(str) == "0")).astype(int) # Ensure comparison with string
        
        # TLS-specific features
        if 'TLS Version' in df.columns:
            processed_df['has_tls_info'] = (df['TLS Version'].astype(str) != "").astype(int) # Renamed from 'has_tls' to avoid clash if 'is_tls' is main protocol
            processed_df['has_obsolete_tls'] = df['TLS Version'].apply(
                lambda x: 1 if isinstance(x, str) and any(ver in str(x) for ver in ["1.0", "SSL"]) else 0
            )
        
        # ARP-specific features
        if 'ARP Opcode' in df.columns:
            processed_df['is_arp_request'] = df['ARP Opcode'].astype(str).str.contains("request", case=False, na=False).astype(int)
            processed_df['is_arp_reply'] = df['ARP Opcode'].astype(str).str.contains("reply", case=False, na=False).astype(int)
        
        # Packet length
        if 'Length' in df.columns:
            processed_df['packet_length'] = pd.to_numeric(df['Length'], errors='coerce').fillna(0)
            processed_df['is_large_packet'] = (processed_df['packet_length'] > 1500).astype(int)

        # Additional detailed features (examples)
        if 'UDP Length' in df.columns:
            processed_df['udp_length_val'] = pd.to_numeric(df['UDP Length'], errors='coerce').fillna(0)
        if 'HTTP Status' in df.columns: # HTTP Status Code
            processed_df['http_status_client_error'] = df['HTTP Status'].astype(str).str.startswith('4').astype(int)
            processed_df['http_status_server_error'] = df['HTTP Status'].astype(str).str.startswith('5').astype(int)
        if 'DNS QType' in df.columns: # DNS Query Type
             processed_df['dns_qtype_is_any'] = (df['DNS QType'].astype(str) == "255").astype(int) # ANY query type (often suspicious)
        if 'TLS Content Type' in df.columns:
            processed_df['tls_is_handshake'] = (df['TLS Content Type'].astype(str) == "22").astype(int)
            processed_df['tls_is_app_data'] = (df['TLS Content Type'].astype(str) == "23").astype(int)
        if 'TLS Handshake Type' in df.columns:
            processed_df['tls_is_client_hello'] = (df['TLS Handshake Type'].astype(str) == "1").astype(int)
            
        # Ensure all expected columns are present, fill with 0 if not
        expected_detailed_cols = [
            'protocol_str', 'is_tcp', 'is_udp', 'is_icmp', 'is_http', 'is_dns', 'is_tls', 'is_snmp', 'is_dhcp', 'is_arp',
            'src_ip_is_private', 'dst_ip_is_private', 'src_port_suspicious', 'dst_port_suspicious',
            'has_suspicious_flags', 'has_syn', 'has_rst', 'has_fin', 'has_ack', 'has_psh', 'has_urg',
            'ttl', 'has_low_ttl', 'has_http_method', 'is_http_get', 'is_http_post',
            'has_suspicious_http_path', 'has_suspicious_http_host', 'has_dns_query', 'has_suspicious_dns_query',
            'is_icmp_scan', 'has_tls_info', 'has_obsolete_tls', 'is_arp_request', 'is_arp_reply',
            'packet_length', 'is_large_packet', 'udp_length_val', 'http_status_client_error', 'http_status_server_error',
            'dns_qtype_is_any', 'tls_is_handshake', 'tls_is_app_data', 'tls_is_client_hello'
        ]
        for col in expected_detailed_cols:
            if col not in processed_df.columns:
                processed_df[col] = 0
        
        # Generate labels based on comprehensive threat indicators
        processed_df[self.label_column] = (
            (processed_df['src_port_suspicious'] > 0) | 
            (processed_df['dst_port_suspicious'] > 0) | 
            (processed_df.get('has_suspicious_flags', 0) > 0) |
            (processed_df.get('has_suspicious_http_path', 0) > 0) |
            (processed_df.get('has_suspicious_http_host', 0) > 0) |
            (processed_df.get('has_suspicious_dns_query', 0) > 0) |
            (processed_df.get('has_obsolete_tls', 0) > 0) |
            (processed_df.get('is_icmp_scan',0) > 0) | # Added ICMP scan to label
            (processed_df.get('dns_qtype_is_any',0) > 0) | # Added suspicious DNS QType
            (processed_df.get('tls_is_handshake',0) > 0) | # Added TLS handshake to label
            (processed_df.get('tls_is_app_data',0) > 0) | # Added TLS app data to label
            (processed_df.get('tls_is_client_hello',0) > 0) | # Added TLS client hello to label
            (processed_df.get('http_status_client_error',0) > 0) | # Added HTTP client error to label
            (processed_df.get('http_status_server_error',0) > 0) # Added HTTP server error to label
        ).astype(int)
        
        print(f"Detailed preprocessed_df columns: {processed_df.columns.tolist()}")
        print(f"Generated {processed_df[self.label_column].sum()} threat labels from {len(processed_df)} detailed packets")
        return processed_df
    
    def train(self, data, labels=None):
        """
        Train the threat detection model
        
        Args:
            data: DataFrame with preprocessed features
            labels: Optional array of labels (if None, will use self.label_column from data)
        
        Returns:
            Trained model
        """
        print("Training threat detection model...")
        
        if labels is None and self.label_column in data.columns:
            labels = data[self.label_column]
            # Remove label column from features
            features = data.drop(columns=[self.label_column])
        else:
            features = data
        
        # Store feature columns for future predictions
        self.feature_columns = features.columns.tolist()
        
        # Create a pipeline with preprocessing and classifier
        numeric_features = features.select_dtypes(include=['int64', 'float64']).columns.tolist()
        categorical_features = features.select_dtypes(include=['object', 'category']).columns.tolist()
        
        # Define preprocessing for numerical and categorical features
        numeric_transformer = Pipeline(steps=[
            ('scaler', StandardScaler())
        ])
        
        categorical_transformer = Pipeline(steps=[
            ('onehot', OneHotEncoder(handle_unknown='ignore'))
        ])
        
        # Create column transformer
        preprocessor = ColumnTransformer(
            transformers=[
                ('num', numeric_transformer, numeric_features),
                ('cat', categorical_transformer, categorical_features)
            ],
            remainder='passthrough'
        )
        
        self.preprocessor = preprocessor
        
        # Create pipeline with preprocessing and classifier
        # Use RandomForest for good performance with minimal tuning
        pipeline = Pipeline(steps=[
            ('preprocessor', preprocessor),
            ('classifier', RandomForestClassifier(
                n_estimators=100, 
                max_depth=10,
                random_state=42,
                class_weight='balanced'
            ))
        ])
        
        # Train the model
        pipeline.fit(features, labels)
        self.model = pipeline
        
        # Print feature importances
        if hasattr(pipeline['classifier'], 'feature_importances_'):
            importances = pipeline['classifier'].feature_importances_
            
            # Get feature names after transformation by the preprocessor
            try:
                transformed_feature_names = pipeline['preprocessor'].get_feature_names_out()
            except AttributeError:
                print("Warning (train): Could not get transformed feature names. Using original feature names. Feature importance plot might be less interpretable.")
                # Fallback: try to get original names if preprocessor is not fitted or doesn't have the method
                # This is a simplified fallback; a full solution would need to ensure `features` variable is always available
                if self.feature_columns:
                    transformed_feature_names = self.feature_columns
                else: # Should not happen if model is trained
                    transformed_feature_names = [f"feature_{i}" for i in range(len(importances))]

            if len(transformed_feature_names) == len(importances):
                # Sort features by importance and get top 10
                feature_importance_pairs = sorted(zip(transformed_feature_names, importances), key=lambda x: x[1], reverse=True)
                top_features = feature_importance_pairs[:10]
                top_feature_names = [name for name, imp in top_features]
                top_importances = [imp for name, imp in top_features]
                
                indices = np.argsort(top_importances)[::-1] # This will just be range(10) effectively now

                print("\nTop 10 most important features:")
                for i, (name, imp) in enumerate(zip(top_feature_names, top_importances)):
                    print(f"{i+1}. {name}: {imp:.4f}")
            else:
                print(f"Warning (train): Mismatch in number of transformed feature names ({len(transformed_feature_names)}) and importances ({len(importances)}). Skipping feature importance printout.")

        
        return self.model
    
    def predict(self, data):
        """
        Make predictions with the trained model
        
        Args:
            data: DataFrame with features
            
        Returns:
            numpy array of predictions (0 = normal, 1 = threat)
        """
        if self.model is None:
            raise ValueError("Model not trained. Call train() first.")
        
        # Ensure data has the expected format
        if isinstance(data, pd.DataFrame):
            # Make sure we have the right columns in the right order
            if self.feature_columns:
                available_cols = [col for col in self.feature_columns if col in data.columns]
                data = data[available_cols]
        
        # Make predictions
        try:
            predictions = self.model.predict(data)
            proba_output = self.model.predict_proba(data)
            
            # Check if the model is predicting probabilities for two classes
            if proba_output.shape[1] == 2:
                probabilities = proba_output[:, 1]  # Probability of class 1 (threat)
            elif proba_output.shape[1] == 1:
                # This can happen if the model was trained on data with only one class present
                # or if it's extremely confident in one class for all samples.
                # If positive class (1) is present in model's classes_, use its probability.
                # Otherwise, assume probability of threat is 0 or 1 based on the single predicted class.
                if 1 in self.model['classifier'].classes_:
                    # Find which column corresponds to class 1
                    class_1_idx = list(self.model['classifier'].classes_).index(1)
                    probabilities = proba_output[:, class_1_idx]
                else: # Only class 0 is predicted
                    probabilities = np.zeros(len(predictions)) # All non-threats
                print(f"Warning: predict_proba returned shape {proba_output.shape}. Adjusted probabilities. Model classes: {self.model['classifier'].classes_}")
            else:
                # Unexpected shape
                print(f"Error: predict_proba returned unexpected shape {proba_output.shape}. Setting probabilities to 0.5.")
                probabilities = np.full(len(predictions), 0.5)
            
            return predictions, probabilities
        except Exception as e:
            print(f"Error during prediction: {e}")
            return None, None
    
    def evaluate(self, data, labels=None):
        """
        Evaluate model performance
        
        Args:
            data: DataFrame with features
            labels: Optional array of labels (if None, will use self.label_column from data)
            
        Returns:
            Dictionary with evaluation metrics
        """
        if self.model is None:
            raise ValueError("Model not trained. Call train() first.")
        
        # Extract labels if not provided
        if labels is None and self.label_column in data.columns:
            labels = data[self.label_column]
            # Remove label column from features
            features = data.drop(columns=[self.label_column])
        else:
            features = data
        
        # Make predictions
        y_pred, y_proba = self.predict(features)
        
        if y_pred is None:
            return None
        
        # Calculate metrics
        accuracy = accuracy_score(labels, y_pred)
        conf_matrix = confusion_matrix(labels, y_pred, labels=[0, 1])
        report = classification_report(labels, y_pred, output_dict=True, zero_division=0)
        
        # Print evaluation results
        print("\n" + "="*50)
        print("MODEL EVALUATION")
        print("="*50)
        print(f"Accuracy: {accuracy:.4f}")
        print("\nConfusion Matrix:")
        print(conf_matrix)
        print("\nClassification Report:")
        for label, metrics in report.items():
            if label not in ['accuracy', 'macro avg', 'weighted avg']:
                label_name = 'Normal' if label == '0' else 'Threat'
                print(f"{label_name}:")
                for metric_name, value in metrics.items():
                    if metric_name != 'support':
                        print(f"  {metric_name}: {value:.4f}")
        print("="*50)
        
        # Return metrics as dictionary
        return {
            'accuracy': accuracy,
            'confusion_matrix': conf_matrix,
            'classification_report': report
        }
    
    def save_model(self, filepath):
        """
        Save the trained model
        
        Args:
            filepath: Path to save the model
        """
        if self.model is None:
            raise ValueError("No model to save. Train a model first.")
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        # Save model
        joblib.dump({
            'model': self.model,
            'feature_columns': self.feature_columns,
            'source_type': self.source_type,
            'label_column': self.label_column
        }, filepath)
        
        print(f"Model saved to {filepath}")
    
    def load_model(self, filepath):
        """
        Load a trained model
        
        Args:
            filepath: Path to the saved model
        """
        if not os.path.exists(filepath):
            raise ValueError(f"Model file not found: {filepath}")
        
        # Load model
        model_data = joblib.load(filepath)
        
        self.model = model_data['model']
        self.feature_columns = model_data['feature_columns']
        self.source_type = model_data['source_type']
        self.label_column = model_data.get('label_column', 'is_threat')
        
        print(f"Model loaded from {filepath}")

    def visualize_results(self, data, predictions=None, probabilities=None):
        """
        Visualize model predictions and feature importance
        
        Args:
            data: DataFrame with features and labels
            predictions: Model predictions (optional, will be generated if None)
            probabilities: Prediction probabilities (optional, will be generated if None)
        """
        if self.model is None:
            raise ValueError("Model not trained. Call train() first.")
        
        # Create a figure with multiple subplots
        plt.figure(figsize=(18, 12))
        
        # Extract labels
        if self.label_column in data.columns:
            labels = data[self.label_column]
            features = data.drop(columns=[self.label_column])
        else:
            labels = None
            features = data
        
        # Generate predictions if not provided
        if predictions is None or probabilities is None:
            predictions, probabilities = self.predict(features)
        
        # Plot feature importance if available
        if hasattr(self.model['classifier'], 'feature_importances_'):
            plt.subplot(2, 2, 1)
            importances = self.model['classifier'].feature_importances_
            
            # Get feature names after transformation by the preprocessor
            try:
                transformed_feature_names = self.model['preprocessor'].get_feature_names_out()
            except AttributeError:
                print("Warning (visualize_results): Could not get transformed feature names. Using original feature names. Feature importance plot might be less interpretable.")
                # Fallback: try to get original names if preprocessor is not fitted or doesn't have the method
                # This is a simplified fallback; a full solution would need to ensure `features` variable is always available
                if self.feature_columns:
                    transformed_feature_names = self.feature_columns
                else: # Should not happen if model is trained
                    transformed_feature_names = [f"feature_{i}" for i in range(len(importances))]

            if len(transformed_feature_names) == len(importances):
                # Sort features by importance and get top 10
                feature_importance_pairs = sorted(zip(transformed_feature_names, importances), key=lambda x: x[1], reverse=True)
                top_features = feature_importance_pairs[:10]
                top_feature_names = [name for name, imp in top_features]
                top_importances = [imp for name, imp in top_features]
                
                indices = np.argsort(top_importances)[::-1] # This will just be range(10) effectively now

                plt.title('Top 10 Feature Importance')
                plt.bar(range(len(top_feature_names)), top_importances, color='b', align='center')
                plt.xticks(range(len(top_feature_names)), top_feature_names, rotation=90)
                plt.tight_layout()
            else:
                print(f"Warning (visualize_results): Mismatch in number of transformed feature names ({len(transformed_feature_names)}) and importances ({len(importances)}). Skipping feature importance plot.")

        # Plot confusion matrix if labels are available
        if labels is not None:
            plt.subplot(2, 2, 2)
            # Ensure confusion matrix handles cases where not all labels are present
            expected_labels_for_plot = [0, 1] 
            cm = confusion_matrix(labels, predictions, labels=expected_labels_for_plot)
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                        xticklabels=['Normal', 'Threat'], yticklabels=['Normal', 'Threat'])
            plt.title('Confusion Matrix')
            plt.xlabel('Predicted')
            plt.ylabel('Actual')
            plt.tight_layout()
        
        # Plot prediction probabilities histogram
        plt.subplot(2, 2, 3)
        plt.hist(probabilities, bins=20, color='green', alpha=0.6)
        plt.title('Prediction Probability Distribution')
        plt.xlabel('Probability of Threat')
        plt.ylabel('Count')
        plt.tight_layout()
        
        # Plot ROC curve if labels are available
        if labels is not None:
            from sklearn.metrics import roc_curve, auc
            plt.subplot(2, 2, 4)
            
            # Check if there are positive samples and more than one class in labels for ROC curve
            unique_labels = np.unique(labels)
            if len(unique_labels) > 1 and 1 in unique_labels and probabilities is not None:
                fpr, tpr, _ = roc_curve(labels, probabilities)
                roc_auc = auc(fpr, tpr)
                
                plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (area = {roc_auc:.2f})')
                plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
                plt.xlabel('False Positive Rate')
                plt.ylabel('True Positive Rate')
                plt.title('Receiver Operating Characteristic (ROC) Curve')
                plt.legend(loc="lower right")
            else:
                # Display a message if ROC cannot be plotted
                plt.text(0.5, 0.5, "ROC curve not available.\n(Requires positive samples and >1 class in labels,\nand probabilities for the positive class)", 
                         horizontalalignment='center', verticalalignment='center', transform=plt.gca().transAxes, fontsize=9)
                plt.title('Receiver Operating Characteristic (ROC) Curve')
                plt.xlabel('False Positive Rate')
                plt.ylabel('True Positive Rate')

            plt.tight_layout()
        
        plt.tight_layout()
        plt.savefig('threat_detection_results.png')
        plt.show()
        
        # Return the figure path
        return 'threat_detection_results.png'

def compare_models(basic_csv, detailed_csv, output_dir='models'):
    """
    Train and compare models using basic and detailed CSV formats
    
    Args:
        basic_csv: Path to CSV file from sniffer.py (basic format)
        detailed_csv: Path to CSV file from colab.py (detailed format)
        output_dir: Directory to save models and results
        
    Returns:
        Dictionary with comparison results
    """
    os.makedirs(output_dir, exist_ok=True)
    
    print("\n" + "="*60)
    print("COMPARING NETWORK THREAT DETECTION MODELS")
    print("="*60)
    
    # Initialize detectors
    basic_detector = NetworkThreatDetector()
    detailed_detector = NetworkThreatDetector()
    
    # Load and process data
    print("\nLoading basic format data...")
    basic_data = basic_detector.load_data(basic_csv, 'basic')
    
    print("\nLoading detailed format data...")
    detailed_data = detailed_detector.load_data(detailed_csv, 'detailed')
    
    if basic_data is None or detailed_data is None:
        print("Error loading datasets. Aborting comparison.")
        return None
    
    # Training and evaluation
    results = {}
    
    # Train and evaluate basic model
    print("\n" + "-"*50)
    print("TRAINING AND EVALUATING BASIC MODEL")
    print("-"*50)
    
    # Split data for basic model
    X_basic = basic_data.drop(columns=[basic_detector.label_column])
    y_basic = basic_data[basic_detector.label_column]
    X_train_basic, X_test_basic, y_train_basic, y_test_basic = train_test_split(
        X_basic, y_basic, test_size=0.3, random_state=42, stratify=y_basic
    )
    
    # Training
    basic_model = basic_detector.train(
        pd.concat([X_train_basic, y_train_basic], axis=1)
    )
    
    # Evaluation
    basic_metrics = basic_detector.evaluate(
        pd.concat([X_test_basic, y_test_basic], axis=1)
    )
    
    # Save model
    basic_model_path = os.path.join(output_dir, 'basic_model.joblib')
    basic_detector.save_model(basic_model_path)
    
    # Generate visualization
    basic_preds, basic_probs = basic_detector.predict(X_test_basic)
    basic_viz_path = basic_detector.visualize_results(
        pd.concat([X_test_basic, y_test_basic], axis=1),
        basic_preds,
        basic_probs
    )
    
    # Store results
    results['basic'] = {
        'accuracy': basic_metrics['accuracy'],
        'model_path': basic_model_path,
        'visualization': basic_viz_path,
        'feature_count': len(X_basic.columns)
    }
    
    # Train and evaluate detailed model
    print("\n" + "-"*50)
    print("TRAINING AND EVALUATING DETAILED MODEL")
    print("-"*50)
    
    # Split data for detailed model
    X_detailed = detailed_data.drop(columns=[detailed_detector.label_column])
    y_detailed = detailed_data[detailed_detector.label_column]
    X_train_detailed, X_test_detailed, y_train_detailed, y_test_detailed = train_test_split(
        X_detailed, y_detailed, test_size=0.3, random_state=42, stratify=y_detailed
    )
    
    # Training
    detailed_model = detailed_detector.train(
        pd.concat([X_train_detailed, y_train_detailed], axis=1)
    )
    
    # Evaluation
    detailed_metrics = detailed_detector.evaluate(
        pd.concat([X_test_detailed, y_test_detailed], axis=1)
    )
    
    # Save model
    detailed_model_path = os.path.join(output_dir, 'detailed_model.joblib')
    detailed_detector.save_model(detailed_model_path)
    
    # Generate visualization
    detailed_preds, detailed_probs = detailed_detector.predict(X_test_detailed)
    detailed_viz_path = detailed_detector.visualize_results(
        pd.concat([X_test_detailed, y_test_detailed], axis=1),
        detailed_preds,
        detailed_probs
    )
    
    # Store results
    results['detailed'] = {
        'accuracy': detailed_metrics['accuracy'],
        'model_path': detailed_model_path,
        'visualization': detailed_viz_path,
        'feature_count': len(X_detailed.columns)
    }
    
    # Print comparison summary
    print("\n" + "="*60)
    print("MODEL COMPARISON SUMMARY")
    print("="*60)
    print(f"Basic model accuracy: {results['basic']['accuracy']:.4f}")
    print(f"Detailed model accuracy: {results['detailed']['accuracy']:.4f}")
    print(f"Accuracy improvement: {results['detailed']['accuracy'] - results['basic']['accuracy']:.4f}")
    print(f"Basic model features: {results['basic']['feature_count']}")
    print(f"Detailed model features: {results['detailed']['feature_count']}")
    print("="*60)
    
    # Save comparison results
    comparison_file = os.path.join(output_dir, 'comparison_results.txt')
    with open(comparison_file, 'w') as f:
        f.write("NETWORK THREAT DETECTION MODEL COMPARISON\n")
        f.write("="*50 + "\n\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("BASIC MODEL (sniffer.py format)\n")
        f.write("-"*30 + "\n")
        f.write(f"Accuracy: {results['basic']['accuracy']:.4f}\n")
        f.write(f"Features: {results['basic']['feature_count']}\n")
        f.write(f"Model file: {results['basic']['model_path']}\n\n")
        
        f.write("DETAILED MODEL (colab.py format)\n")
        f.write("-"*30 + "\n")
        f.write(f"Accuracy: {results['detailed']['accuracy']:.4f}\n")
        f.write(f"Features: {results['detailed']['feature_count']}\n")
        f.write(f"Model file: {results['detailed']['model_path']}\n\n")
        
        f.write("COMPARISON\n")
        f.write("-"*30 + "\n")
        f.write(f"Accuracy improvement: {results['detailed']['accuracy'] - results['basic']['accuracy']:.4f}\n")
        f.write(f"Feature count increase: {results['detailed']['feature_count'] - results['basic']['feature_count']}\n\n")
        
        f.write("CONCLUSION\n")
        f.write("-"*30 + "\n")
        
        if results['detailed']['accuracy'] > results['basic']['accuracy']:
            f.write("The detailed packet capture format provides BETTER threat detection accuracy.\n")
            f.write("This demonstrates that protocol-specific information extracted by colab.py\n")
            f.write("leads to more effective network security monitoring and threat detection.\n")
        else:
            f.write("The basic packet capture format provides similar accuracy to the detailed format.\n")
            f.write("This suggests that the additional protocol-specific information may not be\n")
            f.write("necessary for effective threat detection in this specific dataset.\n")
    
    print(f"\nComparison results saved to {comparison_file}")
    return results

def main():
    parser = argparse.ArgumentParser(description="Network Threat Detection using Machine Learning")
    parser.add_argument('--csv', help='Path to the CSV file containing network packet data')
    parser.add_argument('--source', choices=['basic', 'detailed'], help='Source format of the CSV (basic=sniffer.py, detailed=colab.py)')
    parser.add_argument('--train', action='store_true', help='Train a new model')
    parser.add_argument('--evaluate', action='store_true', help='Evaluate model performance')
    parser.add_argument('--model', help='Path to save/load model')
    parser.add_argument('--compare', action='store_true', help='Compare basic and detailed models')
    parser.add_argument('--basic-csv', help='Path to basic format CSV (for comparison)')
    parser.add_argument('--detailed-csv', help='Path to detailed format CSV (for comparison)')
    parser.add_argument('--output-dir', default='models', help='Directory to save models and results')
    
    args = parser.parse_args()
    
    # Compare models if requested
    if args.compare:
        if not args.basic_csv or not args.detailed_csv:
            print("Error: Both --basic-csv and --detailed-csv are required for comparison")
            return
        
        compare_models(args.basic_csv, args.detailed_csv, args.output_dir)
        return
    
    # Single model training/evaluation workflow
    if not args.csv:
        print("Error: CSV file path is required. Use --csv to specify.")
        return
    
    detector = NetworkThreatDetector()
    
    # Load data
    data = detector.load_data(args.csv, args.source)
    
    if data is None:
        print("Failed to load data. Exiting.")
        return
    
    # Train or load model
    if args.train:
        detector.train(data)
        
        if args.model:
            detector.save_model(args.model)
    elif args.model:
        try:
            detector.load_model(args.model)
        except Exception as e:
            print(f"Error loading model: {e}")
            return
    
    # Evaluate if requested
    if args.evaluate:
        if detector.model is None:
            print("Error: No model available for evaluation. Train or load a model first.")
            return
        
        detector.evaluate(data)
        detector.visualize_results(data)
    
    print("Completed successfully.")

if __name__ == "__main__":
    main() 