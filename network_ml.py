import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, StratifiedKFold, GridSearchCV
from sklearn.preprocessing import StandardScaler, OneHotEncoder, LabelEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, precision_recall_curve
from sklearn.cluster import KMeans
import joblib
import warnings
import time
import scipy.stats as stats
from collections import Counter, defaultdict
from scipy.stats import entropy
import gc
import os

def load_and_preprocess_data(csv_file):
    """Load and preprocess the network traffic dataset with optimized feature engineering."""
    start_time = time.time()
    print(f"Loading data from {csv_file}...")
    
    # Load the CSV data
    df = pd.read_csv(csv_file)
    
    # Display basic information
    print(f"Dataset shape: {df.shape}")
    print(f"Columns: {df.columns.tolist()}")
    
    # Remove rows with missing values or fill them
    df = df.dropna(subset=['Source IP', 'Destination IP', 'Protocol'])
    
    # Convert timestamp to datetime and extract features
    df['Timestamp'] = pd.to_datetime(df['Timestamp'])
    df['Hour'] = df['Timestamp'].dt.hour
    df['Minute'] = df['Timestamp'].dt.minute
    df['Day'] = df['Timestamp'].dt.day_of_week
    
    # Add temporal features (hour of day patterns)
    df['Is_Business_Hours'] = ((df['Hour'] >= 9) & (df['Hour'] <= 17)).astype(int)
    df['Is_Night'] = ((df['Hour'] >= 22) | (df['Hour'] <= 5)).astype(int)
    
    # Feature engineering
    # Convert packet length to numeric if it's not already
    df['Packet Length'] = pd.to_numeric(df['Packet Length'], errors='coerce')
    
    # Convert ports to numeric, replacing N/A with -1
    df['Source Port'] = pd.to_numeric(df['Source Port'].replace('N/A', -1), errors='coerce')
    df['Destination Port'] = pd.to_numeric(df['Destination Port'].replace('N/A', -1), errors='coerce')
    
    # Create binary features for TCP flags
    # Vectorized operation for all TCP flags at once
    tcp_flags = ['SYN', 'ACK', 'FIN', 'RST', 'PSH', 'URG']
    for flag in tcp_flags:
        df[f'Has_{flag}'] = df['TCP Flags'].str.contains(flag, na=False).astype(int)
    
    # Count total flags in each packet (potential indicator of anomalies)
    df['Flag_Count'] = df[[f'Has_{flag}' for flag in tcp_flags]].sum(axis=1)
    
    # Create features from IPs
    private_ip_patterns = ('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', 
                          '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', 
                          '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.')
    
    df['Is_Local_Source'] = df['Source IP'].str.startswith(private_ip_patterns).astype(int)
    df['Is_Local_Dest'] = df['Destination IP'].str.startswith(private_ip_patterns).astype(int)
    
    # Compute source and destination IP entropy (higher values might indicate scanning)
    src_ip_counts = Counter(df['Source IP'])
    dst_ip_counts = Counter(df['Destination IP'])
    total_ips = len(df)
    
    # Calculate entropy of source/destination IPs
    src_ip_probs = np.array([count/total_ips for count in src_ip_counts.values()])
    dst_ip_probs = np.array([count/total_ips for count in dst_ip_counts.values()])
    
    try:
        src_entropy = entropy(src_ip_probs)
        dst_entropy = entropy(dst_ip_probs)
        print(f"Source IP entropy: {src_entropy:.2f}, Destination IP entropy: {dst_entropy:.2f}")
    except:
        print("Skipping entropy calculation due to insufficient data")
        src_entropy = dst_entropy = 0
    
    # Add new features for anomaly detection
    # Identify common/uncommon port numbers with wider coverage
    common_ports = [20, 21, 22, 23, 25, 53, 80, 110, 123, 143, 161, 443, 445, 465, 
                    587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443]
    df['Is_Common_SrcPort'] = df['Source Port'].isin(common_ports).astype(int)
    df['Is_Common_DestPort'] = df['Destination Port'].isin(common_ports).astype(int)
    
    # Calculate port entropy - higher entropy means more diverse port usage (potential scanning)
    src_port_counts = Counter(df['Source Port'])
    dst_port_counts = Counter(df['Destination Port'])
    total_ports = len(df)
    
    # Calculate port entropy
    try:
        src_port_probs = np.array([count/total_ports for count in src_port_counts.values()])
        dst_port_probs = np.array([count/total_ports for count in dst_port_counts.values()])
        src_port_entropy = entropy(src_port_probs)
        dst_port_entropy = entropy(dst_port_probs)
        print(f"Source port entropy: {src_port_entropy:.2f}, Destination port entropy: {dst_port_entropy:.2f}")
        
        # Assign entropy values to each row based on its source/destination port
        df['Src_Port_Rarity'] = df['Source Port'].map(lambda p: 1 - (src_port_counts[p]/total_ports))
        df['Dst_Port_Rarity'] = df['Destination Port'].map(lambda p: 1 - (dst_port_counts[p]/total_ports))
    except:
        print("Skipping port entropy calculation due to insufficient data")
        df['Src_Port_Rarity'] = 0
        df['Dst_Port_Rarity'] = 0
    
    # Flag potentially suspicious port combinations - expanded list
    suspicious_ports = [0, 31337, 1337, 4444, 6666, 6667, 12345, 54321]
    malware_ports = [666, 1024, 2222, 4444, 5554, 6667, 6666, 27374, 27665, 31337]
    trojan_ports = [12345, 31337, 31338, 27374, 27665, 20034, 1000, 1999]
    
    # Use vectorized operations for performance
    df['Has_Suspicious_SrcPort'] = df['Source Port'].isin(suspicious_ports + malware_ports + trojan_ports).astype(int)
    df['Has_Suspicious_DstPort'] = df['Destination Port'].isin(suspicious_ports + malware_ports + trojan_ports).astype(int)
    df['Has_Suspicious_Ports'] = ((df['Has_Suspicious_SrcPort'] == 1) | (df['Has_Suspicious_DstPort'] == 1)).astype(int)
    
    # Flag unusual TCP flag combinations using vectorized operations
    conditions = [
        # SYN+FIN combination (often used in scanning)
        ((df['Has_SYN'] == 1) & (df['Has_FIN'] == 1)),
        # Christmas tree packet (all flags set)
        ((df['Has_SYN'] == 1) & (df['Has_FIN'] == 1) & (df['Has_ACK'] == 1) & 
         (df['Has_PSH'] == 1) & (df['Has_URG'] == 1) & (df['Has_RST'] == 1)),
        # NULL flags (no flags set in TCP)
        ((df['Protocol'] == 'TCP') & (df['Flag_Count'] == 0))
    ]
    choices = [1, 1, 1]
    df['Has_Unusual_Flags'] = np.select(conditions, choices, default=0)
    
    # Extract flow-based features
    print("Extracting flow-based features...")
    
    # Group packets by IP pairs to create flows
    df['Flow_Key'] = df.apply(lambda x: f"{x['Source IP']}_{x['Destination IP']}" 
                                if x['Source IP'] < x['Destination IP'] 
                                else f"{x['Destination IP']}_{x['Source IP']}", axis=1)
    
    # Calculate flow statistics
    flow_stats = df.groupby('Flow_Key').agg({
        'Timestamp': ['count', lambda x: (x.max() - x.min()).total_seconds()],
        'Packet Length': ['mean', 'std', 'sum'],
    })
    
    flow_stats.columns = ['Packets_In_Flow', 'Flow_Duration', 'Mean_Packet_Size', 
                         'Std_Packet_Size', 'Flow_Volume']
    
    # Handle potential division by zero
    flow_stats['Flow_Duration'] = flow_stats['Flow_Duration'].replace(0, 0.001)
    
    # Calculate packets per second for each flow
    flow_stats['Packets_Per_Second'] = flow_stats['Packets_In_Flow'] / flow_stats['Flow_Duration']
    
    # Calculate bytes per second for each flow
    flow_stats['Bytes_Per_Second'] = flow_stats['Flow_Volume'] / flow_stats['Flow_Duration']
    
    # Merge flow stats back to the original dataframe
    df = df.merge(flow_stats, left_on='Flow_Key', right_index=True)
    
    # Calculate inter-arrival times for flows (need timestamp sorting)
    flows = {}
    for flow_key, group in df.sort_values(['Flow_Key', 'Timestamp']).groupby('Flow_Key'):
        timestamps = group['Timestamp'].values
        if len(timestamps) > 1:
            # Handle numpy.timedelta64 objects by converting to seconds directly
            try:
                # First attempt: try standard pandas approach
                inter_arrival_times = []
                for i in range(1, len(timestamps)):
                    delta = timestamps[i] - timestamps[i-1]
                    # Convert to seconds - handle both timedelta and numpy.timedelta64
                    if hasattr(delta, 'total_seconds'):
                        seconds = delta.total_seconds()
                    else:
                        # For numpy.timedelta64, convert to nanoseconds then to seconds
                        seconds = delta.astype('timedelta64[ns]').astype(np.int64) / 1e9
                    inter_arrival_times.append(seconds)
            except:
                # Fallback: Convert timestamps to unix timestamps (seconds since epoch)
                # and calculate differences directly
                try:
                    unix_timestamps = [pd.Timestamp(ts).timestamp() for ts in timestamps]
                    inter_arrival_times = [unix_timestamps[i] - unix_timestamps[i-1] 
                                          for i in range(1, len(unix_timestamps))]
                except:
                    # If all else fails, use a default small value
                    print(f"Warning: Could not calculate inter-arrival times for flow {flow_key}")
                    inter_arrival_times = [0.1] * (len(timestamps) - 1)
            
            if inter_arrival_times:
                # Store mean and std of inter-arrival times
                flows[flow_key] = {
                    'Mean_IAT': np.mean(inter_arrival_times),
                    'Std_IAT': np.std(inter_arrival_times) if len(inter_arrival_times) > 1 else 0,
                    'Min_IAT': np.min(inter_arrival_times),
                    'Max_IAT': np.max(inter_arrival_times)
                }
            else:
                flows[flow_key] = {'Mean_IAT': 0, 'Std_IAT': 0, 'Min_IAT': 0, 'Max_IAT': 0}
        else:
            flows[flow_key] = {'Mean_IAT': 0, 'Std_IAT': 0, 'Min_IAT': 0, 'Max_IAT': 0}
    
    # Create a DataFrame from the flows dictionary
    flow_df = pd.DataFrame.from_dict(flows, orient='index').reset_index()
    flow_df.rename(columns={'index': 'Flow_Key'}, inplace=True)
    
    # Merge inter-arrival times back to the original dataframe
    df = df.merge(flow_df, on='Flow_Key', how='left')
    
    # Fill NaN values in the new columns
    df.fillna({
        'Mean_IAT': 0, 
        'Std_IAT': 0, 
        'Min_IAT': 0, 
        'Max_IAT': 0, 
        'Std_Packet_Size': 0
    }, inplace=True)
    
    # Calculate IAT entropy for each flow
    flow_iat_entropy = {}
    for flow_key, group in df.sort_values(['Flow_Key', 'Timestamp']).groupby('Flow_Key'):
        timestamps = group['Timestamp'].values
        if len(timestamps) > 2:  # Need at least 3 points to calculate meaningful entropy
            try:
                # First attempt: try standard pandas approach
                inter_arrival_times = []
                for i in range(1, len(timestamps)):
                    delta = timestamps[i] - timestamps[i-1]
                    # Convert to seconds - handle both timedelta and numpy.timedelta64
                    if hasattr(delta, 'total_seconds'):
                        seconds = delta.total_seconds()
                    else:
                        # For numpy.timedelta64, convert to nanoseconds then to seconds
                        seconds = delta.astype('timedelta64[ns]').astype(np.int64) / 1e9
                    inter_arrival_times.append(seconds)
            except:
                # Fallback: Convert timestamps to unix timestamps (seconds since epoch)
                # and calculate differences directly
                try:
                    unix_timestamps = [pd.Timestamp(ts).timestamp() for ts in timestamps]
                    inter_arrival_times = [unix_timestamps[i] - unix_timestamps[i-1] 
                                          for i in range(1, len(unix_timestamps))]
                except:
                    # If all else fails, use a default small value
                    inter_arrival_times = [0.1] * (len(timestamps) - 1)
                    
            # Discretize IATs for entropy calculation
            try:
                iat_bins = pd.cut(inter_arrival_times, bins=5, labels=False)
                iat_counts = Counter(iat_bins)
                total = len(iat_bins)
                probs = np.array([count/total for count in iat_counts.values()])
                iat_entropy = entropy(probs)
                flow_iat_entropy[flow_key] = iat_entropy
            except:
                # In case binning fails
                flow_iat_entropy[flow_key] = 0
        else:
            flow_iat_entropy[flow_key] = 0
    
    # Add IAT entropy to each flow
    df['IAT_Entropy'] = df['Flow_Key'].map(flow_iat_entropy).fillna(0)
    
    # Extremely large or small packet sizes with statistical thresholds
    packet_size_stats = df['Packet Length'].describe()
    
    # Packet size z-score for more robust outlier detection
    mean_packet_size = packet_size_stats['mean']
    std_packet_size = packet_size_stats['std']
    
    # Avoid division by zero
    if std_packet_size == 0:
        std_packet_size = 1
        
    df['Packet_Size_ZScore'] = (df['Packet Length'] - mean_packet_size) / std_packet_size
    
    # Flag unusual packet sizes based on z-score
    df['Is_Unusual_Size'] = ((df['Packet_Size_ZScore'].abs() > 3) | 
                            ((df['Packet Length'] < packet_size_stats['25%'] * 0.5) & 
                             (df['Has_ACK'] == 0))).astype(int)
    
    # Source-destination pair frequency
    ip_pair_count = Counter(zip(df['Source IP'], df['Destination IP']))
    df['IP_Pair_Frequency'] = df.apply(lambda x: ip_pair_count[(x['Source IP'], x['Destination IP'])], axis=1)
    
    # Normalize IP_Pair_Frequency for better model handling (log scale to handle skewed distribution)
    max_freq = df['IP_Pair_Frequency'].max()
    if max_freq > 0:
        df['IP_Pair_Freq_Normalized'] = np.log1p(df['IP_Pair_Frequency']) / np.log1p(max_freq)
    else:
        df['IP_Pair_Freq_Normalized'] = 0
    
    # Protocol encoding using LabelEncoder for efficiency
    protocol_encoder = LabelEncoder()
    df['Protocol_Encoded'] = protocol_encoder.fit_transform(df['Protocol'])
    
    # We'll use Packet Direction as our target variable for the direction model
    # Make sure it's clean and handle any unusual values
    direction_counts = df['Packet Direction'].value_counts()
    print(f"Direction distribution: {direction_counts}")
    
    # Filter out rows with direction values other than Inbound/Outbound
    accepted_directions = ['Inbound', 'Outbound']
    
    # Check if we need to add more valid direction labels
    if direction_counts.shape[0] > 2:
        print(f"Found additional direction values besides Inbound/Outbound: {direction_counts.index.tolist()}")
        # If there are many Local/External, include them
        for extra_dir in ['Local', 'External', 'Broadcast']:
            if extra_dir in direction_counts and direction_counts[extra_dir] > 100:
                accepted_directions.append(extra_dir)
                print(f"Including '{extra_dir}' direction in training data ({direction_counts[extra_dir]} packets)")
    
    print(f"Using direction values: {accepted_directions}")
    df = df[df['Packet Direction'].isin(accepted_directions)]
    
    # Check for NaN values in dataframe
    nan_counts = df.isna().sum()
    if nan_counts.sum() > 0:
        print("Found NaN values in the preprocessed data:")
        for col in nan_counts[nan_counts > 0].index:
            print(f"  {col}: {nan_counts[col]} NaN values")
        
        # Fill NaN values appropriately
        print("Applying automatic NaN replacement...")
        
        # Numeric columns: fill with median
        numeric_cols = df.select_dtypes(include=['int64', 'float64']).columns
        for col in numeric_cols:
            if df[col].isna().any():
                median_val = df[col].median()
                df[col] = df[col].fillna(median_val)
                print(f"  Filled {col} NaNs with median: {median_val}")
        
        # Object/Category columns: fill with most frequent
        obj_cols = df.select_dtypes(include=['object', 'category']).columns
        for col in obj_cols:
            if df[col].isna().any():
                if df[col].isna().all():
                    mode_val = 'Unknown'
                else:
                    mode_val = df[col].mode().iloc[0]
                df[col] = df[col].fillna(mode_val)
                print(f"  Filled {col} NaNs with mode: {mode_val}")
    
    # Encode the target variable
    direction_encoder = LabelEncoder()
    df['Direction_Encoded'] = direction_encoder.fit_transform(df['Packet Direction'])
    
    # Select relevant features for direction prediction
    direction_feature_cols = [
        'Protocol_Encoded', 'Packet Length', 'Source Port', 'Destination Port',
        'Hour', 'Minute', 'Day', 'Is_Business_Hours', 'Is_Night',
        'Has_SYN', 'Has_ACK', 'Has_FIN', 'Has_RST', 'Has_PSH', 'Has_URG',
        'Is_Local_Source', 'Is_Local_Dest'
    ]
    
    # Additional features for anomaly detection
    anomaly_feature_cols = direction_feature_cols + [
        'Is_Common_SrcPort', 'Is_Common_DestPort', 'Flag_Count',
        'Has_Suspicious_SrcPort', 'Has_Suspicious_DstPort',
        'Has_Unusual_Flags', 'Is_Unusual_Size', 'IP_Pair_Freq_Normalized',
        'Src_Port_Rarity', 'Dst_Port_Rarity', 'Packet_Size_ZScore',
        'Packets_In_Flow', 'Flow_Duration', 'Mean_Packet_Size', 
        'Std_Packet_Size', 'Flow_Volume', 'Packets_Per_Second',
        'Bytes_Per_Second', 'Mean_IAT', 'Std_IAT', 'Min_IAT', 'Max_IAT',
        'IAT_Entropy'
    ]
    
    # Extract the features and make sure all features exist in the dataframe
    missing_direction_features = [col for col in direction_feature_cols if col not in df.columns]
    missing_anomaly_features = [col for col in anomaly_feature_cols if col not in df.columns]
    
    if missing_direction_features:
        print(f"Warning: Missing direction features: {missing_direction_features}")
        # Create missing features with default values
        for feature in missing_direction_features:
            df[feature] = 0
    
    if missing_anomaly_features:
        print(f"Warning: Missing anomaly features: {missing_anomaly_features}")
        # Create missing features with default values
        for feature in missing_anomaly_features:
            df[feature] = 0
    
    X_direction = df[direction_feature_cols]
    X_anomaly = df[anomaly_feature_cols]
    y = df['Direction_Encoded']
    
    # Final check for NaN values before returning
    if X_direction.isna().any().any() or X_anomaly.isna().any().any():
        print("Warning: NaN values still present in feature matrices. Applying final cleaning...")
        X_direction = X_direction.fillna(0)
        X_anomaly = X_anomaly.fillna(0)
    
    # Store encoders for later use during prediction
    encoders = {
        'protocol': protocol_encoder,
        'direction': direction_encoder
    }
    
    print(f"Preprocessing completed in {time.time() - start_time:.2f} seconds")
    print(f"Direction features: {len(direction_feature_cols)}, Anomaly features: {len(anomaly_feature_cols)}")
    
    return X_direction, X_anomaly, y, direction_feature_cols, anomaly_feature_cols, encoders

def build_direction_model(X, y, feature_cols):
    """Build and train the traffic direction prediction model using cross-validation and hyperparameter tuning."""
    print("Building and optimizing traffic direction model...")
    start_time = time.time()
    
    # Check for and handle NaN values
    print("Checking for missing values in direction data...")
    nan_count = X.isna().sum().sum()
    if nan_count > 0:
        print(f"Found {nan_count} missing values. Applying imputation...")
        
        # Show which columns have NaN values
        cols_with_nans = X.columns[X.isna().any()].tolist()
        print(f"Columns with missing values: {cols_with_nans}")
        
        # Impute missing values before proceeding
        from sklearn.impute import SimpleImputer
        
        # Handle numeric columns
        numeric_cols = X.select_dtypes(include=['int64', 'float64']).columns
        if not numeric_cols.empty:
            numeric_imputer = SimpleImputer(strategy='median')
            X[numeric_cols] = numeric_imputer.fit_transform(X[numeric_cols])
        
        # Handle categorical columns
        categorical_cols = X.select_dtypes(include=['object', 'category']).columns
        if not categorical_cols.empty:
            for col in categorical_cols:
                # Fill with most frequent, or 'Unknown' if column is all NaN
                if X[col].isna().all():
                    X[col] = X[col].fillna('Unknown')
                else:
                    most_frequent = X[col].mode().iloc[0]
                    X[col] = X[col].fillna(most_frequent)
    
    # Use StratifiedKFold for better model validation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    
    # Identify categorical and numerical columns for preprocessing
    categorical_cols = X.select_dtypes(include=['object', 'category']).columns.tolist()
    numerical_cols = X.select_dtypes(include=['int64', 'float64']).columns.tolist()
    
    print(f"Direction model: Processing {len(numerical_cols)} numerical features and {len(categorical_cols)} categorical features")
    
    # Create optimized preprocessor - use only StandardScaler for numerical features
    # since we're already using LabelEncoder for categorical features
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', StandardScaler(), numerical_cols)
        ],
        remainder='passthrough'  # Keep other columns as is (they should already be encoded)
    )
    
    # Create pipeline with preprocessor and model
    pipeline = Pipeline(steps=[
        ('preprocessor', preprocessor),
        ('classifier', RandomForestClassifier(random_state=42))
    ])
    
    # Define hyperparameter search space for GridSearchCV
    param_grid = {
        'classifier__n_estimators': [100, 200],
        'classifier__max_depth': [None, 20, 30],
        'classifier__min_samples_split': [2, 5],
        'classifier__min_samples_leaf': [1, 2],
        'classifier__class_weight': ['balanced', None]
    }
    
    # Use GridSearchCV for hyperparameter tuning
    print("Performing hyperparameter tuning with cross-validation...")
    grid_search = GridSearchCV(
        pipeline, 
        param_grid=param_grid,
        cv=cv,
        scoring='f1_weighted',
        n_jobs=-1,  # Use all available cores
        verbose=1
    )
    
    # Split data into training and testing sets for final evaluation
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # Fit the grid search to find the best parameters
    grid_search.fit(X_train, y_train)
    
    # Get the best model
    best_model = grid_search.best_estimator_
    print(f"Best parameters: {grid_search.best_params_}")
    print(f"Best cross-validation score: {grid_search.best_score_:.4f}")
    
    # Evaluate the best model on the test set
    y_pred = best_model.predict(X_test)
    y_prob = best_model.predict_proba(X_test)[:, 1]  # Probability for the positive class
    
    # Calculate ROC AUC score
    roc_auc = roc_auc_score(y_test, y_prob)
    
    print("\nDirection model evaluation on test set:")
    print(classification_report(y_test, y_pred))
    print(f"ROC AUC: {roc_auc:.4f}")
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    # Extract feature importances if using RandomForest
    feature_importance = None
    if hasattr(best_model[-1], 'feature_importances_'):
        importances = best_model[-1].feature_importances_
        # Map importances back to the original feature names
        # We need to handle the preprocessor's transformation
        if categorical_cols:
            # This is approximate - depends on the exact structure of your pipeline
            feature_importance = {feature: importance for feature, importance 
                                in zip(feature_cols, importances)}
        else:
            feature_importance = {feature: importance for feature, importance 
                                in zip(feature_cols, importances)}
            
        # Print top 10 features by importance
        sorted_importances = sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)
        print("\nTop 10 features by importance:")
        for feature, importance in sorted_importances[:10]:
            print(f"{feature}: {importance:.4f}")
    
    print(f"Direction model training completed in {time.time() - start_time:.2f} seconds")
    
    return best_model, X_test, y_test, feature_importance

def build_anomaly_model(X, feature_cols):
    """Build and train optimized anomaly detection models with hyperparameter tuning."""
    print("Building and optimizing anomaly detection models...")
    start_time = time.time()
    
    # Check for and handle NaN values
    print("Checking for missing values...")
    nan_count = X.isna().sum().sum()
    if nan_count > 0:
        print(f"Found {nan_count} missing values. Applying imputation...")
        
        # Show which columns have NaN values
        cols_with_nans = X.columns[X.isna().any()].tolist()
        print(f"Columns with missing values: {cols_with_nans}")
        
        # Impute missing values before proceeding
        # For numeric columns, use median
        # For categorical columns, use most frequent value
        from sklearn.impute import SimpleImputer
        
        # Handle numeric columns
        numeric_cols = X.select_dtypes(include=['int64', 'float64']).columns
        if not numeric_cols.empty:
            numeric_imputer = SimpleImputer(strategy='median')
            X[numeric_cols] = numeric_imputer.fit_transform(X[numeric_cols])
        
        # Handle categorical columns
        categorical_cols = X.select_dtypes(include=['object', 'category']).columns
        if not categorical_cols.empty:
            for col in categorical_cols:
                # Fill with most frequent, or 'Unknown' if column is all NaN
                if X[col].isna().all():
                    X[col] = X[col].fillna('Unknown')
                else:
                    most_frequent = X[col].mode().iloc[0]
                    X[col] = X[col].fillna(most_frequent)
        
        # Verify imputation worked
        remaining_nans = X.isna().sum().sum()
        if remaining_nans > 0:
            print(f"Warning: {remaining_nans} NaN values remain after imputation.")
            # Last resort: drop remaining rows with NaN values
            X = X.dropna()
            print(f"Dropped rows with remaining NaNs. Shape now: {X.shape}")
    
    # Identify categorical and numerical columns
    categorical_cols = X.select_dtypes(include=['object', 'category']).columns.tolist()
    numerical_cols = X.select_dtypes(include=['int64', 'float64']).columns.tolist()
    
    print(f"Processing {len(numerical_cols)} numerical features and {len(categorical_cols)} categorical features")
    
    # Create optimized preprocessor
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', StandardScaler(), numerical_cols)
        ],
        remainder='passthrough'  # Keep categorical columns as-is (should be encoded already)
    )
    
    # Preprocess the data
    print("Preprocessing data for anomaly detection...")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        X_processed = preprocessor.fit_transform(X)
    
    # Double-check for NaN values in processed data
    if np.isnan(X_processed).any():
        print("Warning: Still found NaNs after preprocessing. Replacing with zeros...")
        X_processed = np.nan_to_num(X_processed)
    
    # Calculate optimal contamination rate based on data distribution
    # This is more data-driven than using a fixed value
    print("Determining optimal contamination rate...")
    
    # Create a basic Isolation Forest to help determine contamination rate
    base_iforest = IsolationForest(n_estimators=100, random_state=42)
    base_scores = -base_iforest.fit(X_processed).score_samples(X_processed)
    
    # Find anomaly threshold using distribution analysis
    q75, q25 = np.percentile(base_scores, [75, 25])
    iqr = q75 - q25
    upper_bound = q75 + 1.5 * iqr
    
    # Count potential anomalies using the IQR method
    potential_anomalies = np.sum(base_scores > upper_bound)
    contamination_rate = max(0.001, min(0.1, potential_anomalies / len(base_scores)))
    print(f"Detected potential contamination rate: {contamination_rate:.4f}")
    
    # Tune Isolation Forest with GridSearchCV
    print("Tuning Isolation Forest hyperparameters...")
    iforest_pipeline = Pipeline([
        ('isolation_forest', IsolationForest(random_state=42))
    ])
    
    param_grid = {
        'isolation_forest__n_estimators': [100, 200],
        'isolation_forest__max_samples': ['auto', 0.5, 0.7],
        'isolation_forest__contamination': [contamination_rate, 0.05, 0.01],
        'isolation_forest__max_features': [0.8, 1.0]
    }
    
    # For unsupervised learning like Isolation Forest, we need a custom scoring function
    def negative_outlier_score(estimator, X):
        return -np.mean(np.abs(estimator.decision_function(X)))
    
    # Use GridSearchCV with custom scoring
    grid_search = GridSearchCV(
        iforest_pipeline,
        param_grid=param_grid,
        scoring=negative_outlier_score,
        cv=5,
        n_jobs=-1,
        verbose=1
    )
    
    grid_search.fit(X_processed)
    
    # Get the best Isolation Forest model
    best_iforest = grid_search.best_estimator_
    print(f"Best Isolation Forest parameters: {grid_search.best_params_}")
    
    # Create a pipeline for future use with the best model
    anomaly_pipeline = Pipeline(steps=[
        ('preprocessor', preprocessor),
        ('anomaly_detector', best_iforest.named_steps['isolation_forest'])
    ])
    
    # Optimize K-means clustering
    print("Optimizing K-means clustering...")
    
    # Determine optimal number of clusters using Silhouette Score
    from sklearn.metrics import silhouette_score
    
    max_clusters = min(8, X_processed.shape[0] // 20)  # Don't create too many clusters for small datasets
    silhouette_scores = []
    clusters_range = range(2, max_clusters + 1)
    
    # Sample data if it's too large (for performance)
    sample_size = min(10000, X_processed.shape[0])
    if X_processed.shape[0] > sample_size:
        indices = np.random.choice(X_processed.shape[0], sample_size, replace=False)
        X_sample = X_processed[indices]
    else:
        X_sample = X_processed
    
    for n_clusters in clusters_range:
        kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
        cluster_labels = kmeans.fit_predict(X_sample)
        
        # Calculate silhouette score
        try:
            silhouette_avg = silhouette_score(X_sample, cluster_labels)
            silhouette_scores.append(silhouette_avg)
            print(f"For n_clusters = {n_clusters}, the silhouette score is {silhouette_avg:.3f}")
        except:
            silhouette_scores.append(-1)  # In case of failure
    
    # Find the best number of clusters
    best_n_clusters = clusters_range[np.argmax(silhouette_scores)]
    print(f"Best number of clusters: {best_n_clusters}")
    
    # Train final K-means model with optimal clusters
    kmeans = KMeans(n_clusters=best_n_clusters, random_state=42, n_init=10)
    kmeans.fit(X_processed)
    
    # Calculate distance to nearest cluster center for each point (vectorized for performance)
    print("Calculating distance metrics...")
    cluster_labels = kmeans.predict(X_processed)
    
    # Vectorized distance calculation
    distances = np.zeros(X_processed.shape[0])
    for i in range(best_n_clusters):
        # Get points belonging to cluster i
        cluster_points = X_processed[cluster_labels == i]
        if len(cluster_points) > 0:
            # Calculate distance from each point to its cluster center
            cluster_dists = np.linalg.norm(cluster_points - kmeans.cluster_centers_[i], axis=1)
            distances[cluster_labels == i] = cluster_dists
    
    # Calculate adaptive thresholds based on cluster distributions
    cluster_thresholds = {}
    for i in range(best_n_clusters):
        cluster_dists = distances[cluster_labels == i]
        if len(cluster_dists) > 10:  # Only if we have enough samples
            # Use 97.5th percentile for the specific cluster
            cluster_thresholds[i] = np.percentile(cluster_dists, 97.5)
        else:
            # Default threshold for small clusters
            cluster_thresholds[i] = np.percentile(distances, 95)
    
    # Global threshold is the 95th percentile of all distances
    global_threshold = np.percentile(distances, 95)
    
    print(f"K-means global anomaly threshold: {global_threshold:.4f}")
    print(f"Per-cluster thresholds range: {min(cluster_thresholds.values()):.4f} - {max(cluster_thresholds.values()):.4f}")
    
    # Generate isolation forest anomaly scores for normalization reference
    iforest_scores = best_iforest.decision_function(X_processed)
    
    # Return both models and required metadata
    anomaly_models = {
        'isolation_forest': anomaly_pipeline,
        'isolation_forest_params': grid_search.best_params_,
        'kmeans': kmeans,
        'kmeans_n_clusters': best_n_clusters,
        'kmeans_global_threshold': global_threshold,
        'kmeans_cluster_thresholds': cluster_thresholds,
        'preprocessor': preprocessor,
        'iforest_score_min': np.min(iforest_scores),
        'iforest_score_max': np.max(iforest_scores)
    }
    
    print(f"Anomaly detection model training completed in {time.time() - start_time:.2f} seconds")
    
    return anomaly_models

def save_models(direction_model, anomaly_models, direction_features, anomaly_features, encoders,
                model_file="network_models.pkl"):
    """Save all trained models to a single file using joblib for better performance."""
    print(f"Saving models to {model_file}...")
    start_time = time.time()
    
    model_data = {
        'direction_model': direction_model,
        'anomaly_models': anomaly_models,
        'direction_features': direction_features,
        'anomaly_features': anomaly_features,
        'encoders': encoders,
        'metadata': {
            'created': time.strftime("%Y-%m-%d %H:%M:%S"),
            'version': '2.0',
            'direction_features_count': len(direction_features),
            'anomaly_features_count': len(anomaly_features)
        }
    }
    
    # Use joblib for faster serialization and better compression
    joblib.dump(model_data, model_file, compress=3)
    
    print(f"Models saved successfully in {time.time() - start_time:.2f} seconds")
    
    # Output model file size for reference
    file_size_mb = os.path.getsize(model_file) / (1024 * 1024)
    print(f"Model file size: {file_size_mb:.2f} MB")

def prepare_features_for_prediction(new_data, required_features, encoders=None, feature_type='direction'):
    """Prepare a dataframe for prediction by ensuring it has all required features with efficient vectorized operations."""
    # Process protocol encoding if needed
    if encoders and 'protocol' in encoders and 'Protocol' in new_data.columns and 'Protocol_Encoded' in required_features:
        # Handle unknown categories by mapping to the most common one
        protocol_encoder = encoders['protocol']
        # Get unique values in the dataset
        unique_protocols = new_data['Protocol'].unique()
        # Find which ones are unknown to the encoder
        try:
            unknown_protocols = [p for p in unique_protocols if p not in protocol_encoder.classes_]
            if unknown_protocols:
                print(f"Warning: Unknown protocol categories found: {unknown_protocols}")
                # Replace with the most common protocol from training
                most_common = protocol_encoder.classes_[0]  # First class is usually most common
                for protocol in unknown_protocols:
                    new_data.loc[new_data['Protocol'] == protocol, 'Protocol'] = most_common
            # Apply encoding
            new_data['Protocol_Encoded'] = protocol_encoder.transform(new_data['Protocol'])
        except:
            print("Warning: Error applying protocol encoding, using default value 0")
            new_data['Protocol_Encoded'] = 0
    
    # Process TCP flags if they exist in the data
    if 'TCP Flags' in new_data.columns:
        tcp_flags = ['SYN', 'ACK', 'FIN', 'RST', 'PSH', 'URG']
        for flag in tcp_flags:
            flag_col = f'Has_{flag}'
            if flag_col in required_features and flag_col not in new_data.columns:
                new_data[flag_col] = new_data['TCP Flags'].str.contains(flag, na=False).astype(int)
        
        # Calculate Flag_Count if needed
        if 'Flag_Count' in required_features and 'Flag_Count' not in new_data.columns:
            flag_cols = [f'Has_{flag}' for flag in tcp_flags if f'Has_{flag}' in new_data.columns]
            if flag_cols:
                new_data['Flag_Count'] = new_data[flag_cols].sum(axis=1)
            else:
                new_data['Flag_Count'] = 0
    
    # Handle IP-based features
    if ('Is_Local_Source' in required_features and 'Is_Local_Source' not in new_data.columns) or \
       ('Is_Local_Dest' in required_features and 'Is_Local_Dest' not in new_data.columns):
        private_ip_patterns = ('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', 
                          '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', 
                          '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.')
        
        if 'Source IP' in new_data.columns and 'Is_Local_Source' in required_features:
            new_data['Is_Local_Source'] = new_data['Source IP'].str.startswith(private_ip_patterns).astype(int)
        
        if 'Destination IP' in new_data.columns and 'Is_Local_Dest' in required_features:
            new_data['Is_Local_Dest'] = new_data['Destination IP'].str.startswith(private_ip_patterns).astype(int)
    
    # Handle temporal features
    if 'Timestamp' in new_data.columns:
        if 'Hour' in required_features and 'Hour' not in new_data.columns:
            new_data['Hour'] = pd.to_datetime(new_data['Timestamp']).dt.hour
        
        if 'Minute' in required_features and 'Minute' not in new_data.columns:
            new_data['Minute'] = pd.to_datetime(new_data['Timestamp']).dt.minute
        
        if 'Day' in required_features and 'Day' not in new_data.columns:
            new_data['Day'] = pd.to_datetime(new_data['Timestamp']).dt.day_of_week
        
        if 'Is_Business_Hours' in required_features and 'Is_Business_Hours' not in new_data.columns:
            new_data['Is_Business_Hours'] = ((new_data['Hour'] >= 9) & (new_data['Hour'] <= 17)).astype(int)
        
        if 'Is_Night' in required_features and 'Is_Night' not in new_data.columns:
            new_data['Is_Night'] = ((new_data['Hour'] >= 22) | (new_data['Hour'] <= 5)).astype(int)
    
    # Process port-based features
    if ('Is_Common_SrcPort' in required_features and 'Is_Common_SrcPort' not in new_data.columns) or \
       ('Is_Common_DestPort' in required_features and 'Is_Common_DestPort' not in new_data.columns):
        common_ports = [20, 21, 22, 23, 25, 53, 80, 110, 123, 143, 161, 443, 445, 465, 
                        587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443]
        
        if 'Source Port' in new_data.columns and 'Is_Common_SrcPort' in required_features:
            new_data['Is_Common_SrcPort'] = new_data['Source Port'].isin(common_ports).astype(int)
        
        if 'Destination Port' in new_data.columns and 'Is_Common_DestPort' in required_features:
            new_data['Is_Common_DestPort'] = new_data['Destination Port'].isin(common_ports).astype(int)
    
    # Process suspicious port features
    if ('Has_Suspicious_SrcPort' in required_features and 'Has_Suspicious_SrcPort' not in new_data.columns) or \
       ('Has_Suspicious_DstPort' in required_features and 'Has_Suspicious_DstPort' not in new_data.columns):
        suspicious_ports = [0, 31337, 1337, 4444, 6666, 6667, 12345, 54321, 
                           666, 1024, 2222, 5554, 27374, 27665, 31338, 20034, 1000, 1999]
        
        if 'Source Port' in new_data.columns and 'Has_Suspicious_SrcPort' in required_features:
            new_data['Has_Suspicious_SrcPort'] = new_data['Source Port'].isin(suspicious_ports).astype(int)
        
        if 'Destination Port' in new_data.columns and 'Has_Suspicious_DstPort' in required_features:
            new_data['Has_Suspicious_DstPort'] = new_data['Destination Port'].isin(suspicious_ports).astype(int)
        
        if 'Has_Suspicious_Ports' in required_features and 'Has_Suspicious_Ports' not in new_data.columns:
            if 'Has_Suspicious_SrcPort' in new_data.columns and 'Has_Suspicious_DstPort' in new_data.columns:
                new_data['Has_Suspicious_Ports'] = ((new_data['Has_Suspicious_SrcPort'] == 1) | 
                                                  (new_data['Has_Suspicious_DstPort'] == 1)).astype(int)
            else:
                new_data['Has_Suspicious_Ports'] = 0
    
    # Handle any remaining missing features
    missing_features = set(required_features) - set(new_data.columns)
    if missing_features:
        print(f"Warning: Missing {feature_type} features in data: {missing_features}")
        # Create missing features with default values efficiently
        default_0_features = ['Has_SYN', 'Has_ACK', 'Has_FIN', 'Has_RST', 'Has_PSH', 'Has_URG',
                             'Is_Local_Source', 'Is_Local_Dest', 'Is_Common_SrcPort', 'Is_Common_DestPort', 
                             'Has_Suspicious_Ports', 'Has_Suspicious_SrcPort', 'Has_Suspicious_DstPort',
                             'Has_Unusual_Flags', 'Is_Unusual_Size', 'Is_Business_Hours', 'Is_Night',
                             'Flag_Count']
        
        float_features = ['IP_Pair_Freq_Normalized', 'Packet_Size_ZScore', 'Src_Port_Rarity', 
                         'Dst_Port_Rarity', 'Mean_IAT', 'Std_IAT', 'Min_IAT', 'Max_IAT',
                         'IAT_Entropy', 'Packets_Per_Second', 'Bytes_Per_Second',
                         'Flow_Duration', 'Packets_In_Flow', 'Mean_Packet_Size', 
                         'Std_Packet_Size', 'Flow_Volume']
        
        for feature in missing_features:
            if feature in default_0_features:
                new_data[feature] = 0
            elif feature == 'IP_Pair_Frequency':
                new_data[feature] = 1  # Default to 1 occurrence
            elif feature in float_features:
                new_data[feature] = 0.0
            else:
                new_data[feature] = -1
    
    # Ensure all required features are present and in the right order
    return new_data[required_features]

def predict_traffic(model_file, new_data):
    """Use the trained models to predict traffic direction and check for anomalies with optimized calculations."""
    print("Running predictions using model...")
    start_time = time.time()
    
    # Load models with joblib for faster loading
    try:
        model_data = joblib.load(model_file)
    except:
        # Fallback to pickle if joblib fails
        print("Warning: Using pickle fallback for model loading")
        with open(model_file, 'rb') as f:
            model_data = pickle.load(f)
    
    direction_model = model_data['direction_model']
    anomaly_models = model_data['anomaly_models']
    direction_features = model_data['direction_features']
    anomaly_features = model_data['anomaly_features']
    encoders = model_data.get('encoders', None)  # Backward compatibility
    
    # Prepare data for direction prediction with optimized feature preparation
    direction_data = prepare_features_for_prediction(new_data, direction_features, encoders, 'direction')
    
    # Make direction prediction
    print("Predicting traffic direction...")
    direction_pred = direction_model.predict(direction_data)
    direction_prob = direction_model.predict_proba(direction_data)
    
    # If direction encoder is available, convert predictions back to human-readable labels
    if encoders and 'direction' in encoders:
        direction_pred = encoders['direction'].inverse_transform(direction_pred)
    
    # Prepare data for anomaly detection with optimized feature preparation
    anomaly_data = prepare_features_for_prediction(new_data, anomaly_features, encoders, 'anomaly')
    
    # Get isolation forest parameters from model data
    print("Detecting anomalies...")
    isolation_forest = anomaly_models['isolation_forest']
    
    # Get min/max scores for normalization
    iforest_score_min = anomaly_models.get('iforest_score_min', -0.5)  # Default fallback values
    iforest_score_max = anomaly_models.get('iforest_score_max', 0.5)
    
    # Isolation Forest prediction
    # Calculate anomaly scores (-ve means anomaly, +ve means normal)
    isolation_forest_scores = isolation_forest.decision_function(anomaly_data)
    
    # Normalize scores to 0-1 range where 1 is anomalous
    # Convert decision scores to normalized anomaly scores (0-1)
    normalized_iforest_scores = 1 - ((isolation_forest_scores - iforest_score_min) / 
                                   (iforest_score_max - iforest_score_min))
    # Clip to 0-1
    normalized_iforest_scores = np.clip(normalized_iforest_scores, 0, 1)
    
    # Binary anomaly flags (1 = anomaly)
    isolation_forest_anomaly = (normalized_iforest_scores > 0.8).astype(int)
    
    # K-means anomaly detection with optimized approach (vectorized)
    # Process with the same preprocessor used during training
    preprocessor = anomaly_models['preprocessor']
    kmeans = anomaly_models['kmeans']
    n_clusters = anomaly_models['kmeans_n_clusters']
    global_threshold = anomaly_models['kmeans_global_threshold']
    cluster_thresholds = anomaly_models['kmeans_cluster_thresholds']
    
    # Transform the data
    processed_data = preprocessor.transform(anomaly_data)
    
    # Predict cluster assignments
    kmeans_clusters = kmeans.predict(processed_data)
    
    # Vectorized distance calculation to cluster centers
    cluster_distances = np.zeros(processed_data.shape[0])
    
    # For each cluster, calculate distances for all points in that cluster
    for i in range(n_clusters):
        # Get points belonging to cluster i
        cluster_mask = (kmeans_clusters == i)
        cluster_points = processed_data[cluster_mask]
        
        if len(cluster_points) > 0:
            # Calculate distance from each point to its cluster center
            cluster_dists = np.linalg.norm(cluster_points - kmeans.cluster_centers_[i], axis=1)
            cluster_distances[cluster_mask] = cluster_dists
    
    # Normalize cluster distances to 0-1 range
    max_dist = np.max(cluster_distances) if cluster_distances.size > 0 and np.max(cluster_distances) > 0 else 1
    normalized_kmeans_scores = cluster_distances / max_dist
    
    # Use cluster-specific thresholds for more accurate detection
    kmeans_anomaly = np.zeros(processed_data.shape[0], dtype=int)
    
    for i in range(n_clusters):
        cluster_mask = (kmeans_clusters == i)
        # Use cluster-specific threshold if available, otherwise use global
        threshold = cluster_thresholds.get(i, global_threshold)
        kmeans_anomaly[cluster_mask] = (cluster_distances[cluster_mask] > threshold).astype(int)
    
    # Combine anomaly signals with weighted approach
    # If either model has high confidence, mark as anomaly
    combined_anomaly = np.zeros(processed_data.shape[0], dtype=int)
    
    # Strong signals from either model (where score > 0.85)
    strong_iforest = normalized_iforest_scores > 0.85
    strong_kmeans = normalized_kmeans_scores > 0.85
    
    # Medium signals from both models (where both scores > 0.7)
    medium_both = (normalized_iforest_scores > 0.7) & (normalized_kmeans_scores > 0.7)
    
    # Combined logical OR of strong and medium conditions
    combined_anomaly = (strong_iforest | strong_kmeans | medium_both).astype(int)
    
    # Calculate final anomaly scores (0 to 1, where 1 is most anomalous)
    # Weighted average of both models, with more weight given to isolation forest (better for outliers)
    weighted_anomaly_scores = (0.6 * normalized_iforest_scores + 
                              0.4 * normalized_kmeans_scores)
    
    # Create additional context information for each anomaly
    anomaly_contexts = []
    for idx, is_anomaly in enumerate(combined_anomaly):
        if is_anomaly:
            context = {}
            
            # Get model contributions
            context['isolation_forest_score'] = normalized_iforest_scores[idx]
            context['kmeans_score'] = normalized_kmeans_scores[idx]
            
            # Identify most likely reason for anomaly
            reasons = []
            
            # Check packet features for common anomaly patterns
            if idx < len(anomaly_data):
                # Unusual flags
                if anomaly_data['Has_Unusual_Flags'].iloc[idx] == 1:
                    reasons.append("Unusual TCP flags")
                
                # Unusual packet size
                if anomaly_data['Is_Unusual_Size'].iloc[idx] == 1:
                    reasons.append("Unusual packet size")
                
                # Suspicious ports
                if anomaly_data['Has_Suspicious_Ports'].iloc[idx] == 1:
                    reasons.append("Suspicious port usage")
                
                # Rare port
                if 'Src_Port_Rarity' in anomaly_data.columns and anomaly_data['Src_Port_Rarity'].iloc[idx] > 0.9:
                    reasons.append("Rare source port")
                if 'Dst_Port_Rarity' in anomaly_data.columns and anomaly_data['Dst_Port_Rarity'].iloc[idx] > 0.9:
                    reasons.append("Rare destination port")
                    
                # Unusual flow characteristics
                if 'Packets_Per_Second' in anomaly_data.columns and anomaly_data['Packets_Per_Second'].iloc[idx] > 100:
                    reasons.append("High packet rate")
                if 'IAT_Entropy' in anomaly_data.columns and anomaly_data['IAT_Entropy'].iloc[idx] > 2:
                    reasons.append("Unusual timing pattern")
            
            if not reasons:
                reasons.append("Statistical outlier")
                
            context['reasons'] = reasons
            anomaly_contexts.append(context)
        else:
            anomaly_contexts.append(None)
    
    print(f"Prediction completed in {time.time() - start_time:.2f} seconds")
    
    # Return comprehensive results
    return {
        'direction': direction_pred,
        'direction_probability': np.max(direction_prob, axis=1),
        'is_anomaly': combined_anomaly,
        'anomaly_score': weighted_anomaly_scores,
        'model_signals': {
            'isolation_forest_score': normalized_iforest_scores,
            'kmeans_score': normalized_kmeans_scores,
            'isolation_forest_binary': isolation_forest_anomaly,
            'kmeans_binary': kmeans_anomaly
        },
        'anomaly_contexts': anomaly_contexts
    }

def create_api_server(model_file="network_models.pkl", host="0.0.0.0", port=5000):
    """Create a FastAPI server for real-time prediction."""
    try:
        from fastapi import FastAPI, HTTPException
        from pydantic import BaseModel
        import uvicorn
        from typing import List, Optional, Dict, Any
        import pandas as pd
        import numpy as np
        import time
        
        # Define data models
        class NetworkPacket(BaseModel):
            timestamp: str
            source_ip: str
            source_mac: str
            destination_ip: str
            destination_mac: str
            protocol: str
            packet_length: int
            source_port: Optional[int] = None
            destination_port: Optional[int] = None
            tcp_flags: Optional[str] = None
            direction: Optional[str] = None
            
        class PredictionRequest(BaseModel):
            packets: List[NetworkPacket]
            
        class PredictionResponse(BaseModel):
            results: List[Dict[str, Any]]
            prediction_time: float
            model_version: str
            
        # Create FastAPI app
        app = FastAPI(
            title="Network Traffic Analyzer API",
            description="API for predicting network traffic direction and detecting anomalies",
            version="1.0.0"
        )
        
        # Load model at startup
        model_data = joblib.load(model_file)
        model_version = model_data.get('metadata', {}).get('version', 'unknown')
        
        @app.post("/predict", response_model=PredictionResponse)
        async def predict(request: PredictionRequest):
            """Predict traffic direction and detect anomalies for a batch of packets."""
            start_time = time.time()
            
            # Convert request to DataFrame
            packet_dicts = []
            for packet in request.packets:
                packet_dict = packet.dict()
                # Map field names to match model expectations
                packet_dicts.append({
                    'Timestamp': packet_dict['timestamp'],
                    'Source IP': packet_dict['source_ip'],
                    'Source MAC': packet_dict['source_mac'],
                    'Destination IP': packet_dict['destination_ip'],
                    'Destination MAC': packet_dict['destination_mac'],
                    'Protocol': packet_dict['protocol'],
                    'Packet Length': packet_dict['packet_length'],
                    'Source Port': packet_dict['source_port'] if packet_dict['source_port'] is not None else -1,
                    'Destination Port': packet_dict['destination_port'] if packet_dict['destination_port'] is not None else -1,
                    'TCP Flags': packet_dict['tcp_flags'] if packet_dict['tcp_flags'] is not None else '',
                    'Packet Direction': packet_dict['direction'] if packet_dict['direction'] is not None else 'Unknown'
                })
            
            df = pd.DataFrame(packet_dicts)
            
            # Make predictions
            try:
                predictions = predict_traffic(model_file, df)
                
                # Format results
                results = []
                for i in range(len(df)):
                    packet_result = {
                        'predicted_direction': str(predictions['direction'][i]),
                        'direction_confidence': float(predictions['direction_probability'][i]),
                        'is_anomaly': bool(predictions['is_anomaly'][i]),
                        'anomaly_score': float(predictions['anomaly_score'][i]),
                        'isolation_forest_score': float(predictions['model_signals']['isolation_forest_score'][i]),
                        'kmeans_score': float(predictions['model_signals']['kmeans_score'][i])
                    }
                    
                    # Include anomaly context if available
                    if predictions['anomaly_contexts'][i] is not None:
                        packet_result['anomaly_reasons'] = predictions['anomaly_contexts'][i]['reasons']
                    
                    results.append(packet_result)
                
                return PredictionResponse(
                    results=results,
                    prediction_time=time.time() - start_time,
                    model_version=model_version
                )
            
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Prediction error: {str(e)}")
                
        # Start server
        print(f"Starting API server on http://{host}:{port}")
        uvicorn.run(app, host=host, port=port)
        
    except ImportError:
        print("Error: FastAPI and uvicorn packages are required for API server.")
        print("Install with: pip install fastapi uvicorn")
        return

def main():
    """Main function with extended command-line options."""
    import sys
    import argparse
    import os
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Network Traffic Analyzer with ML")
    parser.add_argument("--train", action="store_true", help="Train new models")
    parser.add_argument("--input", type=str, default="log1.csv", help="Input CSV file for training")
    parser.add_argument("--output", type=str, default="network_models.pkl", help="Output model file")
    parser.add_argument("--serve", action="store_true", help="Start API server")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="API server host")
    parser.add_argument("--port", type=int, default=5000, help="API server port")
    parser.add_argument("--analyze", type=str, help="Analyze CSV file with existing model")
    parser.add_argument("--model", type=str, default="network_models.pkl", help="Model file to use for analysis")
    
    args = parser.parse_args()
    
    # Handle --serve option
    if args.serve:
        print(f"Starting API server with model {args.model}...")
        create_api_server(args.model, args.host, args.port)
        return
        
    # Handle --analyze option
    if args.analyze:
        if not os.path.exists(args.analyze):
            print(f"Error: Input file {args.analyze} not found")
            return
            
        if not os.path.exists(args.model):
            print(f"Error: Model file {args.model} not found")
            return
            
        print(f"Analyzing {args.analyze} with model {args.model}...")
        import pandas as pd
        
        # Load data
        df = pd.read_csv(args.analyze)
        
        # Analyze the data
        predictions = predict_traffic(args.model, df)
        
        # Print summary statistics
        anomaly_count = sum(predictions['is_anomaly'])
        total_count = len(predictions['is_anomaly'])
        anomaly_percent = 100 * anomaly_count / total_count if total_count > 0 else 0
        
        print("\nAnalysis Results:")
        print(f"Total packets analyzed: {total_count}")
        print(f"Anomalous packets detected: {anomaly_count} ({anomaly_percent:.2f}%)")
        
        # Direction distribution
        direction_counts = pd.Series(predictions['direction']).value_counts()
        print("\nDirection distribution:")
        for direction, count in direction_counts.items():
            percent = 100 * count / total_count
            print(f"  {direction}: {count} ({percent:.2f}%)")
        
        # Top anomaly reasons
        if anomaly_count > 0:
            all_reasons = []
            for ctx in predictions['anomaly_contexts']:
                if ctx is not None:
                    all_reasons.extend(ctx['reasons'])
            
            reason_counts = pd.Series(all_reasons).value_counts()
            print("\nTop anomaly reasons:")
            for reason, count in reason_counts.iloc[:5].items():
                percent = 100 * count / len(all_reasons)
                print(f"  {reason}: {count} ({percent:.2f}%)")
        
        # Save analysis results
        output_file = os.path.splitext(args.analyze)[0] + "_analysis.csv"
        
        # Create result DataFrame
        result_df = df.copy()
        result_df['Predicted_Direction'] = predictions['direction']
        result_df['Direction_Confidence'] = predictions['direction_probability']
        result_df['Is_Anomaly'] = predictions['is_anomaly']
        result_df['Anomaly_Score'] = predictions['anomaly_score']
        
        # Add anomaly reasons
        reasons = []
        for ctx in predictions['anomaly_contexts']:
            if ctx is not None:
                reasons.append("; ".join(ctx['reasons']))
            else:
                reasons.append("")
        
        result_df['Anomaly_Reasons'] = reasons
        
        # Save to CSV
        result_df.to_csv(output_file, index=False)
        print(f"\nDetailed analysis saved to {output_file}")
        return
    
    # Default: train new models
    csv_file = args.input
    output_file = args.output
    
    if not os.path.exists(csv_file):
        print(f"Error: Input file {csv_file} not found")
        return
    
    print(f"Training models using {csv_file}...")
    
    # Memory management - use garbage collection before large operations
    gc.collect()
    
    # Load and preprocess data
    X_direction, X_anomaly, y, direction_features, anomaly_features, encoders = load_and_preprocess_data(csv_file)
    
    # Build direction prediction model
    direction_model, X_test, y_test, feature_importance = build_direction_model(X_direction, y, direction_features)
    
    # Memory management between training operations
    gc.collect()
    
    # Build anomaly detection models
    anomaly_models = build_anomaly_model(X_anomaly, anomaly_features)
    
    # Save models
    save_models(direction_model, anomaly_models, direction_features, anomaly_features, encoders, output_file)
    
    print(f"\nModel training complete! Model saved to {output_file}")
    print("\nNext steps:")
    print(f"  - Analyze data: python network_ml.py --analyze new_data.csv --model {output_file}")
    print(f"  - Start API server: python network_ml.py --serve --model {output_file}")
    print("  - Import in code: from network_ml import predict_traffic")

if __name__ == "__main__":
    main()
