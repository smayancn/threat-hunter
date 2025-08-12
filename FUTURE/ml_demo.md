# Network Threat Detection ML Demonstration

This project demonstrates how more detailed network packet data leads to better ML-based threat detection. It includes tools for:

1. Capturing network traffic with two different levels of detail:
   - `sniffer.py`: Basic network packet capture with minimal information
   - `colab.py`: Detailed packet capture with protocol-specific fields

2. Machine learning-based threat detection:
   - `threat_detector.py`: ML model that works with both data formats

3. Test data generation:
   - `generate_test_data.py`: Generate synthetic network traffic for testing

## Key Concepts

This demonstration shows that when using the more detailed protocol information from `colab.py`, machine learning models can achieve higher accuracy in detecting network threats compared to using basic packet information from `sniffer.py`.

## Requirements

- Python 3.7+
- Required Python packages:
  - pandas
  - numpy
  - scikit-learn
  - matplotlib
  - seaborn
  - joblib
  - scapy (for actual packet capture)

Install the requirements:

```bash
pip install pandas numpy scikit-learn matplotlib seaborn joblib scapy
```

## Usage

### Step 1: Generate Test Data

Generate synthetic network packet data for both formats:

```bash
# Generate basic format data (like sniffer.py output)
python generate_test_data.py --format basic --count 5000 --output basic_network_data.csv

# Generate detailed format data (like colab.py output)
python generate_test_data.py --format detailed --count 5000 --output detailed_network_data.csv
```

### Step 2: Compare Model Performance

Train and evaluate models on both data formats:

```bash
python threat_detector.py --compare --basic-csv basic_network_data.csv --detailed-csv detailed_network_data.csv --output-dir models
```

This will:
1. Train a model on the basic data
2. Train a model on the detailed data
3. Evaluate both models
4. Generate comparison reports and visualizations
5. Save trained models in the `models` directory

### Step 3: Review Results

The comparison results will be saved in `models/comparison_results.txt`, showing:
- Accuracy of each model
- Number of features used by each model
- Overall improvement from using detailed data

The visualization images will show:
- Feature importance
- Confusion matrices
- Detection probability distributions
- ROC curves

### Capturing Real Network Data

You can also use the included packet capture tools to gather real network data:

```bash
# Basic packet capture
python sniffer.py

# Detailed packet capture
python colab.py
```

Then use the ML model on your real data:

```bash
# Train on captured data
python threat_detector.py --csv captured_data.csv --train --model my_model.joblib

# Evaluate on captured data
python threat_detector.py --csv captured_data.csv --evaluate --model my_model.joblib
```

## Key Files

- `sniffer.py`: Basic network packet capture tool
- `colab.py`: Detailed network packet capture tool with protocol-specific information
- `threat_detector.py`: ML-based threat detection that works with both data formats
- `generate_test_data.py`: Generates synthetic network data for testing
- `sniffer_gui.py`: GUI interface for network packet capture and analysis

## How It Works

1. **Data Collection:**
   - The basic format captures standard packet metadata (IPs, ports, protocol)
   - The detailed format additionally captures protocol-specific fields (HTTP methods, DNS queries, TCP flags, etc.)

2. **Feature Engineering:**
   - Basic data yields a limited set of features
   - Detailed data allows extraction of rich, protocol-aware features

3. **Model Training:**
   - Random Forest classifier trained on labeled data
   - Models automatically adapt to available features

4. **Evaluation:**
   - Side-by-side comparison of model performance
   - Visualization of key metrics and feature importance

## Conclusion

This demonstration shows that ML models benefit significantly from the detailed protocol-specific information. The improved accuracy stems from:

1. **Protocol-specific threat indicators:** The detailed format captures HTTP paths, DNS queries, TLS versions, etc.
2. **Contextual awareness:** Protocol fields provide context that helps differentiate normal vs. suspicious traffic
3. **More features:** The detailed format provides more signals for the ML model to learn from

The takeaway is that when designing network security monitoring solutions, capturing detailed protocol information leads to more effective threat detection.

# Machine Learning Model for Network Threat Detection

This document outlines the machine learning model used in `threat_detector.py` to identify network threats based on packet data. The core idea is to demonstrate that richer, more detailed packet information leads to a more accurate threat detection model.

## 1. Model Architecture and Workflow

The system employs a `NetworkThreatDetector` class which encapsulates all the ML-related functionalities:

1.  **Data Loading (`load_data`)**:
    *   Accepts a CSV file containing network packet data.
    *   Crucially, it can automatically detect the source of the CSV:
        *   `'basic'`: Data from `sniffer.py` (e.g., `capture_20250521-222829.csv`). This format has fewer, more general features.
        *   `'detailed'`: Data from `colab.py` (e.g., `network_logs.csv`). This format is much richer, containing protocol-specific fields.
    *   Based on the detected type, it routes the data to the appropriate preprocessing function.

2.  **Data Preprocessing**:
    *   **`_preprocess_basic_data`**:
        *   Handles data from `sniffer.py`.
        *   Performs necessary cleaning (filling missing values).
        *   Feature Engineering: Creates numerical and categorical features from the limited columns available (e.g., `protocol`, `source_ip`, `destination_ip`, `source_port`, `destination_port`, `tcp_flags`, `length`, `ttl`, `packet_direction`, `dns_query`, `http_method`, `http_host`, `http_path`).
        *   Label Generation (`is_threat`): Creates a binary target variable. A packet is labeled as a threat if it matches simple, predefined rules based on suspicious ports, TCP flags, or basic HTTP/DNS indicators.
    *   **`_preprocess_detailed_data`**:
        *   Handles the more comprehensive data from `colab.py`.
        *   Performs similar cleaning steps.
        *   Extensive Feature Engineering: Leverages the rich set of columns available in `network_logs.csv`. This includes:
            *   Basic features similar to the basic preprocessor.
            *   Advanced TCP flag analysis (SYN, RST, FIN, ACK presence).
            *   TTL analysis (e.g., detecting low TTL values).
            *   Detailed HTTP features: methods (GET, POST), suspicious paths, known malware domains in hosts.
            *   Detailed DNS features: query names, detection of suspicious Top-Level Domains (TLDs like `.xyz`, `.tk`).
            *   ICMP features: type/code analysis for scanning patterns (e.g., Echo Request).
            *   TLS features: version (detecting obsolete/insecure versions like SSLv3, TLS 1.0), content type, handshake type.
            *   ARP features: opcode analysis (request/reply).
            *   UDP length, HTTP status codes.
        *   Label Generation (`is_threat`): Uses a more comprehensive set of rules for labeling threats, incorporating the detailed protocol information. For instance, it can flag obsolete TLS versions, specific ICMP scan patterns, or suspicious DNS query types, which wouldn't be possible with the basic dataset.

3.  **Model Training (`train`)**:
    *   Input: Preprocessed data (features and labels).
    *   Splits data into features (X) and labels (y).
    *   Stores the list of feature columns used for training; this is important for ensuring consistency during prediction.
    *   **Preprocessing Pipeline**:
        *   Identifies `numeric_features` and `categorical_features`.
        *   Numeric Transformer: Applies `StandardScaler` to numeric features to standardize them (mean 0, variance 1).
        *   Categorical Transformer: Applies `OneHotEncoder` (with `handle_unknown='ignore'`) to categorical features. This converts categorical variables into a numerical format that the model can understand.
        *   `ColumnTransformer`: Combines these transformers to apply them to the correct columns. `remainder='passthrough'` ensures that any columns not specified as numeric or categorical are passed through without transformation (though ideally, all features should be explicitly handled).
    *   **Classifier**:
        *   Uses a `RandomForestClassifier`. This ensemble model is generally robust, performs well with a mix of feature types, and provides feature importances.
        *   Key parameters: `n_estimators=100` (number of trees), `max_depth=10` (limits tree depth to prevent overfitting), `random_state=42` (for reproducibility), `class_weight='balanced'` (important for imbalanced datasets where threat instances might be rare, as it adjusts weights inversely proportional to class frequencies).
        *   **Scikit-learn Pipeline**: The `ColumnTransformer` (for preprocessing) and the `RandomForestClassifier` are combined into a single `Pipeline`. This ensures that the same preprocessing steps are applied consistently during training, evaluation, and prediction.
        *   The pipeline is then trained using `pipeline.fit(features, labels)`.
        *   Feature Importances: If the classifier supports it (RandomForest does), it prints the top 10 most important features identified by the model.

4.  **Prediction (`predict`)**:
    *   Input: New, unseen preprocessed data.
    *   Ensures the input data has the same feature columns (in the same order) as the data used for training.
    *   Uses the trained `self.model` (the scikit-learn pipeline) to make predictions (`model.predict()`) and predict probabilities (`model.predict_proba()`).
    *   Output: An array of predictions (0 for normal, 1 for threat) and an array of probabilities for the threat class.

5.  **Evaluation (`evaluate`)**:
    *   Input: Preprocessed test data and corresponding true labels.
    *   Makes predictions on the test data.
    *   Calculates and prints key performance metrics:
        *   Accuracy
        *   Confusion Matrix (True Positives, True Negatives, False Positives, False Negatives)
        *   Classification Report (precision, recall, F1-score, support for each class).
    *   Output: A dictionary containing these evaluation metrics.

6.  **Model Saving/Loading (`save_model`, `load_model`)**:
    *   Uses `joblib` to serialize and deserialize the trained model pipeline, feature columns, source type, and label column. This allows the trained model to be persisted and reused later without retraining.

7.  **Visualization (`visualize_results`)**:
    *   Generates and saves several plots to help understand model performance:
        *   Top 10 Feature Importances (bar chart).
        *   Confusion Matrix (heatmap).
        *   Prediction Probability Distribution (histogram).
        *   Receiver Operating Characteristic (ROC) Curve and Area Under the Curve (AUC) score.
    *   Saves the combined plot as `threat_detection_results.png`.

## 2. Model Comparison (`compare_models` function)

This is a key function in `threat_detector.py` designed to highlight the impact of data quality:

1.  Takes paths to two CSV files: one basic (`capture_20250521-222829.csv`) and one detailed (`network_logs.csv`).
2.  Creates two separate `NetworkThreatDetector` instances.
3.  Loads and preprocesses data for each, using their respective formats.
4.  **Trains and Evaluates Separately**:
    *   For each dataset (basic and detailed):
        *   Splits the data into training and testing sets (70% train, 30% test) using `train_test_split` with stratification on the label to ensure similar class distribution in train/test sets.
        *   Trains a model using the training set.
        *   Evaluates the trained model on the test set.
        *   Saves the trained model (e.g., `basic_model.joblib`, `detailed_model.joblib`).
        *   Generates and saves visualizations for each model.
5.  **Prints Comparison Summary**:
    *   Displays the accuracy of both models.
    *   Calculates and shows the accuracy improvement achieved by the detailed model.
    *   Shows the number of features used by each model.
6.  **Saves Detailed Comparison Results**:
    *   Writes a text file (`comparison_results.txt`) in the output directory, containing:
        *   Date of the comparison.
        *   Metrics for the basic model (accuracy, feature count, model path).
        *   Metrics for the detailed model (accuracy, feature count, model path).
        *   A direct comparison of accuracy improvement and feature count increase.
        *   A conclusion on whether the detailed format provided better accuracy.

## 3. Key Differences Highlighted by the Model

The setup is designed to demonstrate that:

*   **More Features, Better Context**: The detailed dataset from `colab.py` provides a significantly larger and more specific set of features. This allows the ML model to learn more nuanced patterns associated with network threats.
*   **Improved Accuracy**: Due to the richer feature set, the model trained on the `network_logs.csv` (detailed) data is expected to achieve higher accuracy, better precision, and better recall in detecting threats compared to the model trained on the `capture_20250521-222829.csv` (basic) data.
*   **Sophisticated Threat Indicators**: The feature engineering for the detailed data incorporates more sophisticated threat indicators (e.g., obsolete TLS versions, specific DNS query types, ICMP scanning patterns) that are simply not available in the basic dataset. This directly translates to the model's ability to identify a wider range of, and more subtle, threats.

The `run_demo.py` script orchestrates this comparison, making it easy to see the performance difference side-by-side. 