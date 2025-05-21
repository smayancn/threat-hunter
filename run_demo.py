#!/usr/bin/env python3
import os
import subprocess
import argparse
import sys

def print_header(message):
    """Print a formatted header message"""
    print("\n" + "="*70)
    print(f" {message}")
    print("="*70)

def run_command(command, description):
    """Run a command and print its output in real-time"""
    print_header(description)
    print(f"Running: {' '.join(command)}")
    
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,  # Equivalent to universal_newlines=True
            bufsize=1  # Line-buffered
        )
        
        if process.stdout:
            for line in process.stdout:
                print(line, end='')
        
        return_code = process.wait()
        if return_code != 0:
            print(f"\nCommand failed with return code {return_code}")
            return False
        
        return True
    except Exception as e:
        print(f"Error running command: {e}")
        return False

def check_package(package_name):
    """Check if a Python package is installed"""
    try:
        __import__(package_name)
        return True
    except ImportError:
        return False

def main():
    parser = argparse.ArgumentParser(description="Run the Network Threat Detection ML Demonstration")
    parser.add_argument('--output-dir', default='demo_output', help='Directory to save all output files (models, visualizations, reports)')
    args = parser.parse_args()
    
    # Create base output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Check required packages
    required_packages = ['pandas', 'numpy', 'sklearn', 'matplotlib', 'seaborn', 'joblib']
    missing_packages = [pkg for pkg in required_packages if not check_package(pkg)]
    
    if missing_packages:
        print_header("MISSING REQUIRED PACKAGES")
        print("The following required packages are missing:")
        for pkg in missing_packages:
            print(f"  - {pkg}")
        
        install_prompt = input("\nWould you like to install these packages now? (y/n): ").strip().lower()
        if install_prompt == 'y':
            pip_command = [sys.executable, '-m', 'pip', 'install'] + missing_packages
            if not run_command(pip_command, "INSTALLING REQUIRED PACKAGES"):
                print("\nFailed to install packages. Please install them manually and try again.")
                return
        else:
            print("\nPlease install the required packages and try again.")
            return
    
    print_header("NETWORK THREAT DETECTION ML DEMONSTRATION")
    print("This demonstration will show how detailed protocol information")
    print("improves machine learning-based network threat detection.")
    print("\nSteps:")
    print("1. Provide paths to existing network data (basic and detailed formats).")
    print("2. Train and evaluate ML models on both data formats.")
    print("3. Compare the results and generate visualizations.")
    
    print_header("STEP 1: PROVIDE TEST DATA PATHS")
    basic_data_path = input("Enter the path to the basic format CSV data file (e.g., basic_capture.csv): ").strip()
    detailed_data_path = input("Enter the path to the detailed format CSV data file (e.g., detailed_capture.csv): ").strip()
    
    # Define and create models directory within the main output directory
    models_dir = os.path.join(args.output_dir, "models")
    os.makedirs(models_dir, exist_ok=True)

    print_header("VALIDATING PROVIDED TEST DATA")
    print("Using provided data files:")
    print(f"  - Basic data: {basic_data_path}")
    print(f"  - Detailed data: {detailed_data_path}")
        
    if not os.path.exists(basic_data_path):
        print(f"\nERROR: Basic data file not found: {basic_data_path}")
        print("Please ensure the file exists and you have entered the correct path.")
        return
    if not os.path.exists(detailed_data_path):
        print(f"\nERROR: Detailed data file not found: {detailed_data_path}")
        print("Please ensure the file exists and you have entered the correct path.")
        return
    
    print_header("STEP 2: TRAINING AND COMPARING MODELS")
    
    # Command to run threat_detector.py for comparison
    # It's expected that threat_detector.py saves its outputs (models, visualizations, report)
    # into the --output-dir it receives.
    script_dir = os.path.dirname(os.path.abspath(__file__))
    threat_detector_script_path = os.path.join(script_dir, 'threat_detector.py')
    
    threat_detector_cmd = [
        sys.executable, threat_detector_script_path,
        '--compare', 
        '--basic-csv', basic_data_path, 
        '--detailed-csv', detailed_data_path, 
        '--output-dir', models_dir  # Pass the 'models' subdirectory for threat_detector outputs
    ]

    if not run_command(threat_detector_cmd, "Training and comparing ML models"):
        print("\nFailed to train and compare models. Exiting.")
        return
    
    print_header("STEP 3: RESULTS SUMMARY")
    
    comparison_file = os.path.join(models_dir, 'comparison_results.txt') # This file is created by threat_detector.py
    if os.path.exists(comparison_file):
        print("\nResults from comparison (from comparison_results.txt):")
        try:
            with open(comparison_file, 'r') as f:
                print(f.read())
        except Exception as e:
            print(f"Error reading comparison file '{comparison_file}': {e}")
    else:
        print(f"Comparison results file not found at: {comparison_file}")
        print("This file should have been created by 'threat_detector.py'. Check for errors in the previous step.")
    
    print_header("DEMONSTRATION COMPLETE")
    print("The complete results, including models, visualizations, and reports,")
    print(f"are available in the output directory: {os.path.abspath(args.output_dir)}")
    print(f"Specifically, models and detailed reports are in: {os.path.abspath(models_dir)}")
    print("\nReview 'comparison_results.txt' and visualization images (e.g., basic_model_results.png, detailed_model_results.png) in that 'models' sub-directory.")

if __name__ == "__main__":
    main() 