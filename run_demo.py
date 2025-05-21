#!/usr/bin/env python3
import os
import subprocess
import argparse
import time
import sys

def print_header(message):
    """Print a formatted header message"""
    print("\n" + "="*70)
    print(f" {message}")
    print("="*70)

def run_command(command, description):
    """Run a command and print its output"""
    print_header(description)
    print(f"Running: {' '.join(command)}")
    
    try:
        # Run the command and display output in real-time
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1
        )
        
        # Print output in real-time
        for line in process.stdout:
            print(line, end='')
        
        # Wait for process to complete and check return code
        return_code = process.wait()
        if return_code != 0:
            print(f"Command failed with return code {return_code}")
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
    parser.add_argument('--output-dir', default='demo_output', help='Directory to save all output files')
    args = parser.parse_args()
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Check required packages
    required_packages = ['pandas', 'numpy', 'sklearn', 'matplotlib', 'seaborn', 'joblib']
    missing_packages = [pkg for pkg in required_packages if not check_package(pkg)]
    
    if missing_packages:
        print_header("MISSING REQUIRED PACKAGES")
        print("The following required packages are missing:")
        for pkg in missing_packages:
            print(f"  - {pkg}")
        
        install = input("\nWould you like to install these packages now? (y/n): ")
        if install.lower() == 'y':
            run_command(
                ['pip', 'install'] + missing_packages,
                "INSTALLING REQUIRED PACKAGES"
            )
        else:
            print("Please install the required packages and try again.")
            return
    
    print_header("NETWORK THREAT DETECTION ML DEMONSTRATION")
    print("This demonstration will show how detailed protocol information")
    print("improves machine learning-based network threat detection.")
    print("\nSteps:")
    print("1. Use existing network data (basic and detailed formats)")
    print("2. Train and evaluate ML models on both data formats")
    print("3. Compare the results and generate visualizations")
    
    # Get file paths from user input
    print_header("STEP 1: PROVIDE TEST DATA PATHS")
    basic_data_path = input("Enter the path to the basic format CSV data file (e.g., basic_capture.csv): ")
    detailed_data_path = input("Enter the path to the detailed format CSV data file (e.g., detailed_capture.csv): ")
    models_dir = os.path.join(args.output_dir, "models")
    
    # Step 1: Check for existing data
    print_header("STEP 1: USING PROVIDED TEST DATA")
    print("Using provided data files:")
    print(f"  - Basic data: {basic_data_path}")
    print(f"  - Detailed data: {detailed_data_path}")
        
    # Check if files exist
    if not os.path.exists(basic_data_path):
        print(f"ERROR: Basic data file not found: {basic_data_path}")
        print("Please ensure the file is in the correct location or provide the correct path using --basic-csv.")
        return
    if not os.path.exists(detailed_data_path):
        print(f"ERROR: Detailed data file not found: {detailed_data_path}")
        print("Please ensure the file is in the correct location or provide the correct path using --detailed-csv.")
        return
    
    # Step 2: Train and compare models
    print_header("STEP 2: TRAINING AND COMPARING MODELS")
    
    success = run_command(
        ['python', 'threat_detector.py', 
         '--compare', 
         '--basic-csv', basic_data_path, 
         '--detailed-csv', detailed_data_path, 
         '--output-dir', models_dir],
        "Training and comparing ML models"
    )
    if not success:
        print("Failed to train and compare models. Exiting.")
        return
    
    # Step 3: Display results
    print_header("STEP 3: RESULTS SUMMARY")
    
    comparison_file = os.path.join(models_dir, 'comparison_results.txt')
    if os.path.exists(comparison_file):
        print("\nResults from comparison:")
        with open(comparison_file, 'r') as f:
            print(f.read())
    else:
        print("Comparison results file not found.")
    
    print_header("DEMONSTRATION COMPLETE")
    print("The complete results are available in the output directory:")
    print(f"  {os.path.abspath(args.output_dir)}")
    print("\nVisualization images have been saved to the models directory.")
    print("You can view them to see the detailed comparison between")
    print("the basic and detailed packet data models.")

if __name__ == "__main__":
    main() 