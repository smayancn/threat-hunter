

## Table of Contents
1. [Overview](#overview)
2. [Imports and Constants](#imports-and-constants)
3. [Packet Processing](#packet-processing)
4. [Packet Capture](#packet-capture)
5. [CSV Output](#csv-output)
6. [Main Execution](#main-execution)

## Overview

This tool captures network packets in real-time, extracts relevant information from each packet, and saves the data to a CSV file for analysis. It uses Scapy, a powerful Python packet manipulation library, to capture and parse network packets.

## Imports and Constants

```python
from scapy.all import sniff, Ether, IP, TCP, UDP
import csv, datetime, time
```

- **scapy.all**: Provides network packet capture functionality
  - **sniff**: Function to capture network packets
  - **Ether**: Class representing Ethernet layer packets
  - **IP**: Class representing IP layer packets
  - **TCP**: Class representing TCP layer packets
  - **UDP**: Class representing UDP layer packets
- **csv**: Module for reading/writing CSV files
- **datetime**: Module for handling date and time
- **time**: Module for time-related functions

```python
TCP_FLAGS = {
    'F': 'FIN', 'S': 'SYN', 'R': 'RST', 'P': 'PSH',
    'A': 'ACK', 'U': 'URG', 'E': 'ECE', 'C': 'CWR'
}
```

- Dictionary mapping single-character TCP flag abbreviations to their full names:
  - **F (FIN)**: Finish flag - indicates completion of data transmission
  - **S (SYN)**: Synchronize flag - initiates TCP connection
  - **R (RST)**: Reset flag - resets the connection
  - **P (PSH)**: Push flag - pushes data to the application without buffering
  - **A (ACK)**: Acknowledgment flag - acknowledges received data
  - **U (URG)**: Urgent flag - indicates urgent data
  - **E (ECE)**: ECN-Echo flag - indicates network congestion
  - **C (CWR)**: Congestion Window Reduced flag - response to ECE flag

```python
COLUMNS = ["#", "Time", "Source MAC", "Destination MAC", "Source IP", "Destination IP", 
          "Protocol", "Source Port", "Destination Port", "Length", "TTL", "TCP Flags",
          "UDP Length", "UDP Checksum"]
```

- List defining the columns for the CSV output:
  - **#**: Packet number (sequential counter)
  - **Time**: Timestamp when packet was captured
  - **Source MAC**: MAC address of sending device
  - **Destination MAC**: MAC address of receiving device
  - **Source IP**: IP address of sending device
  - **Destination IP**: IP address of receiving device
  - **Protocol**: Network protocol (TCP, UDP)
  - **Source Port**: Port number on sending device
  - **Destination Port**: Port number on receiving device
  - **Length**: Total length of packet in bytes
  - **TTL**: Time To Live value (hop limit in IP)
  - **TCP Flags**: Active flags in TCP packets
  - **UDP Length**: Length field in UDP header
  - **UDP Checksum**: Checksum value in UDP header

## Packet Processing

```python
def process_packet(pkt, pkt_num):
    row = {
        "#": pkt_num,
        "Time": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "Length": len(pkt),
        "Protocol": "",
        "Source MAC": pkt[Ether].src if Ether in pkt else "",
        "Destination MAC": pkt[Ether].dst if Ether in pkt else "",
        "Source IP": pkt[IP].src if IP in pkt else "",
        "Destination IP": pkt[IP].dst if IP in pkt else "",
        "Source Port": "",
        "Destination Port": "",
        "TTL": pkt[IP].ttl if IP in pkt else "",
        "TCP Flags": "",
        "UDP Length": "",
        "UDP Checksum": ""
    }
```

- **process_packet function**: Extracts information from a packet and formats it for CSV output
  - **Parameters**:
    - **pkt**: Scapy packet object containing the captured packet data
    - **pkt_num**: Sequential packet number
  - **row dictionary**: Initializes a dictionary with all columns (matches COLUMNS list)
    - Uses conditional expressions (`x if condition else y`) to safely extract packet data
    - For example: `pkt[Ether].src if Ether in pkt else ""` checks if the packet has an Ethernet layer before trying to access the source MAC address
    - Time is formatted as YYYY-MM-DD HH:MM:SS using `strftime`
    - Length is obtained using Python's `len()` function on the packet object

```python
    if TCP in pkt:
        flags = '+'.join(TCP_FLAGS[f] for f in str(pkt[TCP].flags))
        row.update({
            "Protocol": "TCP",
            "Source Port": pkt[TCP].sport,
            "Destination Port": pkt[TCP].dport,
            "TCP Flags": flags
        })
```

- **TCP packet processing**:
  - Checks if packet contains TCP layer using `TCP in pkt`
  - **flags** variable:
    - `str(pkt[TCP].flags)` converts TCP flags to a string representation (like 'SA' for SYN+ACK)
    - Uses a list comprehension with generator expression to map each character to its full name
    - `'+'.join(...)` combines the flag names with '+' separators (e.g., "SYN+ACK")
  - `row.update()` modifies the dictionary with TCP-specific information:
    - Sets Protocol to "TCP"
    - Extracts source port (`sport`) and destination port (`dport`)
    - Sets TCP Flags to the previously constructed flags string

```python
    elif UDP in pkt:
        row.update({
            "Protocol": "UDP",
            "Source Port": pkt[UDP].sport,
            "Destination Port": pkt[UDP].dport,
            "UDP Length": pkt[UDP].len,
            "UDP Checksum": hex(pkt[UDP].chksum) if pkt[UDP].chksum else ""
        })
```

- **UDP packet processing**:
  - Only executed if packet is not TCP but contains UDP layer
  - Sets Protocol to "UDP"
  - Extracts UDP-specific information:
    - Source and destination ports
    - UDP Length field from the UDP header
    - UDP Checksum converted to hexadecimal format using `hex()` (only if checksum exists)

```python
    return row
```

- Returns the completed dictionary containing all packet information

## Packet Capture

```python
def capture_packets(duration=5):
    packets = []
    stop_time = time.time() + duration
    pkt_count = 1
```

- **capture_packets function**: Main function to capture network packets
  - **Parameters**:
    - **duration**: Number of seconds to capture packets (default: 5)
  - **packets**: List to store captured packet information
  - **stop_time**: Calculated end time (current time + duration)
  - **pkt_count**: Counter for packet numbering

```python
    def packet_callback(pkt):
        nonlocal pkt_count
        packets.append(process_packet(pkt, pkt_count))
        pkt_count += 1
        if time.time() >= stop_time:
            return True
```

- **packet_callback**: Nested function called for each captured packet
  - Uses `nonlocal pkt_count` to access the outer function's pkt_count variable
  - Processes each packet with process_packet() and adds result to packets list
  - Increments packet counter
  - Returns True if capture duration has elapsed (signals Scapy to stop sniffing)

```python
    print(f"Capturing packets for {duration} seconds...")
    # Redirect Scapy's output to prevent the False values
    import sys, os
    with open(os.devnull, 'w') as f:
        old_stdout = sys.stdout
        sys.stdout = f
        try:
            sniff(prn=packet_callback, store=0, timeout=duration)
        finally:
            sys.stdout = old_stdout
    return packets
```

- **Output redirection**:
  - Imports sys and os modules for stdout redirection
  - Opens os.devnull (null device) as a write-only file
  - Temporarily redirects standard output (stdout) to prevent Scapy's debug output
  - Uses try/finally to ensure stdout is restored even if an exception occurs

- **Packet sniffing**:
  - `sniff()`: Scapy function that captures network packets
    - **prn**: Function to call for each packet (packet_callback)
    - **store=0**: Don't store packets in memory (process them immediately)
    - **timeout**: Stop after specified duration

- Returns the list of processed packet dictionaries

## CSV Output

```python
def save_csv(packets, filename="network_logs.csv"):
    if not packets:
        return
        
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(packets)
    print(f"Saved {len(packets)} packets to {filename}")
```

- **save_csv function**: Saves packet data to a CSV file
  - **Parameters**:
    - **packets**: List of dictionaries containing packet information
    - **filename**: Target CSV file (default: "network_logs.csv")
  - Returns early if no packets were captured
  - Opens file in write mode with newline="" (prevents extra line breaks on Windows)
  - Uses csv.DictWriter:
    - **fieldnames=COLUMNS**: Uses the column names defined earlier
    - **writeheader()**: Writes the first row with column names
    - **writerows(packets)**: Writes all packet dictionaries at once
  - Prints confirmation message with packet count

## Main Execution

```python
if __name__ == "__main__":
    duration = int(input("Enter capture duration in seconds [default: 5]: ") or 5)
    packets = capture_packets(duration)
    save_csv(packets)
```

- **if __name__ == "__main__"**: Standard Python idiom to execute code only when run directly (not when imported)
- **duration**: Prompts user for capture duration
  - `input()` gets user input as string
  - `or 5` provides default value if input is empty
  - `int()` converts to integer
- Calls capture_packets() with the specified duration
- Calls save_csv() to save the captured packets to CSV

## Technical Notes

1. **Cross-Platform Compatibility**: Uses Scapy which works on Windows, macOS, and Linux
2. **Memory Efficiency**: Processes packets as they arrive rather than storing raw packet data
3. **Error Handling**: Uses try/finally to ensure resources are properly cleaned up
4. **Modularity**: Separates packet processing, capturing, and CSV output into distinct functions 