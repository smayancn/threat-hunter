# Network Packet Capture Tool Documentation

This document provides a detailed line-by-line explanation of the network packet capture tool implemented in `colab.py`.

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

### Import Statements
```python
from scapy.all import sniff, Ether, IP, TCP, UDP
```
- This line imports specific functions and classes from the scapy.all module:
  - `sniff`: A function that captures network packets from network interfaces
  - `Ether`: A class that represents Ethernet frames and provides access to Ethernet header fields
  - `IP`: A class that represents IP packets and provides access to IP header fields
  - `TCP`: A class that represents TCP segments and provides access to TCP header fields
  - `UDP`: A class that represents UDP datagrams and provides access to UDP header fields

```python
import csv, datetime, time
```
- This line imports three standard Python modules:
  - `csv`: Used for reading and writing CSV files
  - `datetime`: Used to get current time for packet timestamps
  - `time`: Used to measure elapsed time during packet capture

### Constants

```python
TCP_FLAGS = {
    'F': 'FIN', 'S': 'SYN', 'R': 'RST', 'P': 'PSH',
    'A': 'ACK', 'U': 'URG', 'E': 'ECE', 'C': 'CWR'
}
```
- This creates a dictionary named `TCP_FLAGS` that maps single-character flag codes to their full names
- Each key-value pair represents one TCP flag:
  - 'F' maps to 'FIN' (used when a connection is being terminated)
  - 'S' maps to 'SYN' (used when initiating a connection)
  - 'R' maps to 'RST' (used to reset a connection)
  - 'P' maps to 'PSH' (instructs to push buffered data to the application)
  - 'A' maps to 'ACK' (acknowledges received data)
  - 'U' maps to 'URG' (marks data as urgent)
  - 'E' maps to 'ECE' (indicates ECN-Echo, related to network congestion)
  - 'C' maps to 'CWR' (indicates Congestion Window Reduced)

```python
COLUMNS = ["#", "Time", "Source MAC", "Destination MAC", "Source IP", "Destination IP", 
          "Protocol", "Source Port", "Destination Port", "Length", "TTL", "TCP Flags",
          "UDP Length", "UDP Checksum"]
```
- This creates a list named `COLUMNS` that defines the order and names of columns in the CSV output
- Each string in the list represents one column header
- Used for initializing dictionary keys and providing column names to the CSV DictWriter

## Packet Processing

```python
def process_packet(pkt, pkt_num):
```
- Defines a function named `process_packet` that takes two parameters:
  - `pkt`: A Scapy packet object that contains all the captured packet data
  - `pkt_num`: An integer representing the packet's sequential number

```python
    row = {
        "#": pkt_num,
```
- Creates a dictionary named `row` that will store packet information
- Sets the "#" key to the packet number (from pkt_num parameter)

```python
        "Time": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
```
- Sets the "Time" key to the current date and time
- `datetime.now()` gets the current date and time as a datetime object
- `.strftime('%Y-%m-%d %H:%M:%S')` formats it as a string in the format "YYYY-MM-DD HH:MM:SS"

```python
        "Length": len(pkt),
```
- Sets the "Length" key to the total length of the packet in bytes
- `len(pkt)` calls Python's built-in len() function on the packet object

```python
        "Protocol": "",
        "Source MAC": pkt[Ether].src if Ether in pkt else "",
        "Destination MAC": pkt[Ether].dst if Ether in pkt else "",
```
- Initializes "Protocol" with an empty string (will be updated later if TCP or UDP is found)
- Sets "Source MAC" by checking if the packet has an Ethernet layer:
  - `Ether in pkt` tests if the packet contains an Ethernet layer
  - If it does, `pkt[Ether].src` extracts the source MAC address
  - If not, sets an empty string
- Similarly sets "Destination MAC" using `pkt[Ether].dst` if available

```python
        "Source IP": pkt[IP].src if IP in pkt else "",
        "Destination IP": pkt[IP].dst if IP in pkt else "",
```
- Sets "Source IP" by checking if the packet has an IP layer:
  - `IP in pkt` tests if the packet contains an IP layer
  - If it does, `pkt[IP].src` extracts the source IP address
  - If not, sets an empty string
- Similarly sets "Destination IP" using `pkt[IP].dst` if available

```python
        "Source Port": "",
        "Destination Port": "",
        "TTL": pkt[IP].ttl if IP in pkt else "",
```
- Initializes "Source Port" and "Destination Port" with empty strings (updated later for TCP/UDP)
- Sets "TTL" (Time To Live) by extracting `pkt[IP].ttl` if the packet has an IP layer

```python
        "TCP Flags": "",
        "UDP Length": "",
        "UDP Checksum": ""
```
- Initializes TCP and UDP specific fields with empty strings
- These will only be populated if the packet contains TCP or UDP data

```python
    if TCP in pkt:
```
- Checks if the packet contains TCP data by testing if the TCP layer is present

```python
        flags = '+'.join(TCP_FLAGS[f] for f in str(pkt[TCP].flags))
```
- Creates a string representation of the TCP flags:
  1. `str(pkt[TCP].flags)` converts the flags attribute to a string (like 'SA' for SYN+ACK)
  2. `for f in str(pkt[TCP].flags)` iterates through each character in that string
  3. `TCP_FLAGS[f]` looks up each character in the TCP_FLAGS dictionary to get the full name
  4. The list comprehension produces a list of full flag names
  5. `'+'.join(...)` joins these names with '+' between them (e.g., "SYN+ACK")

```python
        row.update({
            "Protocol": "TCP",
            "Source Port": pkt[TCP].sport,
            "Destination Port": pkt[TCP].dport,
            "TCP Flags": flags
        })
```
- Updates multiple values in the row dictionary:
  - Sets "Protocol" to "TCP"
  - Sets "Source Port" to the TCP source port (`pkt[TCP].sport`)
  - Sets "Destination Port" to the TCP destination port (`pkt[TCP].dport`)
  - Sets "TCP Flags" to the flags string created above

```python
    elif UDP in pkt:
```
- Only executes if the packet does not contain TCP (due to elif) but does contain UDP

```python
        row.update({
            "Protocol": "UDP",
            "Source Port": pkt[UDP].sport,
            "Destination Port": pkt[UDP].dport,
```
- Updates the row dictionary with UDP-specific information:
  - Sets "Protocol" to "UDP"
  - Sets "Source Port" to the UDP source port (`pkt[UDP].sport`)
  - Sets "Destination Port" to the UDP destination port (`pkt[UDP].dport`)

```python
            "UDP Length": pkt[UDP].len,
```
- Sets "UDP Length" to the length field from the UDP header (`pkt[UDP].len`)
- This represents the length of the UDP header plus payload in bytes

```python
            "UDP Checksum": hex(pkt[UDP].chksum) if pkt[UDP].chksum else ""
```
- Sets "UDP Checksum" to the hexadecimal value of the UDP checksum:
  - `pkt[UDP].chksum` gets the checksum value
  - `if pkt[UDP].chksum else ""` checks if the checksum exists (not None or zero)
  - If it exists, `hex(pkt[UDP].chksum)` converts it to a hexadecimal string
  - If not, sets an empty string

```python
    return row
```
- Returns the completed row dictionary containing all the extracted packet information

## Packet Capture

```python
def capture_packets(duration=5):
```
- Defines a function named `capture_packets` that takes one parameter:
  - `duration`: Number of seconds to capture packets (default value: 5)

```python
    packets = []
```
- Creates an empty list named `packets` to store the captured packet information

```python
    stop_time = time.time() + duration
```
- Calculates when to stop capturing packets:
  - `time.time()` gets the current time in seconds since epoch
  - Adds the duration to get the stopping time

```python
    pkt_count = 1
```
- Initializes a counter for packet numbering (starts at 1)

```python
    def packet_callback(pkt):
```
- Defines a nested function named `packet_callback` that takes one parameter:
  - `pkt`: A Scapy packet object (automatically passed by sniff())
- This function will be called for each packet captured by Scapy's sniff function

```python
        nonlocal pkt_count
```
- Declares `pkt_count` as nonlocal to access the variable from the outer function
- This allows modifying pkt_count rather than creating a new local variable

```python
        packets.append(process_packet(pkt, pkt_count))
```
- Processes the packet and adds it to the packets list:
  1. `process_packet(pkt, pkt_count)` calls the function to extract packet info
  2. `packets.append(...)` adds the resulting dictionary to the packets list

```python
        pkt_count += 1
```
- Increments the packet counter for the next packet

```python
        if time.time() >= stop_time:
            return True
```
- Checks if the capture duration has elapsed:
  - `time.time()` gets the current time
  - If it's greater than or equal to stop_time, returns True
  - This signals Scapy's sniff function to stop capturing packets

```python
    print(f"Capturing packets for {duration} seconds...")
```
- Prints a message to inform the user that packet capturing has started
- Uses an f-string to include the duration value in the message

```python
    # Redirect Scapy's output to prevent the False values
    import sys, os
```
- Imports the sys and os modules inside the function
- These are used to redirect Scapy's output to prevent "False" values from being printed

```python
    with open(os.devnull, 'w') as f:
```
- Opens the null device as a writable file:
  - `os.devnull` is a special file that discards all data written to it
  - `'w'` mode opens it for writing
  - `as f` assigns the file object to variable f
- This is the beginning of a context manager that will automatically close the file

```python
        old_stdout = sys.stdout
```
- Saves the current standard output (stdout) to restore it later

```python
        sys.stdout = f
```
- Redirects the standard output to the null device
- Any print statements or outputs will now be discarded

```python
        try:
            sniff(prn=packet_callback, store=0, timeout=duration)
```
- Begins a try block to ensure stdout is restored even if an error occurs
- Calls Scapy's sniff function with these parameters:
  - `prn=packet_callback`: Function to call for each packet
  - `store=0`: Don't store packet objects in memory (save RAM)
  - `timeout=duration`: Stop capturing after the specified duration

```python
        finally:
            sys.stdout = old_stdout
```
- The finally block always executes, regardless of exceptions
- Restores the original stdout so normal printing works again

```python
    return packets
```
- Returns the list of processed packet dictionaries

## CSV Output

```python
def save_csv(packets, filename="network_logs.csv"):
```
- Defines a function named `save_csv` that takes two parameters:
  - `packets`: List of dictionaries containing packet information
  - `filename`: Name of the CSV file to create (default: "network_logs.csv")

```python
    if not packets:
        return
```
- Checks if the packets list is empty:
  - `not packets` is True if packets is empty
  - If empty, returns from the function without doing anything

```python
    with open(filename, "w", newline="") as f:
```
- Opens the CSV file for writing:
  - `filename` is the name of the file to create
  - `"w"` mode creates a new file or overwrites an existing one
  - `newline=""` prevents extra line breaks on Windows
  - `as f` assigns the file object to variable f
- This is a context manager that will automatically close the file

```python
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
```
- Creates a DictWriter object:
  - `f` is the file to write to
  - `fieldnames=COLUMNS` uses the COLUMNS list to define the column order
  - This writer knows how to write dictionaries as CSV rows

```python
        writer.writeheader()
```
- Writes the first row of the CSV file containing the column names (headers)
- The names come from the COLUMNS list

```python
        writer.writerows(packets)
```
- Writes all packet dictionaries to the CSV file:
  - `packets` is the list of dictionaries from capture_packets()
  - `writerows()` efficiently writes multiple rows at once

```python
    print(f"Saved {len(packets)} packets to {filename}")
```
- Prints a confirmation message:
  - Uses an f-string to include dynamic values
  - `len(packets)` gets the number of packets captured
  - Shows the filename where data was saved

## Main Execution

```python
if __name__ == "__main__":
```
- Checks if the script is being run directly (not imported as a module):
  - `__name__` is a special variable that equals "__main__" when the script is run directly
  - This is a common Python idiom to prevent code from running when imported

```python
    duration = int(input("Enter capture duration in seconds [default: 5]: ") or 5)
```
- Gets the capture duration from the user:
  1. `input(...)` displays a prompt and waits for user input
  2. `or 5` provides a default value (5) if the user just presses Enter
  3. `int(...)` converts the input to an integer

```python
    packets = capture_packets(duration)
```
- Calls the capture_packets function with the user-specified duration
- Stores the returned packet list in the packets variable

```python
    save_csv(packets)
```
- Calls the save_csv function to write the packets to a CSV file
- Uses the default filename "network_logs.csv" since no filename is specified 