## Protocol-Specific Parameters Extracted

This section details the unique parameters extracted for various network protocols by the `colab.py` script and provides a brief explanation of their meaning.

**General Parameters (Extracted for most IP packets):**
*   `#`: Sequential packet number in the capture.
*   `Time`: Timestamp when the packet was processed.
*   `Source MAC`, `Destination MAC`: Layer 2 MAC addresses (if Ethernet).
*   `Source IP`, `Destination IP`: Layer 3 IP addresses.
*   `Length`: Total length of the packet in bytes.
*   `TTL`: Time To Live (for IP packets).

---

**1. TCP (Transmission Control Protocol)**
   *Transport layer protocol for reliable, ordered, and error-checked data delivery.*
   *   **`TCP Flags`**: Indicate TCP segment state/purpose (e.g., `SYN` for initiation, `ACK` for acknowledgment, `FIN` for termination).
   *   **`Source Port`**, **`Destination Port`**: Identify sending/receiving applications.

---

**2. UDP (User Datagram Protocol)**
   *Simpler, connectionless transport layer protocol for faster, but less reliable, data delivery.*
   *   **`UDP Length`**: Length of UDP header and data.
   *   **`UDP Checksum`**: Basic error-checking for UDP header/payload.
   *   **`Source Port`**, **`Destination Port`**: Identify sending/receiving applications.

---

**3. HTTP (HyperText Transfer Protocol)**
   *Application layer protocol for web data communication (typically over TCP).*
   *   **`HTTP Method`**: Action on a resource (e.g., `GET`, `POST`).
   *   **`HTTP Host`**: Server's domain name.
   *   **`HTTP Path`**: Specific resource on the server.
   *   **`HTTP Status`**: (In responses) 3-digit result code (e.g., `200 OK`, `404 Not Found`).
   *   *If "HTTP (Raw)" is logged, it means a basic keyword match in raw TCP payload, with the first payload line in `HTTP Path`.*

---

**4. TLS (Transport Layer Security) / SSL (Secure Sockets Layer)**
   *Application layer protocols for secure communication (typically over TCP, e.g., HTTPS).*
   *   **`TLS Content Type`**: Type of data in TLS record (e.g., `22` for Handshake, `23` for ApplicationData).
   *   **`TLS Version`**: Protocol version (e.g., `0x0303` for TLS 1.2).
   *   **`TLS Handshake Type`**: Specific handshake message if content is Handshake (e.g., `1` for ClientHello).

---

**5. DNS (Domain Name System)**
   *Application layer protocol for resolving domain names to IP addresses (typically over UDP).*
   *   **`DNS ID`**: Transaction ID to match queries and replies.
   *   **`DNS QR`**: Query (`0`) or Response (`1`) indicator.
   *   **`DNS Opcode`**: Query type (e.g., `0` for standard query).
   *   **`DNS QName`**: Queried domain name.
   *   **`DNS QType`**: Type of DNS record requested (e.g., A, AAAA, MX).
   *   **`DNS AnsName`**: Domain name in the answer record.
   *   **`DNS AnsRData`**: Response data (e.g., IP address).
   *   **`DNS AnsType`**: Type of DNS record in the answer.

---

**6. DHCP (Dynamic Host Configuration Protocol)**
   *Application layer protocol for automatic IP address assignment (typically over UDP).*
   *   **`DHCP Msg Type`**: Type of DHCP message (e.g., `DISCOVER`, `OFFER`, `REQUEST`, `ACK`).

---

**7. SNMP (Simple Network Management Protocol)**
   *Application layer protocol for managing network devices (typically over UDP).*
   *   **`SNMP Community`**: Community string for basic authentication.
   *   **`SNMP PDU Type`**: SNMP operation type (e.g., `GetRequest`, `GetResponse`, `Trap`).
   *   **`SNMP ReqID`**: Request ID to match requests/responses.
   *   **`SNMP OID`**: Object Identifier for a managed object.
   *   **`SNMP Value`**: Value associated with the OID.

---

**8. ICMP (Internet Control Message Protocol)**
   *Network layer protocol for error messages and operational information.*
   *   **`ICMP Type`**: ICMP message type (e.g., `0` Echo Reply, `8` Echo Request).
   *   **`ICMP Code`**: Further specifies ICMP type (e.g., for Destination Unreachable type `3`, code `1` means Host Unreachable).

---

**9. ARP (Address Resolution Protocol)**
   *Network layer protocol to resolve IP to MAC addresses on a local network.*
   *   **`ARP Opcode`**: ARP operation (`request` (1) or `reply` (2)).
   *   **`ARP HW Src`**: Sender's MAC address.
   *   **`ARP IP Src`**: Sender's IP address.
   *   **`ARP HW Dst`**: Target's MAC address (often 00:00:00:00:00:00 in requests).
   *   **`ARP IP Dst`**: Target's IP address.

---

# Network Packet Capture and Analysis Tool (`colab.py`)

This document provides a detailed line-by-line explanation of the `colab.py` script, which captures network packets, analyzes them for various protocols, and logs the information to a CSV file.

## Table of Contents
1.  [Overview](#overview)
2.  [Imports](#imports)
3.  [Global Constants](#global-constants)
    *   [TCP_FLAGS](#tcp_flags)
    *   [COLUMNS](#columns)
    *   [Protocol Port Sets](#protocol-port-sets)
4.  [Helper Functions](#helper-functions)
    *   [`_safe_decode`](#_safe_decode)
    *   [`_get_base_packet_info`](#_get_base_packet_info)
    *   [`_process_tcp_payloads`](#_process_tcp_payloads)
    *   [`_process_udp_payloads`](#_process_udp_payloads)
    *   [`_process_icmp_packet`](#_process_icmp_packet)
    *   [`_process_arp_packet`](#_process_arp_packet)
5.  [Main Packet Processing Function (`process_packet`)](#process_packet)
6.  [Packet Capture (`capture_packets`)](#capture_packets)
7.  [CSV Output (`save_csv`)](#save_csv)
8.  [Main Execution Block](#main-execution-block)

## 1. Overview

The `colab.py` script is a command-line tool that uses the Scapy library to capture network packets from a network interface. It inspects each packet to identify its protocol (Ethernet, IP, TCP, UDP, HTTP, TLS, DNS, DHCP, SNMP, ICMP, ARP) and extracts key information. This information is then compiled into a structured format and saved as a CSV file, which can be used for network monitoring, basic traffic analysis, or educational purposes.

## 2. Imports

```python
from scapy.all import sniff, Ether, IP, TCP, UDP, DNS, ICMP, ARP, Raw
from scapy.layers.http import HTTP
from scapy.layers.dhcp import DHCP
from scapy.layers.snmp import SNMP
from scapy.layers.tls.all import TLS # For TLS record layer, specific handshake messages might need more specific imports
import csv, datetime, time
```
-   `from scapy.all import sniff, Ether, IP, TCP, UDP, DNS, ICMP, ARP, Raw`: Imports core components from Scapy, a powerful packet manipulation library.
    -   `sniff`: Function used to capture packets.
    -   `Ether`, `IP`, `TCP`, `UDP`, `DNS`, `ICMP`, `ARP`, `Raw`: Classes representing different network protocol layers. `Raw` is used for payload data that isn't dissected into a specific Scapy layer.
-   `from scapy.layers.http import HTTP`: Imports the `HTTP` layer class for parsing HTTP traffic.
-   `from scapy.layers.dhcp import DHCP`: Imports the `DHCP` layer class for parsing DHCP traffic.
-   `from scapy.layers.snmp import SNMP`: Imports the `SNMP` layer class for parsing SNMP traffic.
-   `from scapy.layers.tls.all import TLS`: Imports the `TLS` layer class for parsing TLS (SSL) traffic. The comment notes that more specific imports might be needed for detailed TLS handshake message parsing, but for basic identification, this is usually sufficient.
-   `import csv`: Imports the `csv` module for working with CSV files (reading and writing).
-   `import datetime`: Imports the `datetime` module to get current timestamps for packets.
-   `import time`: Imports the `time` module, used here to manage the duration of packet capture.

## 3. Global Constants

These constants are defined at the module level for use throughout the script.

### TCP_FLAGS
```python
TCP_FLAGS = {
    'F': 'FIN', 'S': 'SYN', 'R': 'RST', 'P': 'PSH',
    'A': 'ACK', 'U': 'URG', 'E': 'ECE', 'C': 'CWR'
}
```
-   A dictionary mapping single-character TCP flag codes to their descriptive names.
    -   Example: `'S'` maps to `'SYN'` (synchronize), used in connection establishment.
-   This is used to make the TCP flags in the output more human-readable.

### COLUMNS
```python
COLUMNS = ["#", "Time", "Source MAC", "Destination MAC", "Source IP", "Destination IP", 
          "Protocol", "Source Port", "Destination Port", "Length", "TTL", "TCP Flags",
          "UDP Length", "UDP Checksum",
          "HTTP Method", "HTTP Host", "HTTP Path", "HTTP Status",
          "DNS ID", "DNS QR", "DNS Opcode", "DNS QName", "DNS QType", "DNS AnsName", "DNS AnsRData", "DNS AnsType",
          "ICMP Type", "ICMP Code",
          "ARP Opcode", "ARP HW Src", "ARP IP Src", "ARP HW Dst", "ARP IP Dst",
          "DHCP Msg Type",
          "SNMP Community", "SNMP PDU Type", "SNMP ReqID", "SNMP OID", "SNMP Value",
          "TLS Content Type", "TLS Version", "TLS Handshake Type"
          ]
```
-   A list of strings defining the column headers for the output CSV file.
-   It establishes the order and names of all fields that will be extracted from packets.

### Protocol Port Sets
```python
HTTP_PORTS = {80, 8080}
TLS_PORTS = {443, 8443}
DNS_PORTS = {53}
DHCP_PORTS = {67, 68}
SNMP_PORTS = {161, 162}
```
-   These sets define common network ports used by various application-layer protocols.
-   Using sets (`{}`) provides efficient checking (e.g., `port in HTTP_PORTS`).
    -   `HTTP_PORTS`: Common ports for HTTP traffic.
    -   `TLS_PORTS`: Common ports for TLS/SSL encrypted traffic (often HTTPS).
    -   `DNS_PORTS`: Standard port for Domain Name System.
    -   `DHCP_PORTS`: Ports used by Dynamic Host Configuration Protocol.
    -   `SNMP_PORTS`: Ports used by Simple Network Management Protocol.
-   These help in identifying potential application-layer protocols based on port numbers, in addition to Scapy's layer detection.

## 4. Helper Functions

These functions encapsulate specific pieces of logic to keep the main processing function cleaner.

### `_safe_decode`
```python
def _safe_decode(data, encoding='utf-8', errors='ignore'):
    if isinstance(data, bytes):
        return data.decode(encoding, errors)
    return str(data) # Ensure it's a string if not bytes
```
-   `def _safe_decode(data, encoding='utf-8', errors='ignore'):`: Defines a function to safely decode byte strings to Python strings.
    -   `data`: The input data to decode (can be bytes or already a string).
    -   `encoding='utf-8'`: Specifies the default encoding to use (UTF-8 is common).
    -   `errors='ignore'`: If a byte sequence cannot be decoded, the problematic bytes are ignored instead of raising an error.
-   `if isinstance(data, bytes):`: Checks if the input `data` is a byte string.
    -   `isinstance()`: A built-in function to check an object's type.
-   `return data.decode(encoding, errors)`: If `data` is bytes, it's decoded using the specified `encoding` and `error` handling.
-   `return str(data)`: If `data` is not bytes (e.g., already a string, or an integer), it's converted to a string using `str()` to ensure consistent output type. This is important for fields that might sometimes be numbers but are stored as strings in the CSV.

### `_get_base_packet_info`
```python
def _get_base_packet_info(pkt, pkt_num):
    row = {col: "" for col in COLUMNS}
    row.update({
        "#": pkt_num,
        "Time": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "Length": len(pkt),
        "Source MAC": _safe_decode(pkt[Ether].src) if Ether in pkt else "",
        "Destination MAC": _safe_decode(pkt[Ether].dst) if Ether in pkt else "",
        "Source IP": _safe_decode(pkt[IP].src) if IP in pkt else "",
        "Destination IP": _safe_decode(pkt[IP].dst) if IP in pkt else "",
        "TTL": pkt[IP].ttl if IP in pkt else ""
    })
    return row
```
-   `def _get_base_packet_info(pkt, pkt_num):`: Defines a function to initialize a dictionary (`row`) for a packet and populate it with common, basic information.
    -   `pkt`: The Scapy packet object.
    -   `pkt_num`: The sequential number of the packet.
-   `row = {col: "" for col in COLUMNS}`: Initializes `row` as a dictionary where each key is a column name from the global `COLUMNS` list, and each value is an empty string. This ensures all columns exist in the `row` dictionary from the start.
    -   This is a dictionary comprehension.
-   `row.update({...})`: Updates the `row` dictionary with specific packet details.
    -   `"#": pkt_num`: Sets the packet number.
    -   `"Time": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')`: Records the current time as the packet's timestamp, formatted as "YYYY-MM-DD HH:MM:SS".
        -   `datetime.datetime.now()`: Gets the current local date and time.
        -   `.strftime(...)`: Formats the datetime object into a string.
    -   `"Length": len(pkt)`: Sets the total length of the packet in bytes.
    -   `"Source MAC": _safe_decode(pkt[Ether].src) if Ether in pkt else ""`: Extracts the source MAC address if an Ethernet layer (`Ether`) exists in the packet. Uses `_safe_decode` in case the address is in bytes. If no Ethernet layer, it's an empty string.
        -   `pkt[Ether].src`: Accesses the source MAC field of the Ethernet layer.
    -   `"Destination MAC": ...`: Similar to Source MAC, for the destination MAC address.
    -   `"Source IP": _safe_decode(pkt[IP].src) if IP in pkt else ""`: Extracts the source IP address if an IP layer (`IP`) exists.
        -   `pkt[IP].src`: Accesses the source IP field.
    -   `"Destination IP": ...`: Similar for the destination IP address.
    -   `"TTL": pkt[IP].ttl if IP in pkt else ""`: Extracts the Time To Live value from the IP header, if present.
-   `return row`: Returns the populated `row` dictionary.

### `_process_tcp_payloads`
```python
def _process_tcp_payloads(pkt, row):
    row["Protocol"] = "TCP"
    row["Source Port"] = pkt[TCP].sport
    row["Destination Port"] = pkt[TCP].dport
    row["TCP Flags"] = '+'.join(TCP_FLAGS[f] for f in str(pkt[TCP].flags))

    # HTTP Detection (over TCP)
    if pkt[TCP].sport in HTTP_PORTS or pkt[TCP].dport in HTTP_PORTS:
        if pkt.haslayer(HTTP):
            http_layer = pkt.getlayer(HTTP)
            row["Protocol"] = "HTTP"
            if hasattr(http_layer, 'Method'): row["HTTP Method"] = _safe_decode(http_layer.Method)
            if hasattr(http_layer, 'Host'): row["HTTP Host"] = _safe_decode(http_layer.Host)
            if hasattr(http_layer, 'Path'): row["HTTP Path"] = _safe_decode(http_layer.Path)
            if hasattr(http_layer, 'Status_Code'): row["HTTP Status"] = _safe_decode(http_layer.Status_Code)
        elif pkt.haslayer(Raw): # Basic check for HTTP in Raw layer
            try:
                # Check if TLS already claimed this packet based on port, if so, don't mark as HTTP (Raw)
                is_tls_port = pkt[TCP].sport in TLS_PORTS or pkt[TCP].dport in TLS_PORTS
                if not (is_tls_port and pkt.haslayer(TLS)):
                    load = _safe_decode(pkt[Raw].load).split('\\r\\n')[0]
                    if any(method in load for method in ["GET ", "POST ", "PUT ", "DELETE ", "HTTP/"]):
                        row["Protocol"] = "HTTP (Raw)"
                        row["HTTP Path"] = load
            except Exception:
                pass 

    # TLS Detection (over TCP)
    if pkt[TCP].sport in TLS_PORTS or pkt[TCP].dport in TLS_PORTS:
        if pkt.haslayer(TLS):
            row["Protocol"] = "TLS" # TLS takes precedence if detected on its common ports
            tls_layer = pkt.getlayer(TLS)
            if hasattr(tls_layer, 'type'): row["TLS Content Type"] = tls_layer.type
            if hasattr(tls_layer, 'version'): row["TLS Version"] = tls_layer.version
            if hasattr(tls_layer, 'msg') and tls_layer.msg and hasattr(tls_layer.msg[0], 'msgtype'):
                row["TLS Handshake Type"] = tls_layer.msg[0].msgtype
```
-   `def _process_tcp_payloads(pkt, row):`: Defines a function to process TCP packets and their potential application-layer payloads (HTTP, TLS).
-   `row["Protocol"] = "TCP"`: Initially sets the protocol to "TCP". This might be overridden later if a specific application protocol like HTTP or TLS is identified.
-   `row["Source Port"] = pkt[TCP].sport`: Extracts the TCP source port.
-   `row["Destination Port"] = pkt[TCP].dport`: Extracts the TCP destination port.
-   `row["TCP Flags"] = '+'.join(TCP_FLAGS[f] for f in str(pkt[TCP].flags))`: Parses and formats TCP flags.
    -   `str(pkt[TCP].flags)`: Converts Scapy's flag object (e.g., `SA` for SYN-ACK) into a string.
    -   `for f in ...`: Iterates through each character of the flag string (e.g., 'S', then 'A').
    -   `TCP_FLAGS[f]`: Looks up the full name of the flag in the `TCP_FLAGS` dictionary.
    -   `'+'.join(...)`: Joins the full flag names with a '+' separator (e.g., "SYN+ACK").

-   **HTTP Detection (over TCP)**:
    -   `if pkt[TCP].sport in HTTP_PORTS or pkt[TCP].dport in HTTP_PORTS:`: Checks if either the source or destination TCP port is a known HTTP port.
    -   `if pkt.haslayer(HTTP):`: If Scapy has successfully dissected an HTTP layer:
        -   `http_layer = pkt.getlayer(HTTP)`: Gets the HTTP layer object.
        -   `row["Protocol"] = "HTTP"`: Updates the protocol.
        -   `if hasattr(http_layer, 'FieldName'): row["FieldName"] = _safe_decode(http_layer.FieldName)`: For various HTTP fields (`Method`, `Host`, `Path`, `Status_Code`), it checks if the field exists in the layer (`hasattr`) and, if so, extracts and decodes it using `_safe_decode`.
    -   `elif pkt.haslayer(Raw):`: If no formal HTTP layer was parsed by Scapy, but there's raw payload data, it attempts a basic heuristic check for HTTP.
        -   `try...except Exception: pass`: Wraps the raw parsing in a try-except block to catch any errors during payload processing (e.g., if the payload isn't text).
        -   `is_tls_port = pkt[TCP].sport in TLS_PORTS or pkt[TCP].dport in TLS_PORTS`: Checks if the packet is on a common TLS port.
        -   `if not (is_tls_port and pkt.haslayer(TLS)):`: This condition attempts to prevent misidentifying TLS handshake data as "HTTP (Raw)". If the packet is on a TLS port AND Scapy has identified a TLS layer, this raw HTTP check is skipped.
        -   `load = _safe_decode(pkt[Raw].load).split('\\r\\n')[0]`: Decodes the raw payload, takes the first line (HTTP requests/responses often have key info on the first line). `\\r\\n` is the standard line ending for HTTP.
        -   `if any(method in load for method in ["GET ", "POST ", ...]):`: Checks if common HTTP methods or "HTTP/" string are present in the first line.
            -   `any(...)`: Returns `True` if any item in the iterable is true.
        -   `row["Protocol"] = "HTTP (Raw)"`: Marks the protocol.
        -   `row["HTTP Path"] = load`: Stores the first line (potentially the request line) as "HTTP Path" for basic info.

-   **TLS Detection (over TCP)**:
    -   `if pkt[TCP].sport in TLS_PORTS or pkt[TCP].dport in TLS_PORTS:`: Checks if ports match common TLS ports.
    -   `if pkt.haslayer(TLS):`: If Scapy detects a TLS layer:
        -   `row["Protocol"] = "TLS"`: Sets protocol to "TLS". This will override "TCP" or even "HTTP" if, for example, HTTPS traffic was initially identified by port 80 then a TLS layer was found (uncommon scenario but covers precedence).
        -   `tls_layer = pkt.getlayer(TLS)`: Gets the TLS layer object.
        -   `if hasattr(tls_layer, 'type'): row["TLS Content Type"] = tls_layer.type`: Extracts TLS content type (e.g., 22 for Handshake).
        -   `if hasattr(tls_layer, 'version'): row["TLS Version"] = tls_layer.version`: Extracts TLS version (e.g., 0x0303 for TLS 1.2).
        -   `if hasattr(tls_layer, 'msg') and tls_layer.msg and hasattr(tls_layer.msg[0], 'msgtype'):`: Attempts to extract the handshake message type (e.g., 1 for Client Hello) from the first message in the TLS record. TLS records can contain multiple messages.
            -   `tls_layer.msg`: Is often a list of TLS messages within the record.

### `_process_udp_payloads`
```python
def _process_udp_payloads(pkt, row):
    row["Protocol"] = "UDP"
    row["Source Port"] = pkt[UDP].sport
    row["Destination Port"] = pkt[UDP].dport
    row["UDP Length"] = pkt[UDP].len
    row["UDP Checksum"] = hex(pkt[UDP].chksum) if pkt[UDP].chksum else ""

    # DNS Detection (over UDP)
    if pkt[UDP].sport in DNS_PORTS or pkt[UDP].dport in DNS_PORTS:
        if pkt.haslayer(DNS):
            row["Protocol"] = "DNS"
            dns_layer = pkt.getlayer(DNS)
            if hasattr(dns_layer, 'id'): row["DNS ID"] = dns_layer.id
            if hasattr(dns_layer, 'qr'): row["DNS QR"] = dns_layer.qr
            if hasattr(dns_layer, 'opcode'): row["DNS Opcode"] = dns_layer.opcode
            if dns_layer.qdcount > 0 and hasattr(dns_layer, 'qd') and dns_layer.qd is not None:
                if hasattr(dns_layer.qd, 'qname'): row["DNS QName"] = _safe_decode(dns_layer.qd.qname)
                if hasattr(dns_layer.qd, 'qtype'): row["DNS QType"] = dns_layer.qd.qtype
            if dns_layer.ancount > 0 and hasattr(dns_layer, 'an') and dns_layer.an is not None:
                answers = dns_layer.an
                if not isinstance(answers, list): answers = [answers]
                if answers:
                    first_ans = answers[0]
                    if hasattr(first_ans, 'rrname'): row["DNS AnsName"] = _safe_decode(first_ans.rrname)
                    if hasattr(first_ans, 'rdata'): row["DNS AnsRData"] = _safe_decode(first_ans.rdata)
                    if hasattr(first_ans, 'type'): row["DNS AnsType"] = first_ans.type
    
    # DHCP Detection (over UDP) - check only if not already identified as DNS
    elif pkt[UDP].sport in DHCP_PORTS or pkt[UDP].dport in DHCP_PORTS: 
        if pkt.haslayer(DHCP):
            row["Protocol"] = "DHCP"
            dhcp_layer = pkt.getlayer(DHCP)
            dhcp_options = getattr(dhcp_layer, 'options', [])
            for opt in dhcp_options:
                if isinstance(opt, tuple) and opt[0] == 'message-type':
                    msg_type_map = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}
                    row["DHCP Msg Type"] = msg_type_map.get(opt[1], str(opt[1]))
                    break
    
    # SNMP Detection (over UDP) - check only if not already DNS or DHCP
    elif pkt[UDP].sport in SNMP_PORTS or pkt[UDP].dport in SNMP_PORTS:
        if pkt.haslayer(SNMP):
            row["Protocol"] = "SNMP"
            snmp_layer = pkt.getlayer(SNMP)
            if hasattr(snmp_layer, 'community'): row["SNMP Community"] = _safe_decode(snmp_layer.community)
            pdu_type_map = {0: "GetRequest", 1: "GetNextRequest", 2: "GetResponse", 3: "SetRequest", 4: "Trap", 5: "GetBulkRequest", 6: "InformRequest", 7: "SNMPv2-Trap", 8: "Report"}
            pdu = getattr(snmp_layer, 'PDU', None)
            if pdu:
                if hasattr(pdu, 'type'): row["SNMP PDU Type"] = pdu_type_map.get(pdu.type, str(pdu.type))
                if hasattr(pdu, 'id'): row["SNMP ReqID"] = pdu.id
                if hasattr(pdu, 'varbindlist') and pdu.varbindlist:
                    actual_varbinds = pdu.varbindlist
                    if not isinstance(actual_varbinds, list): actual_varbinds = [actual_varbinds]
                    if actual_varbinds:
                        first_varbind = actual_varbinds[0]
                        if hasattr(first_varbind, 'oid') and hasattr(first_varbind.oid, 'val'):
                            row["SNMP OID"] = _safe_decode(first_varbind.oid.val)
                        if hasattr(first_varbind, 'value'):
                            value_obj = first_varbind.value
                            if hasattr(value_obj, 'val'):
                                row["SNMP Value"] = _safe_decode(value_obj.val)
                            else:
                                row["SNMP Value"] = _safe_decode(value_obj)
```
-   `def _process_udp_payloads(pkt, row):`: Defines a function to process UDP packets and their potential application-layer payloads (DNS, DHCP, SNMP).
-   `row["Protocol"] = "UDP"`: Sets the default protocol.
-   `row["Source Port"] = pkt[UDP].sport`, `row["Destination Port"] = pkt[UDP].dport`: Extracts UDP ports.
-   `row["UDP Length"] = pkt[UDP].len`: Extracts UDP datagram length.
-   `row["UDP Checksum"] = hex(pkt[UDP].chksum) if pkt[UDP].chksum else ""`: Extracts and hex-formats the UDP checksum if present.

-   **DNS Detection (over UDP)**:
    -   `if pkt[UDP].sport in DNS_PORTS or pkt[UDP].dport in DNS_PORTS:`: Checks for standard DNS port.
    -   `if pkt.haslayer(DNS):`: If Scapy detects a DNS layer:
        -   `row["Protocol"] = "DNS"`: Updates protocol.
        -   `dns_layer = pkt.getlayer(DNS)`: Gets DNS layer.
        -   Extracts various DNS fields: `id` (transaction ID), `qr` (query/response flag), `opcode` (query type).
        -   `if dns_layer.qdcount > 0 ...`: If there's a question section (`qdcount` > 0):
            -   Extracts `qname` (queried name) and `qtype` (query type) from the first question record (`dns_layer.qd`).
        -   `if dns_layer.ancount > 0 ...`: If there's an answer section (`ancount` > 0):
            -   `answers = dns_layer.an`: Gets the answer records.
            -   `if not isinstance(answers, list): answers = [answers]`: Ensures `answers` is a list, as Scapy might return a single object if only one answer.
            -   `if answers: first_ans = answers[0]`: Takes the first answer record.
            -   Extracts `rrname` (resource record name), `rdata` (response data, e.g., IP address), and `type` (answer type) from `first_ans`.

-   **DHCP Detection (over UDP)**:
    -   `elif pkt[UDP].sport in DHCP_PORTS or pkt[UDP].dport in DHCP_PORTS:`: Uses `elif` to ensure this block is checked only if the packet wasn't identified as DNS (in case of non-standard port usage, though DHCP and DNS have distinct standard ports).
    -   `if pkt.haslayer(DHCP):`: If Scapy detects a DHCP layer:
        -   `row["Protocol"] = "DHCP"`
        -   `dhcp_layer = pkt.getlayer(DHCP)`
        -   `dhcp_options = getattr(dhcp_layer, 'options', [])`: Safely gets the DHCP options; `getattr` with a default `[]` prevents errors if `options` field is missing.
        -   `for opt in dhcp_options:`: Iterates through DHCP options.
            -   `if isinstance(opt, tuple) and opt[0] == 'message-type':`: DHCP options are often tuples; this looks for the 'message-type' option.
                -   `msg_type_map = {...}`: A dictionary to map numeric DHCP message types to readable names (e.g., 1 to "DISCOVER").
                -   `row["DHCP Msg Type"] = msg_type_map.get(opt[1], str(opt[1]))`: Sets the DHCP message type, falling back to the numeric value if not in the map.
                -   `break`: Stops after finding the message type.

-   **SNMP Detection (over UDP)**:
    -   `elif pkt[UDP].sport in SNMP_PORTS or pkt[UDP].dport in SNMP_PORTS:`: `elif` ensures exclusivity from prior UDP protocol checks.
    -   `if pkt.haslayer(SNMP):`: If Scapy detects an SNMP layer:
        -   `row["Protocol"] = "SNMP"`
        -   `snmp_layer = pkt.getlayer(SNMP)`
        -   `if hasattr(snmp_layer, 'community'): row["SNMP Community"] = _safe_decode(snmp_layer.community)`: Extracts SNMP community string.
        -   `pdu_type_map = {...}`: Maps numeric SNMP PDU (Protocol Data Unit) types to names (e.g., 0 to "GetRequest").
        -   `pdu = getattr(snmp_layer, 'PDU', None)`: Safely gets the PDU.
        -   `if pdu:`: If PDU exists:
            -   Extracts PDU `type` and `id` (request ID).
            -   `if hasattr(pdu, 'varbindlist') and pdu.varbindlist:`: If there's a list of variable bindings (VarBindList):
                -   `actual_varbinds = pdu.varbindlist`: Gets the varbinds.
                -   `if not isinstance(actual_varbinds, list): ...`: Ensures it's a list.
                -   `if actual_varbinds: first_varbind = actual_varbinds[0]`: Takes the first variable binding.
                -   Extracts `oid` (Object Identifier) and `value` from `first_varbind`. The value itself can be complex, so `_safe_decode` is used.

### `_process_icmp_packet`
```python
def _process_icmp_packet(pkt, row):
    row["Protocol"] = "ICMP"
    icmp_layer = pkt.getlayer(ICMP)
    if hasattr(icmp_layer, 'type'): row["ICMP Type"] = icmp_layer.type
    if hasattr(icmp_layer, 'code'): row["ICMP Code"] = icmp_layer.code
```
-   `def _process_icmp_packet(pkt, row):`: Defines a function to process ICMP packets.
-   `row["Protocol"] = "ICMP"`: Sets the protocol.
-   `icmp_layer = pkt.getlayer(ICMP)`: Gets the ICMP layer object.
-   `if hasattr(icmp_layer, 'type'): row["ICMP Type"] = icmp_layer.type`: Extracts ICMP message type.
-   `if hasattr(icmp_layer, 'code'): row["ICMP Code"] = icmp_layer.code`: Extracts ICMP message code.

### `_process_arp_packet`
```python
def _process_arp_packet(pkt, row):
    row["Protocol"] = "ARP"
    arp_layer = pkt.getlayer(ARP)
    op_map = {1: "request", 2: "reply"}
    if hasattr(arp_layer, 'op'): row["ARP Opcode"] = op_map.get(arp_layer.op, str(arp_layer.op))
    if hasattr(arp_layer, 'hwsrc'): row["ARP HW Src"] = _safe_decode(arp_layer.hwsrc)
    if hasattr(arp_layer, 'psrc'): row["ARP IP Src"] = _safe_decode(arp_layer.psrc)
    if hasattr(arp_layer, 'hwdst'): row["ARP HW Dst"] = _safe_decode(arp_layer.hwdst)
    if hasattr(arp_layer, 'pdst'): row["ARP IP Dst"] = _safe_decode(arp_layer.pdst)
```
-   `def _process_arp_packet(pkt, row):`: Defines a function to process ARP packets.
-   `row["Protocol"] = "ARP"`: Sets the protocol.
-   `arp_layer = pkt.getlayer(ARP)`: Gets the ARP layer object.
-   `op_map = {1: "request", 2: "reply"}`: Maps ARP operation codes to names.
-   `if hasattr(arp_layer, 'op'): row["ARP Opcode"] = op_map.get(arp_layer.op, str(arp_layer.op))`: Extracts and maps the ARP opcode.
-   Extracts hardware source/destination (`hwsrc`, `hwdst`) and protocol (IP) source/destination (`psrc`, `pdst`) addresses using `_safe_decode`.

## 5. Main Packet Processing Function (`process_packet`)
```python
def process_packet(pkt, pkt_num):
    row = _get_base_packet_info(pkt, pkt_num)

    if TCP in pkt:
        _process_tcp_payloads(pkt, row)
    elif UDP in pkt:
        _process_udp_payloads(pkt, row)
    elif ICMP in pkt:
        _process_icmp_packet(pkt, row)
    elif ARP in pkt:
        _process_arp_packet(pkt, row)
    elif IP in pkt and not row["Protocol"]: # Fallback for unknown IP protocols
        proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        row["Protocol"] = proto_map.get(pkt[IP].proto, str(pkt[IP].proto))

    return row
```
-   `def process_packet(pkt, pkt_num):`: This is the main function called for each captured packet.
-   `row = _get_base_packet_info(pkt, pkt_num)`: Initializes the `row` dictionary with basic packet information by calling the helper function.
-   `if TCP in pkt:`: Checks if the packet has a TCP layer.
    -   `_process_tcp_payloads(pkt, row)`: If TCP, calls the TCP processing function.
-   `elif UDP in pkt:`: If not TCP, checks for a UDP layer.
    -   `_process_udp_payloads(pkt, row)`: If UDP, calls the UDP processing function.
-   `elif ICMP in pkt:`: If not TCP or UDP, checks for an ICMP layer.
    -   `_process_icmp_packet(pkt, row)`: If ICMP, calls the ICMP processing function.
-   `elif ARP in pkt:`: If none of the above, checks for an ARP layer.
    -   `_process_arp_packet(pkt, row)`: If ARP, calls the ARP processing function.
-   `elif IP in pkt and not row["Protocol"]:`: If the packet has an IP layer but the protocol hasn't been set yet (meaning it wasn't TCP, UDP, ICMP, or a higher-layer protocol parsed by those handlers), this acts as a fallback.
    -   `proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}`: A map for common IP protocol numbers.
    -   `row["Protocol"] = proto_map.get(pkt[IP].proto, str(pkt[IP].proto))`: Sets the protocol based on the IP protocol number (`pkt[IP].proto`). If the number is not in `proto_map`, it uses the number itself as a string.
-   `return row`: Returns the fully processed `row` dictionary.

## 6. Packet Capture (`capture_packets`)
```python
def capture_packets(duration=5):
    packets = []
    stop_time = time.time() + duration
    pkt_count = 1
    
    def packet_callback(pkt):
        nonlocal pkt_count
        packets.append(process_packet(pkt, pkt_count))
        pkt_count += 1
        if time.time() >= stop_time:
            return True
    
    print(f"Capturing packets for {duration} seconds...")
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
-   `def capture_packets(duration=5):`: Defines the function responsible for capturing packets.
    -   `duration=5`: Sets a default capture duration of 5 seconds if no duration is provided.
-   `packets = []`: Initializes an empty list to store the processed packet data.
-   `stop_time = time.time() + duration`: Calculates the Unix timestamp when capturing should stop.
    -   `time.time()`: Returns the current time in seconds since the Epoch.
-   `pkt_count = 1`: Initializes a counter for numbering packets.
-   `def packet_callback(pkt):`: Defines a nested callback function. Scapy's `sniff` function will call this for every packet it captures.
    -   `nonlocal pkt_count`: Allows this nested function to modify `pkt_count` from the outer `capture_packets` scope.
    -   `packets.append(process_packet(pkt, pkt_count))`: Calls the main `process_packet` function for the current packet (`pkt`) and its number (`pkt_count`), then appends the resulting dictionary to the `packets` list.
    -   `pkt_count += 1`: Increments the packet counter.
    -   `if time.time() >= stop_time: return True`: Checks if the current time has reached or passed `stop_time`. If so, it returns `True`, signaling Scapy's `sniff` function to stop capturing.
-   `print(f"Capturing packets for {duration} seconds...")`: Informs the user that capture is starting.
-   `import sys, os`: Imports modules needed for output redirection.
-   `with open(os.devnull, 'w') as f:`: Opens the system's "null device" (e.g., `/dev/null` on Unix-like systems, `NUL` on Windows) in write mode. Writing to this device discards the data. This is used to suppress Scapy's default console output during sniffing.
    -   `os.devnull`: A platform-independent way to refer to the null device.
    -   The `with` statement ensures the file `f` is automatically closed.
-   `old_stdout = sys.stdout`: Stores the original standard output stream.
-   `sys.stdout = f`: Redirects standard output to the null device `f`. Any prints from Scapy itself will now be discarded.
-   `try...finally`: Ensures that standard output is restored even if an error occurs during sniffing.
    -   `sniff(prn=packet_callback, store=0, timeout=duration)`: Starts packet sniffing.
        -   `prn=packet_callback`: Specifies the function to call for each captured packet.
        -   `store=0`: Tells Scapy not to store the captured packets in memory internally (we are processing them one by one and storing our extracted data). This saves memory.
        -   `timeout=duration`: Sniff for the specified `duration` in seconds. Note: The `packet_callback` also has a time check; `timeout` is another way Scapy can stop.
    -   `finally: sys.stdout = old_stdout`: This block always executes, restoring the original standard output.
-   `return packets`: Returns the list of processed packet dictionaries.

## 7. CSV Output (`save_csv`)
```python
def save_csv(packets, filename="network_logs.csv"):
    if not packets:
        print("No packets captured to save.")
        return
        
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(packets)
    print(f"Saved {len(packets)} packets to {filename}")
```
-   `def save_csv(packets, filename="network_logs.csv"):`: Defines the function to save collected packet data to a CSV file.
    -   `packets`: The list of packet dictionaries.
    -   `filename="network_logs.csv"`: Default CSV filename.
-   `if not packets:`: Checks if the `packets` list is empty.
    -   `print("No packets captured to save.")`: Informs the user.
    -   `return`: Exits the function if there's nothing to save.
-   `with open(filename, "w", newline="") as f:`: Opens the specified file in write mode (`"w"`).
    -   `newline=""`: Important for `csv` module on Windows to prevent extra blank rows.
    -   The `with` statement ensures the file is properly closed.
-   `writer = csv.DictWriter(f, fieldnames=COLUMNS)`: Creates a `csv.DictWriter` object. This object can write dictionaries to CSV rows, using the `fieldnames` (from the global `COLUMNS` list) as headers and to determine which dictionary keys to write in which order.
    -   `f`: The file object to write to.
-   `writer.writeheader()`: Writes the header row to the CSV file using the `fieldnames`.
-   `writer.writerows(packets)`: Writes all dictionaries in the `packets` list as rows in the CSV file.
-   `print(f"Saved {len(packets)} packets to {filename}")`: Prints a confirmation message with the number of packets saved and the filename.

## 8. Main Execution Block
```python
if __name__ == "__main__":
    duration = int(input("Enter capture duration in seconds [default: 5]: ") or 5)
    packets = capture_packets(duration)
    save_csv(packets)
```
-   `if __name__ == "__main__":`: This is a standard Python construct. The code inside this block only runs when the script is executed directly (e.g., `python colab.py`), not when it's imported as a module into another script.
-   `duration = int(input("Enter capture duration in seconds [default: 5]: ") or 5)`: Prompts the user to enter the capture duration.
    -   `input(...)`: Displays the prompt and reads user input as a string.
    -   `or 5`: If the user presses Enter without typing anything (providing an empty string), this expression evaluates to `5` (the default duration).
    -   `int(...)`: Converts the resulting string (either user input or "5") to an integer.
-   `packets = capture_packets(duration)`: Calls the `capture_packets` function with the specified `duration` and stores the returned list of packet data.
-   `save_csv(packets)`: Calls the `save_csv` function to save the captured `packets` data to the default CSV file. 