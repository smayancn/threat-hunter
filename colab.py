from scapy.all import sniff, Ether, IP, TCP, UDP
import csv, datetime, time

TCP_FLAGS = {
    'F': 'FIN', 'S': 'SYN', 'R': 'RST', 'P': 'PSH',
    'A': 'ACK', 'U': 'URG', 'E': 'ECE', 'C': 'CWR'
}

COLUMNS = ["#", "Time", "Source MAC", "Destination MAC", "Source IP", "Destination IP", 
          "Protocol", "Source Port", "Destination Port", "Length", "TTL", "TCP Flags",
          "UDP Length", "UDP Checksum"]

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
    
    if TCP in pkt:
        flags = '+'.join(TCP_FLAGS[f] for f in str(pkt[TCP].flags))
        row.update({
            "Protocol": "TCP",
            "Source Port": pkt[TCP].sport,
            "Destination Port": pkt[TCP].dport,
            "TCP Flags": flags
        })
    elif UDP in pkt:
        row.update({
            "Protocol": "UDP",
            "Source Port": pkt[UDP].sport,
            "Destination Port": pkt[UDP].dport,
            "UDP Length": pkt[UDP].len,
            "UDP Checksum": hex(pkt[UDP].chksum) if pkt[UDP].chksum else ""
        })
    
    return row

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

def save_csv(packets, filename="network_logs.csv"):
    if not packets:
        return
        
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(packets)
    print(f"Saved {len(packets)} packets to {filename}")

if __name__ == "__main__":
    duration = int(input("Enter capture duration in seconds [default: 5]: ") or 5)
    packets = capture_packets(duration)
    save_csv(packets)