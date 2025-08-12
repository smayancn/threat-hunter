from scapy.all import sniff, Ether, IP, TCP, UDP, DNS, ICMP, ARP, Raw, get_working_ifaces
from scapy.layers.http import HTTP
from scapy.layers.tls.all import TLS 
import csv, datetime, time, os, sys

TCP_FLAGS = {'F': 'FIN', 'S': 'SYN', 'R': 'RST', 'P': 'PSH', 'A': 'ACK', 'U': 'URG', 'E': 'ECE', 'C': 'CWR'}
COLUMNS = ["#", "Time", "Source MAC", "Destination MAC", "Source IP", "Destination IP", 
          "Protocol", "Source Port", "Destination Port", "Length", "TTL", "TCP Flags",
          "UDP Length", "HTTP Method", "HTTP Host", "HTTP Path", "HTTP Status",
          "DNS ID", "DNS QR", "DNS QName", "DNS QType", "ICMP Type", "ICMP Code",
          "ARP Opcode", "ARP IP Src", "ARP IP Dst"]
HTTP_PORTS, TLS_PORTS, DNS_PORTS = {80, 8080}, {443, 8443}, {53}

def select_interface():
    print("\nAvailable Network Interfaces:")
    interfaces = get_working_ifaces()
    valid_interfaces = [iface.name for iface in interfaces]
    
    for idx, iface in enumerate(interfaces, 1):
        ip = getattr(iface, 'ip', 'No IP')
        print(f"{idx}. {iface.name} ({ip})")
    
    while True:
        try:
            choice = input(f"\nSelect interface [1]: ").strip() or "1"
            idx = int(choice) - 1
            if 0 <= idx < len(valid_interfaces):
                return valid_interfaces[idx]
            print("Invalid selection.")
        except ValueError:
            print("Enter a valid number.")

def _safe_decode(data):
    return data.decode('utf-8', errors='ignore') if isinstance(data, bytes) else str(data)

def _get_base_packet_info(pkt, pkt_num):
    row = {col: "" for col in COLUMNS}
    row.update({
        "#": pkt_num, "Time": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "Length": len(pkt),
        "Source MAC": _safe_decode(pkt[Ether].src) if Ether in pkt else "",
        "Destination MAC": _safe_decode(pkt[Ether].dst) if Ether in pkt else "",
        "Source IP": _safe_decode(pkt[IP].src) if IP in pkt else "",
        "Destination IP": _safe_decode(pkt[IP].dst) if IP in pkt else "",
        "TTL": pkt[IP].ttl if IP in pkt else ""
    })
    return row

def _process_tcp_payloads(pkt, row):
    row.update({"Protocol": "TCP", "Source Port": pkt[TCP].sport, "Destination Port": pkt[TCP].dport,
                "TCP Flags": '+'.join(TCP_FLAGS[f] for f in str(pkt[TCP].flags))})

    # HTTP Detection
    if pkt[TCP].sport in HTTP_PORTS or pkt[TCP].dport in HTTP_PORTS:
        if pkt.haslayer(HTTP):
            http_layer = pkt.getlayer(HTTP)
            row["Protocol"] = "HTTP"
            for attr, field in [('Method', 'HTTP Method'), ('Host', 'HTTP Host'), ('Path', 'HTTP Path'), ('Status_Code', 'HTTP Status')]:
                if hasattr(http_layer, attr): row[field] = _safe_decode(getattr(http_layer, attr))
        elif pkt.haslayer(Raw):
            try:
                if not ((pkt[TCP].sport in TLS_PORTS or pkt[TCP].dport in TLS_PORTS) and pkt.haslayer(TLS)):
                    load = _safe_decode(pkt[Raw].load).split('\\r\\n')[0]
                    if any(method in load for method in ["GET ", "POST ", "PUT ", "DELETE ", "HTTP/"]):
                        row["Protocol"], row["HTTP Path"] = "HTTP (Raw)", load
            except: pass

    # TLS Detection
    if (pkt[TCP].sport in TLS_PORTS or pkt[TCP].dport in TLS_PORTS) and pkt.haslayer(TLS):
        row["Protocol"] = "TLS"

def _process_udp_payloads(pkt, row):
    row.update({"Protocol": "UDP", "Source Port": pkt[UDP].sport, "Destination Port": pkt[UDP].dport, "UDP Length": pkt[UDP].len})

    # DNS Detection
    if (pkt[UDP].sport in DNS_PORTS or pkt[UDP].dport in DNS_PORTS) and pkt.haslayer(DNS):
        row["Protocol"] = "DNS"
        dns_layer = pkt.getlayer(DNS)
        for attr, field in [('id', 'DNS ID'), ('qr', 'DNS QR')]:
            if hasattr(dns_layer, attr): row[field] = getattr(dns_layer, attr)
        if dns_layer.qdcount > 0 and hasattr(dns_layer, 'qd') and dns_layer.qd:
            if hasattr(dns_layer.qd, 'qname'): row["DNS QName"] = _safe_decode(dns_layer.qd.qname)
            if hasattr(dns_layer.qd, 'qtype'): row["DNS QType"] = dns_layer.qd.qtype

def _process_icmp_packet(pkt, row):
    row["Protocol"] = "ICMP"
    icmp_layer = pkt.getlayer(ICMP)
    for attr, field in [('type', 'ICMP Type'), ('code', 'ICMP Code')]:
        if hasattr(icmp_layer, attr): row[field] = getattr(icmp_layer, attr)

def _process_arp_packet(pkt, row):
    row["Protocol"] = "ARP"
    arp_layer = pkt.getlayer(ARP)
    if hasattr(arp_layer, 'op'): row["ARP Opcode"] = {1: "request", 2: "reply"}.get(arp_layer.op, str(arp_layer.op))
    for attr, field in [('psrc', 'ARP IP Src'), ('pdst', 'ARP IP Dst')]:
        if hasattr(arp_layer, attr): row[field] = _safe_decode(getattr(arp_layer, attr))

def process_packet(pkt, pkt_num):
    row = _get_base_packet_info(pkt, pkt_num)
    if TCP in pkt: _process_tcp_payloads(pkt, row)
    elif UDP in pkt: _process_udp_payloads(pkt, row)
    elif ICMP in pkt: _process_icmp_packet(pkt, row)
    elif ARP in pkt: _process_arp_packet(pkt, row)
    elif IP in pkt and not row["Protocol"]: row["Protocol"] = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(pkt[IP].proto, str(pkt[IP].proto))
    return row

def capture_packets(duration=5):
    packets, pkt_count = [], 1
    iface = select_interface()
    
    def packet_callback(pkt):
        nonlocal pkt_count
        packets.append(process_packet(pkt, pkt_count))
        pkt_count += 1
    
    print(f"\nCapturing on {iface} for {duration}s...")
    with open(os.devnull, 'w') as f:
        old_stdout = sys.stdout
        sys.stdout = f
        try: sniff(iface=iface, prn=packet_callback, store=0, timeout=duration)
        finally: sys.stdout = old_stdout
    return packets

def save_csv(packets, filename="network_logs.csv"):
    if not packets: return
    full_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    with open(full_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(packets)
    print(f"Saved {len(packets)} packets to {full_path}")

if __name__ == "__main__":
    try: duration = int(input("\nCapture duration [5]: ").strip() or "5")
    except: duration = 5
    packets = capture_packets(duration)
    save_csv(packets)