from scapy.all import sniff, Ether, IP, TCP, UDP, DNS, ICMP, ARP, Raw, conf, get_working_ifaces
from scapy.layers.http import HTTP
from scapy.layers.dhcp import DHCP
from scapy.layers.snmp import SNMP
from scapy.layers.tls.all import TLS 
import csv, datetime, time

TCP_FLAGS = {
    'F': 'FIN', 'S': 'SYN', 'R': 'RST', 'P': 'PSH',
    'A': 'ACK', 'U': 'URG', 'E': 'ECE', 'C': 'CWR'
}

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

HTTP_PORTS = {80, 8080}
TLS_PORTS = {443, 8443}
DNS_PORTS = {53}
DHCP_PORTS = {67, 68}
SNMP_PORTS = {161, 162}

def select_interface():
    """
    Display available network interfaces and let user select one.
    Returns the name of the selected interface.
    """
    print("\nAvailable Network Interfaces:")
    print("-" * 60)
    print(f"{'Index':<6} {'Name':<15} {'IP Address':<15} {'Description'}")
    print("-" * 60)
    
    # Get list of working interfaces
    interfaces = get_working_ifaces()
    valid_interfaces = []
    
    for idx, iface in enumerate(interfaces, 1):
        name = iface.name
        # Get IP address if available
        ip = iface.ip if hasattr(iface, 'ip') else 'No IP'
        # Get description or use interface name if not available
        description = getattr(iface, 'description', name)
        
        print(f"{idx:<6} {name:<15} {ip:<15} {description}")
        valid_interfaces.append(name)
    
    print("-" * 60)
    
    while True:
        try:
            choice = input("\nSelect interface by number [1]: ").strip() or "1"
            idx = int(choice) - 1
            if 0 <= idx < len(valid_interfaces):
                selected = valid_interfaces[idx]
                print(f"\nSelected interface: {selected}")
                return selected
            else:
                print("Invalid selection. Please try again.")
        except ValueError:
            print("Please enter a valid number.")

def _safe_decode(data, encoding='utf-8', errors='ignore'):
    if isinstance(data, bytes):
        return data.decode(encoding, errors)
    return str(data) # Ensure it's a string if not bytes

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
    elif pkt[UDP].sport in DHCP_PORTS or pkt[UDP].dport in DHCP_PORTS: # elif to ensure mutual exclusivity with DNS on port 53 (though unlikely)
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

def _process_icmp_packet(pkt, row):
    row["Protocol"] = "ICMP"
    icmp_layer = pkt.getlayer(ICMP)
    if hasattr(icmp_layer, 'type'): row["ICMP Type"] = icmp_layer.type
    if hasattr(icmp_layer, 'code'): row["ICMP Code"] = icmp_layer.code

def _process_arp_packet(pkt, row):
    row["Protocol"] = "ARP"
    arp_layer = pkt.getlayer(ARP)
    op_map = {1: "request", 2: "reply"}
    if hasattr(arp_layer, 'op'): row["ARP Opcode"] = op_map.get(arp_layer.op, str(arp_layer.op))
    if hasattr(arp_layer, 'hwsrc'): row["ARP HW Src"] = _safe_decode(arp_layer.hwsrc)
    if hasattr(arp_layer, 'psrc'): row["ARP IP Src"] = _safe_decode(arp_layer.psrc)
    if hasattr(arp_layer, 'hwdst'): row["ARP HW Dst"] = _safe_decode(arp_layer.hwdst)
    if hasattr(arp_layer, 'pdst'): row["ARP IP Dst"] = _safe_decode(arp_layer.pdst)

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

def capture_packets(duration=5):
    packets = []
    stop_time = time.time() + duration
    pkt_count = 1
    
    # Select interface before starting capture
    iface = select_interface()
    
    def packet_callback(pkt):
        nonlocal pkt_count
        packets.append(process_packet(pkt, pkt_count))
        pkt_count += 1
        if time.time() >= stop_time:
            return True
    
    print(f"\nCapturing packets on interface {iface} for {duration} seconds...")
    import sys, os
    with open(os.devnull, 'w') as f:
        old_stdout = sys.stdout
        sys.stdout = f
        try:
            sniff(iface=iface, prn=packet_callback, store=0, timeout=duration)
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
    while True:
        try:
            duration_input = input("\nEnter capture duration in seconds [default: 5]: ").strip()
            if not duration_input:  # If empty, use default
                duration = 5
                break
            duration = int(duration_input)
            if duration <= 0:
                print("Duration must be a positive number.")
                continue
            break
        except ValueError:
            print("Please enter a valid number.")
    
    packets = capture_packets(duration)
    save_csv(packets)