import time, csv, datetime
from scapy.all import sniff, Ether, IP, TCP, UDP

PROTO = {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6"}
IP_PROTO = {1: "ICMP", 6: "TCP", 17: "UDP", 41: "IPv6"}

def capture_packets(duration=5, limit=None):
    pkts = []
    stop = time.time() + duration
    
    def cb(pkt):
        info = {"ts": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "size": len(pkt)}
        
        if Ether in pkt:
            info.update({"src_mac": pkt[Ether].src,
                        "dst_mac": pkt[Ether].dst,
                        "proto": pkt[Ether].type})
        
        if IP in pkt:
            info.update({"ip_ver": pkt[IP].version,
                        "hdr_len": pkt[IP].ihl * 4,
                        "ttl": pkt[IP].ttl,
                        "ip_proto": pkt[IP].proto,
                        "proto_name": IP_PROTO.get(pkt[IP].proto, "?"),
                        "src_ip": pkt[IP].src,
                        "dst_ip": pkt[IP].dst})
            
            if TCP in pkt:
                info.update({"src_port": pkt[TCP].sport,
                           "dst_port": pkt[TCP].dport,
                           "flags": pkt[TCP].flags})
            elif UDP in pkt:
                info.update({"src_port": pkt[UDP].sport,
                           "dst_port": pkt[UDP].dport,
                           "len": pkt[UDP].len})
        
        pkts.append(info)
        return time.time() >= stop or (limit and len(pkts) >= limit)
    
    import sys, os
    with open(os.devnull, 'w') as f:
        old, sys.stdout = sys.stdout, f
        try: sniff(prn=cb, store=0, timeout=duration)
        finally: sys.stdout = old
    
    return pkts[:limit] if limit else pkts

def save_csv(pkts, fname="network_logs.csv"):
    if not pkts: return False
    with open(fname, "w", newline="") as f:
        w = csv.DictWriter(f, sorted(set().union(*(p.keys() for p in pkts))))
        w.writeheader()
        w.writerows(pkts)
    return True

def main():
    from argparse import ArgumentParser
    p = ArgumentParser(description="Network Packet Capture")
    p.add_argument("-t", type=int, help="Duration (sec)")
    p.add_argument("-n", type=int, help="Packet limit")
    p.add_argument("-o", default="network_logs.csv", help="Output file")
    a = p.parse_args()
    
    dur = a.t if a.t else int(input("Duration (sec) [5]: ") or 5)
    print(f"Capturing for {dur}s...")
    
    pkts = capture_packets(dur, a.n)
    if pkts and save_csv(pkts, a.o):
        print(f"Saved {len(pkts)} packets to {a.o}")

if __name__ == "__main__": main()