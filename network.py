from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        
        protocol_name = "Unknown"
        if proto == 6:
            protocol_name = "TCP"
        elif proto == 17:
            protocol_name = "UDP"
        elif proto == 1:
            protocol_name = "ICMP"

        print(f"[+] Packet Captured: {src_ip} -> {dst_ip} | Protocol: {protocol_name}")

        if TCP in packet:
            print(f"    - TCP Packet | Source Port: {packet[TCP].sport}, Destination Port: {packet[TCP].dport}")
        elif UDP in packet:
            print(f"    - UDP Packet | Source Port: {packet[UDP].sport}, Destination Port: {packet[UDP].dport}")
        elif ICMP in packet:
            print(f"    - ICMP Packet | Type: {packet[ICMP].type}, Code: {packet[ICMP].code}")

# Sniff packets on the default network interface
print("[*] Starting Network Sniffer...")
sniff(prn=packet_callback, store=False)
