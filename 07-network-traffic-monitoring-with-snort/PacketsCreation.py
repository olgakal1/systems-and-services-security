from scapy.all import*
from datetime import datetime
import base64
import random

#helper function to generate a random IP address
def generate_ip():
    ip = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
    return ip

def generate_src_port():
    return random.randint(1024, 65535)

name = "Arximidis"
student_id = "2022030026"

https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers 
ports = [
    80,     # HTTP 
    443,    # HTTPS 
    22,     # SSH 
    23,     # TELNET 
    21,     # FTP 
    53,     # DNS uses UDP
    554,    # RTSP 
    1433,   # SQL 
    3389,   # RDP 
    1883    # MQTT
]
# all others use TCP

# 1 Student packet
def student_packet():
    ip = IP(src=generate_ip(), dst="192.168.1.1")
    tcp = TCP(sport=generate_src_port(), dport=54321)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    payload = f"{name}-{student_id} {timestamp}"
    return ip / tcp / payload

# 10 port scan packets
def port_scan_packets():
    pkts = []
    for port in ports:
        ip = IP(src=generate_ip(), dst="192.168.1.2")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        payload = f"{name}-{student_id} {timestamp}"
        # only DNS uses UDP else TCP
        if port == 53:
            udp = UDP(sport=generate_src_port(), dport=port)
            pkts.append(ip / udp / payload)
        else:
            tcp = TCP(sport=generate_src_port(), dport=port)
            pkts.append(ip / tcp / payload)

    return pkts

# 5 Base64 malicious packets
def base64_malicious_packets():
    pkts = []
    payload = base64.b64encode(student_id.encode()).decode()
    for _ in range(5):
        ip = IP(src=generate_ip(), dst="192.168.1.3")
        tcp = TCP(sport=generate_src_port(), dport=8080)
        pkts.append(ip / tcp / payload)
    return pkts

# 1 DNS suspicious domain packet
def dns_suspicious_packet():
    ip = IP(src=generate_ip(), dst="127.0.0.53")
    udp = UDP(sport=generate_src_port(), dport=53)
    dns_pack = DNS(rd=1, qd=DNSQR(qname="malicious.example.com"))
    return ip / udp / dns_pack

# Ping test packet
def ping_test_packet():
    ip = IP(src=generate_ip(), dst="192.168.1.4")
    icmp = ICMP()
    return ip / icmp / "PingTest-2024"

#generate packets
packets = []
packets.append(student_packet())
packets.extend(port_scan_packets())
packets.extend(base64_malicious_packets())
packets.append(dns_suspicious_packet())
packets.append(ping_test_packet())

# write packets to PCAP file and store it to folder
out_pcap = "/home/student/Desktop/assignment7/snort/lab/assignment_packets.pcap"
wrpcap(out_pcap, packets)

print(f"[OK] Created {len(packets)} packets and saved to {out_pcap}")
