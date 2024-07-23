from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        print(f"IP Packet: {ip_src} -> {ip_dst}, Protocol: {protocol}")

        # Check for TCP packets
        if protocol == 6 and TCP in packet:
            print("TCP Packet:")
            print(f"Source Port: {packet[TCP].sport}, Destination Port: {packet[TCP].dport}")
            if packet[TCP].payload:
                print(f"Payload: {bytes(packet[TCP].payload)}")

        # Check for UDP packets
        elif protocol == 17 and UDP in packet:
            print("UDP Packet:")
            print(f"Source Port: {packet[UDP].sport}, Destination Port: {packet[UDP].dport}")
            if packet[UDP].payload:
                print(f"Payload: {bytes(packet[UDP].payload)}")

        print("-" * 50)

# Start sniffing
print("Starting packet sniffer...")
sniff(prn=packet_callback, store=0)