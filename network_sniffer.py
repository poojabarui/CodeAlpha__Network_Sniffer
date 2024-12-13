from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

def  analyze_packet(packet):
    print("=" * 50)
    print(f"Packet Captured: {packet.summary()}")

    if IP in packet:
        print("\n[IP Layer]")
        print(f"Source IP: {packet[IP].src}")
        print(f"Destination IP: {packet[IP].dst}")
        print(f"Protocol: {packet[IP].proto}")
    
    if TCP in packet:
        print("\n[TCP Layer]")
        print(f"Source Port: {packet[TCP].sport}")
        print(f"Destination Port: {packet[TCP].dport}")
        
        

    if UDP in packet:
        print("\n[UDP Layer]")
        print(f"Source Port: {packet[UDP].sport}")
        print(f"Destination Port: {packet[UDP].dport}")
        
        

   
    print("=" * 50)

if __name__ == "__main__":
    print("Starting packet capture......Press Ctrl+C to stop.")

    sniff(filter="ip", prn=analyze_packet, store=False)