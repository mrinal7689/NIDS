from scapy.all import sniff, IP, TCP, UDP
import pandas as pd

# Store captured packets
packets_list = []

def extract_packet(packet):
    try:
        packet_info = {
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "protocol": packet[IP].proto,
            "length": len(packet),
        }
        if TCP in packet:
            packet_info["src_port"] = packet[TCP].sport
            packet_info["dst_port"] = packet[TCP].dport
            packet_info["flags"] = packet[TCP].flags
        elif UDP in packet:
            packet_info["src_port"] = packet[UDP].sport
            packet_info["dst_port"] = packet[UDP].dport
            packet_info["flags"] = None
        else:
            packet_info["src_port"] = None
            packet_info["dst_port"] = None
            packet_info["flags"] = None

        packets_list.append(packet_info)
    except:
        pass

print("Capturing network packets... Press Ctrl+C to stop.")
sniff(prn=extract_packet, count=100)  # Capture 100 packets for demo

# Save captured data
df = pd.DataFrame(packets_list)
df.to_csv("../data/captured_packets.csv", index=False)
print("Packets saved to captured_packets.csv")
