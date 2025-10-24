import pandas as pd
import random
import os

# Ensure output file goes into the data folder
output_file = os.path.join(os.path.dirname(__file__), "processed_packets.csv")

# Simulate 200 packets
data = []
for _ in range(200):
    pkt = {
        "src_ip": f"192.168.1.{random.randint(1,254)}",
        "dst_ip": f"10.0.0.{random.randint(1,254)}",
        "protocol": random.choice([6, 17, 1]),  # TCP=6, UDP=17, ICMP=1
        "length": random.randint(60,1500),
        "src_port": random.randint(1024,65535),
        "dst_port": random.randint(1024,65535),
        "flags": random.choice([0,2,16,18,None]),
        "label": random.choice([0,1])  # 0=Normal, 1=Malicious
    }
    data.append(pkt)

df = pd.DataFrame(data)

# Feature engineering
protocol_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
df["protocol_name"] = df["protocol"].map(protocol_map)
df = pd.get_dummies(df, columns=["protocol_name"])
df["is_large_packet"] = df["length"].apply(lambda x: 1 if x>1000 else 0)

# Save processed dataset
df.to_csv(output_file, index=False)
print(f"Sample processed_packets.csv created at {output_file}!")
