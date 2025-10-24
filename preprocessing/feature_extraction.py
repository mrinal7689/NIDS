import pandas as pd

# Load captured packets
df = pd.read_csv("../data/captured_packets.csv")

# Convert protocol numbers to names
protocol_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
df["protocol_name"] = df["protocol"].map(protocol_map).fillna("Other")

# Encode categorical features
df = pd.get_dummies(df, columns=["protocol_name"])

# Optional: Add derived features
df["is_large_packet"] = df["length"].apply(lambda x: 1 if x > 1000 else 0)

# For demo purposes, create a fake label (normally you use datasets or simulated attacks)
import random
df["label"] = [random.choice([0,1]) for _ in range(len(df))]  # 0=Normal, 1=Malicious

df.to_csv("../data/processed_packets.csv", index=False)
print("Feature extraction completed. Data saved to processed_packets.csv")
