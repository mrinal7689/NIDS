import os
import random
from collections import deque
from flask import Flask, render_template
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier

app = Flask(__name__)

# ---------- Paths ----------
base_dir = os.path.dirname(os.path.abspath(__file__))
model_dir = os.path.join(base_dir, "..", "model")
data_dir = os.path.join(base_dir, "..", "data")
os.makedirs(model_dir, exist_ok=True)
os.makedirs(data_dir, exist_ok=True)

model_file = os.path.join(model_dir, "model_multi.pkl")
processed_csv = os.path.join(data_dir, "processed_packets_multi.csv")

# ---------- Sliding window for live trends ----------
BATCH_HISTORY = 10
malicious_trend = deque(maxlen=BATCH_HISTORY)

# ---------- Synthetic dataset ----------
def create_synthetic_processed_csv(path, n=600):
    attack_types = ["Normal", "DoS", "Port Scan", "Malware"]
    rows = []
    for _ in range(n):
        protocol = random.choice([6,17,1])  # TCP, UDP, ICMP
        length = random.randint(60, 1500)
        src_port = random.randint(1, 65535)
        dst_port = random.randint(1, 65535)
        label = random.choices(attack_types, weights=[0.7,0.1,0.1,0.1])[0]
        rows.append({
            "src_ip": f"192.168.1.{random.randint(2,250)}",
            "dst_ip": f"10.0.0.{random.randint(2,250)}",
            "protocol": protocol,
            "length": length,
            "src_port": src_port,
            "dst_port": dst_port,
            "label": label
        })
    df = pd.DataFrame(rows)
    df["is_large_packet"] = (df["length"]>1200).astype(int)
    df["src_dst_same_subnet"] = df.apply(lambda r: 1 if r["src_ip"].split(".")[:3]==r["dst_ip"].split(".")[:3] else 0, axis=1)
    df["port_range_flag"] = df.apply(lambda r: 1 if r["src_port"]<1024 or r["dst_port"]<1024 else 0, axis=1)
    df["length_category"] = pd.cut(df["length"], bins=[0,500,1000,2000], labels=["Small","Medium","Large"])
    df = pd.get_dummies(df, columns=["protocol","length_category"])
    df.to_csv(path,index=False)
    print(f"Synthetic processed CSV created at {path}")

# ---------- Train multi-class model ----------
def train_model_from_csv(csv_path, out_model_path):
    df = pd.read_csv(csv_path)
    X = df.drop(columns=["src_ip","dst_ip","label"])
    y = df["label"]
    X = X.fillna(0)
    model = RandomForestClassifier(n_estimators=150,random_state=42)
    model.fit(X,y)
    joblib.dump(model,out_model_path)
    print(f"Multi-class model saved at {out_model_path}")
    return model

def ensure_model():
    if os.path.exists(model_file):
        return joblib.load(model_file)
    if os.path.exists(processed_csv):
        return train_model_from_csv(processed_csv,model_file)
    create_synthetic_processed_csv(processed_csv)
    return train_model_from_csv(processed_csv,model_file)

model = ensure_model()

# ---------- Dashboard route ----------
@app.route("/")
def show_dashboard():
    N = 50
    pkts = []
    for _ in range(N):
        proto = random.choice([6,17,1])
        proto_name = {6:"TCP",17:"UDP",1:"ICMP"}[proto]
        length = random.randint(60,1500)
        pkts.append({
            "src_ip":f"192.168.1.{random.randint(2,250)}",
            "dst_ip":f"10.0.0.{random.randint(2,250)}",
            "protocol":proto,
            "length":length,
            "src_port":random.randint(1,65535),
            "dst_port":random.randint(1,65535),
            "protocol_name":proto_name
        })
    df=pd.DataFrame(pkts)
    df["is_large_packet"]=(df["length"]>1200).astype(int)
    df["src_dst_same_subnet"]=df.apply(lambda r:1 if r["src_ip"].split(".")[:3]==r["dst_ip"].split(".")[:3] else 0, axis=1)
    df["port_range_flag"]=df.apply(lambda r:1 if r["src_port"]<1024 or r["dst_port"]<1024 else 0, axis=1)
    df=pd.get_dummies(df,columns=["protocol_name"])
    for col in ["protocol_name_TCP","protocol_name_UDP","protocol_name_ICMP"]:
        if col not in df.columns: df[col]=0
    feature_cols=list(model.feature_names_in_) if hasattr(model,"feature_names_in_") else df.columns
    for c in feature_cols:
        if c not in df.columns: df[c]=0
    X=df[feature_cols].fillna(0)
    df["prediction"]=model.predict(X)
    df["protocol"]=df.apply(lambda r:"TCP" if r.get("protocol_name_TCP",0) else "UDP" if r.get("protocol_name_UDP",0) else "ICMP",axis=1)
    rows=df.to_dict(orient="records")
    total=len(rows)
    counts={k:sum(1 for r in rows if r["prediction"]==k) for k in ["Normal","DoS","Port Scan","Malware"]}
    protocols = ["TCP","UDP","ICMP"]
    protocol_counts={}
    for proto in protocols:
        proto_rows=[r for r in rows if r["protocol"]==proto]
        protocol_counts[proto]={k:sum(1 for r in proto_rows if r["prediction"]==k) for k in ["Normal","DoS","Port Scan","Malware"]}
    
    # ---------- Top Talkers ----------
    src_ips = [r["src_ip"] for r in rows]
    top_talkers = dict(pd.Series(src_ips).value_counts().head(5))
    
    # ---------- Update sliding window for malicious trend ----------
    malicious_count = counts["DoS"] + counts["Port Scan"] + counts["Malware"]
    malicious_trend.append(malicious_count)
    trend_batches = list(range(1,len(malicious_trend)+1))
    trend_counts = list(malicious_trend)
    
    return render_template(
        "index.html",
        rows=rows,
        total=total,
        counts=counts,
        protocols=protocols,
        protocol_counts=protocol_counts,
        top_talkers=top_talkers,
        trend_batches=trend_batches,
        trend_counts=trend_counts,
        model_info=f"RandomForest ({os.path.basename(model_file)})"
    )

if __name__=="__main__":
    print("Interview-Ready NIDS Dashboard running at http://127.0.0.1:5000/")
    app.run(debug=True)
