Network Intrusion Detection System (NIDS) Dashboard

Real-time Intrusion Detection | Machine Learning | Cybersecurity Analytics

This project is a real-time Network Intrusion Detection System (NIDS) that captures live IP packets, extracts features, and classifies network activity into:

-Normal

-DoS Attack

-Port Scan

-Malware Traffic

The dashboard is fully interactive and displays live statistics, visualizations, and packet logs, making it ideal for cybersecurity demonstrations, academic work, and resume/portfolio projects.

⭐ Key Features
🔍 Real-Time Packet Capture

-Captures live Layer 3 (IP) packets using Windows-compatible raw sockets.

-No WinPcap/Npcap required.

🤖 Machine Learning Classification

-Uses a Random Forest multi-class model

-Predicts Normal, DoS, Port Scan, Malware

Includes custom security-focused feature engineering:

-Packet size flags

-Subnet comparison

-Port range analysis

📊 Professional Web Dashboard

Built with Flask + Bootstrap + Plotly, the UI includes:

-Attack distribution pie chart

-Protocol vs Attack stacked bar chart

-Top Talkers (src IP) chart

-Malicious trend graph (sliding window)

-Fully color-coded, scrollable packet table

-Real-time refresh with updated predictions

🛠️ Tech Stack

Backend: Python, Flask, scikit-learn, Pandas
Network: Raw sockets (Windows), Scapy (feature extraction)
Frontend: HTML, Bootstrap 5, Plotly JS
ML: Random Forest, feature engineering, model persistence via joblib

📁 Project Structure
NIDS-ML/
│
├─ dashboard/
│   ├─ app.py
│   ├─ templates/
│   │   └─ index.html
│
├─ model/
│   └─ model_multi.pkl
│
├─ data/
│   └─ processed_packets_multi.csv
│
└─ requirements.txt



📌 Future Improvements

Support for automatic model retraining

Integration with PCAP file uploads

Advanced ML models (XGBoost, Deep Learning)

Threat intelligence rule-based detection

Linux support for Layer-2 capture
