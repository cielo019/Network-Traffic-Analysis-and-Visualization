import os
import pandas as pd
import matplotlib.pyplot as plt

# -------------------------------
# 1️⃣ Load CSV safely
# -------------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSV_PATH = os.path.join(BASE_DIR, 'data', 'processed', 'traffic.csv')

df = pd.read_csv(CSV_PATH)

# -------------------------------
# 2️⃣ Data Cleanup
# -------------------------------
df['length'] = pd.to_numeric(df['length'], errors='coerce')
df['time'] = pd.to_datetime(df['time'], errors='coerce')
df.dropna(inplace=True)

# Keep only valid IP packets
valid_ips = df['src_ip'].str.match(r'\d{1,3}(\.\d{1,3}){3}$') | df['src_ip'].str.contains(':')
df = df[valid_ips]

# Keep only known protocols
VALID_PROTOCOLS = ['TCP', 'UDP', 'ICMP', 'TLS', 'HTTP', 'HTTPS']
df = df[df['protocol'].isin(VALID_PROTOCOLS)]

# -------------------------------
# 3️⃣ Prepare Data
# -------------------------------
protocol_counts = df['protocol'].value_counts()
protocol_bandwidth = df.groupby('protocol')['length'].sum()

PROTOCOL = 'TCP'
top_ips = (
    df[df['protocol'] == PROTOCOL]
    .groupby('src_ip')
    .size()
    .sort_values(ascending=False)
    .head(10)
)

time_proto_bw = (
    df.groupby([df['time'].dt.floor('s'), 'protocol'])['length']
    .sum()
    .unstack(fill_value=0)
)

SUSPICIOUS_PACKET_LIMIT = 500
suspicious_protocols = protocol_counts[protocol_counts > SUSPICIOUS_PACKET_LIMIT]
colors_suspicious = ['red' if proto in suspicious_protocols else 'blue' for proto in protocol_counts.index]

# -------------------------------
# 4️⃣ Plot All Graphs in One Figure
# -------------------------------
fig, axes = plt.subplots(3, 2, figsize=(15, 12))  # 3 rows x 2 cols

# Packet Count per Protocol
protocol_counts.plot(kind='bar', ax=axes[0,0], color='skyblue', title="Packet Count per Protocol")
axes[0,0].set_xlabel("Protocol")
axes[0,0].set_ylabel("Packet Count")

# Bandwidth per Protocol
protocol_bandwidth.plot(kind='bar', ax=axes[0,1], color='orange', title="Bandwidth per Protocol")
axes[0,1].set_xlabel("Protocol")
axes[0,1].set_ylabel("Bytes")

# Top Source IPs
top_ips.plot(kind='bar', ax=axes[1,0], color='green', title=f"Top Source IPs ({PROTOCOL})")
axes[1,0].set_xlabel("Source IP")
axes[1,0].set_ylabel("Packet Count")

# Protocol-wise Bandwidth Over Time
time_proto_bw.plot(ax=axes[1,1])
axes[1,1].set_xlabel("Time")
axes[1,1].set_ylabel("Bandwidth (Bytes/sec)")
axes[1,1].set_title("Protocol-wise Bandwidth Over Time")

# Suspicious Protocol Detection
protocol_counts.plot(kind='bar', ax=axes[2,0], color=colors_suspicious, title="Suspicious Protocol Detection")
axes[2,0].set_xlabel("Protocol")
axes[2,0].set_ylabel("Packet Count")

# Hide empty subplot (2,1)
axes[2,1].axis('off')

plt.tight_layout()
plt.show()
