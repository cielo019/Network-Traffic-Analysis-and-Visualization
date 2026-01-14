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

# Keep only valid IP packets (IPv4 or IPv6)
valid_ips = df['src_ip'].str.match(r'\d{1,3}(\.\d{1,3}){3}$') | df['src_ip'].str.contains(':')
df = df[valid_ips]

# Keep only known protocols
VALID_PROTOCOLS = ['TCP', 'UDP', 'ICMP', 'TLS', 'HTTP', 'HTTPS']
df = df[df['protocol'].isin(VALID_PROTOCOLS)]

print("Data loaded successfully")
print(f"Total packets after filtering: {len(df)}")
print(df.head())

# -------------------------------
# 3️⃣ Packet Count per Protocol
# -------------------------------
protocol_counts = df['protocol'].value_counts()

plt.figure()
protocol_counts.plot(kind='bar', color='skyblue')
plt.xlabel("Protocol")
plt.ylabel("Packet Count")
plt.title("Packet Count per Protocol")
plt.tight_layout()
plt.show()

# -------------------------------
# 4️⃣ Bandwidth Usage per Protocol
# -------------------------------
protocol_bandwidth = df.groupby('protocol')['length'].sum()

plt.figure()
protocol_bandwidth.plot(kind='bar', color='orange')
plt.xlabel("Protocol")
plt.ylabel("Total Bandwidth (Bytes)")
plt.title("Bandwidth Usage per Protocol")
plt.tight_layout()
plt.show()

# -------------------------------
# 5️⃣ Top Source IPs per Protocol
# -------------------------------
PROTOCOL = 'TCP'  # Change to UDP / ICMP / TLS / HTTP / HTTPS

top_ips = (
    df[df['protocol'] == PROTOCOL]
    .groupby('src_ip')
    .size()
    .sort_values(ascending=False)
    .head(10)
)

plt.figure()
top_ips.plot(kind='bar', color='green')
plt.xlabel("Source IP")
plt.ylabel("Packet Count")
plt.title(f"Top Source IPs using {PROTOCOL}")
plt.tight_layout()
plt.show()

# -------------------------------
# 6️⃣ Protocol-wise Bandwidth Over Time
# -------------------------------
time_proto_bw = (
    df.groupby([df['time'].dt.floor('s'), 'protocol'])['length']
    .sum()
    .unstack(fill_value=0)
)

time_proto_bw.plot()
plt.xlabel("Time")
plt.ylabel("Bandwidth (Bytes/sec)")
plt.title("Protocol-wise Bandwidth Over Time")
plt.tight_layout()
plt.show()

# -------------------------------
# 7️⃣ Suspicious Protocol Detection
# -------------------------------
SUSPICIOUS_PACKET_LIMIT = 500
suspicious_protocols = protocol_counts[protocol_counts > SUSPICIOUS_PACKET_LIMIT]

print("\nSuspicious Protocols:")
print(suspicious_protocols)

colors = [
    'red' if proto in suspicious_protocols else 'blue'
    for proto in protocol_counts.index
]

plt.figure()
protocol_counts.plot(kind='bar', color=colors)
plt.xlabel("Protocol")
plt.ylabel("Packet Count")
plt.title("Suspicious Protocol Detection")
plt.tight_layout()
plt.show()

# -------------------------------
# 8️⃣ ICMP Attack Detection
# -------------------------------
icmp_df = df[df['protocol'] == 'ICMP']
icmp_ip_counts = icmp_df.groupby('src_ip').size()

print("\nTop ICMP Senders:")
print(icmp_ip_counts.sort_values(ascending=False).head(5))

# -------------------------------
# 9️⃣ UDP Flood Detection
# -------------------------------
udp_df = df[df['protocol'] == 'UDP']
udp_ip_bandwidth = udp_df.groupby('src_ip')['length'].sum()

print("\nHigh UDP Bandwidth IPs:")
print(udp_ip_bandwidth.sort_values(ascending=False).head(5))
