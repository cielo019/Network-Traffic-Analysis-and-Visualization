import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import os

# Load Your Existing CSV
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSV_PATH = os.path.join(BASE_DIR, "data", "processed", "traffic.csv")

df = pd.read_csv(CSV_PATH)
df['time'] = pd.to_datetime(df['time'])
df['length'] = pd.to_numeric(df['length'], errors='coerce')
df.dropna(inplace=True)

st.title("📡 Network Traffic Analysis Dashboard")
st.markdown("Real-time inspired traffic analysis with protocol and security insights")

# Protocol Filter
protocols = st.multiselect(
    "Select Protocols",
    options=df['protocol'].unique(),
    default=df['protocol'].unique()
)

filtered_df = df[df['protocol'].isin(protocols)]

# Protocol Distribution Chart
st.subheader("Protocol Distribution")

protocol_count = filtered_df['protocol'].value_counts()

fig, ax = plt.subplots()
protocol_count.plot(kind='bar', ax=ax)
ax.set_xlabel("Protocol")
ax.set_ylabel("Packet Count")

st.pyplot(fig)

# Bandwidth Usage Over Time
st.subheader("Bandwidth Usage Over Time")

filtered_df['second'] = filtered_df['time'].dt.floor('S')
bandwidth = filtered_df.groupby('second')['length'].sum()

fig, ax = plt.subplots()
ax.plot(bandwidth.index, bandwidth.values)
ax.set_xlabel("Time")
ax.set_ylabel("Bytes/sec")

st.pyplot(fig)

# Suspicious IP Detection
st.subheader("🚨 Suspicious IP Detection")

SUSPICIOUS_THRESHOLD = 50

ip_counts = filtered_df['src_ip'].value_counts()
suspicious_ips = ip_counts[ip_counts > SUSPICIOUS_THRESHOLD]

if not suspicious_ips.empty:
    st.error("Suspicious IPs Detected")
    st.dataframe(suspicious_ips)
else:
    st.success("No suspicious IP activity detected")
