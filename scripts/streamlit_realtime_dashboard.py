import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import os
import time

st.set_page_config(layout="wide")

st.title("📡 Real-Time Network Traffic Analysis Dashboard")
st.markdown("Live monitoring of network traffic with protocol & security insights")
st.caption("⏱ Auto-refresh every 5 seconds")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSV_PATH = os.path.join(BASE_DIR, "data", "processed", "realtime_traffic.csv")

if not os.path.exists(CSV_PATH):
    st.warning("Waiting for live traffic data...")
    st.stop()

df = pd.read_csv(CSV_PATH)

if df.empty:
    st.warning("No packets captured yet.")
    st.stop()

df['time'] = pd.to_datetime(df['time'])
df['length'] = pd.to_numeric(df['length'], errors='coerce')
df.dropna(inplace=True)

# ===== LAST 30 SECONDS WINDOW =====
latest = df['time'].max()
df = df[df['time'] >= latest - pd.Timedelta(seconds=30)]

# ===== FILTER =====
protocols = st.multiselect(
    "Filter Protocols",
    df['protocol'].unique(),
    default=df['protocol'].unique()
)

df = df[df['protocol'].isin(protocols)]

# ===== LAYOUT =====
col1, col2 = st.columns(2)

with col1:
    st.subheader("📊 Protocol Distribution")
    fig, ax = plt.subplots(figsize=(4,3))
    df['protocol'].value_counts().plot(kind='bar', ax=ax)
    st.pyplot(fig)

with col2:
    st.subheader("📈 Bandwidth Usage")
    df['second'] = df['time'].dt.floor('S')
    bandwidth = df.groupby('second')['length'].sum()

    fig, ax = plt.subplots(figsize=(4,3))
    ax.plot(bandwidth.index, bandwidth.values)
    ax.set_ylabel("Bytes/sec")
    st.pyplot(fig)

# ===== SECURITY =====
st.subheader("🚨 Suspicious IP Detection")
THRESHOLD = 50
ip_counts = df['src_ip'].value_counts()
suspicious = ip_counts[ip_counts > THRESHOLD]

if not suspicious.empty:
    st.error("Suspicious IPs detected")
    st.dataframe(suspicious)
else:
    st.success("No suspicious activity detected")

# ===== AUTO REFRESH =====
time.sleep(5)
st.rerun()
