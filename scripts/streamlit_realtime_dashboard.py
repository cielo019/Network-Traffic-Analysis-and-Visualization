import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import os
import time
import matplotlib.dates as mdates

plt.style.use("dark_background")

st.set_page_config(
    page_title="Real-Time Network Traffic Dashboard",
    layout="wide"
)

st.title("📡 Real-Time Network Traffic Analysis Dashboard")
st.markdown("Live monitoring of network traffic with protocol & security insights")
st.caption("⏱ Auto-refresh every 5 seconds")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSV_PATH = os.path.join(BASE_DIR, "data", "processed", "realtime_traffic.csv")

# ---------- SAFE CSV READ ----------
try:
    if not os.path.exists(CSV_PATH) or os.path.getsize(CSV_PATH) == 0:
        st.warning("Waiting for live traffic data...")
        time.sleep(2)
        st.rerun()

    df = pd.read_csv(CSV_PATH)

except pd.errors.EmptyDataError:
    st.warning("Live data is updating... please wait")
    time.sleep(2)
    st.rerun()

# ---------- DATA CLEANING ----------
if df.empty:
    st.warning("No packets captured yet.")
    time.sleep(2)
    st.rerun()

df['time'] = pd.to_datetime(df['time'], errors='coerce')
df['length'] = pd.to_numeric(df['length'], errors='coerce')
df.dropna(inplace=True)

# Show only last 30 seconds
latest_time = df['time'].max()
df = df[df['time'] >= latest_time - pd.Timedelta(seconds=30)]

# ---------- FILTER ----------
protocols = st.multiselect(
    "Filter Protocols",
    df['protocol'].unique(),
    default=df['protocol'].unique()
)

df = df[df['protocol'].isin(protocols)]

col1, col2 = st.columns(2)

# ---------- PROTOCOL DISTRIBUTION ----------
with col1:
    st.subheader("📊 Protocol Distribution")
    fig, ax = plt.subplots(figsize=(5, 3), facecolor='none')
    df['protocol'].value_counts().plot(
        kind='bar',
        ax=ax,
        color="#00E5FF"
    )
    ax.set_facecolor("#0E1117")
    ax.grid(True, alpha=0.3)
    st.pyplot(fig, transparent=True)
   

# ---------- BANDWIDTH ----------
with col2:
    st.subheader("📈 Bandwidth Usage")
    
    # Floor to seconds
    df['second'] = df['time'].dt.floor('s')
    bandwidth = df.groupby('second')['length'].sum()
    
    fig, ax = plt.subplots(figsize=(4, 3), facecolor='none')  # Transparent figure
    ax.plot(
        bandwidth.index,
        bandwidth.values,
        color="#FF9100",
        linewidth=2
    )
    
    # Transparent axes
    ax.set_facecolor("none")
    
    # Grid
    ax.grid(True, alpha=0.3)
    
    # Format x-axis as HH:MM:SS
    import matplotlib.dates as mdates
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
    fig.autofmt_xdate(rotation=45)  # Rotate and align labels
    
    # Optional: set x-axis limits to last 30 seconds
    ax.set_xlim([bandwidth.index.min(), bandwidth.index.max()])
    
    st.pyplot(fig, transparent=True)


# ---------- SUSPICIOUS IPs ----------
st.subheader("🚨 Suspicious IP Detection")

THRESHOLD = 50
ip_counts = df['src_ip'].value_counts()
suspicious = ip_counts[ip_counts > THRESHOLD]

if not suspicious.empty:
    st.error("Suspicious IPs detected")
    st.dataframe(suspicious)
else:
    st.success("No suspicious activity detected")

time.sleep(5)
st.rerun()
