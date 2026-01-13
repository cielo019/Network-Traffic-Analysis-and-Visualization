import pyshark
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter
import threading
import time
import asyncio

# ===== SETTINGS =====
INTERFACE = 'Wi-Fi'        # Change to your interface
MAX_PACKETS = 1000         # Keep recent packets in memory
UPDATE_INTERVAL = 2        # seconds for updating graphs
SUSPICIOUS_PACKET_THRESHOLD = 50  # packets from one IP in recent window
BANDWIDTH_SPIKE_THRESHOLD = 2000  # bytes/sec considered high

# ===== GLOBAL VARIABLES =====
packet_data = []

# ===== FUNCTION: CAPTURE PACKETS =====
def capture_packets():
    # Fix asyncio issue in thread
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    capture = pyshark.LiveCapture(interface=INTERFACE)
    for pkt in capture.sniff_continuously():
        try:
            packet_data.append({
                'time': pkt.sniff_time,
                'src_ip': pkt.ip.src if hasattr(pkt, "ip") else 'IPv6',
                'protocol': pkt.highest_layer,
                'length': int(pkt.length)
            })
            if len(packet_data) > MAX_PACKETS:
                packet_data.pop(0)
        except:
            continue

# ===== FUNCTION: LIVE PLOT + ALERTS =====
def live_plot():
    plt.ion()  # interactive mode
    fig, ax = plt.subplots(2,1, figsize=(10,6))

    while True:
        if packet_data:
            df = pd.DataFrame(packet_data)

            # Protocol distribution plot
            ax[0].clear()
            protocol_count = df['protocol'].value_counts()
            protocol_count.plot(kind='bar', ax=ax[0], color='skyblue')
            ax[0].set_title("Protocol Distribution (Live)")
            ax[0].set_ylabel("Packet Count")

            # Bandwidth usage
            ax[1].clear()
            df['second'] = df['time'].dt.floor('S')
            bandwidth = df.groupby('second')['length'].sum()
            bandwidth.plot(ax=ax[1], color='orange')
            ax[1].set_title("Bandwidth Usage Over Time (Live)")
            ax[1].set_ylabel("Bytes/sec")

            # ----- ALERT: Bandwidth Spike -----
            if not bandwidth.empty and bandwidth.iloc[-1] > BANDWIDTH_SPIKE_THRESHOLD:
                print(f"[ALERT] Bandwidth spike detected: {bandwidth.iloc[-1]} bytes/sec at {bandwidth.index[-1]}")

            # ----- ALERT: Suspicious IPs -----
            recent_window = df[df['second'] >= df['second'].max() - pd.Timedelta(seconds=10)]
            ip_counts = recent_window['src_ip'].value_counts()
            suspicious_ips = ip_counts[ip_counts > SUSPICIOUS_PACKET_THRESHOLD]
            for ip, count in suspicious_ips.items():
                print(f"[ALERT] Suspicious IP detected: {ip} sent {count} packets in last 10 seconds")

            plt.tight_layout()
            plt.pause(UPDATE_INTERVAL)
        else:
            time.sleep(1)

# ===== MAIN =====
if __name__ == "__main__":
    capture_thread = threading.Thread(target=capture_packets, daemon=True)
    capture_thread.start()
    live_plot()
