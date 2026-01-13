import pyshark
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter
import threading
import time
import asyncio

# ===== SETTINGS =====
INTERFACE = 'Wi-Fi'  # change to your network interface name
MAX_PACKETS = 1000   # number of packets to keep in memory for live plotting
UPDATE_INTERVAL = 2  # seconds between updates

# ===== GLOBAL VARIABLES =====
packet_data = []

# ===== FUNCTION: CAPTURE PACKETS =====
def capture_packets():
    # Fix for Python 3.12 asyncio in threads
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    capture = pyshark.LiveCapture(interface=INTERFACE)
    for pkt in capture.sniff_continuously():
        try:
            packet_data.append({
                'time': pkt.sniff_time,
                'protocol': pkt.highest_layer,
                'length': int(pkt.length)
            })
            if len(packet_data) > MAX_PACKETS:
                packet_data.pop(0)
        except:
            continue

# ===== FUNCTION: LIVE PLOT =====
def live_plot():
    plt.ion()  # interactive mode on
    fig, ax = plt.subplots(2,1, figsize=(10,6))
    
    while True:
        if packet_data:
            df = pd.DataFrame(packet_data)
            
            # Protocol count plot
            ax[0].clear()
            protocol_count = df['protocol'].value_counts()
            protocol_count.plot(kind='bar', ax=ax[0], color='skyblue')
            ax[0].set_title("Protocol Distribution (Live)")
            ax[0].set_ylabel("Packet Count")
            
            # Bandwidth plot
            ax[1].clear()
            df['second'] = df['time'].dt.floor('S')
            bandwidth = df.groupby('second')['length'].sum()
            bandwidth.plot(ax=ax[1], color='orange')
            ax[1].set_title("Bandwidth Usage Over Time (Live)")
            ax[1].set_ylabel("Bytes/sec")
            
            plt.tight_layout()
            plt.pause(UPDATE_INTERVAL)
        else:
            time.sleep(1)

# ===== MAIN =====
if __name__ == "__main__":
    # Start packet capture in a separate thread
    capture_thread = threading.Thread(target=capture_packets, daemon=True)
    capture_thread.start()
    
    # Start live plotting
    live_plot()
