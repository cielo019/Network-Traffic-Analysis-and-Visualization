import pyshark
import pandas as pd
import os
import asyncio
from datetime import datetime

# ================= SETTINGS =================
INTERFACE = 'Wi-Fi'
MAX_PACKETS = 1000

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_CSV = os.path.join(BASE_DIR, "data", "processed", "realtime_traffic.csv")

# ===========================================
packet_buffer = []

def capture_packets():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    capture = pyshark.LiveCapture(interface=INTERFACE)

    for pkt in capture.sniff_continuously():
        try:
            packet_buffer.append({
                "time": pkt.sniff_time,
                "src_ip": pkt.ip.src if hasattr(pkt, "ip") else "IPv6",
                "protocol": pkt.highest_layer,
                "length": int(pkt.length)
            })

            if len(packet_buffer) > MAX_PACKETS:
                packet_buffer.pop(0)

            # Write buffer to CSV
            df = pd.DataFrame(packet_buffer)
            df.to_csv(OUTPUT_CSV, index=False)

        except:
            continue


if __name__ == "__main__":
    print("[INFO] Starting live traffic capture...")
    capture_packets()
