import pyshark
import pandas as pd
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

pcap_path = os.path.join(
    BASE_DIR,
    "data",
    "raw_captures",
    "sample_traffic.pcap"
)

output_csv = os.path.join(
    BASE_DIR,
    "data",
    "processed",
    "traffic.csv"
)

capture = pyshark.FileCapture(
    pcap_path,
    keep_packets=False
)

rows = []
MAX_PACKETS = 500   # LIMIT packets

count = 0
for pkt in capture:
    if count >= MAX_PACKETS:
        break
    try:
        rows.append({
            "time": pkt.sniff_time,
            "src_ip": pkt.ip.src if hasattr(pkt, "ip") else "IPv6",
            "dst_ip": pkt.ip.dst if hasattr(pkt, "ip") else "IPv6",
            "protocol": pkt.highest_layer,
            "length": int(pkt.length)
        })
        count += 1
    except:
        pass

df = pd.DataFrame(rows)
df.to_csv(output_csv, index=False)

print(f"Saved {len(df)} packets to traffic.csv")
