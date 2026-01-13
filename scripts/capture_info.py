import pyshark
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

pcap_path = os.path.join(
    BASE_DIR,
    "data",
    "raw_captures",
    "sample_traffic.pcap"
)

capture = pyshark.FileCapture(
    pcap_path,
    only_summaries=True
)

count = 0
for packet in capture:
    print(packet)
    count += 1
    if count == 10:
        break
