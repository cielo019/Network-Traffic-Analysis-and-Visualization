import pandas as pd
import matplotlib.pyplot as plt
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

csv_path = os.path.join(
    BASE_DIR,
    "data",
    "processed",
    "traffic.csv"
)

df = pd.read_csv(csv_path)

protocol_count = df['protocol'].value_counts()

plt.figure()
protocol_count.plot(kind='bar')
plt.title("Protocol Distribution")
plt.xlabel("Protocol")
plt.ylabel("Packet Count")
plt.tight_layout()
plt.show()
