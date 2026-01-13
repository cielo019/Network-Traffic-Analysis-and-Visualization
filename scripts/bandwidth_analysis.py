import pandas as pd
import matplotlib.pyplot as plt
import os

# Project base directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

csv_path = os.path.join(
    BASE_DIR,
    "data",
    "processed",
    "traffic.csv"
)

# Load traffic data
df = pd.read_csv(csv_path)

# Convert time column to datetime
df['time'] = pd.to_datetime(df['time'])

# Group packets by second
df['second'] = df['time'].dt.floor('S')

# Calculate bandwidth usage (bytes per second)
bandwidth = df.groupby('second')['length'].sum()

# Plot bandwidth usage
plt.figure()
plt.plot(bandwidth.index, bandwidth.values)
plt.title("Bandwidth Usage Over Time")
plt.xlabel("Time (seconds)")
plt.ylabel("Bytes Transferred")
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()
