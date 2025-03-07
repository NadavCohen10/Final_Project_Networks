import pandas as pd  # Importing Pandas for data analysis
import matplotlib.pyplot as plt  # Importing Matplotlib for visualization
from collections import defaultdict  # Importing defaultdict for efficient counting
import os  # Import os to interact with the filesystem
import glob  # Import glob to find files matching a pattern


CSV_DIR = 'csv_files'  # Directory where CSV files will be stored

def get_csv_files(directory):
    return glob.glob(os.path.join(directory, "*.csv"))  # List all .cvs files in the directory


# Detect and process all .csv files in the directory
csv_files = get_csv_files(CSV_DIR)

for file_path in csv_files:
    df = pd.read_csv(file_path)  # Read CSV file into a DataFrame

    # Convert timestamp column to datetime format
    df["Timestamp"] = pd.to_datetime(df["Timestamp"], unit="s")

    # Analyze IP addresses (count packets per IP)
    ip_stats = defaultdict(int)
    for _, row in df.iterrows():
        ip_stats[row["Source IP"]] += 1  # Count packets from source IP
        ip_stats[row["Destination IP"]] += 1  # Count packets to destination IP

    sorted_ips = sorted(ip_stats.items(), key=lambda x: x[1], reverse=True)[:10]  # Get top 10 IPs
    ips, counts = zip(*sorted_ips)

    plt.figure(figsize=(12, 6))
    plt.bar(ips, counts, color='blue')
    plt.xlabel("IP Address")
    plt.ylabel("Number of Packets")
    plt.title("IP Header Statistics from CSV")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.show()

    # Analyze TCP port usage
    tcp_stats = defaultdict(int)
    for _, row in df.iterrows():
        src_port = str(row["Source Port"]).strip()
        dst_port = str(row["Destination Port"]).strip()
        if src_port.isdigit():
            tcp_stats[src_port] += 1
        if dst_port.isdigit():
            tcp_stats[dst_port] += 1

    sorted_ports = sorted(tcp_stats.items(), key=lambda x: x[1], reverse=True)[:10]
    if sorted_ports:
        ports, counts = zip(*sorted_ports)
        plt.figure(figsize=(12, 6))
        plt.bar(ports, counts, color='green')
        plt.xlabel("TCP Port")
        plt.ylabel("Number of Packets")
        plt.title("TCP Port Statistics from CSV")
        plt.xticks(rotation=45, ha="right")
        plt.tight_layout()
        plt.show()

    # Compute average packet size
    average_packet_size = df["Size"].mean()
    plt.figure(figsize=(6, 6))
    bar = plt.bar("CSV Data", [average_packet_size], color='purple')
    plt.xlabel("Data Source")
    plt.ylabel("Average Packet Size (bytes)")
    plt.title("Average Packet Size from CSV")
    plt.text(bar[0].get_x() + bar[0].get_width() / 2, bar[0].get_height() + 5,
             f'{average_packet_size:.2f}', ha='center', va='bottom')
    plt.tight_layout()
    plt.show()

    # Compute inter-arrival times between packets
    df["Inter Arrival Time"] = df["Timestamp"].diff().dt.total_seconds().dropna()
    plt.figure(figsize=(12, 6))
    counts, bins, patches = plt.hist(df["Inter Arrival Time"], bins=50, alpha=0.7, color='blue', edgecolor='black')
    for count, bin_patch in zip(counts, patches):
        if count > 0:
            plt.text(bin_patch.get_x() + bin_patch.get_width() / 2, count, f'{int(count)}',
                     ha='center', va='bottom', fontsize=10, color='black', fontweight='bold')
    plt.xlabel("Inter-Arrival Time (Seconds)")
    plt.ylabel("Frequency")
    plt.title("Inter-Arrival Time Distribution from CSV")
    plt.grid(axis="y", linestyle="--", alpha=0.7)
    plt.xticks(rotation=45)
    plt.show()

    # Analyze packet size distribution
    plt.figure(figsize=(12, 6))
    plt.hist(df["Size"], bins=50, color='blue', edgecolor='black')
    plt.xlabel("Packet Size (Bytes)")
    plt.ylabel("Frequency")
    plt.title("Packet Size Distribution from CSV")
    plt.tight_layout()
    plt.show()

    # Compute total bytes transmitted
    flow_volume = df["Size"].sum()
    plt.figure(figsize=(6, 6))
    bar = plt.bar("CSV Data", [flow_volume], color='orange')
    plt.xlabel("Data Source")
    plt.ylabel("Total Bytes Transmitted")
    plt.title("Flow Volume from CSV")
    plt.text(bar[0].get_x() + bar[0].get_width() / 2, bar[0].get_height() + 5,
             f'{flow_volume:,}', ha='center', va='bottom')
    plt.tight_layout()
    plt.show()