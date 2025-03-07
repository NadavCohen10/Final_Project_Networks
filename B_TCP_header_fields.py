import pyshark  # Importing PyShark for network packet capture analysis
import matplotlib.pyplot as plt  # Importing Matplotlib for data visualization
from collections import defaultdict  # Importing defaultdict to store TCP port statistics
import os  # Import os to interact with the filesystem
import glob  # Import glob to find files matching a pattern


# Function to analyze a pcapng file and extract TCP port statistics
def analyze_tcp_pcap(pcap_file):
    cap = pyshark.FileCapture(pcap_file, keep_packets=False)  # Open the pcap file without storing packets in memory
    tcp_stats = defaultdict(int)  # Dictionary to count occurrences of each TCP port

    for packet in cap:
        try:
            if 'TCP' in packet:  # Ensure the packet contains a TCP layer
                # Extract source and destination TCP ports
                tcp_src_port = packet.tcp.srcport  # Source port
                tcp_dst_port = packet.tcp.dstport  # Destination port

                # Increment occurrence count for source and destination ports
                tcp_stats[tcp_src_port] += 1
                tcp_stats[tcp_dst_port] += 1
        except Exception as e:
            continue  # Ignore errors and proceed to the next packet

    cap.close()  # Close the pcap file to release resources
    return tcp_stats  # Return dictionary containing TCP port statistics


# Function to plot TCP port statistics for a specific pcap file
def plot_tcp_stats_for_file(tcp_stats, pcap_file):
    # Limit the number of ports shown to avoid overcrowding the x-axis
    sorted_ports = sorted(tcp_stats.items(), key=lambda x: x[1], reverse=True)[:10]  # Show top 10 TCP ports
    ports, counts = zip(*sorted_ports)  # Unpack ports and packet counts

    # Create a bar chart to visualize TCP port statistics
    plt.figure(figsize=(12, 6))  # Set figure size for better readability
    plt.bar(ports, counts, color='green')  # Create a bar chart with TCP ports and packet counts
    plt.xlabel('TCP Port')  # Label for x-axis
    plt.ylabel('Number of Packets')  # Label for y-axis
    plt.title(f'TCP Port Statistics (Number of Packets per Port) for {os.path.basename(pcap_file)}')  # Set title

    # Rotate the x-axis labels for better readability
    plt.xticks(rotation=45, ha="right")

    plt.tight_layout()  # Adjust layout to prevent overlapping labels
    plt.show()  # Display the plot


# Function to get all .pcapng files in the folder
def get_pcap_files(directory):
    return glob.glob(os.path.join(directory, "*.pcapng"))  # List all .pcapng files in the directory

# Directory containing PCAPNG files
PCAP_DIR = 'pcapng_files'

# Detect and process all .pcapng files in the directory
pcap_files = get_pcap_files(PCAP_DIR)

# Loop through each pcap file, analyze and plot the TCP statistics
for pcap_file in pcap_files:
    tcp_stats = analyze_tcp_pcap(pcap_file)  # Analyze network packets in the file
    plot_tcp_stats_for_file(tcp_stats, pcap_file)  # Generate a plot for each file
