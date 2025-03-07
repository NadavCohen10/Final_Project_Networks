import pyshark  # Importing PyShark for network packet capture analysis
import matplotlib.pyplot as plt  # Importing Matplotlib for data visualization
from collections import defaultdict  # Importing defaultdict to store TLS version statistics
import os  # Import os to interact with the filesystem
import glob  # Import glob to find files matching a pattern


# Function to analyze a pcapng file and extract TLS version statistics
def analyze_tls_pcap(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter='tls', keep_packets=False)  # Open pcap file and filter TLS packets
    tls_stats = defaultdict(int)  # Dictionary to count occurrences of each TLS version

    for packet in cap:
        try:
            if 'TLS' in packet:  # Ensure the packet contains a TLS layer
                # Check if the packet has a TLS record version
                if hasattr(packet.tls, 'record_version'):
                    tls_version = packet.tls.record_version  # Extract the TLS version
                    tls_stats[tls_version] += 1  # Increment count for the TLS version
        except Exception as e:
            continue  # Ignore errors and proceed to the next packet

    cap.close()  # Close the pcap file to release resources
    return tls_stats  # Return dictionary containing TLS version statistics


# Function to plot TLS version statistics for a specific pcap file
def plot_tls_stats_for_file(tls_stats, pcap_file):
    # Check if we have any TLS data to plot
    if not tls_stats:
        print(f"No TLS data found in {os.path.basename(pcap_file)}")  # Print message if no TLS packets were detected
        return

    # Sort TLS versions by occurrence count
    sorted_tls_versions = sorted(tls_stats.items(), key=lambda x: x[1], reverse=True)  # Sort by highest occurrences
    tls_versions, counts = zip(*sorted_tls_versions)  # Unpack TLS versions and counts

    # Create a bar chart to visualize TLS version statistics
    plt.figure(figsize=(12, 6))  # Set figure size for better readability
    plt.bar(tls_versions, counts, color='purple')  # Create a bar chart with TLS versions and packet counts
    plt.xlabel('TLS Version')  # Label for x-axis
    plt.ylabel('Number of Packets')  # Label for y-axis
    plt.title(f'TLS Version Statistics (Number of Packets per Version) for {os.path.basename(pcap_file)}')  # Set title

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

# Loop through each pcap file, analyze and plot the TLS version statistics
for pcap_file in pcap_files:
    tls_stats = analyze_tls_pcap(pcap_file)  # Analyze network packets in the file
    plot_tls_stats_for_file(tls_stats, pcap_file)  # Generate a plot for each file
