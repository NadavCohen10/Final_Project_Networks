import pyshark  # Importing PyShark to analyze network packets from pcap files
import matplotlib.pyplot as plt  # Importing Matplotlib for plotting graphs
from collections import defaultdict  # Importing defaultdict to store IP statistics
from ipaddress import ip_address, ip_network  # Importing IP address utilities
import os  # Import os to interact with the filesystem
import glob  # Import glob to find files matching a pattern



# Function to check if an IP address is within a specified range
def is_ip_in_range(ip, range):
    return ip_address(ip) in ip_network(range)


# Function to analyze a pcapng file and extract IP header statistics
def analyze_pcap(pcap_file):
    cap = pyshark.FileCapture(pcap_file, keep_packets=False)  # Load the pcap file without storing packets in memory
    ip_stats = defaultdict(int)  # Dictionary to store IP occurrences

    for packet in cap:
        try:
            if 'IP' in packet:  # Check if the packet contains an IP layer
                ip_src = packet.ip.src  # Extract source IP address
                ip_dst = packet.ip.dst  # Extract destination IP address
                ip_stats[ip_src] += 1  # Increment occurrence count for source IP
                ip_stats[ip_dst] += 1  # Increment occurrence count for destination IP
        except Exception as e:
            continue  # Ignore errors and move to the next packet

    cap.close()  # Close the pcap file to free resources

    return ip_stats  # Return dictionary containing IP statistics


# Function to plot IP statistics for a specific file
def plot_ip_stats_for_file(ip_stats, pcap_file):
    # Limit the number of IPs shown to avoid overcrowding the x-axis
    sorted_ips = sorted(ip_stats.items(), key=lambda x: x[1], reverse=True)[:10]  # Show top 10 IPs
    ips, counts = zip(*sorted_ips)  # Separate IP addresses and packet counts

    # Create a bar chart to visualize IP header statistics
    plt.figure(figsize=(12, 6))  # Set figure size for better visibility
    plt.bar(ips, counts, color='blue')  # Create a bar chart with IPs and packet counts
    plt.xlabel('IP Address')  # Label for x-axis
    plt.ylabel('Number of Packets')  # Label for y-axis
    plt.title(f'IP Header Statistics (Number of Packets per IP) for {os.path.basename(pcap_file)}')  # Set title

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

# Loop through each pcap file, analyze and plot the IP statistics
for pcap_file in pcap_files:
    ip_stats = analyze_pcap(pcap_file)  # Analyze network packets in the file
    plot_ip_stats_for_file(ip_stats, pcap_file)  # Generate a plot for each file
