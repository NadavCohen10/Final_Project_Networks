import pyshark  # Importing PyShark for network packet capture analysis
import matplotlib.pyplot as plt  # Importing Matplotlib for data visualization
import os  # Import os to interact with the filesystem
import glob  # Import glob to find files matching a pattern

# Function to analyze a PCAP file and extract packet size distribution
def analyze_packet_size_distribution(pcap_file):
    cap = pyshark.FileCapture(pcap_file, keep_packets=False)  # Open pcap file without storing packets in memory
    packet_sizes = []  # List to store packet sizes

    for packet in cap:
        try:
            if 'IP' in packet:  # Ensure packet contains an IP layer
                # Append the packet size to the list
                packet_sizes.append(int(packet.length))
        except AttributeError:
            continue  # Ignore packets with missing attributes and proceed

    cap.close()  # Close the pcap file to release resources
    return packet_sizes  # Return the list of packet sizes


# Function to plot a histogram of packet size distribution
def plot_packet_size_distribution(packet_sizes, pcap_file):
    # Create a histogram for packet sizes
    plt.figure(figsize=(12, 6))  # Set figure size for better readability
    plt.hist(packet_sizes, bins=50, color='blue', edgecolor='black')  # Create histogram
    plt.xlabel('Packet Size (Bytes)')  # Label for x-axis
    plt.ylabel('Frequency')  # Label for y-axis
    plt.title(f'Packet Size Distribution for {os.path.basename(pcap_file)}')  # Set title
    plt.tight_layout()  # Adjust layout to avoid overlapping labels
    plt.show()  # Display the plot



# Function to get all .pcapng files in the folder
def get_pcap_files(directory):
    return glob.glob(os.path.join(directory, "*.pcapng"))  # List all .pcapng files in the directory

# Directory containing PCAPNG files
PCAP_DIR = 'pcapng_files'

# Detect and process all .pcapng files in the directory
pcap_files = get_pcap_files(PCAP_DIR)


# For each PCAP file, analyze and plot the packet size distribution
for pcap_file in pcap_files:
    packet_sizes = analyze_packet_size_distribution(pcap_file)  # Analyze packet sizes
    plot_packet_size_distribution(packet_sizes, pcap_file)  # Generate a plot for each file
