import pyshark  # Importing PyShark for network packet capture analysis
import matplotlib.pyplot as plt  # Importing Matplotlib for data visualization
import os  # Import os to interact with the filesystem
import glob  # Import glob to find files matching a pattern

# Function to calculate the total bytes transmitted in a PCAP file
def analyze_flow_volume(pcap_file):
    cap = pyshark.FileCapture(pcap_file, keep_packets=False)  # Open pcap file without storing packets in memory
    total_bytes = 0  # Variable to store total bytes transmitted

    for packet in cap:
        try:
            if 'IP' in packet:  # Ensure the packet contains an IP layer
                total_bytes += int(packet.length)  # Add packet size to total volume
        except AttributeError:
            continue  # Ignore packets with missing attributes and proceed

    cap.close()  # Close the pcap file to release resources
    return total_bytes  # Return total transmitted bytes


# Function to plot a bar chart for Flow Volume (total bytes transmitted per PCAP file)
def plot_flow_volume(flow_volumes, pcap_files):
    # Extract only the file names from the full paths
    file_names = [os.path.basename(file) for file in pcap_files]
    plt.figure(figsize=(12, 6))  # Set figure size for better readability
    bars = plt.bar(file_names, flow_volumes, color='purple')  # Create a bar chart
    plt.xlabel('PCAP File')  # Label for x-axis
    plt.ylabel('Total Bytes Transmitted')  # Label for y-axis
    plt.title('Flow Volume (Total Bytes Transmitted per PCAP File)')  # Set title

    # Add byte volume labels above each bar
    for bar, volume in zip(bars, flow_volumes):
        yval = bar.get_height()  # Get height of each bar (total bytes transmitted)
        plt.text(bar.get_x() + bar.get_width() / 2, yval + 5000, f'{volume:,}', ha='center', va='bottom')

    plt.xticks(rotation=45, ha="right")  # Rotate x-axis labels for better visibility
    plt.tight_layout()  # Adjust layout to prevent overlapping labels
    plt.show()  # Display the plot


# Function to get all .pcapng files in the folder
def get_pcap_files(directory):
    return glob.glob(os.path.join(directory, "*.pcapng"))  # List all .pcapng files in the directory

# Directory containing PCAPNG files
PCAP_DIR = 'pcapng_files'

# Detect and process all .pcapng files in the directory
pcap_files = get_pcap_files(PCAP_DIR)

# Compute total bytes transmitted for each PCAP file
flow_volumes = [analyze_flow_volume(pcap_file) for pcap_file in pcap_files]

# Display the Flow Volume plot
plot_flow_volume(flow_volumes, pcap_files)
