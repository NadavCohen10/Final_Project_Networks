import pyshark  # Importing PyShark for network packet capture analysis
import matplotlib.pyplot as plt  # Importing Matplotlib for data visualization
import os  # Import os to interact with the filesystem
import glob  # Import glob to find files matching a pattern

# Function to calculate inter-arrival times between packets
def analyze_inter_arrival_times(pcap_file):
    cap = pyshark.FileCapture(pcap_file, keep_packets=False)  # Open pcap file without storing packets in memory
    inter_arrival_times = []  # List to store inter-arrival times between packets

    previous_timestamp = None  # Variable to store the timestamp of the previous packet

    for packet in cap:
        try:
            timestamp = float(packet.sniff_time.timestamp())  # Extract arrival time of the packet

            if previous_timestamp is not None:
                inter_arrival_time = timestamp - previous_timestamp  # Compute time difference
                inter_arrival_times.append(inter_arrival_time)  # Store the inter-arrival time

            previous_timestamp = timestamp  # Update the last packet timestamp

        except AttributeError:
            continue  # Ignore packets with missing attributes and proceed

    cap.close()  # Close the pcap file to release resources
    return inter_arrival_times  # Return the list of inter-arrival times


# Function to plot a histogram of inter-arrival times with count labels
def plot_inter_arrival_times(inter_arrival_times, pcap_file):
    plt.figure(figsize=(12, 6))  # Set figure size for better readability

    # Create a histogram for inter-arrival times
    counts, bins, patches = plt.hist(inter_arrival_times, bins=50, alpha=0.7, color='blue', edgecolor='black')

    # Add count labels above each bar in the histogram
    for count, bin_patch in zip(counts, patches):
        if count > 0:  # Avoid displaying zero counts
            plt.text(bin_patch.get_x() + bin_patch.get_width() / 2, count, f'{int(count)}',
                     ha='center', va='bottom', fontsize=10, color='black', fontweight='bold')

    plt.xlabel('Inter-Arrival Time (Seconds)')  # Label for x-axis
    plt.ylabel('Frequency')  # Label for y-axis
    plt.title(f'Inter-Arrival Time Distribution for {os.path.basename(pcap_file)}')  # Set title
    plt.grid(axis='y', linestyle='--', alpha=0.7)  # Add grid for better readability
    plt.xticks(rotation=45)  # Rotate x-axis labels for better visibility
    plt.show()  # Display the plot



# Function to get all .pcapng files in the folder
def get_pcap_files(directory):
    return glob.glob(os.path.join(directory, "*.pcapng"))  # List all .pcapng files in the directory

# Directory containing PCAPNG files
PCAP_DIR = 'pcapng_files'

# Detect and process all .pcapng files in the directory
pcap_files = get_pcap_files(PCAP_DIR)

# For each PCAP file, compute and plot inter-arrival times
for pcap_file in pcap_files:
    inter_arrival_times = analyze_inter_arrival_times(pcap_file)  # Analyze inter-arrival times
    plot_inter_arrival_times(inter_arrival_times, pcap_file)  # Generate a plot for each file
