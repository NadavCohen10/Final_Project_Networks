import pyshark  # Importing PyShark for network packet capture analysis
import matplotlib.pyplot as plt  # Importing Matplotlib for data visualization
import os  # Import os to interact with the filesystem
import glob  # Import glob to find files matching a pattern


# Function to analyze a PCAP file and calculate the average packet size
def analyze_average_packet_size(pcap_file):
    cap = pyshark.FileCapture(pcap_file, keep_packets=False)  # Open pcap file without storing packets in memory
    total_size = 0  # Total size of all packets
    packet_count = 0  # Total number of packets

    for packet in cap:
        try:
            if 'IP' in packet:  # Ensure packet contains an IP layer
                packet_size = int(packet.length)  # Extract packet size in bytes
                total_size += packet_size  # Add packet size to total
                packet_count += 1  # Increment packet count
        except Exception as e:
            continue  # Ignore errors and proceed to the next packet

    cap.close()  # Close the pcap file to free resources

    # Calculate the average packet size
    if packet_count > 0:
        average_size = total_size / packet_count  # Compute average size
    else:
        average_size = 0  # Default to 0 if no packets are present

    return average_size  # Return the computed average size



# Function to plot a bar chart of the average packet size per PCAP file
def plot_average_packet_size(average_sizes, pcap_files):
    # Extract only the file names from the full paths
    file_names = [os.path.basename(file) for file in pcap_files]
    # Create a bar chart to visualize average packet size per file
    plt.figure(figsize=(12, 6))  # Set figure size for better visibility
    bars = plt.bar(file_names, average_sizes, color='green')  # Create a bar chart
    plt.xlabel('PCAP File')  # Label for x-axis
    plt.ylabel('Average Packet Size (bytes)')  # Label for y-axis
    plt.title('Average Packet Size per PCAP File')  # Set chart title

    # Add numeric values on top of bars for better readability
    for bar, avg_size in zip(bars, average_sizes):
        yval = bar.get_height()  # Get height of each bar (average packet size)
        plt.text(bar.get_x() + bar.get_width() / 2, yval + 5, f'{avg_size:.2f}', ha='center', va='bottom')

    # Rotate x-axis labels for better readability
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()  # Adjust layout to avoid overlapping labels
    plt.show()  # Display the plot



# Function to get all .pcapng files in the folder
def get_pcap_files(directory):
    return glob.glob(os.path.join(directory, "*.pcapng"))  # List all .pcapng files in the directory

# Directory containing PCAPNG files
PCAP_DIR = 'pcapng_files'

# Detect and process all .pcapng files in the directory
pcap_files = get_pcap_files(PCAP_DIR)

# Compute the average packet size for each PCAP file
average_sizes = []
for pcap_file in pcap_files:
    average_size = analyze_average_packet_size(pcap_file)  # Analyze packet size
    average_sizes.append(average_size)  # Store the computed average

# Display the plot
plot_average_packet_size(average_sizes, pcap_files)  # Generate the plot
