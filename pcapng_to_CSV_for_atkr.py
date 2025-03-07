import pyshark  # Importing PyShark for network packet capture analysis
import pandas as pd  # Importing Pandas for data manipulation
import asyncio  # Import asyncio to handle event loop issues
import os  # Import os to interact with the filesystem
import glob  # Import glob to find files matching a pattern

# Directories
PCAP_DIR = 'pcapng_files'  # Directory containing .pcapng files
CSV_DIR = 'csv_files'  # Directory where CSV files will be stored

# Ensure the CSV directory exists
os.makedirs(CSV_DIR, exist_ok=True)

# Function to analyze a PCAP file and extract network traffic information
def analyze_pcap(file_path, output_csv):
    cap = pyshark.FileCapture(file_path, display_filter="ip")  # Open pcap file with IP filter
    traffic_data = []  # List to store extracted packet data

    for pkt in cap:
        try:
            timestamp = float(pkt.sniff_time.timestamp())  # Extract timestamp of the packet
            size = int(pkt.length)  # Extract packet size in bytes
            src_ip = pkt.ip.src if hasattr(pkt, 'ip') else "Unknown"  # Extract source IP
            dst_ip = pkt.ip.dst if hasattr(pkt, 'ip') else "Unknown"  # Extract destination IP

            # Check if the packet has a transport layer (TCP/UDP) before accessing ports
            if hasattr(pkt, 'transport_layer') and pkt.transport_layer:
                src_port = getattr(pkt[pkt.transport_layer], 'srcport', "Unknown")  # Extract source port
                dst_port = getattr(pkt[pkt.transport_layer], 'dstport', "Unknown")  # Extract destination port
            else:
                src_port = "Unknown"  # Default to "Unknown" if no transport layer is found
                dst_port = "Unknown"

            # Append extracted data to the list
            traffic_data.append([timestamp, size, src_ip, dst_ip, src_port, dst_port])

        except AttributeError:
            continue  # Skip packets that do not have necessary fields

    # Properly close the capture
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.ensure_future(cap.close_async())  # Schedule close asynchronously
        else:
            loop.run_until_complete(cap.close_async())  # Close the capture file properly
    except RuntimeError:  # In case the event loop is already running
        pass

    # Convert extracted data to a Pandas DataFrame for analysis
    df = pd.DataFrame(traffic_data,
                      columns=["Timestamp", "Size", "Source IP", "Destination IP", "Source Port", "Destination Port"])

    df.to_csv(output_csv, index=False)  # Save the results to a CSV file
    print(f"Analysis saved to {output_csv}")  # Notify user of saved analysis


# Function to get all .pcapng files in the folder
def get_pcap_files(directory):
    return glob.glob(os.path.join(directory, "*.pcapng"))  # List all .pcapng files in the directory


# Detect and process all .pcapng files in the directory
pcap_files = get_pcap_files(PCAP_DIR)

for pcap_file in pcap_files:
    filename = os.path.basename(pcap_file).replace(".pcapng", "_analysis.csv")  # Extract filename
    output_file = os.path.join(CSV_DIR, filename)  # Save in CSV directory
    analyze_pcap(pcap_file, output_file)