import pandas as pd  # Importing Pandas for data analysis
import matplotlib.pyplot as plt  # Importing Matplotlib for visualization
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

    # Compute the average packet size
    average_packet_size = df["Size"].mean()

    plt.figure(figsize=(6, 6))  # Set figure size for better visualization
    bar = plt.bar("CSV Data", [average_packet_size], color='purple')  # Create a bar chart
    plt.xlabel("Data Source")  # Label for x-axis
    plt.ylabel("Average Packet Size (bytes)")  # Label for y-axis
    plt.title("Average Packet Size from CSV")  # Set title

    # Add text label with the average packet size value
    plt.text(bar[0].get_x() + bar[0].get_width() / 2, bar[0].get_height() + 5,
             f'{average_packet_size:.2f}', ha='center', va='bottom')

    plt.tight_layout()  # Adjust layout for better readability
    plt.show()  # Display the plot

    # Compute inter-arrival times between packets
    df["Inter Arrival Time"] = df["Timestamp"].diff().dt.total_seconds().dropna()

    plt.figure(figsize=(12, 6))  # Set figure size for better visualization

    # Create a histogram of inter-arrival times
    counts, bins, patches = plt.hist(df["Inter Arrival Time"], bins=50, alpha=0.7, color='blue', edgecolor='black')

    # Add count labels above each bar in the histogram
    for count, bin_patch in zip(counts, patches):
        if count > 0:  # Avoid displaying zero counts
            plt.text(bin_patch.get_x() + bin_patch.get_width() / 2, count, f'{int(count)}',
                     ha='center', va='bottom', fontsize=10, color='black', fontweight='bold')

    plt.xlabel("Inter-Arrival Time (Seconds)")  # Label for x-axis
    plt.ylabel("Frequency")  # Label for y-axis
    plt.title("Inter-Arrival Time Distribution from CSV")  # Set title
    plt.grid(axis="y", linestyle="--", alpha=0.7)  # Add grid for better readability
    plt.xticks(rotation=45)  # Rotate x-axis labels for better visibility
    plt.show()  # Display the plot

    # Plot packet size distribution
    plt.figure(figsize=(12, 6))  # Set figure size for better visualization
    plt.hist(df["Size"], bins=50, color='blue', edgecolor='black')  # Create histogram
    plt.xlabel("Packet Size (Bytes)")  # Label for x-axis
    plt.ylabel("Frequency")  # Label for y-axis
    plt.title("Packet Size Distribution from CSV")  # Set title
    plt.tight_layout()  # Adjust layout for better readability
    plt.show()  # Display the plot

    # Compute and display Flow Volume (total bytes transmitted)
    flow_volume = df["Size"].sum()  # Compute total bytes transmitted

    plt.figure(figsize=(6, 6))  # Set figure size for better visualization
    bar = plt.bar("CSV Data", [flow_volume], color='orange')  # Create a bar chart
    plt.xlabel("Data Source")  # Label for x-axis
    plt.ylabel("Total Bytes Transmitted")  # Label for y-axis
    plt.title("Flow Volume (Total Bytes Transmitted) from CSV")  # Set title

    # Add text label with total bytes transmitted value
    plt.text(bar[0].get_x() + bar[0].get_width() / 2, bar[0].get_height() + 5,
             f'{flow_volume:,}', ha='center', va='bottom')


    plt.tight_layout()  # Adjust layout for better readability
    plt.show()  # Display the plot
