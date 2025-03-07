# Network Traffic Analysis Project

## Overview
Everyday applications, such as emailing, web surfing, and streaming, generate network traffic with distinct characteristics. This project analyzes these characteristics using Python scripts that process packet capture files (PCAPNG format). The goal is to extract and study various network traffic features, including:

- **IP header fields**: Information about the source and destination of packets.
- **TCP header fields**: Transport layer details relevant to connections.
- **TLS header fields**: Data related to encrypted communication.
- **Packet sizes**: The distribution and variation of packet sizes.
- **Packet inter-arrival times**: The time intervals between consecutive packets.
- **Flow size**: The total number of packets in a given communication flow.
- **Flow volume**: The total number of bytes transmitted in a communication flow.

Understanding traffic characteristics has several critical applications, such as improving network performance, detecting anomalies, and identifying security threats. Even when encryption is used, traffic metadata can reveal information about user activity, making network forensics a crucial field of study. 

This project allows users to analyze and visualize network data, enabling insights into how different applications interact with the internet. The scripts provide a structured approach to converting raw packet data into meaningful statistics and visual representations for further analysis.

## Features
- Extracts IP, TCP, and TLS header fields.
- Computes packet sizes and flow statistics.
- Converts PCAPNG files into CSV format for analysis.
- Analyzes inter-arrival times of packets.


## Installation
### Prerequisites
Ensure you have Python installed on your system. You can install the required dependencies using the following command:

```bash
pip install -r requirements.txt
```

### Dependencies
The project requires the following Python libraries:
- `matplotlib`
- `pandas`
- `pyshark`

## Usage
Each script is designed for a specific aspect of network traffic analysis:

- `A_IP_header_fields.py`: Extracts IP header fields from packets.
- `B_TCP_header_fields.py`: Extracts TCP header fields.
- `C_TLS_header_fields.py`: Extracts TLS header fields.
- `D_packet_sizes.py`: Computes various packet size statistics.
- `E_packets_inter_arrivals.py`: Analyzes packet inter-arrival times.
- `F_flow_size.py`: Computes flow size information.
- `G_flow_volume.py`: Computes flow volume statistics.
- `pcapng_to_CSV_for_atkr.py`: Converts PCAPNG files into CSV format.
- `atkr_part_A.py` and `atkr_part_B.py`: Additional attack-related traffic analysis scripts (require converted CSV files).

### Note on Using `atkr` Scripts
To use the `atkr_part_A.py` and `atkr_part_B.py` scripts, you must first run the `pcapng_to_CSV_for_atkr.py` script to convert the PCAPNG files into CSV format.

To run a script, execute the following command:

```bash
python script_name.py
```

Replace `script_name.py` with the desired script filename.

## Authors
This project was developed by:
- Nadav Choen
- Aviv Oz
- Naama Yahav
- Noam Glikman


