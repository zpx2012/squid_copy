import pandas as pd

def calculate_rtt(file_path):
    """
    Calculates the Round-Trip Time (RTT) for a TCP connection from a tshark CSV file.

    It matches data packets from a client to the corresponding ACK packets from the
    server and calculates the time difference. This version uses the standard
    pandas.read_csv for efficient data loading.

    Args:
        file_path (str): The path to the CSV file.

    Returns:
        None. It prints the min, max, and average RTT directly.
    """
    try:
        # --- Standard Data Loading using Pandas ---
        column_names = [
            'time_epoch', 'ip_id', 'src_ip', 'srcport', 'dstport',
            'data_len', 'tcp_seq_rel', 'tcp_ack_rel', 'rwnd', 'out_of_order'
        ]
        # Use pandas.read_csv directly for efficiency.
        df = pd.read_csv(
            file_path, 
            header=None, 
            names=column_names,
            usecols=['time_epoch', 'src_ip', 'data_len', 'tcp_seq_rel', 'tcp_ack_rel'],
            low_memory=False
        )

        # --- Data Cleaning ---
        for col in ['time_epoch', 'data_len', 'tcp_seq_rel', 'tcp_ack_rel']:
            df[col] = pd.to_numeric(df[col], errors='coerce')
        df.dropna(inplace=True)
        
        # --- Identify Client and Server ---
        # Find the two unique IPs involved in the conversation from the src_ip column.
        unique_ips = df['src_ip'].unique()
        if len(unique_ips) < 2:
            print("Could not identify two distinct IPs in the conversation.")
            return
            
        # The client is the source of the first packet in the capture.
        client_ip = df.iloc[0]['src_ip']
        # The server is the other IP.
        server_ip = [ip for ip in unique_ips if ip != client_ip][0]

        print(f"Identified Client IP: {client_ip}")
        print(f"Identified Server IP: {server_ip}")

        # --- Separate Data and ACK packets ---
        # Data packets are sent *from* the client and have a data length > 0
        data_packets = df[(df['src_ip'] == client_ip) & (df['data_len'] > 0)].copy()
        
        # ACK packets are sent *from* the server in response
        ack_packets = df[df['src_ip'] == server_ip].copy()

        # --- Match Data to ACKs and Calculate RTT ---
        # Dictionary to store the time a data segment was sent.
        # Key: The sequence number the server should ACK (seq + len)
        # Value: The time the data packet was sent.
        sent_times = {}
        for _, row in data_packets.iterrows():
            expected_ack = row['tcp_seq_rel'] + row['data_len']
            # Only store the first time this sequence was sent to handle retransmissions
            if expected_ack not in sent_times:
                sent_times[expected_ack] = row['time_epoch']

        rtt_samples = []
        for _, ack in ack_packets.iterrows():
            ack_num = ack['tcp_ack_rel']
            # If this ACK corresponds to a data packet we've recorded
            if ack_num in sent_times:
                sent_time = sent_times[ack_num]
                rtt = (ack['time_epoch'] - sent_time) * 1000  # Convert to milliseconds
                if rtt > 0: # RTT must be a positive value
                    rtt_samples.append(rtt)
                # Remove the entry to ensure we match an ACK only once
                del sent_times[ack_num]

        # --- Display Results ---
        if not rtt_samples:
            print("\nCould not find any matching Data/ACK pairs to calculate RTT.")
            return

        min_rtt = min(rtt_samples)
        max_rtt = max(rtt_samples)
        avg_rtt = sum(rtt_samples) / len(rtt_samples)

        print("\n--- TCP RTT Calculation Results ---")
        print(f"Number of RTT samples calculated: {len(rtt_samples)}")
        print(f"Minimum RTT: {min_rtt:.2f} ms")
        print(f"Maximum RTT: {max_rtt:.2f} ms")
        print(f"Average RTT: {avg_rtt:.2f} ms")

    except Exception as e:
        print(f"An error occurred: {e}")

# --- Execution ---
calculate_rtt('port45366.tshark.csv')

