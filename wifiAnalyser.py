import pyshark
import numpy as np

def calculate_metrics_live(interface, packet_count=1000):
    """
    Capture live network traffic on a specified interface and calculate metrics.
    Parameters:
        interface (str): Network interface to capture packets on.
        packet_count (int): Number of packets to capture (default is 1000).
    Returns:
        dict: Calculated metrics for the captured traffic.
    """
    capture = pyshark.LiveCapture(interface=interface)
    metrics = {

        "DestinationPort": 0,
        "FlowDuration": 0,
        "TotalFwdPackets": 0,
        "TotalBackwardPackets": 0,
        "TotalLengthofFwdPackets": 0,
        "TotalLengthofBwdPackets": 0,
        "FwdPacketLengthMax": 0,
        "FwdPacketLengthMin": float('inf'),
        "FwdPacketLengthMean": 0,
        "FwdPacketLengthStd": 0,
        "BwdPacketLengthMax": 0,
        "BwdPacketLengthMin": float('inf'),
        "FlowBytes/s": 0,
        "FlowPackets/s": 0,
        "FwdIATMean": 0,
        "FwdIATStd": 0,
        "FwdHeaderLength": 0,
        "PacketLengthMean": 0,
        "PacketLengthStd": 0,
        "AveragePacketSize": 0,
        "IdleMean": 0,
        "IdleStd": 0
        
    }

    fwd_packet_lengths = []
    bwd_packet_lengths = []
    flow_start_time = None
    flow_end_time = None

    print("Capturing traffic. Press Ctrl+C to stop.")

    try:
        for packet in capture.sniff_continuously(packet_count=packet_count):
            if 'IP' not in packet or 'TCP' not in packet:
                continue

            try:
                length = int(packet.length)
                timestamp = float(packet.sniff_timestamp)
                dest_port = int(packet.tcp.dstport)

                # Update flow times
                if flow_start_time is None:
                    flow_start_time = timestamp
                flow_end_time = timestamp

                # Forward packets
                metrics["TotalFwdPackets"] += 1
                metrics["TotalLengthofFwdPackets"] += length
                fwd_packet_lengths.append(length)

                metrics["FwdPacketLengthMax"] = max(metrics["FwdPacketLengthMax"], length)
                metrics["FwdPacketLengthMin"] = min(metrics["FwdPacketLengthMin"], length)

                metrics["DestinationPort"] = dest_port

            except Exception as e:
                print(f"Error processing packet: {e}")
                continue

    except KeyboardInterrupt:
        print("Capture stopped.")

    # Calculate flow duration
    if flow_start_time and flow_end_time:
        metrics["FlowDuration"] = (flow_end_time - flow_start_time) * 1e6  # Convert to microseconds

    # Calculate statistics
    if fwd_packet_lengths:
        metrics["FwdPacketLengthMean"] = np.mean(fwd_packet_lengths)
        metrics["FwdPacketLengthStd"] = np.std(fwd_packet_lengths)

    all_packet_lengths = fwd_packet_lengths + bwd_packet_lengths
    if all_packet_lengths:
        metrics["PacketLengthMean"] = np.mean(all_packet_lengths)
        metrics["PacketLengthStd"] = np.std(all_packet_lengths)
        metrics["AveragePacketSize"] = np.mean(all_packet_lengths)

    if metrics["FlowDuration"] > 0:
        metrics["FlowBytes/s"] = (metrics["TotalLengthofFwdPackets"] + metrics["TotalLengthofBwdPackets"]) / (metrics["FlowDuration"] / 1e6)
        metrics["FlowPackets/s"] = (metrics["TotalFwdPackets"] + metrics["TotalBackwardPackets"]) / (metrics["FlowDuration"] / 1e6)

    return metrics
