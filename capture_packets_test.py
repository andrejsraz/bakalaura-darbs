import csv
import pyshark
import signal
import sys
import time
import netifaces
from datetime import datetime


available_interfaces = netifaces.interfaces()

print("Available interfaces:")
for idx, interface in enumerate(available_interfaces):
    print(f"{idx+1}. {interface}")

selected_interface = None
while True:
    try:
        choice = int(input("Choose interface number: "))
        if 1 <= choice <= len(available_interfaces):
            selected_interface = available_interfaces[choice - 1]
            break
        else:
            print("Invalid choice. Please enter a valid interface number.")
    except ValueError:
        print("Invalid choice. Please enter a valid interface number.")

capture = pyshark.LiveCapture(interface=selected_interface)

csv_file = '/home/wireshark/scripts/protocol_counts.csv'

total_packets = 0
total_bytes = 0
endpoints = set()
icmp_packet_counts_inbound = {}
latencies = []

own_ip_address = '192.168.101.37'

start_time = None

unique_macs = set()
MAC_TABLE_SIZE_WARNING_THRESHOLD = 1
mac_table_overflow_triggered = False
icmp_attack_triggered = False

def packet_callback(pkt):
    global total_packets, total_bytes, outbound_icmp_packets, latencies, icmp_attack_triggered, mac_table_overflow_triggered

    packet_time = datetime.fromtimestamp(float(pkt.sniff_timestamp))
    current_time = datetime.now()
    latency = (current_time - packet_time).total_seconds() * 1000  
    latencies.append(latency)

    protocol = pkt.highest_layer

    total_packets += 1
    total_bytes += int(pkt.length)

    if 'ip' in pkt:
        source_ip = pkt.ip.src
        destination_ip = pkt.ip.dst

        if protocol == 'ICMP':
            if source_ip != own_ip_address:
                icmp_packet_counts_inbound[source_ip] = icmp_packet_counts_inbound.get(source_ip, 0) + 1
                if icmp_packet_counts_inbound[source_ip] > 50 and not icmp_attack_triggered:
                    print(f"Warning: Possible ICMP flooding attack detected from {source_ip}")
                    icmp_attack_triggered = True

        if pkt.transport_layer is not None:
            source_port = pkt[pkt.transport_layer].srcport
            destination_port = pkt[pkt.transport_layer].dstport

            endpoints.add((source_ip, source_port))
            endpoints.add((destination_ip, destination_port))
        else:
            endpoints.add((source_ip, None))
            endpoints.add((destination_ip, None))

    source_mac = pkt.eth.src
    unique_macs.add(source_mac)

    if len(unique_macs) > MAC_TABLE_SIZE_WARNING_THRESHOLD and not mac_table_overflow_triggered:
        print("Warning: Potential MAC Address Table Overflow Detected")
        mac_table_overflow_triggered = True

def signal_handler(signal, frame):
    end_time = time.strftime('%Y-%m-%d %H:%M:%S')

    duration = int(time.time() - start_time)

    if duration >= 60:
        minutes, seconds = divmod(duration, 60)
        duration_formatted = f"{minutes} minutes {seconds} seconds"
    else:
        duration_formatted = f"{duration} seconds"

    avg_packet_size = total_bytes / total_packets if total_packets > 0 else 0
    packets_per_second = total_packets / duration if duration > 0 else 0
    avg_data_rate = total_bytes / duration if duration > 0 else 0

    sorted_endpoints = sorted(endpoints, key=lambda x: (x[0], x[1] or ''))

    min_latency = min(latencies) if latencies else 0
    max_latency = max(latencies) if latencies else 0
    avg_latency = sum(latencies) / len(latencies) if latencies else 0

    with open(csv_file, mode='w', newline='') as file:
        writer = csv.writer(file)

        writer.writerow(['Starting Time', time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time))])
        writer.writerow(['Ending Time', end_time])
        writer.writerow(['Duration', duration_formatted])
        writer.writerow(['-----------------------------------'])
        writer.writerow(['FOR LATENCY STATISTICS'])
        writer.writerow(['-----------------------------------'])
        writer.writerow(['Min Latency (ms)', min_latency])
        writer.writerow(['Max Latency (ms)', max_latency])
        writer.writerow(['Average Latency (ms)', avg_latency])
        writer.writerow(['Total Packets', total_packets])
        writer.writerow(['Total Bytes', total_bytes])
        writer.writerow(['Average Packet Size', avg_packet_size])
        writer.writerow(['Packets per Second', packets_per_second])
        writer.writerow(['Average Data Rate', avg_data_rate])
        writer.writerow(['------------------------------------------------'])
        writer.writerow(['DDOS ATTACK SYMPTOM DETECTION'])
        writer.writerow(['------------------------------------------------'])
        writer.writerow(['-----------------------------------'])
        writer.writerow(['FOR MAC FLOODING ATTACK DETECTION'])
        writer.writerow(['-----------------------------------'])
        writer.writerow(['Unique MAC Addresses', len(unique_macs)])
        writer.writerow(['MAC Address Table Overflow Warning', 'Yes' if mac_table_overflow_triggered else 'No'])
        writer.writerow(['-----------------------------------'])
        writer.writerow(['FOR PING FLOOD ATTACK DETECTION'])
        writer.writerow(['-----------------------------------'])
        writer.writerow(['ICMP Attack Warning', 'Yes' if icmp_attack_triggered else 'No'])
        writer.writerow(['INBOUND IP', 'ICMP Packets'])
        for source_ip, icmp_count in icmp_packet_counts_inbound.items():
            writer.writerow([source_ip, icmp_count])

        writer.writerow(['OUTBOUND TRAFFIC'])
        writer.writerow(['Outbound IP', 'ICMP Packets'])
        writer.writerow([own_ip_address, outbound_icmp_packets])
        writer.writerow(['------------------------------------------------'])
        writer.writerow(['Endpoint IP', 'Port'])
        for endpoint in sorted_endpoints:
            endpoint = list(endpoint)
            endpoint[1] = 'None' if endpoint[1] is None else endpoint[1]
            writer.writerow(endpoint)

    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

print("Network Analysis is in action. Please press CTRL+C to stop and save the file.")

outbound_icmp_packets = 0

try:
    start_time = time.time()  
    capture.apply_on_packets(packet_callback)
except KeyboardInterrupt:
    signal_handler(signal.SIGINT, None)
