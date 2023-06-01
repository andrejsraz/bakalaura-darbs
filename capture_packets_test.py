import csv
import pyshark
import signal
import sys
import time
import netifaces
import datetime
import psycopg2

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

total_packets = 0
total_bytes = 0
endpoints = set()
icmp_packet_counts_inbound = {}
icmp_packet_counts_outbound = {}
latencies = []

own_ip_address = '192.168.101.37'

start_time = None

unique_macs = set()
MAC_TABLE_SIZE_WARNING_THRESHOLD = 1000
mac_table_overflow_triggered = False
icmp_attack_triggered = False

def packet_callback(pkt):
    global total_packets, total_bytes, latencies, icmp_attack_triggered, mac_table_overflow_triggered

    packet_time = datetime.datetime.fromtimestamp(float(pkt.sniff_timestamp))
    current_time = datetime.datetime.now()
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
                if icmp_packet_counts_inbound[source_ip] > 1 and not icmp_attack_triggered:
                    print(f"Warning: Possible ICMP flooding attack detected from {source_ip}")
                    icmp_attack_triggered = True
            else:
                icmp_packet_counts_outbound[destination_ip] = icmp_packet_counts_outbound.get(destination_ip, 0) + 1

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
    end_time = datetime.datetime.now()

    duration = int(time.time() - start_time)

    start_time_datetime = datetime.datetime.fromtimestamp(start_time)

    avg_packet_size = total_bytes / total_packets if total_packets > 0 else 0
    packets_per_second = total_packets / duration if duration > 0 else 0
    avg_data_rate = total_bytes / duration if duration > 0 else 0

    min_latency = min(latencies) if latencies else 0
    max_latency = max(latencies) if latencies else 0
    avg_latency = sum(latencies) / len(latencies) if latencies else 0

    with open('network_analysis.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Starting Time", start_time_datetime])
        writer.writerow(["Ending Time", end_time])
        writer.writerow(["Duration", f"{duration//60} minutes {duration%60} seconds"])
        writer.writerow(["FOR LATENCY STATISTICS"])
        writer.writerow(["Min Latency (ms)", min_latency])
        writer.writerow(["Max Latency (ms)", max_latency])
        writer.writerow(["Average Latency (ms)", avg_latency])
        writer.writerow(["Total Packets", total_packets])
        writer.writerow(["Total Bytes", total_bytes])
        writer.writerow(["Average Packet Size", avg_packet_size])
        writer.writerow(["Packets per Second", packets_per_second])
        writer.writerow(["Average Data Rate", avg_data_rate])
        writer.writerow(["DDOS ATTACK SYMPTOM DETECTION"])
        writer.writerow(["FOR MAC FLOODING ATTACK DETECTION"])
        writer.writerow(["Unique MAC Addresses", len(unique_macs)])
        writer.writerow(["MAC Address Table Overflow Warning", mac_table_overflow_triggered])
        writer.writerow(["FOR PING FLOOD ATTACK DETECTION"])
        writer.writerow(["ICMP Attack Warning", icmp_attack_triggered])
        writer.writerow(["INBOUND IP", "ICMP Packets"])
        for ip, count in icmp_packet_counts_inbound.items():
            writer.writerow([ip, count])
        writer.writerow(["OUTBOUND TRAFFIC"])
        writer.writerow(["Outbound IP", "ICMP Packets"])
        for ip, count in icmp_packet_counts_outbound.items():
            writer.writerow([ip, count])
        writer.writerow(["Endpoint IP", "Port"])
        for endpoint in endpoints:
            writer.writerow(endpoint)

    with psycopg2.connect(
        dbname="data",
        user="wireshark",
        password="29100021001",
        host="localhost"
    ) as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO network_analysis (
                start_time,
                end_time,
                min_latency,
                max_latency,
                avg_latency,
                total_packets,
                total_bytes,
                avg_packet_size,
                packets_per_second,
                avg_data_rate,
                unique_macs,
                mac_table_overflow_triggered,
                icmp_attack_triggered
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id
            """,
            (
                start_time_datetime,
                end_time,
                min_latency,
                max_latency,
                avg_latency,
                total_packets,
                total_bytes,
                avg_packet_size,
                packets_per_second,
                avg_data_rate,
                len(unique_macs),
                mac_table_overflow_triggered,
                icmp_attack_triggered
            )
        )

        analysis_id = cur.fetchone()[0]

        for endpoint in endpoints:
            ip, port = endpoint
            cur.execute(
                """
                INSERT INTO endpoints (
                    network_analysis_id,
                    ip,
                    port
                ) VALUES (%s, %s, %s)
                """,
                (
                    analysis_id,
                    ip,
                    port
                )
            )

    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

print("Network Analysis is in action. Please press CTRL+C to stop and save the data.")
start_time = time.time()

capture.apply_on_packets(packet_callback)
