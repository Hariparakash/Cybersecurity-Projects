# ============================================================
# IMPORTS
# ============================================================

import scapy.all as scapy
from datetime import datetime
import json
from pathlib import Path
import threading


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.json"

try:
    with open(CONFIG_PATH, "r", encoding="utf-8") as file:
        config = json.load(file)
except FileNotFoundError:
    print(f"Error: config.json was not found at {CONFIG_PATH}")
    raise SystemExit(1)
except json.JSONDecodeError as error:
    print(f"Error: config.json contains invalid JSON: {error}")
    raise SystemExit(1)
except OSError as error:
    print(f"Error: could not read config.json: {error}")
    raise SystemExit(1)


# Validate required configuration values before using them.
try:
    suspicious_ports = config["suspicious_ports"]
    scan_threshold = config["scan_threshold"]
    scan_time_window_seconds = config["scan_time_window_seconds"]

    if not isinstance(suspicious_ports, list) or any(
        not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535
        for port in suspicious_ports
    ):
        raise ValueError("'suspicious_ports' must be a list of port numbers from 1 to 65535.")

    if (
        not isinstance(scan_threshold, int)
        or isinstance(scan_threshold, bool)
        or scan_threshold < 1
    ):
        raise ValueError("'scan_threshold' must be a positive whole number.")

    if (
        not isinstance(scan_time_window_seconds, (int, float))
        or isinstance(scan_time_window_seconds, bool)
        or scan_time_window_seconds <= 0
    ):
        raise ValueError("'scan_time_window_seconds' must be greater than zero.")

except KeyError as error:
    print(f"Error: config.json is missing the required setting {error}.")
    raise SystemExit(1)
except ValueError as error:
    print(f"Error: invalid config.json setting: {error}")
    raise SystemExit(1)


# ============================================================
# GLOBAL DATA
# ============================================================

packets = []
local_ip = None
capture_stop_event = threading.Event()


# ============================================================
# PACKET PARSING
# Purpose: Extract useful information from a captured packet
# ============================================================

def parse_packet(packet, local_ip):
    # This analyzer currently extracts IPv4 packets only.
    if not packet.haslayer(scapy.IP):
        return None

    # IPv4 detection
    ip_layer = packet[scapy.IP]
    source_ip = ip_layer.src
    destination_ip = ip_layer.dst

    # Direction detection — identify OUTBOUND vs INBOUND
    if source_ip == local_ip:
        direction = "OUTBOUND"
    else:
        direction = "INBOUND"

    # Protocol number to protocol name
    protocol = ip_layer.proto
    protocol_field = scapy.IP().get_field("proto")
    protocol_name = protocol_field.i2repr(None, protocol).upper()

    # Packet length
    packet_length = len(packet)

    # Packet timestamp
    timestamp = datetime.fromtimestamp(float(packet.time)).strftime("%d/%m/%Y %H:%M:%S.%f")[:-3]
    packet_info = {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol_name,
        "length": packet_length,
        "direction": direction
    }

    info = "N/A"

    # TCP communication protocol
    if packet.haslayer(scapy.TCP) and protocol == 6:
        tcp_layer = packet[scapy.TCP]
        source_port = tcp_layer.sport
        destination_port = tcp_layer.dport
        info = f"{source_port} → {destination_port}"
        packet_info["source_port"] = source_port
        packet_info["destination_port"] = destination_port

    # UDP communication protocol
    elif packet.haslayer(scapy.UDP) and protocol == 17:
        udp_layer = packet[scapy.UDP]
        source_port = udp_layer.sport
        destination_port = udp_layer.dport
        info = f"{source_port} → {destination_port}"
        packet_info["source_port"] = source_port
        packet_info["destination_port"] = destination_port

    # ICMP communication protocol
    elif packet.haslayer(scapy.ICMP) and protocol == 1:
        icmp_layer = packet[scapy.ICMP]
        icmp_type = icmp_layer.type
        icmp_code = icmp_layer.code

        icmp_descriptions = {
            0: "Echo Reply",
            3: "Destination Unreachable",
            5: "Redirect",
            8: "Echo Request",
            9: "Router Advertisement",
            10: "Router Solicitation",
            11: "Time Exceeded",
            12: "Parameter Problem"
        }

        icmp_description = icmp_descriptions.get(
            icmp_type, "Unknown ICMP Type"
        )

        info = (
            f"{icmp_description} | "
            f"Type: {icmp_type} | Code: {icmp_code}"
        )

        packet_info["icmp_type"] = icmp_type
        packet_info["icmp_code"] = icmp_code
        packet_info["icmp_description"] = icmp_description

    packet_info["Info"] = info
    return packet_info


# ============================================================
# PACKET PROCESSING
# Purpose: Process and store parsed packets
# ============================================================

def process_packet(packet):
    packet_info = parse_packet(packet, local_ip)

    if packet_info is not None:
        packet_info["packet_number"] = len(packets) + 1
        packets.append(packet_info)


# ============================================================
# TRAFFIC ANALYSIS — PROTOCOL STATISTICS
# Purpose: Count packets by protocol
# ============================================================

def protocol_statistics(packets):
    protocol_count = {}

    for packet in packets:
        protocol = packet["protocol"]
        if protocol in protocol_count:
            protocol_count[protocol] += 1
        else:
            protocol_count[protocol] = 1

    return protocol_count


# ============================================================
# INTERFACE DISCOVERY
# Purpose: Extract available network interfaces and IP addresses
# ============================================================

def get_interfaces():
    interfaces = scapy.get_if_list()
    interfaces_info = []

    for interface in interfaces:
        ip_address = scapy.get_if_addr(interface)
        interface_info = {
            "interface": interface,
            "IP address": ip_address
        }
        interfaces_info.append(interface_info)

    return interfaces_info


# ============================================================
# PACKET DISPLAY
# Purpose: Display captured packet information
# ============================================================

def display_packets():
    for packet in packets:
        print(
            f"{packet['packet_number']} | {packet['timestamp']} | "
            f"{packet['source_ip']} | {packet['destination_ip']} | "
            f"{packet['direction']} | {packet['protocol']} | "
            f"{packet['length']} | {packet['Info']}"
        )


# ============================================================
# TRAFFIC FILTERING
# Purpose: Filter captured packets by protocol
# ============================================================

def filter_packets(packets, protocol):
    filtered_packets = []

    for packet in packets:
        if packet["protocol"] == protocol:
            filtered_packets.append(packet)

    return filtered_packets


# ============================================================
# TRAFFIC ANALYSIS — CONNECTION SUMMARIES
# Purpose: Group TCP/UDP packets into bidirectional connections
# ============================================================

def connection_summaries(packets):
    summaries = {}

    for packet in packets:
        if (
            packet.get("protocol") in ("TCP", "UDP")
            and "source_port" in packet
            and "destination_port" in packet
        ):
            endpoint1 = f"{packet['source_ip']}:{packet['source_port']}"
            endpoint2 = f"{packet['destination_ip']}:{packet['destination_port']}"

            if endpoint1 < endpoint2:
                connection = f"{endpoint1} ↔ {endpoint2}"
            else:
                connection = f"{endpoint2} ↔ {endpoint1}"

            if connection in summaries:
                summaries[connection] += 1
            else:
                summaries[connection] = 1

    return summaries


# ============================================================
# SECURITY ANALYSIS — SUSPICIOUS PORTS
# Purpose: Flag packets using configured suspicious ports
# ============================================================

def detect_suspicious_ports(packets, suspicious_ports):
    suspicious_packets = []

    for packet in packets:
        if "source_port" in packet and packet["source_port"] in suspicious_ports:
            suspicious_packets.append({
                "packet": packet,
                "matched_port": packet["source_port"],
                "port_role": "source"
            })

        if (
            "destination_port" in packet
            and packet["destination_port"] in suspicious_ports
        ):
            suspicious_packets.append({
                "packet": packet,
                "matched_port": packet["destination_port"],
                "port_role": "destination"
            })

    return suspicious_packets


# ============================================================
# SECURITY ANALYSIS — PORT-SCAN DETECTION
# Purpose: Detect outbound connections to many unique ports
#          on one destination within a configured time window
# ============================================================

def detect_port_scans(packets):
    packet_scans = []
    ip_group = {}

    for packet in packets:
        if (
            packet.get("protocol") in ("TCP", "UDP")
            and packet.get("direction") == "OUTBOUND"
            and "source_ip" in packet
            and "destination_ip" in packet
            and "destination_port" in packet
            and "timestamp" in packet
        ):
            try:
                timestamp = datetime.strptime(
                    packet["timestamp"], "%d/%m/%Y %H:%M:%S.%f"
                )
            except (TypeError, ValueError):
                # Ignore packets with timestamps that cannot be parsed.
                continue

            source_ip = packet["source_ip"]
            destination_ip = packet["destination_ip"]
            destination_port = packet["destination_port"]
            key = (source_ip, destination_ip)

            if key not in ip_group:
                ip_group[key] = []

            ip_group[key].append((destination_port, timestamp))

    for key, ports in ip_group.items():
        ports.sort(key=lambda item: item[1])

        for i, (destination_port, current_time) in enumerate(ports):
            unique_ports = set()

            for earlier_port, earlier_time in ports[:i + 1]:
                time_difference = (current_time - earlier_time).total_seconds()

                if 0 <= time_difference <= scan_time_window_seconds:
                    unique_ports.add(earlier_port)

            if len(unique_ports) >= scan_threshold:
                packet_scans.append({
                    "source_ip": key[0],
                    "destination_ip": key[1],
                    "unique_ports": len(unique_ports),
                    "destination_ports": sorted(unique_ports),
                    "time_window_seconds": scan_time_window_seconds
                })
                # One alert per source/destination pair is enough.
                break

    return packet_scans

def main():
    global local_ip
    # ============================================================
    # INTERFACE SETUP AND VALIDATION
    # Purpose: Discover and validate the capture interface
    # ============================================================

    try:
        interfaces_info = get_interfaces()
    except (OSError, RuntimeError) as error:
        print(f"Error: could not discover network interfaces: {error}")
        raise SystemExit(1)

    if not interfaces_info:
        print("Error: no network interfaces were found.")
        raise SystemExit(1)

    for interface_info in interfaces_info:
        print(interface_info["interface"], interface_info["IP address"])

    available_interfaces = {
        item["interface"]: item["IP address"]
        for item in interfaces_info
    }

    selected_interface = input("Select the interface: ").strip()

    if selected_interface not in available_interfaces:
        print(f"Error: '{selected_interface}' is not a valid interface.")
        print("Available interfaces:", ", ".join(available_interfaces))
        raise SystemExit(1)

    capture_interface = selected_interface
    local_ip = available_interfaces[capture_interface]


    # ============================================================
    # CAPTURE CONFIGURATION
    # Purpose: Configure the number of packets to capture
    # ============================================================

    while True:
        try:
            packet_count = int(input("Specify Number of packets to Capture: "))

            if not 1 <= packet_count <= 10000:
                print("Enter a whole number from 1 to 10000.")
                continue

            break
        except ValueError:
            print("Invalid input. Please enter a whole number.")

    print(f"Ready to capture up to {packet_count} packets.")


    # ============================================================
    # PACKET CAPTURE
    # Purpose: Capture packets from the selected interface
    # ============================================================

    try:
        scapy.sniff(
            iface=capture_interface,
            prn=process_packet,
            count=packet_count,
            store=False
        )
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    except (OSError, RuntimeError, ValueError) as error:
        print(f"\nCapture error: {error}")
        raise SystemExit(1)


    # ============================================================
    # TRAFFIC ANALYSIS — RESULTS
    # Purpose: Display packet details and analysis results
    # ============================================================

    print("\n=== CAPTURED PACKETS ===")
    display_packets()

    print("\n=== PROTOCOL STATISTICS ===")
    protocol_counts = protocol_statistics(packets)

    if protocol_counts:
        for protocol, count in protocol_counts.items():
            print(f"{protocol}: {count}")
    else:
        print("No IPv4 packets were captured for analysis.")


    print("\n=== CONNECTION SUMMARIES ===")
    connection_summary = connection_summaries(packets)

    if connection_summary:
        for connection, count in connection_summary.items():
            print(f"{connection}: {count} packet(s)")
    else:
        print("No TCP/UDP connections were found.")


    print("\n=== TCP PACKET FILTER ===")
    filter_protocol = filter_packets(packets, "TCP")

    if filter_protocol:
        for packet in filter_protocol:
            print(packet)
    else:
        print("No TCP packets were captured.")


    print("\n=== CAPTURE RATE ===")
    if len(packets) >= 2:
        starttime = datetime.strptime(
            packets[0]["timestamp"], "%d/%m/%Y %H:%M:%S.%f"
        )
        endtime = datetime.strptime(
            packets[-1]["timestamp"], "%d/%m/%Y %H:%M:%S.%f"
        )
        duration = endtime - starttime
        duration_seconds = duration.total_seconds()

        if duration_seconds > 0:
            packet_rate = len(packets) / duration_seconds
            print(f"Capture duration: {duration_seconds:.6f} seconds")
            print(f"Packet rate: {packet_rate:.2f} packets/second")
        else:
            print("Packet rate unavailable: capture duration is zero.")
    else:
        print("Packet rate unavailable: fewer than two IPv4 packets were captured.")


    # ============================================================
    # SECURITY RESULTS — SUSPICIOUS PORTS
    # ============================================================

    print("\n=== SUSPICIOUS PORT CHECK ===")
    suspicious_packets = detect_suspicious_ports(packets, suspicious_ports)

    if suspicious_packets:
        for alert in suspicious_packets:
            original_packet = alert["packet"]
            print(
                f"Packet No. {original_packet['packet_number']} | "
                f"Source IP: {original_packet['source_ip']} | "
                f"Destination IP: {original_packet['destination_ip']} | "
                f"Protocol: {original_packet['protocol']} | "
                f"Matched port: {alert['matched_port']} | "
                f"Port role: {alert['port_role']}"
            )
    else:
        print("No packets matched the configured suspicious ports.")


    # ============================================================
    # SECURITY RESULTS — PORT-SCAN DETECTION
    # ============================================================

    print("\n=== OUTBOUND PORT-SCAN CHECK ===")
    packets_scan = detect_port_scans(packets)

    if packets_scan:
        for scan in packets_scan:
            print(
                f"Possible port scan: {scan['source_ip']} -> "
                f"{scan['destination_ip']} | "
                f"Unique destination ports within the configured window: "
                f"{scan['unique_ports']}"
            )
    else:
        print("No outbound port-scan pattern detected.")


if __name__ == "__main__":
    main()
