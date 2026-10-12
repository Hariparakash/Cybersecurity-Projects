# Custom Network Packet Sniffer & Analyzer

A Python-based desktop network monitoring and security analysis application built with **Scapy** and **Tkinter** on Kali Linux.

The application captures network packets, extracts protocol information, summarizes traffic, and identifies selected suspicious-port activity and potential outbound port-scanning patterns. This project demonstrates practical skills in Python programming, network protocols, packet analysis, GUI development, and basic security monitoring.

## Features

- **Live packet capture:** Capture packets from a selected network interface using Scapy.
- **Protocol analysis:** Extract IPv4, TCP, UDP, and ICMP information from supported packets.
- **Traffic direction:** Classify packets as inbound or outbound relative to the selected interface's IP address.
- **Protocol statistics:** Display packet counts, protocol distribution, capture duration, and packet-processing rate.
- **Suspicious-port detection:** Generate alerts when observed source or destination ports match the configured suspicious-port list.
- **Outbound port-scan detection:** Identify traffic reaching a configured number of unique destination ports within a rolling time window.
- **Connection summaries:** Group traffic by bidirectional endpoint pairs.
- **Security alert dashboard:** Display suspicious-port and port-scan alerts in the GUI.
- **Capture management:** Save captured records as JSON and handle existing capture data through Save, Discard, or Cancel prompts.
- **Configurable detection:** Adjust suspicious ports, scan thresholds, and time-window settings through `config.json`.
- **Synthetic testing:** Test detection behavior against controlled packet records and boundary conditions.

## Technology Stack

| Component | Technology |
|---|---|
| Programming language | Python |
| Packet capture and parsing | Scapy |
| Desktop interface | Tkinter and ttk |
| Configuration | JSON |
| Testing | Previously executed synthetic test cases |
| Development environment | Kali Linux |

## Project Structure

```text
Custom-Network-Packet-Sniffer/
├── main.py
├── GUI.py
├── config.json
├── requirements.txt
└── README.md
```

- `main.py` — Packet parsing, protocol statistics, connection summaries, and security detection logic.
- `GUI.py` — Desktop interface, capture controls, packet table, statistics, security alerts, and capture export.
- `config.json` — Suspicious-port list and port-scan detection parameters.
- `requirements.txt` — Project dependencies.

## Architecture

```text
                 config.json
                      |
                      v
          +----------------------+
          |       main.py        |
          | Parsing and Analysis |
          | Security Detection   |
          +----------------------+
                      ^
                      |
          +----------------------+
          |        GUI.py        |
          |     Tkinter / ttk    |
          | Controls and Display |
          +----------------------+
                      |
                      v
          +----------------------+
          |   Scapy AsyncSniffer |
          |   Network Capture    |
          +----------------------+
```

The project separates packet-analysis functions from the graphical interface. The GUI uses Scapy's `AsyncSniffer` for asynchronous packet capture and displays processed information through Tkinter. The backend contains reusable functions for parsing packets, calculating statistics, summarizing connections, and detecting selected traffic patterns.

*This diagram is a simplified conceptual view of the components and their responsibilities.*

## How It Works

### 1. Packet Capture and Parsing

Scapy captures packets from the selected network interface. The parser processes IPv4 packets and extracts information including:

- Timestamp
- Source and destination IP addresses
- Protocol
- Packet length
- Inbound or outbound direction
- TCP or UDP source and destination ports, when applicable
- ICMP type, code, and description, when applicable

Packets without an IPv4 layer, including ARP packets, are excluded from the parsed packet dataset.

### 2. Traffic Analysis

The analysis backend calculates protocol statistics and organizes traffic into connection summaries.

Connection summaries use canonical endpoint pairs so that traffic in both directions can be grouped into the same conversation summary. These summaries describe observed traffic rather than maintaining a complete TCP connection state machine.

### 3. Suspicious-Port Monitoring

The application compares observed source and destination ports against the suspicious-port list defined in `config.json`.

Matching traffic can generate a security alert. A port match is a reason to investigate, not proof of malicious activity.

### 4. Outbound Port-Scan Detection

The detector examines eligible outbound TCP and UDP packet records and groups them by source and destination IP addresses.

Within each group, records are sorted by timestamp and evaluated using a rolling time window. The detector counts **unique destination ports** accessed within that window. When the number reaches or exceeds the configured threshold, an alert is generated for the corresponding source-destination pair.

Conceptually, the detector checks:

- **Traffic direction:** Outbound
- **Grouping:** Source IP and destination IP
- **Measurement:** Unique destination ports
- **Time constraint:** Configured rolling time window
- **Alert condition:** Unique-port count reaches the configured threshold

This is a threshold-based heuristic for identifying potential scanning behavior. It is not a complete intrusion-detection system.

## Configuration

The `config.json` file controls the detection parameters.

| Setting | Purpose |
|---|---|
| `suspicious_ports` | Ports that should trigger investigation alerts |
| `scan_threshold` | Minimum number of unique destination ports required for a scan alert |
| `scan_time_window_seconds` | Rolling time interval used by the scan detector |

The current configuration uses a scan threshold of **10 unique destination ports within 5 seconds**. The suspicious-port list includes ports such as 23, 4444, 5555, 5900, 6379, 9200, 11211, and 27017.

These are configurable heuristic settings, not universal indicators of compromise.

### Testing and Verification

The port-scan detection logic was previously tested using synthetic packet records designed to check boundary conditions and source-target tracking behavior.

**Previously recorded result: 6/6 synthetic boundary tests passed.**

The test script has since been removed from the repository, so these tests cannot currently be rerun from the project files. The recorded result does not establish comprehensive real-world detection accuracy or guarantee detection of every port scan.

## Limitations

- **IPv4-focused parsing:** IPv6 packets are not covered by the parsed dataset.
- **ARP exclusion:** ARP packets are not included in the parsed packet records.
- **Direction heuristic:** Direction is inferred using the selected interface's IP address rather than full operating-system routing analysis.
- **Threshold-based detection:** Port-scan detection relies on packet direction, IP grouping, unique destination ports, timestamps, and configured thresholds.
- **No malicious-intent determination:** A detection alert does not establish that traffic is malicious.
- **Simplified connection summaries:** Endpoint grouping does not implement a complete TCP connection state machine or track every TCP flag and connection transition.
- **Capture permissions:** Packet capture may require elevated privileges on Linux.
- **Authorized use:** Capture traffic only on systems and networks you own or have permission to monitor.

## Screenshots

Screenshots can be added here when available:

- Main dashboard showing captured packets and protocol statistics.
- Security Alerts panel showing suspicious-port and port-scan detections.
- Connection summaries window showing grouped endpoints.

## Learning Outcomes

Through this project, I gained practical experience with:

- Structuring a Python application into separate modules.
- Capturing and parsing network packets with Scapy.
- Working with IPv4, TCP, UDP, and ICMP fields.
- Inferring traffic direction from a network interface.
- Implementing configurable security heuristics.
- Detecting potential scanning behavior with a rolling time window.
- Building a desktop interface using Tkinter.
- Previously tested detection logic with synthetic boundary cases.
- Debugging implementation issues and documenting technical limitations.

## AI-Assisted Development and My Contribution

ChatGPT played a significant role in developing this project. I used its guidance to work through the packet parsing, protocol handling, and security-detection logic, then used AI assistance to complete and refine the implementation.

The graphical user interface (GUI) was generated by ChatGPT. My role was to connect the GUI to the backend, integrate the application components, run tests, and verify that packet capture, security alerts, and other features worked together as expected.

I also used AI assistance for smaller improvements, including code cleanup, consistent naming, formatting, and targeted fixes. This helped me avoid spending unnecessary time on repetitive edits and focus on integration, testing, and understanding how the application works.

I contributed through configuring, integrating, testing, debugging, and reviewing the application. I do not claim to have independently written every component. My goal was to build a working project while learning about packet analysis, network protocols, security-detection heuristics, and the practical challenges of combining a Python backend with a graphical interface.

I can discuss the project's architecture, explain the detection approach and its limitations, and demonstrate the application and its tests.

## Future Improvements

Potential extensions include:

- IPv6 packet parsing and analysis.
- More detailed protocol and traffic analysis.
- Additional scan-detection heuristics.
- More synthetic boundary tests and controlled live-network validation.
- Improved documentation and automated test coverage.