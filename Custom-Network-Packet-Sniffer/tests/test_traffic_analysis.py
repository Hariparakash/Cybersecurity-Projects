
import unittest
import main


class TrafficAnalysisTests(unittest.TestCase):

    def setUp(self):
        self.sample_packets = [
            {
                "protocol": "TCP",
                "source_ip": "192.168.1.10",
                "destination_ip": "8.8.8.8",
                "source_port": 50000,
                "destination_port": 443
            },
            {
                "protocol": "UDP",
                "source_ip": "192.168.1.10",
                "destination_ip": "8.8.8.8",
                "source_port": 53000,
                "destination_port": 53
            },
            {
                "protocol": "TCP",
                "source_ip": "192.168.1.20",
                "destination_ip": "192.168.1.10",
                "source_port": 443,
                "destination_port": 50000
            },
            {
                "protocol": "ICMP",
                "source_ip": "8.8.8.8",
                "destination_ip": "192.168.1.10"
            }
        ]

    # ---------------- FILTERING ----------------

    def test_filter_tcp_packets(self):
        result = main.filter_packets(self.sample_packets, "TCP")

        self.assertEqual(len(result), 2)
        self.assertTrue(all(p["protocol"] == "TCP" for p in result))

    def test_filter_udp_packets(self):
        result = main.filter_packets(self.sample_packets, "UDP")

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["protocol"], "UDP")

    def test_filter_with_no_matching_protocol(self):
        result = main.filter_packets(self.sample_packets, "ICMPv6")

        self.assertEqual(result, [])

    def test_filter_empty_packet_list(self):
        result = main.filter_packets([], "TCP")

        self.assertEqual(result, [])

    # ---------------- CONNECTION SUMMARIES ----------------

    def test_connection_summary_counts_tcp_and_udp(self):
        result = main.connection_summaries(self.sample_packets)

        self.assertEqual(sum(result.values()), 3)

    def test_reverse_direction_packets_share_connection(self):
        packets = [
            {
                "protocol": "TCP",
                "source_ip": "192.168.1.10",
                "destination_ip": "8.8.8.8",
                "source_port": 50000,
                "destination_port": 443
            },
            {
                "protocol": "TCP",
                "source_ip": "8.8.8.8",
                "destination_ip": "192.168.1.10",
                "source_port": 443,
                "destination_port": 50000
            }
        ]

        result = main.connection_summaries(packets)

        self.assertEqual(len(result), 1)
        self.assertEqual(list(result.values()), [2])

    def test_icmp_is_excluded_from_connection_summaries(self):
        packets = [
            {
                "protocol": "ICMP",
                "source_ip": "192.168.1.10",
                "destination_ip": "8.8.8.8"
            }
        ]

        result = main.connection_summaries(packets)

        self.assertEqual(result, {})

    def test_packets_without_ports_are_excluded(self):
        packets = [
            {
                "protocol": "TCP",
                "source_ip": "192.168.1.10",
                "destination_ip": "8.8.8.8"
            }
        ]

        result = main.connection_summaries(packets)

        self.assertEqual(result, {})

    # ---------------- SUSPICIOUS PORT DETECTION ----------------

    def test_suspicious_destination_port_is_detected(self):
        packets = [
            {
                "source_ip": "192.168.1.10",
                "destination_ip": "8.8.8.8",
                "source_port": 50000,
                "destination_port": 23
            }
        ]

        result = main.detect_suspicious_ports(packets, [23])

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["matched_port"], 23)
        self.assertEqual(result[0]["port_role"], "destination")

    def test_suspicious_source_port_is_detected(self):
        packets = [
            {
                "source_ip": "192.168.1.10",
                "destination_ip": "8.8.8.8",
                "source_port": 23,
                "destination_port": 50000
            }
        ]

        result = main.detect_suspicious_ports(packets, [23])

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["matched_port"], 23)
        self.assertEqual(result[0]["port_role"], "source")

    def test_both_suspicious_ports_generate_two_alerts(self):
        packets = [
            {
                "source_ip": "192.168.1.10",
                "destination_ip": "8.8.8.8",
                "source_port": 23,
                "destination_port": 445
            }
        ]

        result = main.detect_suspicious_ports(packets, [23, 445])

        self.assertEqual(len(result), 2)
        self.assertEqual(
            {alert["port_role"] for alert in result},
            {"source", "destination"}
        )

    def test_no_suspicious_port_match(self):
        packets = [
            {
                "source_ip": "192.168.1.10",
                "destination_ip": "8.8.8.8",
                "source_port": 50000,
                "destination_port": 443
            }
        ]

        result = main.detect_suspicious_ports(packets, [23, 445])

        self.assertEqual(result, [])

    def test_empty_packet_list_produces_no_alerts(self):
        result = main.detect_suspicious_ports([], [23, 445])

        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
