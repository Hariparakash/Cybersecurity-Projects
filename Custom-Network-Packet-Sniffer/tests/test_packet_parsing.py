
import unittest
from datetime import datetime

import scapy.all as scapy

import main


class PacketParsingTests(unittest.TestCase):

    def setUp(self):
        self.local_ip = "192.168.1.10"

    def build_timestamp(self, packet):
        return datetime.fromtimestamp(
            float(packet.time)
        ).strftime("%d/%m/%Y %H:%M:%S.%f")[:-3]

    def test_tcp_packet_extracts_expected_fields(self):
        packet = (
            scapy.Ether()
            / scapy.IP(src="192.168.1.10", dst="8.8.8.8")
            / scapy.TCP(sport=50000, dport=443)
        )
        packet.time = 1700000000.123

        result = main.parse_packet(packet, self.local_ip)

        self.assertIsNotNone(result)
        self.assertEqual(result["source_ip"], "192.168.1.10")
        self.assertEqual(result["destination_ip"], "8.8.8.8")
        self.assertEqual(result["protocol"], "TCP")
        self.assertEqual(result["source_port"], 50000)
        self.assertEqual(result["destination_port"], 443)
        self.assertEqual(result["direction"], "OUTBOUND")
        self.assertEqual(result["Info"], "50000 → 443")
        self.assertEqual(result["length"], len(packet))
        self.assertEqual(result["timestamp"], self.build_timestamp(packet))

    def test_udp_packet_extracts_expected_fields(self):
        packet = (
            scapy.Ether()
            / scapy.IP(src="192.168.1.20", dst="8.8.8.8")
            / scapy.UDP(sport=53000, dport=53)
        )

        result = main.parse_packet(packet, self.local_ip)

        self.assertIsNotNone(result)
        self.assertEqual(result["protocol"], "UDP")
        self.assertEqual(result["source_port"], 53000)
        self.assertEqual(result["destination_port"], 53)
        self.assertEqual(result["Info"], "53000 → 53")
        self.assertEqual(result["direction"], "INBOUND")

    def test_icmp_echo_request(self):
        packet = (
            scapy.Ether()
            / scapy.IP(src="192.168.1.10", dst="8.8.8.8")
            / scapy.ICMP(type=8, code=0)
        )

        result = main.parse_packet(packet, self.local_ip)

        self.assertIsNotNone(result)
        self.assertEqual(result["protocol"], "ICMP")
        self.assertEqual(result["icmp_type"], 8)
        self.assertEqual(result["icmp_code"], 0)
        self.assertEqual(result["icmp_description"], "Echo Request")
        self.assertIn("Echo Request", result["Info"])

    def test_icmp_echo_reply(self):
        packet = (
            scapy.Ether()
            / scapy.IP(src="8.8.8.8", dst="192.168.1.10")
            / scapy.ICMP(type=0, code=0)
        )

        result = main.parse_packet(packet, self.local_ip)

        self.assertEqual(result["icmp_description"], "Echo Reply")
        self.assertEqual(result["direction"], "INBOUND")

    def test_unknown_icmp_type(self):
        packet = (
            scapy.Ether()
            / scapy.IP(src="192.168.1.10", dst="8.8.8.8")
            / scapy.ICMP(type=99, code=0)
        )

        result = main.parse_packet(packet, self.local_ip)

        self.assertEqual(result["icmp_description"], "Unknown ICMP Type")

    def test_non_ipv4_packet_returns_none(self):
        packet = scapy.Ether() / scapy.ARP()

        result = main.parse_packet(packet, self.local_ip)

        self.assertIsNone(result)

    def test_unsupported_ipv4_protocol(self):
        packet = (
            scapy.Ether()
            / scapy.IP(src="192.168.1.10", dst="8.8.8.8", proto=99)
            / scapy.Raw(load=b"test")
        )

        result = main.parse_packet(packet, self.local_ip)

        self.assertIsNotNone(result)
        self.assertNotIn("source_port", result)
        self.assertNotIn("destination_port", result)
        self.assertEqual(result["Info"], "N/A")

    def test_direction_is_outbound_when_source_matches_local_ip(self):
        packet = (
            scapy.IP(src=self.local_ip, dst="8.8.8.8")
            / scapy.TCP(sport=12345, dport=80)
        )

        result = main.parse_packet(packet, self.local_ip)

        self.assertEqual(result["direction"], "OUTBOUND")

    def test_direction_is_inbound_when_source_differs_from_local_ip(self):
        packet = (
            scapy.IP(src="8.8.8.8", dst=self.local_ip)
            / scapy.TCP(sport=443, dport=12345)
        )

        result = main.parse_packet(packet, self.local_ip)

        self.assertEqual(result["direction"], "INBOUND")


if __name__ == "__main__":
    unittest.main()
