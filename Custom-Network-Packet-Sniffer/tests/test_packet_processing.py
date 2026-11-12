
import unittest

import scapy.all as scapy
import main


class PacketProcessingTests(unittest.TestCase):

    def setUp(self):
        self.original_packets = main.packets
        self.original_local_ip = main.local_ip

        main.packets = []
        main.local_ip = "192.168.1.10"

    def tearDown(self):
        main.packets = self.original_packets
        main.local_ip = self.original_local_ip

    def test_valid_packet_is_added_to_packet_list(self):
        packet = (
            scapy.IP(src="192.168.1.10", dst="8.8.8.8")
            / scapy.TCP(sport=50000, dport=443)
        )

        main.process_packet(packet)

        self.assertEqual(len(main.packets), 1)
        self.assertEqual(main.packets[0]["source_ip"], "192.168.1.10")

    def test_packet_number_is_assigned_correctly(self):
        packet = (
            scapy.IP(src="192.168.1.10", dst="8.8.8.8")
            / scapy.TCP()
        )

        main.process_packet(packet)

        self.assertEqual(main.packets[0]["packet_number"], 1)

    def test_packet_numbers_increase_sequentially(self):
        packet1 = (
            scapy.IP(src="192.168.1.10", dst="8.8.8.8")
            / scapy.TCP(sport=1000, dport=80)
        )
        packet2 = (
            scapy.IP(src="192.168.1.10", dst="1.1.1.1")
            / scapy.UDP(sport=2000, dport=53)
        )

        main.process_packet(packet1)
        main.process_packet(packet2)

        self.assertEqual(len(main.packets), 2)
        self.assertEqual(main.packets[0]["packet_number"], 1)
        self.assertEqual(main.packets[1]["packet_number"], 2)

    def test_non_ipv4_packet_is_not_added(self):
        packet = scapy.ARP()

        main.process_packet(packet)

        self.assertEqual(len(main.packets), 0)

    def test_protocol_statistics_counts_protocols(self):
        sample_packets = [
            {"protocol": "TCP"},
            {"protocol": "TCP"},
            {"protocol": "UDP"},
            {"protocol": "ICMP"},
            {"protocol": "UDP"},
        ]

        result = main.protocol_statistics(sample_packets)

        self.assertEqual(
            result,
            {"TCP": 2, "UDP": 2, "ICMP": 1}
        )

    def test_protocol_statistics_with_empty_list(self):
        result = main.protocol_statistics([])

        self.assertEqual(result, {})


if __name__ == "__main__":
    unittest.main()
