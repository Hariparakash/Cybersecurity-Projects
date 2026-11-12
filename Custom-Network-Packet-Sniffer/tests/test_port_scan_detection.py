
import unittest
from datetime import datetime

import main


class PortScanDetectionTests(unittest.TestCase):

    def setUp(self):
        self.original_threshold = main.scan_threshold
        self.original_time_window = main.scan_time_window_seconds

        main.scan_threshold = 3
        main.scan_time_window_seconds = 10

    def tearDown(self):
        main.scan_threshold = self.original_threshold
        main.scan_time_window_seconds = self.original_time_window

    def make_timestamp(self, seconds):
        return datetime.fromtimestamp(
            1700000000 + seconds
        ).strftime("%d/%m/%Y %H:%M:%S.%f")[:-3]

    def make_packet(
        self,
        destination_port,
        seconds,
        source_ip="192.168.1.10",
        destination_ip="192.168.1.20",
        protocol="TCP",
        direction="OUTBOUND"
    ):
        return {
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "destination_port": destination_port,
            "protocol": protocol,
            "direction": direction,
            "timestamp": self.make_timestamp(seconds)
        }

    def test_three_unique_ports_within_window_trigger_alert(self):
        packets = [
            self.make_packet(22, 0),
            self.make_packet(23, 2),
            self.make_packet(24, 4)
        ]

        result = main.detect_port_scans(packets)

        self.assertEqual(len(result), 1)
        self.assertEqual(
            result[0]["destination_ports"],
            [22, 23, 24]
        )

    def test_fewer_than_threshold_ports_do_not_trigger_alert(self):
        packets = [
            self.make_packet(22, 0),
            self.make_packet(23, 2)
        ]

        result = main.detect_port_scans(packets)

        self.assertEqual(result, [])

    def test_ports_outside_time_window_do_not_trigger_alert(self):
        packets = [
            self.make_packet(22, 0),
            self.make_packet(23, 20),
            self.make_packet(24, 21)
        ]

        result = main.detect_port_scans(packets)

        self.assertEqual(result, [])

    def test_repeated_destination_ports_do_not_count_as_unique_ports(self):
        packets = [
            self.make_packet(22, 0),
            self.make_packet(22, 1),
            self.make_packet(22, 2),
            self.make_packet(22, 3)
        ]

        result = main.detect_port_scans(packets)

        self.assertEqual(result, [])

    def test_inbound_packets_are_ignored(self):
        packets = [
            self.make_packet(22, 0, direction="INBOUND"),
            self.make_packet(23, 1, direction="INBOUND"),
            self.make_packet(24, 2, direction="INBOUND")
        ]

        result = main.detect_port_scans(packets)

        self.assertEqual(result, [])

    def test_icmp_packets_are_ignored(self):
        packets = [
            self.make_packet(22, 0, protocol="ICMP"),
            self.make_packet(23, 1, protocol="ICMP"),
            self.make_packet(24, 2, protocol="ICMP")
        ]

        result = main.detect_port_scans(packets)

        self.assertEqual(result, [])

    def test_different_source_destination_pairs_are_separate(self):
        packets = [
            self.make_packet(
                22, 0,
                source_ip="192.168.1.10",
                destination_ip="192.168.1.20"
            ),
            self.make_packet(
                23, 1,
                source_ip="192.168.1.11",
                destination_ip="192.168.1.20"
            ),
            self.make_packet(
                24, 2,
                source_ip="192.168.1.12",
                destination_ip="192.168.1.20"
            )
        ]

        result = main.detect_port_scans(packets)

        self.assertEqual(result, [])

    def test_udp_port_activity_is_considered(self):
        packets = [
            self.make_packet(53, 0, protocol="UDP"),
            self.make_packet(67, 1, protocol="UDP"),
            self.make_packet(123, 2, protocol="UDP")
        ]

        result = main.detect_port_scans(packets)

        self.assertEqual(len(result), 1)

    def test_invalid_timestamps_are_ignored(self):
        packets = [
            self.make_packet(22, 0),
            self.make_packet(23, 1),
            self.make_packet(24, 2)
        ]

        packets[0]["timestamp"] = "invalid timestamp"

        result = main.detect_port_scans(packets)

        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
