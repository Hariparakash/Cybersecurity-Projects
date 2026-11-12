
import unittest
from unittest.mock import patch

import main


class InterfaceDiscoveryTests(unittest.TestCase):

    @patch("main.scapy.get_if_addr")
    @patch("main.scapy.get_if_list")
    def test_returns_available_interfaces(self, mock_get_if_list, mock_get_if_addr):
        mock_get_if_list.return_value = ["eth0", "wlan0"]

        mock_get_if_addr.side_effect = [
            "192.168.1.10",
            "10.0.0.5"
        ]

        result = main.get_interfaces()

        expected = [
            {
                "interface": "eth0",
                "IP address": "192.168.1.10"
            },
            {
                "interface": "wlan0",
                "IP address": "10.0.0.5"
            }
        ]

        self.assertEqual(result, expected)

    @patch("main.scapy.get_if_list")
    def test_returns_empty_list_when_no_interfaces_exist(self, mock_get_if_list):
        mock_get_if_list.return_value = []

        result = main.get_interfaces()

        self.assertEqual(result, [])

    @patch("main.scapy.get_if_addr")
    @patch("main.scapy.get_if_list")
    def test_retrieves_ip_address_for_each_interface(
        self,
        mock_get_if_list,
        mock_get_if_addr
    ):
        mock_get_if_list.return_value = ["eth0", "wlan0"]

        mock_get_if_addr.side_effect = [
            "192.168.1.10",
            "10.0.0.5"
        ]

        main.get_interfaces()

        self.assertEqual(mock_get_if_addr.call_count, 2)
        mock_get_if_addr.assert_any_call("eth0")
        mock_get_if_addr.assert_any_call("wlan0")


if __name__ == "__main__":
    unittest.main()
