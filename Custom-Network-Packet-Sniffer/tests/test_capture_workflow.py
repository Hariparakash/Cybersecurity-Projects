
import unittest
from unittest.mock import patch

import main


class CaptureWorkflowTests(unittest.TestCase):

    def setUp(self):
        self.original_packets = main.packets
        self.original_local_ip = main.local_ip

        main.packets = []
        main.local_ip = None

        self.interfaces = [
            {
                "interface": "eth0",
                "IP address": "192.168.1.10"
            }
        ]

    def tearDown(self):
        main.packets = self.original_packets
        main.local_ip = self.original_local_ip

    @patch("main.get_interfaces")
    @patch("builtins.input")
    def test_invalid_interface_selection_exits(
        self, mock_input, mock_interfaces
    ):
        mock_interfaces.return_value = self.interfaces
        mock_input.return_value = "invalid0"

        with self.assertRaises(SystemExit) as error:
            main.main()

        self.assertEqual(error.exception.code, 1)

    @patch("main.scapy.sniff")
    @patch("main.get_interfaces")
    @patch("builtins.input")
    def test_valid_interface_and_packet_count_start_capture(
        self, mock_input, mock_interfaces, mock_sniff
    ):
        mock_interfaces.return_value = self.interfaces
        mock_input.side_effect = ["eth0", "5"]

        main.main()

        mock_sniff.assert_called_once()

        kwargs = mock_sniff.call_args.kwargs

        self.assertEqual(kwargs["iface"], "eth0")
        self.assertEqual(kwargs["count"], 5)
        self.assertFalse(kwargs["store"])
        self.assertEqual(kwargs["prn"], main.process_packet)

        self.assertEqual(main.local_ip, "192.168.1.10")

    @patch("main.scapy.sniff")
    @patch("main.get_interfaces")
    @patch("builtins.input")
    def test_invalid_packet_count_is_rejected(
        self, mock_input, mock_interfaces, mock_sniff
    ):
        mock_interfaces.return_value = self.interfaces

        mock_input.side_effect = [
            "eth0",
            "abc",
            "0",
            "10001",
            "5"
        ]

        main.main()

        mock_sniff.assert_called_once()
        self.assertEqual(mock_sniff.call_args.kwargs["count"], 5)

    @patch("main.get_interfaces")
    def test_no_interfaces_causes_exit(self, mock_interfaces):
        mock_interfaces.return_value = []

        with self.assertRaises(SystemExit) as error:
            main.main()

        self.assertEqual(error.exception.code, 1)

    @patch("main.get_interfaces", side_effect=OSError("interface error"))
    def test_interface_discovery_os_error_causes_exit(self, mock_interfaces):
        with self.assertRaises(SystemExit) as error:
            main.main()

        self.assertEqual(error.exception.code, 1)

    @patch("main.scapy.sniff", side_effect=KeyboardInterrupt)
    @patch("main.get_interfaces")
    @patch("builtins.input")
    def test_keyboard_interrupt_is_handled(
        self, mock_input, mock_interfaces, mock_sniff
    ):
        mock_interfaces.return_value = self.interfaces
        mock_input.side_effect = ["eth0", "5"]

        # KeyboardInterrupt should be handled and analysis should continue.
        main.main()

        mock_sniff.assert_called_once()

    @patch("main.scapy.sniff", side_effect=OSError("capture failed"))
    @patch("main.get_interfaces")
    @patch("builtins.input")
    def test_capture_os_error_causes_exit(
        self, mock_input, mock_interfaces, mock_sniff
    ):
        mock_interfaces.return_value = self.interfaces
        mock_input.side_effect = ["eth0", "5"]

        with self.assertRaises(SystemExit) as error:
            main.main()

        self.assertEqual(error.exception.code, 1)

    @patch("main.scapy.sniff", side_effect=RuntimeError("capture failed"))
    @patch("main.get_interfaces")
    @patch("builtins.input")
    def test_capture_runtime_error_causes_exit(
        self, mock_input, mock_interfaces, mock_sniff
    ):
        mock_interfaces.return_value = self.interfaces
        mock_input.side_effect = ["eth0", "5"]

        with self.assertRaises(SystemExit) as error:
            main.main()

        self.assertEqual(error.exception.code, 1)

    @patch("main.scapy.sniff", side_effect=ValueError("invalid capture"))
    @patch("main.get_interfaces")
    @patch("builtins.input")
    def test_capture_value_error_causes_exit(
        self, mock_input, mock_interfaces, mock_sniff
    ):
        mock_interfaces.return_value = self.interfaces
        mock_input.side_effect = ["eth0", "5"]

        with self.assertRaises(SystemExit) as error:
            main.main()

        self.assertEqual(error.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
