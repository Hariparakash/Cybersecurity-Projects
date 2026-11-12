
import unittest
from unittest.mock import Mock, patch

import GUI
import main


class FakeVar:
    def __init__(self, value=""):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


class FakeWidget:
    def __init__(self):
        self.options = {}
        self.rows = {}
        self.next_id = 0

    def config(self, **kwargs):
        self.options.update(kwargs)

    def insert(self, parent, position, values=()):
        self.next_id += 1
        row_id = f"row{self.next_id}"
        self.rows[row_id] = tuple(values)
        return row_id

    def get_children(self):
        return list(self.rows)

    def delete(self, item):
        self.rows.pop(item, None)

    def item(self, item, option=None):
        values = self.rows[item]
        if option == "values":
            return {"values": values}
        return {"values": values}

    def exists(self, item):
        return item in self.rows


class FakeRoot:
    def __init__(self):
        self.scheduled = []

    def after(self, delay, callback):
        self.scheduled.append((delay, callback))


class FakeSniffer:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.running = False
        self.started = False
        self.stopped = False

    def start(self):
        self.started = True
        self.running = True

    def stop(self):
        self.stopped = True
        self.running = False


class GUICaptureTests(unittest.TestCase):

    def setUp(self):
        self.original_packets = main.packets
        self.original_local_ip = main.local_ip

        main.packets = []
        main.local_ip = None
        main.capture_stop_event.clear()

        self.app = GUI.PacketSnifferGUI.__new__(
            GUI.PacketSnifferGUI
        )

        self.app.root = FakeRoot()

        self.app.is_capturing = False
        self.app.sniffer = None
        self.app.displayed_packets = 0

        self.app.capture_start_time = None
        self.app.capture_end_time = None

        self.app.interfaces = {
            "eth0 (192.168.1.10)": {
                "interface": "eth0",
                "IP address": "192.168.1.10"
            },
            "lo (127.0.0.1)": {
                "interface": "lo",
                "IP address": "127.0.0.1"
            }
        }

        self.app.interface_var = FakeVar(
            "eth0 (192.168.1.10)"
        )
        self.app.capture_mode_var = FakeVar("Limited")
        self.app.limit_var = FakeVar("50")

        self.app.start_button = FakeWidget()
        self.app.stop_button = FakeWidget()
        self.app.interface_box = FakeWidget()
        self.app.limit_box = FakeWidget()
        self.app.capture_mode_box = FakeWidget()

        self.app.status_var = FakeVar("Ready")
        self.app.packet_count_var = FakeVar("Packets: 0")
        self.app.protocol_stats_var = FakeVar("Protocols: —")
        self.app.capture_duration_var = FakeVar("Duration: —")
        self.app.packet_rate_var = FakeVar("Rate: —")

        self.app.packet_table = FakeWidget()
        self.app.alerts_table = FakeWidget()

        self.app.connections_window = None
        self.app.connections_table = None
        self.app.connection_rows = {}

        self.app.displayed_suspicious_alerts = set()
        self.app.displayed_scan_alerts = set()

    def tearDown(self):
        main.packets = self.original_packets
        main.local_ip = self.original_local_ip
        main.capture_stop_event.clear()

    @patch("GUI.messagebox.showwarning")
    def test_start_capture_without_interface(self, warning):
        self.app.interface_var.set("")

        self.app.start_capture()

        warning.assert_called_once()
        self.assertFalse(self.app.is_capturing)

    @patch("GUI.messagebox.showwarning")
    def test_start_capture_with_unknown_interface(self, warning):
        self.app.interface_var.set("unknown")

        self.app.start_capture()

        warning.assert_called_once()
        self.assertFalse(self.app.is_capturing)

    @patch("GUI.messagebox.showwarning")
    def test_start_capture_with_invalid_packet_limit(self, warning):
        self.app.limit_var.set("not-a-number")

        self.app.start_capture()

        warning.assert_called_once()
        self.assertFalse(self.app.is_capturing)

    @patch("GUI.messagebox.showwarning")
    def test_start_capture_with_zero_packet_limit(self, warning):
        self.app.limit_var.set("0")

        self.app.start_capture()

        warning.assert_called_once()
        self.assertFalse(self.app.is_capturing)

    @patch("GUI.messagebox.showwarning")
    def test_start_capture_when_interface_has_no_ip(self, warning):
        self.app.interfaces["eth0 (No IP)"] = {
            "interface": "eth0",
            "IP address": "No IP"
        }
        self.app.interface_var.set("eth0 (No IP)")

        self.app.start_capture()

        warning.assert_called_once()
        self.assertFalse(self.app.is_capturing)

    @patch("GUI.AsyncSniffer", FakeSniffer)
    def test_limited_capture_starts_with_selected_limit(self):
        self.app.start_capture()

        self.assertTrue(self.app.is_capturing)
        self.assertTrue(self.app.sniffer.started)
        self.assertEqual(self.app.sniffer.kwargs["iface"], "eth0")
        self.assertEqual(self.app.sniffer.kwargs["count"], 50)
        self.assertFalse(self.app.sniffer.kwargs["store"])
        self.assertEqual(main.local_ip, "192.168.1.10")
        self.assertEqual(len(self.app.root.scheduled), 1)

    @patch("GUI.AsyncSniffer", FakeSniffer)
    def test_continuous_capture_uses_zero_packet_limit(self):
        self.app.capture_mode_var.set("Continuous")

        self.app.start_capture()

        self.assertTrue(self.app.is_capturing)
        self.assertEqual(self.app.sniffer.kwargs["count"], 0)

    @patch("GUI.AsyncSniffer", FakeSniffer)
    def test_start_capture_does_not_start_twice(self):
        self.app.is_capturing = True

        self.app.start_capture()

        self.assertIsNone(self.app.sniffer)

    @patch("GUI.AsyncSniffer")
    @patch("GUI.messagebox.showerror")
    def test_sniffer_start_failure_restores_capture_state(
        self, showerror, sniffer_class
    ):
        sniffer_class.return_value.start.side_effect = RuntimeError(
            "Capture failed"
        )

        self.app.refresh_packets = Mock()
        self.app.update_live_dashboard = Mock()
        self.app.update_connections_view = Mock()

        self.app.start_capture()

        self.assertFalse(self.app.is_capturing)
        showerror.assert_called_once()

    def test_refresh_packets_inserts_new_packet(self):
        main.packets.append({
            "timestamp": "12/11/2026 10:00:00.000",
            "source_ip": "192.168.1.10",
            "destination_ip": "8.8.8.8",
            "protocol": "UDP",
            "direction": "OUTBOUND",
            "length": 60,
            "Info": "50000 → 53"
        })

        self.app.update_live_dashboard = Mock()
        self.app.update_security_alerts = Mock()

        self.app.refresh_packets()

        self.assertEqual(len(self.app.packet_table.rows), 1)
        self.assertEqual(self.app.displayed_packets, 1)

    def test_refresh_packets_does_not_insert_same_packet_twice(self):
        main.packets.append({
            "timestamp": "12/11/2026 10:00:00.000",
            "source_ip": "192.168.1.10",
            "destination_ip": "8.8.8.8",
            "protocol": "UDP",
            "direction": "OUTBOUND",
            "length": 60,
            "Info": "50000 → 53"
        })

        self.app.update_live_dashboard = Mock()
        self.app.update_security_alerts = Mock()

        self.app.refresh_packets()
        self.app.refresh_packets()

        self.assertEqual(len(self.app.packet_table.rows), 1)
        self.assertEqual(self.app.displayed_packets, 1)

    def test_refresh_packets_schedules_next_refresh_while_capturing(self):
        self.app.is_capturing = True
        self.app.sniffer = Mock()
        self.app.sniffer.running = True

        self.app.update_live_dashboard = Mock()
        self.app.update_security_alerts = Mock()

        self.app.refresh_packets()

        self.assertEqual(len(self.app.root.scheduled), 1)
        self.assertEqual(self.app.root.scheduled[0][0], 100)

    def test_update_live_dashboard_with_no_packets(self):
        self.app.update_live_dashboard()

        self.assertEqual(
            self.app.packet_count_var.get(),
            "Packets: 0"
        )
        self.assertEqual(
            self.app.protocol_stats_var.get(),
            "Protocols: —"
        )

    def test_update_live_dashboard_counts_protocols(self):
        main.packets.extend([
            {"protocol": "TCP"},
            {"protocol": "TCP"},
            {"protocol": "UDP"}
        ])

        self.app.update_live_dashboard()

        self.assertEqual(
            self.app.packet_count_var.get(),
            "Packets: 3"
        )
        self.assertEqual(
            self.app.protocol_stats_var.get(),
            "Protocols: TCP: 2, UDP: 1"
        )

    def test_finish_capture_restores_controls(self):
        self.app.is_capturing = True
        self.app.refresh_packets = Mock()
        self.app.update_live_dashboard = Mock()
        self.app.update_connections_view = Mock()

        self.app.finish_capture()

        self.assertFalse(self.app.is_capturing)
        self.assertEqual(
            self.app.start_button.options["state"],
            "normal"
        )
        self.assertEqual(
            self.app.stop_button.options["state"],
            "disabled"
        )
        self.assertEqual(
            self.app.status_var.get(),
            "Capture stopped. Parsed IPv4 packets: 0"
        )

    def test_finish_continuous_capture_keeps_limit_disabled(self):
        self.app.capture_mode_var.set("Continuous")
        self.app.refresh_packets = Mock()
        self.app.update_live_dashboard = Mock()
        self.app.update_connections_view = Mock()

        self.app.finish_capture()

        self.assertEqual(
            self.app.limit_box.options["state"],
            "disabled"
        )


if __name__ == "__main__":
    unittest.main()
