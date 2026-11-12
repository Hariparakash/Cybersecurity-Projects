
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

    def __setitem__(self, key, value):
        self.options[key] = value

    def current(self, index):
        self.options["current"] = index

    def insert(self, parent, position, values=()):
        self.next_id += 1
        row_id = f"row{self.next_id}"
        self.rows[row_id] = tuple(values)
        return row_id

    def get_children(self):
        return list(self.rows)

    def delete(self, item):
        self.rows.pop(item, None)

    def yview(self, *args):
        pass

    def configure(self, **kwargs):
        self.options.update(kwargs)

    def pack(self, **kwargs):
        pass

    def heading(self, column, **kwargs):
        pass

    def column(self, column, **kwargs):
        pass

    def set(self, *args):
        pass


class FakeRoot:
    def __init__(self):
        self.scheduled = []

    def after(self, delay, callback):
        self.scheduled.append((delay, callback))


class FakeWindow:
    def __init__(self, *args, **kwargs):
        self.exists = True
        self.lift_called = False
        self.options = {}

    def title(self, value):
        self.options["title"] = value

    def geometry(self, value):
        self.options["geometry"] = value

    def minsize(self, width, height):
        self.options["minsize"] = (width, height)

    def protocol(self, name, callback):
        self.options["protocol"] = (name, callback)

    def winfo_exists(self):
        return self.exists

    def lift(self):
        self.lift_called = True


class FakeSniffer:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.running = False
        self.started = False

    def start(self):
        self.started = True
        self.running = True


class GUIRemainingTests(unittest.TestCase):

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

        self.app.interfaces = {"eth0 (192.168.1.10)": {"interface": "eth0","IP address": "192.168.1.10"}}
        self.app.interface_box = FakeWidget()

        self.app.interface_var = FakeVar(
            "eth0 (192.168.1.10)"
        )
        self.app.capture_mode_var = FakeVar("Limited")
        self.app.limit_var = FakeVar("50")

        self.app.is_capturing = False
        self.app.sniffer = None
        self.app.displayed_packets = 0

        self.app.capture_start_time = None
        self.app.capture_end_time = None
        self.app.local_ip = None

        self.app.start_button = FakeWidget()
        self.app.stop_button = FakeWidget()
        self.app.limit_box = FakeWidget()
        self.app.capture_mode_box = FakeWidget()

        self.app.status_var = FakeVar("Ready")
        self.app.packet_count_var = FakeVar("Packets: 0")
        self.app.protocol_stats_var = FakeVar("Protocols: —")
        self.app.capture_duration_var = FakeVar("Duration: —")
        self.app.packet_rate_var = FakeVar("Rate: —")

        self.app.packet_table = FakeWidget()
        self.app.alerts_table = FakeWidget()
        self.app.connections_table = FakeWidget()

        self.app.connections_window = None
        self.app.connection_rows = {}

        self.app.displayed_suspicious_alerts = set()
        self.app.displayed_scan_alerts = set()

    def tearDown(self):
        main.packets = self.original_packets
        main.local_ip = self.original_local_ip
        main.capture_stop_event.clear()

    # --------------------------------------------------
    # Interface loading
    # --------------------------------------------------

    @patch("GUI.main.get_interfaces")
    def test_load_interfaces_populates_dropdown(
        self, get_interfaces
    ):
        get_interfaces.return_value = [
            {
                "interface": "eth0",
                "IP address": "192.168.1.10"
            },
            {
                "interface": "lo",
                "IP address": "127.0.0.1"
            }
        ]

        self.app.load_interfaces()

        self.assertEqual(
            self.app.interface_box.options["values"],
            [
                "eth0 (192.168.1.10)",
                "lo (127.0.0.1)"
            ]
        )

        self.assertEqual(
            self.app.interface_box.options["current"],
            0
        )

        self.assertEqual(len(self.app.interfaces), 2)

    @patch("GUI.main.get_interfaces", return_value=[])
    def test_load_interfaces_handles_empty_result(
        self, get_interfaces
    ):
        self.app.load_interfaces()

        self.assertEqual(
            self.app.status_var.get(),
            "No network interfaces found."
        )

        self.assertEqual(
            self.app.interface_box.options["values"],
            []
        )

    @patch("GUI.messagebox.showerror")
    @patch(
        "GUI.main.get_interfaces",
        side_effect=OSError("Interface discovery failed")
    )
    def test_load_interfaces_handles_discovery_error(
        self, get_interfaces, showerror
    ):
        self.app.load_interfaces()

        showerror.assert_called_once()
        self.assertEqual(
            showerror.call_args.args[0],
            "Interface Error"
        )

    # --------------------------------------------------
    # Capture mode
    # --------------------------------------------------

    def test_continuous_mode_disables_packet_limit(self):
        self.app.capture_mode_var.set("Continuous")

        self.app.on_capture_mode_change()

        self.assertEqual(
            self.app.limit_box.options["state"],
            "disabled"
        )

    def test_limited_mode_enables_packet_limit(self):
        self.app.capture_mode_var.set("Limited")

        self.app.on_capture_mode_change()

        self.assertEqual(
            self.app.limit_box.options["state"],
            "readonly"
        )

    # --------------------------------------------------
    # Connection window
    # --------------------------------------------------

    @patch("GUI.ttk.Scrollbar")
    @patch("GUI.ttk.Treeview")
    @patch("GUI.tk.Toplevel")
    def test_show_connections_creates_window(
        self, toplevel, treeview, scrollbar
    ):
        window = FakeWindow()
        table = FakeWidget()
        scroll = FakeWidget()

        toplevel.return_value = window
        treeview.return_value = table
        scrollbar.return_value = scroll

        self.app.update_connections_view = Mock()

        self.app.show_connections()

        toplevel.assert_called_once_with(self.app.root)
        treeview.assert_called_once()
        scrollbar.assert_called_once()

        self.assertIs(
            self.app.connections_window,
            window
        )

        self.assertIs(
            self.app.connections_table,
            table
        )

        self.app.update_connections_view.assert_called_once()

    def test_show_connections_reuses_existing_window(self):
        window = FakeWindow()
        self.app.connections_window = window

        self.app.update_connections_view = Mock()

        with patch("GUI.tk.Toplevel") as toplevel:
            self.app.show_connections()

        toplevel.assert_not_called()
        self.assertTrue(window.lift_called)

        self.app.update_connections_view.assert_called_once()

    # --------------------------------------------------
    # Refresh after capture stops
    # --------------------------------------------------

    def test_refresh_finishes_when_sniffer_stops(self):
        self.app.is_capturing = True

        self.app.sniffer = Mock()
        self.app.sniffer.running = False

        self.app.update_live_dashboard = Mock()
        self.app.update_security_alerts = Mock()
        self.app.finish_capture = Mock()

        self.app.refresh_packets()

        self.app.finish_capture.assert_called_once()

        self.assertEqual(
            self.app.root.scheduled,
            []
        )

    # --------------------------------------------------
    # Previous capture decisions
    # --------------------------------------------------

    @patch("GUI.messagebox.askyesnocancel", return_value=None)
    @patch("GUI.AsyncSniffer", FakeSniffer)
    def test_cancel_keeps_previous_capture(
        self, ask_dialog
    ):
        previous_packet = {"protocol": "TCP"}
        main.packets.append(previous_packet)

        self.app.start_capture()

        self.assertEqual(
            main.packets,
            [previous_packet]
        )

        self.assertFalse(self.app.is_capturing)
        ask_dialog.assert_called_once()

    @patch("GUI.messagebox.askyesnocancel", return_value=True)
    @patch("GUI.AsyncSniffer", FakeSniffer)
    def test_save_failure_aborts_new_capture(
        self, ask_dialog
    ):
        main.packets.append({"protocol": "TCP"})

        self.app.save_capture = Mock(return_value=False)

        self.app.start_capture()

        self.app.save_capture.assert_called_once()

        self.assertEqual(len(main.packets), 1)
        self.assertFalse(self.app.is_capturing)

    @patch("GUI.messagebox.askyesnocancel", return_value=False)
    @patch("GUI.AsyncSniffer", FakeSniffer)
    def test_discard_clears_previous_capture_before_start(
        self, ask_dialog
    ):
        main.packets.append({"protocol": "TCP"})

        self.app.packet_table.insert(
            "", "end", values=("old packet",)
        )
        self.app.alerts_table.insert(
            "", "end", values=("old alert",)
        )
        self.app.connections_table.insert(
            "", "end", values=("old connection",)
        )

        self.app.connection_rows["old"] = "row1"
        self.app.displayed_suspicious_alerts.add(
            ("old", 445, "destination")
        )
        self.app.displayed_scan_alerts.add(
            ("192.168.1.10", "192.168.1.20")
        )

        self.app.start_capture()

        self.assertTrue(self.app.is_capturing)
        self.assertTrue(self.app.sniffer.started)

        self.assertEqual(main.packets, [])
        self.assertEqual(self.app.displayed_packets, 0)

        self.assertEqual(self.app.packet_table.get_children(), [])
        self.assertEqual(self.app.alerts_table.get_children(), [])
        self.assertEqual(
            self.app.connections_table.get_children(),
            []
        )

        self.assertEqual(self.app.connection_rows, {})
        self.assertEqual(
            self.app.displayed_suspicious_alerts,
            set()
        )
        self.assertEqual(
            self.app.displayed_scan_alerts,
            set()
        )

        self.assertEqual(main.local_ip, "192.168.1.10")
        self.assertEqual(
            len(self.app.root.scheduled),
            1
        )

    @patch("GUI.messagebox.askyesnocancel", return_value=True)
    @patch("GUI.AsyncSniffer", FakeSniffer)
    def test_successful_save_allows_new_capture(
        self, ask_dialog
    ):
        main.packets.append({"protocol": "TCP"})

        self.app.save_capture = Mock(return_value=True)

        self.app.start_capture()

        self.app.save_capture.assert_called_once()

        self.assertTrue(self.app.is_capturing)
        self.assertTrue(self.app.sniffer.started)
        self.assertEqual(main.packets, [])


if __name__ == "__main__":
    unittest.main()
