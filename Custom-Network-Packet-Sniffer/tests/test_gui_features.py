
import json
import tempfile
import unittest
from pathlib import Path
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


class FakeTable:
    def __init__(self):
        self.rows = {}
        self.next_id = 0

    def insert(self, parent, position, values=()):
        self.next_id += 1
        row_id = f"row{self.next_id}"
        self.rows[row_id] = tuple(values)
        return row_id

    def get_children(self):
        return list(self.rows)

    def delete(self, row_id):
        self.rows.pop(row_id, None)

    def item(self, row_id, option=None, **kwargs):
        if "values" in kwargs:
            self.rows[row_id] = tuple(kwargs["values"])
    
        values = self.rows[row_id]
    
        if option == "values":
            return values
    
        return {"values": values}

    def exists(self, row_id):
        return row_id in self.rows


class FakeWindow:
    def __init__(self):
        self.lift_called = False
        self.destroy_called = False

    def winfo_exists(self):
        return not self.destroy_called

    def lift(self):
        self.lift_called = True

    def destroy(self):
        self.destroy_called = True

    def title(self, value):
        pass

    def geometry(self, value):
        pass

    def minsize(self, width, height):
        pass

    def protocol(self, name, callback):
        self.close_callback = callback


class FakeRoot:
    def __init__(self):
        self.scheduled = []

    def after(self, delay, callback):
        self.scheduled.append((delay, callback))


class ImmediateThread:
    def __init__(self, target, daemon=False):
        self.target = target
        self.daemon = daemon

    def start(self):
        self.target()


class GUIFeatureTests(unittest.TestCase):

    def setUp(self):
        self.original_packets = main.packets
        main.packets = []

        self.app = GUI.PacketSnifferGUI.__new__(
            GUI.PacketSnifferGUI
        )

        self.app.root = FakeRoot()
        self.app.is_capturing = True
        self.app.sniffer = None

        self.app.start_button = Mock()
        self.app.stop_button = Mock()
        self.app.interface_box = Mock()
        self.app.limit_box = Mock()
        self.app.capture_mode_box = Mock()

        self.app.capture_mode_var = FakeVar("Limited")
        self.app.status_var = FakeVar("Ready")

        self.app.packet_count_var = FakeVar("Packets: 0")
        self.app.protocol_stats_var = FakeVar("Protocols: —")
        self.app.capture_duration_var = FakeVar("Duration: —")
        self.app.packet_rate_var = FakeVar("Rate: —")

        self.app.packet_table = FakeTable()
        self.app.alerts_table = FakeTable()

        self.app.connections_window = None
        self.app.connections_table = None
        self.app.connection_rows = {}

        self.app.displayed_suspicious_alerts = set()
        self.app.displayed_scan_alerts = set()

    def tearDown(self):
        main.packets = self.original_packets

    # Capture stopping

    @patch("GUI.threading.Thread", ImmediateThread)
    def test_stop_capture_stops_running_sniffer(self):
        self.app.sniffer = Mock()
        self.app.sniffer.running = True
        self.app.finish_capture = Mock()

        self.app.stop_capture()

        self.app.sniffer.stop.assert_called_once()
        self.assertEqual(len(self.app.root.scheduled), 1)
        self.assertEqual(self.app.root.scheduled[0][0], 0)
        self.app.root.scheduled[0][1]()
        self.app.finish_capture.assert_called_once()

    @patch("GUI.threading.Thread", ImmediateThread)
    def test_stop_capture_when_sniffer_is_not_running(self):
        self.app.sniffer = Mock()
        self.app.sniffer.running = False
        self.app.finish_capture = Mock()

        self.app.stop_capture()

        self.app.sniffer.stop.assert_not_called()
        self.assertEqual(len(self.app.root.scheduled), 1)

    @patch("GUI.threading.Thread", ImmediateThread)
    def test_stop_capture_handles_sniffer_stop_error(self):
        self.app.sniffer = Mock()
        self.app.sniffer.running = True
        self.app.sniffer.stop.side_effect = RuntimeError("Stop failed")
        self.app.finish_capture = Mock()

        self.app.stop_capture()

        self.app.sniffer.stop.assert_called_once()
        self.assertEqual(len(self.app.root.scheduled), 1)

    @patch("GUI.threading.Thread")
    def test_stop_capture_does_nothing_when_not_capturing(
        self, thread_class
    ):
        self.app.is_capturing = False

        self.app.stop_capture()

        thread_class.assert_not_called()

    # Connection summaries

    def test_update_connections_view_returns_when_window_missing(self):
        self.app.connections_window = None
        self.app.update_connections_view()

        self.assertIsNone(self.app.connections_table)

    def test_update_connections_view_inserts_connections(self):
        self.app.connections_window = FakeWindow()
        self.app.connections_table = FakeTable()

        with patch(
            "GUI.main.connection_summaries",
            return_value={
                "10.0.0.1:5000 ↔ 10.0.0.2:80": 3
            }
        ):
            self.app.update_connections_view()

        self.assertEqual(len(self.app.connections_table.rows), 1)
        row = next(iter(self.app.connections_table.rows.values()))
        self.assertEqual(
            row,
            ("10.0.0.1:5000 ↔ 10.0.0.2:80", 3)
        )

    def test_update_connections_view_updates_existing_row(self):
        self.app.connections_window = FakeWindow()
        self.app.connections_table = FakeTable()

        connection = "10.0.0.1:5000 ↔ 10.0.0.2:80"
        row_id = self.app.connections_table.insert(
            "", "end", values=(connection, 2)
        )
        self.app.connection_rows[connection] = row_id

        with patch(
            "GUI.main.connection_summaries",
            return_value={connection: 7}
        ):
            self.app.update_connections_view()

        self.assertEqual(
            self.app.connections_table.rows[row_id],
            (connection, 7)
        )
        self.assertEqual(len(self.app.connections_table.rows), 1)

    def test_update_connections_view_removes_stale_rows(self):
        self.app.connections_window = FakeWindow()
        self.app.connections_table = FakeTable()

        old_connection = "10.0.0.1:5000 ↔ 10.0.0.2:80"
        row_id = self.app.connections_table.insert(
            "", "end", values=(old_connection, 2)
        )
        self.app.connection_rows[old_connection] = row_id

        with patch(
            "GUI.main.connection_summaries",
            return_value={}
        ):
            self.app.update_connections_view()

        self.assertEqual(len(self.app.connections_table.rows), 1)
        self.assertNotIn(old_connection, self.app.connection_rows)
        row = next(iter(self.app.connections_table.rows.values()))
        self.assertEqual(row, ("No TCP/UDP connections yet", 0))

    def test_update_connections_view_shows_empty_placeholder(self):
        self.app.connections_window = FakeWindow()
        self.app.connections_table = FakeTable()

        with patch(
            "GUI.main.connection_summaries",
            return_value={}
        ):
            self.app.update_connections_view()

        row = next(iter(self.app.connections_table.rows.values()))
        self.assertEqual(row, ("No TCP/UDP connections yet", 0))

    def test_close_connections_window_clears_references(self):
        window = FakeWindow()
        self.app.connections_window = window
        self.app.connections_table = FakeTable()

        self.app.close_connections_window()

        self.assertTrue(window.destroy_called)
        self.assertIsNone(self.app.connections_window)
        self.assertIsNone(self.app.connections_table)

    # Security alerts

    def test_security_alerts_insert_suspicious_port_alert(self):
        packet = {
            "packet_number": 1,
            "timestamp": "12/11/2026 10:00:00.000",
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2"
        }

        with patch(
            "GUI.main.detect_suspicious_ports",
            return_value=[{
                "packet": packet,
                "matched_port": 445,
                "port_role": "destination"
            }]
        ), patch(
            "GUI.main.detect_port_scans",
            return_value=[]
        ):
            self.app.update_security_alerts()

        self.assertEqual(len(self.app.alerts_table.rows), 1)
        row = next(iter(self.app.alerts_table.rows.values()))
        self.assertEqual(row[1], "Suspicious port")
        self.assertIn("Port 445", row[2])

    def test_security_alerts_do_not_duplicate_suspicious_alerts(self):
        packet = {
            "packet_number": 1,
            "timestamp": "12/11/2026 10:00:00.000",
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2"
        }

        suspicious = [{
            "packet": packet,
            "matched_port": 445,
            "port_role": "destination"
        }]

        with patch(
            "GUI.main.detect_suspicious_ports",
            return_value=suspicious
        ), patch(
            "GUI.main.detect_port_scans",
            return_value=[]
        ):
            self.app.update_security_alerts()
            self.app.update_security_alerts()

        self.assertEqual(len(self.app.alerts_table.rows), 1)

    def test_security_alerts_insert_port_scan_alert(self):
        scan = {
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
            "unique_ports": 5,
            "destination_ports": [21, 22, 23, 80, 443]
        }

        with patch(
            "GUI.main.detect_suspicious_ports",
            return_value=[]
        ), patch(
            "GUI.main.detect_port_scans",
            return_value=[scan]
        ):
            self.app.update_security_alerts()

        self.assertEqual(len(self.app.alerts_table.rows), 1)
        row = next(iter(self.app.alerts_table.rows.values()))
        self.assertEqual(row[1], "Possible port scan")
        self.assertIn("5 unique ports", row[2])

    def test_security_alerts_do_not_duplicate_scan_alerts(self):
        scan = {
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
            "unique_ports": 5,
            "destination_ports": [21, 22, 23, 80, 443]
        }

        with patch(
            "GUI.main.detect_suspicious_ports",
            return_value=[]
        ), patch(
            "GUI.main.detect_port_scans",
            return_value=[scan]
        ):
            self.app.update_security_alerts()
            self.app.update_security_alerts()

        self.assertEqual(len(self.app.alerts_table.rows), 1)

    # Saving captures

    @patch("GUI.messagebox.showwarning")
    def test_save_capture_without_packets(self, warning):
        result = self.app.save_capture()

        self.assertFalse(result)
        warning.assert_called_once()

    @patch("GUI.filedialog.asksaveasfilename", return_value="")
    def test_save_capture_when_dialog_cancelled(self, dialog):
        main.packets.append({"protocol": "TCP"})

        result = self.app.save_capture()

        self.assertFalse(result)
        dialog.assert_called_once()

    @patch("GUI.messagebox.showinfo")
    def test_save_capture_writes_valid_json(self, showinfo):
        main.packets.extend([
            {"protocol": "TCP", "source_ip": "10.0.0.1"},
            {"protocol": "UDP", "source_ip": "10.0.0.2"}
        ])

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.json"

            with patch(
                "GUI.filedialog.asksaveasfilename",
                return_value=str(path)
            ):
                result = self.app.save_capture()

            self.assertTrue(result)
            self.assertTrue(path.exists())

            with path.open(encoding="utf-8") as file:
                saved_data = json.load(file)

        self.assertEqual(saved_data, main.packets)
        showinfo.assert_called_once()

    @patch("GUI.messagebox.showerror")
    @patch("GUI.filedialog.asksaveasfilename", return_value="/invalid/path/capture.json")
    def test_save_capture_handles_file_write_error(
        self, dialog, showerror
    ):
        main.packets.append({"protocol": "TCP"})

        result = self.app.save_capture()

        self.assertFalse(result)
        showerror.assert_called_once()


if __name__ == "__main__":
    unittest.main()
