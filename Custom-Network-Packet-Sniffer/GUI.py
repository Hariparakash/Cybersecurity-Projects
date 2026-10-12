
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import main
from scapy.all import AsyncSniffer
from datetime import datetime
import json
from tkinter import filedialog


class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Custom Network Packet Sniffer & Analyzer")
        self.root.geometry("1100x650")
        self.root.minsize(850, 500)

        self.capture_thread = None
        self.is_capturing = False
        self.sniffer = None
        self.displayed_packets = 0
        self.capture_start_time = None
        self.capture_end_time = None
        self.connections_window = None
        self.connections_table = None
        self.connection_rows = {}
        self.displayed_suspicious_alerts = set()
        self.displayed_scan_alerts = set()

        self.create_widgets()
        self.load_interfaces()

    def create_widgets(self):
        # Main heading
        heading = ttk.Label(
            self.root,
            text="Network Packet Sniffer & Analyzer",
            font=("Arial", 18, "bold")
        )
        heading.pack(pady=12)

        # Capture controls
        controls = ttk.Frame(self.root, padding=10)
        controls.pack(fill="x")

        ttk.Label(controls, text="Network interface:").pack(side="left")


        ttk.Label(controls, text="Mode:").pack(side="left", padx=(8, 0))

        self.capture_mode_var = tk.StringVar(value="Limited")
        self.capture_mode_box = ttk.Combobox(
            controls,
            textvariable=self.capture_mode_var,
            values=["Limited", "Continuous"],
            state="readonly",
            width=12
        )
        self.capture_mode_box.pack(side="left", padx=6)
        self.capture_mode_box.bind(
            "<<ComboboxSelected>>", self.on_capture_mode_change
        )


        self.interface_var = tk.StringVar()
        self.interface_box = ttk.Combobox(
            controls,
            textvariable=self.interface_var,
            state="readonly",
            width=25
        )
        self.interface_box.pack(side="left", padx=8)

        ttk.Label(controls, text="Packet limit:").pack(side="left", padx=(12, 0))

        self.limit_var = tk.StringVar(value="100")
        self.limit_box = ttk.Combobox(
            controls,
            textvariable=self.limit_var,
            values=["10", "50", "100", "500", "1000"],
            state="readonly",
            width=8
        )
        self.limit_box.pack(side="left", padx=8)

        self.start_button = ttk.Button(
            controls, text="Start Capture", command=self.start_capture
        )
        self.start_button.pack(side="left", padx=8)

        self.stop_button = ttk.Button(
            controls, text="Stop Capture", command=self.stop_capture,
            state="disabled"
        )
        self.stop_button.pack(side="left", padx=4)

        # Status
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(
            self.root, textvariable=self.status_var, padding=(12, 4)
        ).pack(anchor="w")

        # Packet table
        
        # Packet table
        table_frame = ttk.Frame(self.root, padding=10)
        table_frame.pack(fill="both", expand=True)

        columns = (
            "number", "timestamp", "source", "destination",
            "protocol", "direction", "length", "info"
        )

        self.packet_table = ttk.Treeview(
            table_frame, columns=columns, show="headings"
        )

        headings = {
            "number": "No.",
            "timestamp": "Timestamp",
            "source": "Source IP",
            "destination": "Destination IP",
            "protocol": "Protocol",
            "direction": "Direction",
            "length": "Length",
            "info": "Packet Details"
        }

        widths = {
            "number": 50,
            "timestamp": 175,
            "source": 125,
            "destination": 125,
            "protocol": 75,
            "direction": 100,
            "length": 65,
            "info": 220
        }

        for column in columns:
            self.packet_table.heading(column, text=headings[column])
            self.packet_table.column(
                column, width=widths[column], minwidth=50
            )

        scrollbar = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.packet_table.yview
        )
        self.packet_table.configure(yscrollcommand=scrollbar.set)

        self.packet_table.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")


        # Security alerts panel
        alerts_frame = ttk.LabelFrame(
            self.root, text="Security Alerts", padding=6
        )
        alerts_frame.pack(fill="x", padx=10, pady=(0, 10))

        alert_columns = ("time", "type", "details")

        self.alerts_table = ttk.Treeview(
            alerts_frame,
            columns=alert_columns,
            show="headings",
            height=3
        )

        self.alerts_table.heading("time", text="Time")
        self.alerts_table.heading("type", text="Alert Type")
        self.alerts_table.heading("details", text="Details")

        
        self.alerts_table.column(
            "time", width=175, minwidth=175, stretch=False
        )
        self.alerts_table.column(
            "type", width=150, minwidth=120
        )
        self.alerts_table.column(
            "details", width=650, minwidth=250, stretch=True
        )


        self.alerts_table.pack(fill="x", expand=True)


        # Analysis dashboard
        dashboard = ttk.LabelFrame(
            self.root, text="Capture Analysis", padding=10
        )
        dashboard.pack(fill="x", padx=10, pady=(0, 10))


        # Connection analysis button
        self.connections_button = ttk.Button(
            dashboard,
            text="View Connections",
            command=self.show_connections
        )
        self.connections_button.pack(side="right", padx=8)

        self.save_button = ttk.Button(
            dashboard,
            text="Save Capture",
            command=self.save_capture
        )
        self.save_button.pack(side="right", padx=8)


        self.packet_count_var = tk.StringVar(value="Packets: 0")
        self.protocol_stats_var = tk.StringVar(value="Protocols: —")
        self.capture_duration_var = tk.StringVar(value="Duration: —")
        self.packet_rate_var = tk.StringVar(value="Rate: —")

        ttk.Label(
            dashboard, textvariable=self.packet_count_var
        ).pack(side="left", padx=8)

        ttk.Label(
            dashboard, textvariable=self.protocol_stats_var
        ).pack(side="left", padx=8)

        ttk.Label(
            dashboard, textvariable=self.capture_duration_var
        ).pack(side="left", padx=8)

        ttk.Label(
            dashboard, textvariable=self.packet_rate_var
        ).pack(side="left", padx=8)



    def load_interfaces(self):
        try:
            interfaces = main.get_interfaces()
            self.interfaces = {}

            for item in interfaces:
                name = item["interface"]
                address = item.get("IP address", "No IP")
                display_name = f"{name} ({address})"
                self.interfaces[display_name] = item

            self.interface_box["values"] = list(self.interfaces.keys())

            if self.interfaces:
                self.interface_box.current(0)
            else:
                self.status_var.set("No network interfaces found.")

        except Exception as error:
            messagebox.showerror(
                "Interface Error",
                f"Could not load network interfaces:\n{error}"
            )



    def on_capture_mode_change(self, event=None):
        if self.capture_mode_var.get() == "Continuous":
            self.limit_box.config(state="disabled")
        else:
            self.limit_box.config(state="readonly")

    
    def start_capture(self):
        if self.is_capturing:
            return

        # Ask what to do with the previous capture before clearing it.
        if main.packets:
            choice = messagebox.askyesnocancel(
                "Previous Capture",
                "The current capture contains "
                f"{len(main.packets)} packets.\n\n"
                "Do you want to save the current results "
                "before starting a new capture?\n\n"
                "Yes = Save first\n"
                "No = Discard current results\n"
                "Cancel = Keep current results"
            )

            if choice is None:
                return


            if choice is True:
                if not self.save_capture():
                    return

                
        selected = self.interface_var.get()
        if not selected or selected not in self.interfaces:
            messagebox.showwarning(
                "Select Interface", "Please select a network interface."
            )
            return

        
        capture_mode = self.capture_mode_var.get()

        if capture_mode == "Limited":
            try:
                packet_limit = int(self.limit_var.get())
                if packet_limit < 1:
                    raise ValueError
            except ValueError:
                messagebox.showwarning(
                    "Invalid Limit",
                    "Choose a valid positive packet limit."
                )
                return
        else:
            packet_limit = 0

        interface_data = self.interfaces[selected]
        interface_name = interface_data["interface"]
        self.local_ip = interface_data.get("IP address")

        if not self.local_ip or self.local_ip == "No IP":
            messagebox.showwarning(
                "Missing IP",
                "The selected interface has no IPv4 address."
            )
            return

        
        # Reset this capture session.
        main.packets.clear()
        main.local_ip = self.local_ip
        self.displayed_packets = 0
        self.connection_rows.clear()
        self.displayed_suspicious_alerts.clear()
        self.displayed_scan_alerts.clear()
        for item in self.alerts_table.get_children():
            self.alerts_table.delete(item)

        if self.connections_table is not None:
            for item in self.connections_table.get_children():
                self.connections_table.delete(item)

        self.capture_start_time = None
        self.capture_end_time = None
        self.packet_count_var.set("Packets: 0")
        self.protocol_stats_var.set("Protocols: —")
        self.capture_duration_var.set("Duration: —")
        self.packet_rate_var.set("Rate: —")

        for item in self.packet_table.get_children():
            self.packet_table.delete(item)

        main.capture_stop_event.clear()
        self.is_capturing = True
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.interface_box.config(state="disabled")
        self.limit_box.config(state="disabled")
        self.capture_mode_box.config(state="disabled")
        self.status_var.set(f"Capturing on {interface_name}...")

        try:
            self.sniffer = AsyncSniffer(
                iface=interface_name,
                prn=main.process_packet,
                store=False,
                count=packet_limit
            )
            self.sniffer.start()
            self.capture_start_time = datetime.now()
            self.root.after(100, self.refresh_packets)


        except Exception as error:
            self.finish_capture()
            messagebox.showerror(
                "Capture Error",
                f"Could not start packet capture:\n{error}"
            )

    def refresh_packets(self):
        # Only the Tkinter main thread updates the table.
        current_packets = main.packets

        while self.displayed_packets < len(current_packets):
            packet = current_packets[self.displayed_packets]
            number = self.displayed_packets + 1

            self.packet_table.insert(
                "",
                "end",
                
                values=(
                    number,
                    packet.get("timestamp", ""),
                    packet.get("source_ip", ""),
                    packet.get("destination_ip", ""),
                    packet.get("protocol", ""),
                    packet.get("direction", ""),
                    packet.get("length", ""),
                    packet.get("Info", "")
                )

            )

            self.displayed_packets += 1
            
        self.update_live_dashboard()
        self.update_security_alerts()
        if (self.connections_window is not None 
            and self.connections_window.winfo_exists()):
            self.update_connections_view()

        if self.is_capturing:
            if self.sniffer and not self.sniffer.running:
                self.finish_capture()
            else:
                self.root.after(100, self.refresh_packets)

        

    
    def update_live_dashboard(self):
        captured = len(main.packets)
        self.packet_count_var.set(f"Packets: {captured}")

        counts = main.protocol_statistics(main.packets)
        if counts:
            summary = ", ".join(
                f"{protocol}: {count}"
                for protocol, count in counts.items()
            )
            self.protocol_stats_var.set(f"Protocols: {summary}")
        else:
            self.protocol_stats_var.set("Protocols: —")

        if self.capture_start_time is not None:
            now = datetime.now()
            elapsed = (now - self.capture_start_time).total_seconds()

            self.capture_duration_var.set(
                f"Duration: {elapsed:.1f}s"
            )

            rate = captured / elapsed if elapsed > 0 else 0
            self.packet_rate_var.set(f"Rate: {rate:.2f} pkt/s")


        

    def stop_capture(self):
        if not self.is_capturing:
            return

        self.status_var.set("Stopping capture...")
        self.stop_button.config(state="disabled")

        # Stop the sniffer away from Tkinter's main thread.
        def stop_worker():
            try:
                if self.sniffer and self.sniffer.running:
                    self.sniffer.stop()
            except Exception as error:
                print(f"Capture stop warning: {error}")

            self.root.after(0, self.finish_capture)

        threading.Thread(target=stop_worker, daemon=True).start()

    def finish_capture(self):
        self.is_capturing = False
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.interface_box.config(state="readonly")
        self.capture_mode_box.config(state="readonly")

        if self.capture_mode_var.get() == "Continuous":
            self.limit_box.config(state="disabled")
        else:
            self.limit_box.config(state="readonly")

        captured = len(main.packets)
        self.status_var.set(
            f"Capture stopped. Parsed IPv4 packets: {captured}"
        )

        # Display any packets captured just before stopping.
        self.refresh_packets()

        # Update final statistics and connection summaries.
        self.update_live_dashboard()
        self.update_connections_view()


    def show_connections(self):
        # Reuse the existing window if it is already open.
        if (
            self.connections_window is not None
            and self.connections_window.winfo_exists()
        ):
            self.connections_window.lift()
            self.update_connections_view()
            return

        self.connections_window = tk.Toplevel(self.root)
        self.connections_window.title("Connection Summaries")
        self.connections_window.geometry("850x450")
        self.connections_window.minsize(600, 300)

        self.connections_window.protocol(
            "WM_DELETE_WINDOW",
            self.close_connections_window
        )

        columns = ("connection", "packets")

        self.connections_table = ttk.Treeview(
            self.connections_window,
            columns=columns,
            show="headings"
        )

        self.connections_table.heading(
            "connection", text="Connection (IP:Port)"
        )
        self.connections_table.heading(
            "packets", text="Packet Count"
        )

        self.connections_table.column(
            "connection", width=650, minwidth=300
        )
        self.connections_table.column(
            "packets", width=130, anchor="center"
        )

        scrollbar = ttk.Scrollbar(
            self.connections_window,
            orient="vertical",
            command=self.connections_table.yview
        )
        self.connections_table.configure(
            yscrollcommand=scrollbar.set
        )

        self.connections_table.pack(
            side="left", fill="both", expand=True,
            padx=(10, 0), pady=10
        )
        scrollbar.pack(
            side="right", fill="y", padx=(0, 10), pady=10
        )

        self.update_connections_view()

    def update_connections_view(self):
        
        if (
            self.connections_window is None
            or not self.connections_window.winfo_exists()
            or self.connections_table is None
        ):
            return

        connections = main.connection_summaries(main.packets)

        # Remove the placeholder if real connections have appeared.
        for item in self.connections_table.get_children():
            values = self.connections_table.item(item, "values")
            if values and values[0] == "No TCP/UDP connections yet":
                self.connections_table.delete(item)

        # Update existing rows or insert new ones.
        active_connections = set()

        for connection, packet_count in sorted(
            connections.items(),
            key=lambda item: item[1],
            reverse=True
        ):
            active_connections.add(connection)

            if connection in self.connection_rows:
                row_id = self.connection_rows[connection]

                if self.connections_table.exists(row_id):
                    self.connections_table.item(
                        row_id,
                        values=(connection, packet_count)
                    )
                else:
                    row_id = self.connections_table.insert(
                        "",
                        "end",
                        values=(connection, packet_count)
                    )
                    self.connection_rows[connection] = row_id
            else:
                row_id = self.connections_table.insert(
                    "",
                    "end",
                    values=(connection, packet_count)
                )
                self.connection_rows[connection] = row_id

        # Remove rows for connections no longer present.
        for connection in list(self.connection_rows):
            if connection not in active_connections:
                row_id = self.connection_rows.pop(connection)

                if self.connections_table.exists(row_id):
                    self.connections_table.delete(row_id)

        # Show a placeholder when no TCP/UDP connections exist.
        if not connections and not self.connections_table.get_children():
            self.connections_table.insert(
                "",
                "end",
                values=("No TCP/UDP connections yet", 0)
            )

    
    def update_security_alerts(self):

        
        # Detect suspicious ports.
        suspicious = main.detect_suspicious_ports(
            main.packets, main.suspicious_ports
        )

        for alert in suspicious:
            packet = alert["packet"]

            key = (
                packet.get("packet_number"),
                alert["matched_port"],
                alert["port_role"]
            )

            if key in self.displayed_suspicious_alerts:
                continue

            details = (
                f'{packet.get("source_ip", "?")} -> '
                f'{packet.get("destination_ip", "?")} | '
                f'Port {alert["matched_port"]} '
                f'({alert["port_role"]})'
            )

            self.alerts_table.insert(
                "",
                "end",
                values=(
                    packet.get("timestamp", ""),
                    "Suspicious port",
                    details
                )
            )

            self.displayed_suspicious_alerts.add(key)

        # Detect possible port scans.
        scans = main.detect_port_scans(main.packets)

        for scan in scans:
            key = (
                scan["source_ip"],
                scan["destination_ip"]
            )

            if key in self.displayed_scan_alerts:
                continue

            ports = ", ".join(
                str(port) for port in scan["destination_ports"]
            )

            details = (
                f'{scan["source_ip"]} -> '
                f'{scan["destination_ip"]} | '
                f'{scan["unique_ports"]} unique ports: {ports}'
            )

            self.alerts_table.insert(
                "",
                "end",
                values=(
                    datetime.now().strftime("%H:%M:%S"),
                    "Possible port scan",
                    details
                )
            )

            self.displayed_scan_alerts.add(key)

    def close_connections_window(self):
        if self.connections_window is not None:
            self.connections_window.destroy()
        self.connections_window = None
        self.connections_table = None

    
    def save_capture(self):
        if not main.packets:
            messagebox.showwarning(
                "No Packets",
                "Capture some packets before saving."
            )
            return False

        file_path = filedialog.asksaveasfilename(
            title="Save Packet Capture",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")]
        )

        if not file_path:
            return False

        try:
            with open(file_path, "w", encoding="utf-8") as file:
                json.dump(main.packets, file, indent=4)

            messagebox.showinfo(
                "Capture Saved",
                f"Saved {len(main.packets)} packets to:\n{file_path}"
            )
            return True

        except (OSError, TypeError, ValueError) as error:
            messagebox.showerror(
                "Save Failed",
                f"Could not save capture:\n{error}"
            )
            return False


if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()