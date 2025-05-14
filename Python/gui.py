import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
from scapy.all import get_if_list, conf
import datetime
from tkintermapview import TkinterMapView

from reader import capture_packets_on_interface, packets_data_list, packets_lock

class PacketCaptureGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Capture Tool v1.0")
        self.root.geometry("900x600")
        self.root.minsize(800, 500)

        self.capture_running = False
        self.capture_thread = None
        self.stop_capture_event = threading.Event()
        self.update_thread = None
        self.stop_update_event = threading.Event()

        self.interfaces = []
        self.setup_interface_selection()
        self.setup_controls()
        self.setup_frames()
        self.setup_packet_list()
        self.setup_map()
        self.status_var = tk.StringVar(value="Ready")
        self.setup_status_bar()
        self.packet_tree.bind("<<TreeviewSelect>>", self.on_packet_select)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def setup_interface_selection(self):
        frame = ttk.LabelFrame(self.root, text="Network Interface")
        frame.pack(fill=tk.X, padx=10, pady=5)
        self.interfaces = []
        self.interface_map = {}
        try:
            interface_list = get_if_list()
            for ifname in interface_list:
                iface_obj = conf.ifaces.get(ifname)
                if iface_obj:
                    desc = getattr(iface_obj, "description", None)
                    name = getattr(iface_obj, "name", None)
                    if desc and desc != ifname:
                        display = f"{desc} [{ifname}]"
                    elif name and name != ifname:
                        display = f"{name} [{ifname}]"
                    else:
                        display = ifname
                else:
                    display = ifname
                self.interfaces.append(display)
                self.interface_map[display] = ifname
            if not self.interfaces:
                self.interfaces = interface_list
                self.interface_map = {name: name for name in interface_list}
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get interfaces: {e}")
            self.interfaces = []
            self.interface_map = {}
        ttk.Label(frame, text="Select Interface:").pack(side=tk.LEFT, padx=5)
        self.interface_var = tk.StringVar()
        if self.interfaces:
            self.interface_var.set(self.interfaces[0])
        interface_dropdown = ttk.Combobox(frame, textvariable=self.interface_var, values=self.interfaces, width=60)
        interface_dropdown.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5, pady=5)
        interface_dropdown.state(["readonly"])

    def setup_frames(self):
        self.main_frame = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.list_frame = ttk.Frame(self.main_frame)
        self.main_frame.add(self.list_frame, weight=2)
        self.map_frame = ttk.LabelFrame(self.main_frame, text="Earth Map")
        self.main_frame.add(self.map_frame, weight=1)

    def setup_packet_list(self):
        list_label_frame = ttk.LabelFrame(self.list_frame, text="Captured Packets")
        list_label_frame.pack(fill=tk.BOTH, expand=True)
        scrollbar = ttk.Scrollbar(list_label_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        columns = ("Number", "Length", "Time", "Summary")
        self.packet_tree = ttk.Treeview(list_label_frame, columns=columns, show="headings", yscrollcommand=scrollbar.set)
        self.packet_tree.heading("Number", text="#")
        self.packet_tree.heading("Length", text="Length")
        self.packet_tree.heading("Time", text="Time")
        self.packet_tree.heading("Summary", text="Summary")
        self.packet_tree.column("Number", width=50, anchor=tk.CENTER)
        self.packet_tree.column("Length", width=80, anchor=tk.CENTER)
        self.packet_tree.column("Time", width=150, anchor=tk.CENTER)
        self.packet_tree.column("Summary", width=400)
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.packet_tree.yview)

    def setup_map(self):
        for widget in self.map_frame.winfo_children():
            widget.destroy()
        self.map_widget = TkinterMapView(self.map_frame, width=600, height=300, corner_radius=0)
        self.map_widget.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.map_widget.set_position(20, 0)
        self.map_widget.set_zoom(2)

    def setup_controls(self):
        control_frame = tk.Frame(self.root)
        control_frame.pack(fill=tk.X, padx=10, pady=5, side=tk.TOP)
        self.start_button = ttk.Button(
            control_frame,
            text="Start Capture",
            command=self.start_capture,
            style="Accent.TButton"
        )
        self.start_button.pack(side=tk.LEFT, padx=5, pady=5, ipadx=10, ipady=5)
        self.stop_button = ttk.Button(
            control_frame,
            text="Stop Capture",
            command=self.stop_capture,
            state=tk.DISABLED
        )
        self.stop_button.pack(side=tk.LEFT, padx=5, pady=5, ipadx=10, ipady=5)
        self.clear_button = ttk.Button(
            control_frame,
            text="Clear Packets",
            command=self.clear_packets
        )
        self.clear_button.pack(side=tk.LEFT, padx=5, pady=5, ipadx=10, ipady=5)
        ttk.Separator(control_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=5)
        self.capture_status_label = ttk.Label(
            control_frame,
            text="Status: Ready to capture",
            foreground="blue"
        )
        self.capture_status_label.pack(side=tk.LEFT, padx=5)
        style = ttk.Style()
        try:
            style.configure("Accent.TButton", font=("Helvetica", 10, "bold"))
        except Exception:
            pass

    def setup_status_bar(self):
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def start_capture(self):
        if not self.interfaces:
            messagebox.showerror("Error", "No network interfaces available")
            return
        if self.capture_running:
            messagebox.showinfo("Already Running", "Capture is already in progress")
            return
        display_name = self.interface_var.get()
        if not display_name:
            messagebox.showerror("Error", "Please select a network interface")
            return
        interface_name = self.interface_map.get(display_name, display_name)
        self.clear_packets()
        self.stop_capture_event.clear()
        self.stop_update_event.clear()
        self.status_var.set(f"Preparing to capture on {interface_name}...")
        self.capture_status_label.config(text="Status: Starting capture...", foreground="orange")
        self.root.update()
        self.capture_thread = threading.Thread(
            target=capture_packets_on_interface,
            args=(interface_name, self.stop_capture_event)
        )
        self.capture_thread.daemon = True
        self.capture_thread.start()
        self.update_thread = threading.Thread(target=self.update_packet_list)
        self.update_thread.daemon = True
        self.update_thread.start()
        self.capture_running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_var.set(f"Capturing packets on {interface_name}...")
        self.capture_status_label.config(text="Status: CAPTURING", foreground="green")

    def stop_capture(self):
        if not self.capture_running:
            return
        self.stop_capture_event.set()
        self.stop_update_event.set()
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=5)
        if self.update_thread and self.update_thread.is_alive():
            self.update_thread.join(timeout=5)
        self.capture_running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_var.set(f"Capture stopped. Total packets: {len(packets_data_list)}")
        self.capture_status_label.config(text="Status: STOPPED", foreground="blue")

    def clear_packets(self):
        with packets_lock:
            packets_data_list.clear()
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
        self.status_var.set("Packets cleared")
        self.capture_status_label.config(text="Status: Ready to capture", foreground="blue")

    def update_packet_list(self):
        last_count = 0
        while not self.stop_update_event.is_set():
            with packets_lock:
                current_count = len(packets_data_list)
                if current_count > last_count:
                    for i in range(last_count, current_count):
                        packet_info = packets_data_list[i]
                        timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
                        try:
                            summary = ' '.join([packet_info['data'][j:j+2].hex() for j in range(0, min(16, packet_info['length']), 2)])
                            summary = f"Data: {summary}..."
                        except Exception:
                            summary = "Unable to parse packet"
                        self.root.after(0, self._safe_insert_packet, i+1, packet_info['length'], timestamp, summary)
                    last_count = current_count
                    self.root.after(0, self.status_var.set, f"Capturing... Packets: {current_count}")
            time.sleep(0.1)

    def _safe_insert_packet(self, num, length, timestamp, summary):
        self.packet_tree.insert("", "end", values=(num, length, timestamp, summary))
        self.packet_tree.see(self.packet_tree.get_children()[-1])

    def on_packet_select(self, event):
        pass

    def on_closing(self):
        if self.capture_running:
            if messagebox.askyesno("Exit", "Packet capture is still running. Do you want to stop it and exit?"):
                self.stop_capture()
                self.root.destroy()
        else:
            self.root.destroy()

def start_gui():
    root = tk.Tk()
    app = PacketCaptureGUI(root)
    root.mainloop()

if __name__ == "__main__":
    start_gui()
