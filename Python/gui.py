import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
from scapy.all import get_if_list, conf
import datetime

from reader import capture_packets_on_interface, packets_data_list, packets_lock
from map import MapFrame
from geolocation import IPGeolocation  # or from geolocation_api import IPGeolocationAPI
# Ensure the correct function is imported for global cleanup
from geo_blocker import add_country, remove_country, get_blocked_countries, remove_all_firewall_rules

class PacketCaptureGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PacketUp!")
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
        self.setup_geo_blocking_ui()
        self.setup_frames()
        self.setup_packet_list()
        self.status_var = tk.StringVar(value="Ready")
        self.setup_status_bar()
        self.packet_tree.bind("<<TreeviewSelect>>", self.on_packet_select)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Initialize geolocation service
        try:
            self.geolocator = IPGeolocation()  # or IPGeolocationAPI()
            # Test geolocation with Google's DNS
            test_coords = self.geolocator.geocode_ip("8.8.8.8")
            print(f"[GEOLOCATION TEST] Google DNS (8.8.8.8) coords: {test_coords}")
        except Exception as e:
            # Handle initialization error
            messagebox.showwarning("Geolocation Service", f"Could not initialize geolocation: {e}")
            self.geolocator = None

    def geocode_ip(self, ip_address):
        """Convert an IP address to geographical coordinates."""
        if not self.geolocator:
            return None
        return self.geolocator.geocode_ip(ip_address)

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
        
        self.map_display_frame = MapFrame(self.main_frame)
        self.main_frame.add(self.map_display_frame, weight=1)

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
        """Stop packet capture and clean up resources properly."""
        if not self.capture_running:
            return
            
        # Set events to signal threads to stop
        self.stop_capture_event.set()
        self.stop_update_event.set()
        
        # Clear any pending markers and batch operations
        self.root.after(0, self.map_display_frame.clear_all_markers)
        
        # Wait for threads to terminate
        try:
            if self.capture_thread and self.capture_thread.is_alive():
                self.capture_thread.join(timeout=2)
            if self.update_thread and self.update_thread.is_alive():
                self.update_thread.join(timeout=2)
        except Exception as e:
            print(f"Error while stopping threads: {e}")
        
        # Update UI state
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
        """Monitor packets_data_list and update the UI accordingly."""
        last_count = 0
        try:
            while not self.stop_update_event.is_set():
                new_packets_to_process = []
                with packets_lock:
                    current_count = len(packets_data_list)
                    if current_count > last_count:
                        for i in range(last_count, current_count):
                            new_packets_to_process.append((i, packets_data_list[i]))
                        last_count = current_count
                
                if new_packets_to_process:
                    for i, packet_info in new_packets_to_process:
                        # --- drop packets from blocked countries ---
                        src = packet_info.get('src_ip')
                        if src and self.geolocator:
                            code = self.geolocator.get_country(src)
                            if code in get_blocked_countries():
                                continue
                        
                        timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
                        try:
                            summary_data = packet_info.get('data', b'')
                            summary = ' '.join([summary_data[j:j+2].hex() for j in range(0, min(16, packet_info.get('length', 0)), 2)])
                            summary = f"Data: {summary}..."
                        except Exception as e:
                            summary = "Unable to parse packet"
                        
                        self.root.after(0, self._safe_insert_packet, i+1, packet_info.get('length',0), timestamp, summary)

                        # Check for IP and add map marker for visualization
                        if packet_info.get('src_ip'):
                            ip = packet_info['src_ip']
                            coords = self.geocode_ip(ip)
                            if coords:
                                self.root.after(0,
                                    self.map_display_frame.add_temporary_marker,
                                    coords[0], coords[1], "", 3000
                                )
                
                self.root.after(0, self.status_var.set, f"Capturing... Packets: {last_count}")

                # Limit frequency of updates to prevent recursion depth issues
                time.sleep(0.2)
        except Exception as e:
            print(f"Error in update_packet_list: {e}")
        finally:
            print("Update thread terminating")

    def _safe_insert_packet(self, num, length, timestamp, summary):
        try:
            item_id = self.packet_tree.insert("", "end", values=(num, length, timestamp, summary))
            if item_id:
                 self.packet_tree.see(item_id)
        except Exception as e:
            pass

    def on_packet_select(self, event):
        pass


    def setup_geo_blocking_ui(self):
        frame = ttk.LabelFrame(self.root, text="GeoBlocking (Block by Country Code)")
        frame.pack(fill=tk.X, padx=10, pady=5)

        self.geo_entry = ttk.Entry(frame)
        self.geo_entry.pack(side=tk.LEFT, padx=5)

        add_button = ttk.Button(frame, text="Block Country", command=self.add_country_ui)
        add_button.pack(side=tk.LEFT, padx=5)

        remove_button = ttk.Button(frame, text="Unblock Selected", command=self.remove_country_ui)
        remove_button.pack(side=tk.LEFT, padx=5)
        
        # Add a button to remove all GeoBlock rules from the firewall
        clear_all_button = ttk.Button(frame, text="Clear All Firewall Rules", 
                                     command=self.clear_all_firewall_rules,
                                     style="Accent.TButton")
        clear_all_button.pack(side=tk.LEFT, padx=5)

        self.blocked_listbox = tk.Listbox(frame, height=4)
        self.blocked_listbox.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.refresh_blocked_list()

    def add_country_ui(self):
        code = self.geo_entry.get().strip().upper()
        if code:
            success = add_country(code)
            if not success:
                messagebox.showerror("GeoBlocker", f"Administrator rights required to block {code}.")
            else:
                self.refresh_blocked_list()

    def remove_country_ui(self):
        selected = self.blocked_listbox.curselection()
        if selected:
            code = self.blocked_listbox.get(selected[0])
            success = remove_country(code)
            if not success:
                messagebox.showerror("GeoBlocker", f"Administrator rights required to unblock {code}.")
            else:
                self.refresh_blocked_list()

    def refresh_blocked_list(self):
        self.blocked_listbox.delete(0, tk.END)
        for code in get_blocked_countries():
            self.blocked_listbox.insert(tk.END, code)

    def clear_all_firewall_rules(self):
        """Remove all GeoBlock firewall rules, including those from previous sessions."""
        if messagebox.askyesno("Clear All Rules", 
                              "This will attempt to remove ALL GeoBlock firewall rules from Windows Firewall.\n"
                              "This includes rules created in previous sessions.\n\n"
                              "Continue?"):
            # Call the global cleanup function
            success = remove_all_firewall_rules() # This is geo_blocker.remove_all_firewall_rules
            if not success: # remove_all_firewall_rules now generally returns True, but check console for details
                messagebox.showwarning("GeoBlocker", "Rule removal process completed. Administrator rights are required. Please check the console output for details on success or failure of specific rule deletions.")
            else:
                messagebox.showinfo("GeoBlocker", "Attempted to remove all GeoBlock firewall rules. Please check the console output for details and verify in Windows Firewall.")
            self.refresh_blocked_list()

    def on_closing(self):
        """Handle application shutdown."""
        try:
            if self.capture_running:
                if messagebox.askyesno("Exit", "Packet capture is still running. Do you want to stop it and exit?"):
                    self.stop_capture()
                else:
                    return # User chose not to exit

            # Clear any remaining map markers
            if hasattr(self, 'map_display_frame'):
                self.map_display_frame.clear_all_markers()
            
            # Close geolocation service
            if hasattr(self, 'geolocator') and self.geolocator:
                self.geolocator.close()
                
            # Attempt to remove all GeoBlock firewall rules from any session
            print("[GUI] Application closing. Attempting to clear all GeoBlock firewall rules...")
            if remove_all_firewall_rules(): # Call the global cleanup
                print("[GUI] GeoBlock rule cleanup process completed. Check console for details.")
            else:
                # This path might not be hit if remove_all_firewall_rules always returns True
                print("[GUI] GeoBlock rule cleanup process reported an issue or admin rights were missing. Check console.")
            
            self.root.destroy()

        except Exception as e:
            print(f"Error during shutdown: {e}")
            # Fallback: try to destroy root even if other cleanup fails
            try:
                self.root.destroy()
            except:
                pass



def start_gui():
    root = tk.Tk()
    app = PacketCaptureGUI(root)
    root.mainloop()

if __name__ == "__main__":
    start_gui()
