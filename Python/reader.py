import threading
import time
from scapy.all import sniff, get_if_list, IP

# Depending on your Scapy installation and OS, you might need to configure Npcap/WinPcap.
# from scapy.config import conf
# Example: conf.use_pcap = True or conf.use_npcap = True if issues arise.

# Global list to store captured packets' data
# Each element will be a dictionary: {'length': int, 'data': bytes, 'src_ip': str}
packets_data_list = []

# Lock for thread-safe access to packets_data_list
packets_lock = threading.Lock()

# Packet handler callback
def packet_callback(packet):
    """
    This function is called by Scapy for each captured packet.
    It extracts length, raw data, and source IP (if available),
    then appends to the global list.
    """
    

    with packets_lock:
        packet_info = {
            'length': len(packet),      # Length of the packet
            'data': bytes(packet),      # Raw bytes of the packet
            'src_ip': None,   
            'scapy_pkt': packet           # Placeholder for source IP
        }
        if packet.haslayer(IP):
            packet_info['src_ip'] = packet[IP].src

        packets_data_list.append(packet_info)
        # print(f"[reader.py] Packet captured: length={packet_info['length']}, src_ip={packet_info['src_ip']} (total={len(packets_data_list)})")
        
        if __name__ == "__main__":
            packet_num = len(packets_data_list)
            print(f"\rPacket #{packet_num}: Length={packet_info['length']} bytes", end="")
            
            # Optionally print more detailed info every 10 packets or so
            if packet_num % 10 == 0:
                print(f"\nPacket #{packet_num}: {packet.summary()}")
                print(f"  Length: {packet_info['length']} bytes")
                print(f"  Source IP: {packet_info['src_ip']}")
                # Show first 16 bytes of data as hex
                hex_data = packet_info['data'][:16].hex(' ')
                print(f"  Data (first 16 bytes): {hex_data}")
                print()

def capture_packets_on_interface(interface_name, stop_event):
    """
    Target function for the packet capture thread.
    Sniffs packets on the given interface until stop_event is set.
    """
    print(f"Capture thread started on interface: {interface_name}")
    try:
        # store=0: Scapy doesn't keep packets in its own memory, we handle it.
        # stop_filter: function called for each packet; if it returns True, sniffing stops.
        # prn: function to call for each packet.
        sniff(iface=interface_name, prn=packet_callback, store=0, stop_filter=lambda p: stop_event.is_set())
    except PermissionError:
        print(f"Permission error: Unable to capture on {interface_name}. Try running as root/administrator.")
    except Exception as e:
        # OSError might occur if interface is invalid or pcap is not available.
        print(f"Error in capture thread on {interface_name}: {e}")
    finally:
        print(f"Capture thread on {interface_name} finished.")

def main_python_equivalent():
    """
    Main function to set up and manage packet capture, similar to the C++ main.
    """
    # Initialize: Find available devices (interfaces)
    try:
        available_interfaces = get_if_list()
    except Exception as e:
        print(f"Error finding devices: {e}. Ensure libpcap/Npcap is installed and Scapy has access.")
        return 1
        
    if not available_interfaces:
        print("Error: No network interfaces found. Ensure you have permissions (e.g., run as administrator/root) and Npcap/WinPcap is installed.")
        return 1

    # Display available interfaces and let the user choose
    print("Available network interfaces:")
    for i, iface_name in enumerate(available_interfaces):
        print(f"  {i}: {iface_name}")

    selected_index = -1
    while True:
        try:
            choice = input(f"Enter the number of the interface to use (0-{len(available_interfaces)-1}): ")
            selected_index = int(choice)
            if 0 <= selected_index < len(available_interfaces):
                break
            else:
                print("Invalid selection. Please enter a number from the list.")
        except ValueError:
            print("Invalid input. Please enter a number.")
        except EOFError: # Handle Ctrl+D or similar EOF
            print("\nNo interface selected. Exiting.")
            return 1

    selected_interface_name = available_interfaces[selected_index]
    print(f"Selected interface for capture: {selected_interface_name}")

    # Event to signal the capture thread to stop
    stop_capture_event = threading.Event()

    # Start packet capture in a separate thread
    capture_thread = threading.Thread(
        target=capture_packets_on_interface,
        args=(selected_interface_name, stop_capture_event)
    )
    capture_thread.daemon = True 
    
    print("Starting packet capture thread...")
    capture_thread.start()

    # Start the GUI
    try:
        # Check if GUI module exists and use it
        import gui
        print("Starting GUI...")
        gui.start_gui()
        # If GUI is closed, we'll continue with the console mode below
        print("GUI closed. Continuing with console mode.")
    except ImportError:
        # Otherwise, run in console mode
        print("GUI module not found. Running in console mode.")
        print("Simulating a running application. Press Ctrl+C to stop capturing and exit.")

    try:
        while capture_thread.is_alive():
            time.sleep(0.5) # Keep main thread alive, periodically check thread status
            # Print packet count periodically (only in console mode)
            with packets_lock:
                if packets_data_list:
                    print(f"\rPackets captured: {len(packets_data_list)}", end="")

    except KeyboardInterrupt:
        print("\nKeyboardInterrupt received. Stopping capture...")
    finally:
        if capture_thread.is_alive():
            print("Signaling capture thread to stop...")
            stop_capture_event.set()
            capture_thread.join(timeout=5) # Wait for the thread to finish
            if capture_thread.is_alive():
                print("Capture thread did not stop gracefully.")
        
        print(f"\nTotal packets captured: {len(packets_data_list)}")
        
        # Display detailed info about captured packets (only in console mode)
        if packets_data_list:
            print("\nPacket Summary:")
            max_display = min(10, len(packets_data_list))  # Show at most 10 packets in detail
            for i in range(max_display):
                pkt_info = packets_data_list[i]
                print(f"\nPacket #{i+1}:")
                print(f"  Length: {pkt_info['length']} bytes")
                print(f"  Source IP: {pkt_info['src_ip']}")
                # Show first 32 bytes of data as hex with spacing for readability
                hex_data = ' '.join([pkt_info['data'][j:j+2].hex() for j in range(0, min(32, len(pkt_info['data'])), 2)])
                print(f"  Data: {hex_data}")
            
            if len(packets_data_list) > max_display:
                print(f"\n... and {len(packets_data_list) - max_display} more packets")
                
            # Ask if user wants to see all packets in more detail
            try:
                choice = input("\nDo you want to see all packets in more detail? (y/n): ").lower()
                if choice == 'y':
                    for i, pkt_info in enumerate(packets_data_list):
                        print(f"\nPacket #{i+1}:")
                        print(f"  Length: {pkt_info['length']} bytes")
                        print(f"  Source IP: {pkt_info['src_ip']}")
                        # Show more bytes in detailed view
                        hex_data = ' '.join([pkt_info['data'][j:j+16].hex() for j in range(0, min(64, len(pkt_info['data'])), 16)])
                        print(f"  Data: {hex_data}")
                        # Break after a batch to avoid flooding console, ask to continue
                        if (i+1) % 20 == 0 and i+1 < len(packets_data_list):
                            cont = input("Press Enter to see more, or 'q' to quit: ")
                            if cont.lower() == 'q':
                                break
            except EOFError:
                pass  # Handle Ctrl+D gracefully
        
    print("Program terminated.")
    return 0

if __name__ == "__main__":
    main_python_equivalent()
