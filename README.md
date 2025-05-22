# PacketUp! – Network Packet Capture and GeoBlocking GUI

PacketUp! is a Windows-based Python application for **real-time packet capture, visualization, and country-based network blocking**.
It features a graphical interface built with Tkinter, a live map for IP visualization, and dynamic GeoBlocking using Windows Firewall rules.

---

## Features

* **Packet Capture:**
  Capture and list live network packets on any available interface using [Scapy](https://scapy.net/).

* **GeoIP Visualization:**
  Map packet source IP addresses geographically using the [MaxMind GeoLite2 database](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data).

* **GeoBlocking:**
  Block all network traffic to and from a selected country at the Windows Firewall level (requires Administrator privileges).

* **Firewall Rule Management:**
  Add, remove, and bulk-delete custom firewall rules ("GeoBlock" rules) directly from the GUI.

---

## How It Works

* **Packet Capture:**
  Select a network interface, start capture, and watch packets populate in a live table with summaries.

* **Geolocation:**
  Source IPs are looked up via GeoLite2, with their location visualized as temporary markers on a map.

* **GeoBlocking:**
  Enter a country code (e.g., `RU`, `CN`, `IR`), click "Block Country" to download that country’s IP ranges, and firewall rules will be created to block all inbound and outbound packets for those IPs.

* **Rule Cleanup:**
  "Clear All Firewall Rules" removes all rules created by PacketUp! (across all sessions), ensuring your firewall isn’t cluttered.

---

## Requirements

* **OS:** Windows 10/11 (for firewall management with netsh)
* **Python:** 3.8 or newer
* **Admin Rights:** Needed for GeoBlocking
* **Dependencies:**

  * `scapy`
  * `tkinter`
  * `geoip2`
  * `tkintermapview`
  * `requests`
  * `concurrent.futures`
  * [GeoLite2-Country.mmdb and GeoLite2-City.mmdb](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)

Install dependencies:

```sh
pip install scapy geoip2 requests tkintermapview
```

(`tkinter` is usually included with Python installations.)

Download the MaxMind databases and place them in the project folder:

* `GeoLite2-Country.mmdb`
* `GeoLite2-City.mmdb`

---

## Usage

1. **Run the GUI:**

   ```sh
   python gui.py
   ```

   (Run as Administrator to enable country blocking.)

2. **Capture Packets:**

   * Select a network interface
   * Click "Start Capture"
   * View packets in real-time; IPs are mapped live.

3. **GeoBlocking:**

   * Enter a country code (ISO Alpha-2, e.g., `RU`)
   * Click "Block Country" to block all IPs from that country

4. **Firewall Management:**

   * View and remove blocked countries in the GUI
   * Use "Clear All Firewall Rules" to clean up all GeoBlock rules

5. **Shutdown:**

   * On exit, the app attempts to remove all rules it created.

---

## Notes

* All firewall operations require **Administrator** permissions.
* No permanent system changes are made; all firewall rules are cleaned up when the application closes.
* **GeoBlocking** uses IP blocklists from [ipdeny.com](https://www.ipdeny.com/ipblocks/).

---

## License

This project is for educational and research use only.
IP geolocation and blocklist data copyright by their respective owners.

