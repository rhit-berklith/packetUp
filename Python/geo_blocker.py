import os
import geoip2.database
from threading import Lock
import subprocess
import urllib.request

_geoip_lock = Lock()
mmdb_path = os.path.join(os.path.dirname(__file__), "GeoLite2-Country.mmdb")
_geoip_reader = geoip2.database.Reader(mmdb_path)

_blocked_countries = set()
_ip_cache = {}

FIREWALL_PREFIX = "GeoBlock"

def get_country(ip):
    try:
        with _geoip_lock:
            response = _geoip_reader.country(ip)
            return response.country.iso_code
    except Exception:
        return None

def get_blocked_countries():
    return sorted(_blocked_countries)

def add_country(country_code):
    code = country_code.upper()
    if code in _blocked_countries:
        return

    print(f"[GeoBlocker] Blocking country: {code}")
    _blocked_countries.add(code)

    # Download IP blocks from ipdeny
    try:
        url = f"https://www.ipdeny.com/ipblocks/data/countries/{code.lower()}.zone"
        with urllib.request.urlopen(url) as response:
            ip_list = [line.decode().strip() for line in response.readlines()]
            _ip_cache[code] = ip_list
            create_firewall_rule_netsh(code, ip_list)  # Use netsh version!
    except Exception as e:
        print(f"[GeoBlocker] Failed to get IP list for {code}: {e}")


def remove_country(country_code):
    code = country_code.upper()
    if code not in _blocked_countries:
        return

    print(f"[GeoBlocker] Unblocking country: {code}")
    _blocked_countries.discard(code)
    remove_firewall_rule_netsh(code)  # Use netsh version!


def create_firewall_rule_netsh(country_code, ip_list):
    addresses = ",".join(ip_list[:500])  # Windows has a 1000 address limit per rule; use batching if needed
    rule_name = f"{FIREWALL_PREFIX}_{country_code}"
    netsh_command = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        "dir=in",
        "action=block",
        f"remoteip={addresses}",
        "enable=yes"
    ]
    result = subprocess.run(netsh_command, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[GeoBlocker] Failed to create netsh firewall rule: {result.stderr}")
    else:
        print(f"[GeoBlocker] Successfully created netsh rule '{rule_name}'")

def remove_firewall_rule_netsh(country_code):
    rule_name = f"{FIREWALL_PREFIX}_{country_code}"
    netsh_command = [
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={rule_name}"
    ]
    result = subprocess.run(netsh_command, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[GeoBlocker] Failed to delete netsh firewall rule '{rule_name}': {result.stderr}")
    else:
        print(f"[GeoBlocker] Successfully deleted netsh rule '{rule_name}'")
