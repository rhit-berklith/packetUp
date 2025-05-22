import os
import geoip2.database
from threading import Lock
import subprocess
import urllib.request
import requests
import ctypes
import concurrent.futures
from time import sleep
import ipaddress

_geoip_lock = Lock()
mmdb_path = os.path.join(os.path.dirname(__file__), "GeoLite2-Country.mmdb")
_geoip_reader = geoip2.database.Reader(mmdb_path)

_blocked_countries = set()
_ip_cache = {}

FIREWALL_PREFIX = "GeoBlock"
DEFAULT_CHUNK_SIZE = 250
MAX_WORKERS = 4

def get_country(ip):
    try:
        with _geoip_lock:
            response = _geoip_reader.country(ip)
            return response.country.iso_code
    except Exception:
        return None

def get_blocked_countries():
    return sorted(_blocked_countries)

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def add_country(country_code):
    code = country_code.upper()
    if not is_admin():
        print(f"[GeoBlocker] Admin privileges required to block {code}.")
        return False
    if code in _blocked_countries:
        return True

    print(f"[GeoBlocker] Blocking country: {code}")
    _blocked_countries.add(code)

    # Download IP blocks from ipdeny
    try:
        url = f"https://www.ipdeny.com/ipblocks/data/countries/{code.lower()}.zone"
        with urllib.request.urlopen(url) as response:
            ip_list_str = [line.decode().strip() for line in response.readlines() if line.decode().strip()]
            _ip_cache[code] = ip_list_str
            print(f"[GeoBlocker] Downloaded {len(ip_list_str)} IP ranges for {code}")
            
            # Show sample IPs - simplified from verbose diagnostics
            if ip_list_str:
                print(f"[GeoBlocker] Sample IP ranges: {ip_list_str[:3]}...")

            create_firewall_rule_netsh_parallel(code, ip_list_str)
    except Exception as e:
        print(f"[GeoBlocker] Failed to get IP list for {code}: {e}")
        _blocked_countries.discard(code)  # Remove from blocked set if failed
        return False

    return True

def create_firewall_rule_netsh_parallel(country_code, ip_list):
    # Windows has address length limits - batch into chunks
    chunk_size = DEFAULT_CHUNK_SIZE
    chunks = []
    
    for i in range(0, len(ip_list), chunk_size):
        chunk = ip_list[i:i+chunk_size]
        rule_name = f"{FIREWALL_PREFIX}_{country_code}"
        if i > 0:
            rule_name = f"{rule_name}_{i//chunk_size}"
        chunks.append((rule_name, chunk))
    
    total_chunks = len(chunks)
    completed = 0
    failed = 0
    
    print(f"[GeoBlocker] Creating {total_chunks} firewall rules in parallel...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Submit all tasks
        future_to_chunk = {
            executor.submit(create_single_firewall_rule, rule_name, chunk): 
            (rule_name, chunk) for rule_name, chunk in chunks
        }
        
        # Process results as they complete
        for future in concurrent.futures.as_completed(future_to_chunk):
            rule_name, chunk = future_to_chunk[future]
            try:
                success = future.result()
                completed += 1
                if not success:
                    failed += 1
                
                # Print progress
                print(f"[GeoBlocker] Progress: {completed}/{total_chunks} rules created " +
                      f"({failed} failed) - {int(completed/total_chunks*100)}%")
            except Exception as e:
                print(f"[GeoBlocker] Error creating rule '{rule_name}': {e}")
                failed += 1
    
    if failed > 0:
        print(f"[GeoBlocker] Warning: {failed} out of {total_chunks} rules failed to create")
    print(f"[GeoBlocker] Completed blocking {country_code}")

def create_single_firewall_rule(rule_name, ip_chunk):
    addresses = ",".join(ip_chunk)
    
    # Create inbound rule to block incoming traffic
    inbound_rule_name = rule_name
    inbound_command = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={inbound_rule_name}",
        "dir=in",
        "action=block",
        f"remoteip={addresses}",
        "protocol=any",
        "enable=yes"
    ]
    
    # Create outbound rule to block outgoing traffic to the same IPs
    outbound_rule_name = f"{rule_name}_outbound"
    outbound_command = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={outbound_rule_name}",
        "dir=out",
        "action=block",
        f"remoteip={addresses}",
        "protocol=any",
        "enable=yes"
    ]
    
    try:
        # Create inbound rule
        result_in = subprocess.run(inbound_command, capture_output=True, text=True, timeout=60)
        
        # Create outbound rule
        result_out = subprocess.run(outbound_command, capture_output=True, text=True, timeout=60)
        
        if result_in.returncode != 0 or result_out.returncode != 0:
            error_message = f"[GeoBlocker] Failed to create rule '{rule_name}'."
            if result_in.returncode != 0:
                error_message += f"\nInbound rule failed (Return Code: {result_in.returncode})."
                if result_in.stdout and result_in.stdout.strip():
                    error_message += f"\nNetsh STDOUT (in): {result_in.stdout.strip()}"
                if result_in.stderr and result_in.stderr.strip():
                    error_message += f"\nNetsh STDERR (in): {result_in.stderr.strip()}"
            
            if result_out.returncode != 0:
                error_message += f"\nOutbound rule failed (Return Code: {result_out.returncode})."
                if result_out.stdout and result_out.stdout.strip():
                    error_message += f"\nNetsh STDOUT (out): {result_out.stdout.strip()}"
                if result_out.stderr and result_out.stderr.strip():
                    error_message += f"\nNetsh STDERR (out): {result_out.stderr.strip()}"
            
            print(error_message)
            return False
        
        return True
    except subprocess.TimeoutExpired:
        print(f"[GeoBlocker] Timeout creating rules for '{rule_name}'. The command took too long to execute.")
        return False
    except Exception as e:
        print(f"[GeoBlocker] Exception creating rules for '{rule_name}': {e}")
        return False

def create_firewall_rule_netsh(country_code, ip_list):
    # This function is kept for backward compatibility
    # but we'll use the parallel version by default
    create_firewall_rule_netsh_parallel(country_code, ip_list)

def remove_country(country_code):
    code = country_code.upper()
    if not is_admin():
        print(f"[GeoBlocker] Admin privileges required to unblock {code}.")
        return False
    if code not in _blocked_countries:
        return True

    print(f"[GeoBlocker] Unblocking country: {code}")
    _blocked_countries.discard(code)
    
    # Remove IPs from the local cache
    if code in _ip_cache:
        del _ip_cache[code]
    
    # Remove rules
    remove_firewall_rule_netsh(code)
    
    return True

def remove_firewall_rule_netsh(country_code):
    rule_name = f"{FIREWALL_PREFIX}_{country_code}"
    
    # Delete the base rule and any chunked rules (inbound)
    inbound_command = [
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={rule_name}*"  # Wildcard to catch all chunks
    ]
    
    # Delete the outbound rules
    outbound_command = [
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={rule_name}_outbound*"  # Wildcard to catch all chunks with _outbound suffix
    ]
    
    # Run both commands
    subprocess.run(inbound_command, capture_output=True, text=True)
    subprocess.run(outbound_command, capture_output=True, text=True)
    
    print(f"[GeoBlocker] Deleted rules for '{country_code}'")

def remove_all():
    """Remove all geoblock firewall rules added during this session."""
    for code in list(_blocked_countries):
        remove_country(code)

def diagnose_geoblock_rules():
    """Print all firewall rule names containing 'GeoBlock' using netsh for diagnostics."""
    print("[GeoBlocker] --- DIAGNOSTIC: Listing all firewall rules containing 'GeoBlock' (via netsh) ---")
    result = subprocess.run(
        ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
        capture_output=True, text=True
    )
    rules = []
    for line in result.stdout.splitlines():
        if "GeoBlock" in line:
            rules.append(line.strip())
    if rules:
        for rule in rules:
            print(rule)
    else:
        print("[GeoBlocker] No rules containing 'GeoBlock' found.")
    print("[GeoBlocker] --- END DIAGNOSTIC ---")

def remove_all_firewall_rules():
    """Remove all firewall rules with the GeoBlock prefix from Windows Firewall using netsh only."""
    if not is_admin():
        print(f"[GeoBlocker] Admin privileges required to remove all firewall rules.")
        return False

    print(f"[GeoBlocker] DIAGNOSTIC: Rules BEFORE deletion:")
    diagnose_geoblock_rules()

    print("[GeoBlocker] Enumerating all GeoBlock rules for exact deletion...")
    # Get all rule names containing GeoBlock
    result = subprocess.run(
        ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
        capture_output=True, text=True
    )
    rule_names = []
    for line in result.stdout.splitlines():
        if line.strip().startswith("Rule Name:") and "GeoBlock" in line:
            # Extract the rule name after "Rule Name:"
            rule_name = line.split(":", 1)[1].strip()
            rule_names.append(rule_name)

    deleted_any = False
    for rule_name in rule_names:
        del_result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f'name={rule_name}'],
            capture_output=True, text=True
        )
        if del_result.returncode == 0:
            print(f"[GeoBlocker] Deleted rule: {rule_name}")
            deleted_any = True
        else:
            print(f"[GeoBlocker] Failed to delete rule: {rule_name} (may already be gone)")

    print(f"[GeoBlocker] DIAGNOSTIC: Rules AFTER deletion:")
    diagnose_geoblock_rules()

    _blocked_countries.clear()
    _ip_cache.clear()
    if deleted_any:
        print("[GeoBlocker] All GeoBlock rules purged. Please verify in Windows Firewall.")
    else:
        print("[GeoBlocker] No GeoBlock rules were found to delete. Please verify in Windows Firewall.")
    return True
