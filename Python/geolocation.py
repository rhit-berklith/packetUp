import geoip2.database
import os.path

class IPGeolocation:
    """Provides IP address geolocation using the MaxMind GeoLite2 database."""
    
    def __init__(self, db_path=None):
        """Initialize with the path to the GeoLite2 City database."""
        if db_path is None:
            # Default path - adjust as needed
            db_path = os.path.join(os.path.dirname(__file__), "GeoLite2-City.mmdb")
        
        if not os.path.exists(db_path):
            raise FileNotFoundError(f"GeoIP database not found at {db_path}. Please download from MaxMind.")
            
        self.reader = geoip2.database.Reader(db_path)
        self.cache = {}  # Cache results to avoid redundant lookups
    
    def geocode_ip(self, ip_address):
        """Convert an IP address to (latitude, longitude) coordinates."""
        if not ip_address:
            ##print(f"[GEOLOCATION] Null IP address")
            return None
            
        # Skip private/local IP addresses
        if (ip_address.startswith('127.') or ip_address.startswith('192.168.') or 
            ip_address.startswith('10.') or ip_address.startswith('172.16.')):
            ##print(f"[GEOLOCATION] Private IP skipped: {ip_address}")
            return None
            
        # Check cache first
        if ip_address in self.cache:
            ##print(f"[GEOLOCATION] Cache hit for {ip_address}: {self.cache[ip_address]}")
            return self.cache[ip_address]
        
        try:
            ##print(f"[GEOLOCATION] Looking up {ip_address} in database")
            response = self.reader.city(ip_address)
            if response.location.latitude and response.location.longitude:
                location = (response.location.latitude, response.location.longitude)
                self.cache[ip_address] = location
                ##print(f"[GEOLOCATION] Success for {ip_address}: {location}")
                return location
            ##print(f"[GEOLOCATION] No location data for {ip_address}")
            return None
        except Exception as e:
            ##print(f"[GEOLOCATION] Error looking up {ip_address}: {e}")
            return None
    
    def close(self):
        """Close the database reader."""
        if hasattr(self, 'reader'):
            self.reader.close()
    
    def __del__(self):
        """Ensure the database is closed when the object is garbage-collected."""
        self.close()
