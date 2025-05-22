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
            return None
            
        # Skip private/local IP addresses
        if (ip_address.startswith('127.') or ip_address.startswith('192.168.') or 
            ip_address.startswith('10.') or ip_address.startswith('172.16.')):
            return None
            
        # Check cache first
        if ip_address in self.cache:
            return self.cache[ip_address]
        
        try:
            response = self.reader.city(ip_address)
            if response.location.latitude and response.location.longitude:
                location = (response.location.latitude, response.location.longitude)
                self.cache[ip_address] = location
                return location
            return None
        except Exception as e:
            return None
    
    def get_country(self, ip_address):
        """Return ISO country code for the IP, or None."""
        try:
            resp = self.reader.city(ip_address)
            return resp.country.iso_code
        except Exception:
            return None
    
    def close(self):
        """Close the database reader."""
        if hasattr(self, 'reader'):
            self.reader.close()
    
    def __del__(self):
        """Ensure the database is closed when the object is garbage-collected."""
        self.close()
