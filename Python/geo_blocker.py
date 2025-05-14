import geoip2.database
from threading import Lock

# Thread-safe access to the GeoIP reader and blocked countries
_geoip_lock = Lock()
_geoip_reader = geoip2.database.Reader("GeoLite2-Country.mmdb")
_blocked_countries = set()

def get_country(ip):
    try:
        with _geoip_lock:
            response = _geoip_reader.country(ip)
            return response.country.iso_code
    except Exception:
        return None

def is_blocked(ip):
    country = get_country(ip)
    if country is None:
        return False
    return country in _blocked_countries

def add_country(country_code):
    _blocked_countries.add(country_code.upper())

def remove_country(country_code):
    _blocked_countries.discard(country_code.upper())

def get_blocked_countries():
    return sorted(_blocked_countries)
