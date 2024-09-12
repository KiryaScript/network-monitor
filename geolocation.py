import geoip2.database
import os

class IPGeolocation:
    def __init__(self, db_path='GeoLite2-City.mmdb'):
        self.reader = None
        if os.path.exists(db_path):
            try:
                self.reader = geoip2.database.Reader(db_path)
            except Exception as e:
                print(f"Error loading GeoIP database: {e}")
        else:
            print(f"GeoIP database file not found: {db_path}")

    def get_location(self, ip):
        if self.reader is None:
            return None
        try:
            response = self.reader.city(ip)
            return {
                'country': response.country.name,
                'city': response.city.name,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude
            }
        except:
            return None

    def __del__(self):
        if self.reader:
            self.reader.close()