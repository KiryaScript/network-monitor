import sys
import os
from PyQt5.QtWidgets import QApplication, QMessageBox
from gui.main_window import MainWindow
from traffic_capture import TrafficCapture
from geolocation import IPGeolocation

def main():
    app = QApplication(sys.argv)
    
    db_path = 'GeoLite2-City.mmdb'
    if not os.path.exists(db_path):
        QMessageBox.warning(None, "GeoIP Database Missing", 
                            f"The GeoIP database file '{db_path}' is missing. "
                            "Geolocation features will be disabled.")
    
    geolocation = IPGeolocation(db_path)
    traffic_capture = TrafficCapture(geolocation)
    main_window = MainWindow(traffic_capture)
    main_window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()