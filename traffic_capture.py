from scapy.all import sniff, IP
from traffic_analysis import TrafficAnalyzer
from geolocation import IPGeolocation
from threading import Thread
from collections import deque

class TrafficCapture:
    def __init__(self, geolocation):
        self.packets = deque(maxlen=100)
        self.analyzer = TrafficAnalyzer()
        self.geolocation = geolocation
        self.is_running = False
        self.capture_thread = None

    def start_capture(self, interface=None):
        if self.is_running:
            return
        self.is_running = True
        self.capture_thread = Thread(target=self._capture_packets, args=(interface,))
        self.capture_thread.start()

    def stop_capture(self):
        self.is_running = False
        if self.capture_thread:
            self.capture_thread.join()

    def _capture_packets(self, interface):
        def process_packet(packet):
            if IP in packet:
                packet_info = {
                    "src": packet[IP].src,
                    "dst": packet[IP].dst,
                    "proto": packet[IP].proto,
                    "len": len(packet)
                }
                if self.geolocation and self.geolocation.reader:
                    packet_info['src_location'] = self.geolocation.get_location(packet_info['src']) or {}
                    packet_info['dst_location'] = self.geolocation.get_location(packet_info['dst']) or {}
                self.packets.append(packet_info)
                self.analyzer.analyze_packet(packet_info)

        while self.is_running:
            sniff(iface=interface, prn=process_packet, count=1, timeout=0.1)

    def get_captured_packets(self):
        return list(self.packets)

    def get_analysis_results(self):
        return {
            "top_ips": self.analyzer.get_top_ips(),
            "protocol_distribution": self.analyzer.get_protocol_distribution(),
            "total_bytes": self.analyzer.get_total_bytes(),
            "anomalies": self.analyzer.detect_anomalies(),
            "alerts": self.analyzer.get_alerts()  # Добавьте эту строку
        }