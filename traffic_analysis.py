from collections import defaultdict
import ipaddress

class TrafficAnalyzer:
    def __init__(self):
        self.ip_count = defaultdict(int)
        self.protocol_count = defaultdict(int)
        self.total_bytes = 0
        self.alerts = []
        self.alert_threshold = 1500

    def analyze_packet(self, packet):
        self.ip_count[packet['src']] += 1
        self.ip_count[packet['dst']] += 1
        self.protocol_count[packet['proto']] += 1
        self.total_bytes += packet['len']
        self.ip_count[packet['src']] += 1
        self.ip_count[packet['dst']] += 1
        self.protocol_count[packet['proto']] += 1
        self.total_bytes += packet['len']
        self.check_alerts(packet)

    def set_alert_threshold(self, threshold):
        self.alert_threshold = threshold

    def check_alerts(self, packet):
        if packet['len'] > self.alert_threshold:
            self.alerts.append(f"Large packet detected: {packet['src']} -> {packet['dst']} ({packet['len']} bytes)")

    def get_alerts(self):
        alerts = self.alerts.copy()
        self.alerts.clear()
        return alerts

    def get_top_ips(self, n=5):
        return sorted(self.ip_count.items(), key=lambda x: x[1], reverse=True)[:n]

    def get_protocol_distribution(self):
        return dict(self.protocol_count)

    def get_total_bytes(self):
        return self.total_bytes

    def detect_anomalies(self, threshold=100):
        anomalies = []
        for ip, count in self.ip_count.items():
            if count > threshold:
                anomalies.append((ip, count))
        return anomalies