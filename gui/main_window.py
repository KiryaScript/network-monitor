from PyQt5.QtWidgets import (QMainWindow, QPushButton, QVBoxLayout, QWidget, QTextEdit, 
                             QLabel, QComboBox, QTabWidget, QHBoxLayout, QFileDialog, QListWidget, QLineEdit, QMessageBox, QStackedWidget)
from PyQt5.QtCore import QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QPalette, QColor
from scapy.all import conf
from scapy.arch import get_windows_if_list
from report_generator import generate_report


class CaptureThread(QThread):
    update_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(dict)

    def __init__(self, traffic_capture):
        super().__init__()
        self.traffic_capture = traffic_capture

    def run(self):
        self.traffic_capture.start_capture(packet_count=100)
        for packet in self.traffic_capture.get_captured_packets():
            self.update_signal.emit(f"{packet['src']} -> {packet['dst']}")
        self.finished_signal.emit(self.traffic_capture.get_analysis_results())

class MainWindow(QMainWindow):
    update_signal = pyqtSignal(dict)

    def __init__(self, traffic_capture):
        super().__init__()
        self.traffic_capture = traffic_capture
        self.interfaces = self.get_interfaces()
        self.init_ui()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_analysis)
        self.is_capturing = False

    def get_interfaces(self):
        interfaces = get_windows_if_list()
        return {f"{iface['name']} ({iface['description']})": iface['name'] for iface in interfaces}

    def init_ui(self):
        self.setWindowTitle("NTM")
        self.setGeometry(100, 100, 1200, 800)

        self.apply_discord_style()

        main_layout = QHBoxLayout()
        
        # Создаем боковую панель
        sidebar = self.create_sidebar()
        main_layout.addWidget(sidebar)

        # Создаем основную область контента
        self.content_area = QStackedWidget()
        self.capture_widget = self.create_capture_widget()
        self.analysis_widget = self.create_analysis_widget()
        self.settings_widget = self.create_settings_widget()

        self.content_area.addWidget(self.capture_widget)
        self.content_area.addWidget(self.analysis_widget)
        self.content_area.addWidget(self.settings_widget)

        main_layout.addWidget(self.content_area, 1)
        
        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

    def apply_discord_style(self):
        self.setStyleSheet("""
            QWidget {
                background-color: #36393f;
                color: #dcddde;
                font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
            }
            QPushButton {
                background-color: #7289da;
                border: none;
                color: white;
                padding: 8px 16px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #677bc4;
            }
            QLineEdit, QTextEdit, QComboBox {
                background-color: #40444b;
                border: 1px solid #202225;
                color: #dcddde;
                padding: 5px;
                border-radius: 4px;
            }
            QListWidget {
                background-color: #2f3136;
                border: 1px solid #202225;
                color: #dcddde;
            }
            QTabWidget::pane {
                border: 1px solid #202225;
                background-color: #2f3136;
            }
            QTabBar::tab {
                background-color: #2f3136;
                color: #dcddde;
                padding: 8px 16px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: #36393f;
            }
        """)

    def create_sidebar(self):
        sidebar = QWidget()
        sidebar.setFixedWidth(200)
        sidebar_layout = QVBoxLayout(sidebar)

        capture_btn = QPushButton("Захват")
        analysis_btn = QPushButton("Анализ")
        settings_btn = QPushButton("Настройки")

        capture_btn.clicked.connect(lambda: self.content_area.setCurrentWidget(self.capture_widget))
        analysis_btn.clicked.connect(lambda: self.content_area.setCurrentWidget(self.analysis_widget))
        settings_btn.clicked.connect(lambda: self.content_area.setCurrentWidget(self.settings_widget))

        sidebar_layout.addWidget(capture_btn)
        sidebar_layout.addWidget(analysis_btn)
        sidebar_layout.addWidget(settings_btn)
        sidebar_layout.addStretch()

        return sidebar

    def create_capture_widget(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        interface_layout = QHBoxLayout()
        interface_layout.addWidget(QLabel("Выберите интерфейс:"))
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(self.interfaces.keys())
        interface_layout.addWidget(self.interface_combo)
        
        layout.addLayout(interface_layout)
        
        self.start_button = QPushButton("Начать захват")
        self.start_button.clicked.connect(self.toggle_capture)
        layout.addWidget(self.start_button)
        
        self.text_area = QTextEdit()
        self.text_area.setReadOnly(True)
        layout.addWidget(self.text_area)

        return widget

    def create_analysis_widget(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        self.analysis_text = QTextEdit()
        self.analysis_text.setReadOnly(True)
        layout.addWidget(self.analysis_text)
        
        self.generate_report_button = QPushButton("Создать отчет")
        self.generate_report_button.clicked.connect(self.generate_report)
        layout.addWidget(self.generate_report_button)
        
        layout.addWidget(QLabel("Оповещения:"))
        self.alerts_list = QListWidget()
        layout.addWidget(self.alerts_list)

        return widget

    def create_settings_widget(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        threshold_layout = QHBoxLayout()
        threshold_layout.addWidget(QLabel("Порог предупреждения (bytes):"))
        self.threshold_input = QLineEdit()
        self.threshold_input.setText("1500")  # Default value
        threshold_layout.addWidget(self.threshold_input)
        layout.addLayout(threshold_layout)

        self.apply_settings_button = QPushButton("Применить настройки")
        self.apply_settings_button.clicked.connect(self.apply_settings)
        layout.addWidget(self.apply_settings_button)

        return widget

    def apply_settings(self):
        try:
            threshold = int(self.threshold_input.text())
            self.traffic_capture.analyzer.set_alert_threshold(threshold)
            QMessageBox.information(self, "Настройки сохраненны", "Новые настройки были успешно применены.")
        except ValueError:
            QMessageBox.warning(self, "Неверный ввод", "Введите действительное число для порога оповещения.")

    def generate_report(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Сохранить отчет", "", "PDF Files (*.pdf)")
        if filename:
            # Получаем данные анализа
            data = self.traffic_capture.get_analysis_results()
        
            # Добавляем геолокацию к данным
            data['geolocation'] = {}
            for ip, _ in data['top_ips']:
                location = self.traffic_capture.geolocation.get_location(ip)
                if location:
                    data['geolocation'][ip] = location
        
            # Генерируем отчет
            generate_report(filename, data)
        
            QMessageBox.information(self, "Отчёт создан", f"Отчет был сохранен в {filename}")

    def toggle_capture(self):
        if not self.is_capturing:
            self.start_capture()
        else:
            self.stop_capture()

    def start_capture(self):
        self.text_area.clear()
        self.analysis_text.clear()
        selected_interface_name = self.interface_combo.currentText()
        selected_interface = self.interfaces[selected_interface_name]
        self.traffic_capture.start_capture(interface=selected_interface)
        self.timer.start(150)  # Обновление каждые 0.15 секунды
        self.is_capturing = True
        self.start_button.setText("Остановить захват")

    def stop_capture(self):
        self.traffic_capture.stop_capture()
        self.timer.stop()
        self.is_capturing = False
        self.start_button.setText("Начать захват")

    def update_analysis(self):
        packets = self.traffic_capture.get_captured_packets()
        results = self.traffic_capture.get_analysis_results()
        self.show_packets(packets)
        self.show_analysis_results(results)

    def show_analysis_results(self, results):
        self.analysis_text.clear()
        self.analysis_text.append("Топ IP-адреса:")
        for ip, count in results['top_ips']:
            self.analysis_text.append(f"{ip}: {count}")
        self.analysis_text.append("\nРаспределение протоколов:")
        for proto, count in results['protocol_distribution'].items():
            self.analysis_text.append(f"{proto}: {count}")
        self.analysis_text.append(f"\nВсего байт: {results['total_bytes']}")
        self.analysis_text.append("\nАномалии:")
        for ip, count in results['anomalies']:
            self.analysis_text.append(f"{ip}: {count}")
    
        # Обработка оповещений
        self.alerts_list.clear()
        if 'alerts' in results and results['alerts']:
            for alert in results['alerts']:
                self.alerts_list.addItem(alert)
        else:
            self.alerts_list.addItem("Нет оповещений")

    def show_packets(self, packets):
        self.text_area.clear()
        for packet in packets[-50:]:
            src_location = packet.get('src_location') or {}
            dst_location = packet.get('dst_location') or {}
        
            src_info = f"{packet['src']} ({src_location.get('country', 'Unknown')}, {src_location.get('city', 'Unknown')})"
            dst_info = f"{packet['dst']} ({dst_location.get('country', 'Unknown')}, {dst_location.get('city', 'Unknown')})"
        
            self.text_area.append(f"{src_info} -> {dst_info} "
                                f"(Proto: {packet['proto']}, Len: {packet['len']})")