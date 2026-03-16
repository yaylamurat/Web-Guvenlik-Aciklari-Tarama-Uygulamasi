#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Port Tarama Modülü
Açık portları tespit etmek için kapsamlı port tarama özellikleri
"""

import socket
import threading
import time
import concurrent.futures
from datetime import datetime
import json
import subprocess
import re

class PortScanner:
    def __init__(self, target, timeout=3, max_threads=100):
        self.target = target
        self.timeout = timeout
        self.max_threads = max_threads
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        self.services = {}
        
        # Port kategorileri ve açıklamaları
        self.port_categories = {
            'common_web': {
                'ports': [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995],
                'description': 'Common Web & Network Services'
            },
            'database': {
                'ports': [1433, 1521, 3306, 5432, 6379, 27017, 27018, 27019],
                'description': 'Database Services'
            },
            'mail': {
                'ports': [25, 110, 143, 465, 587, 993, 995],
                'description': 'Mail Services'
            },
            'ftp': {
                'ports': [20, 21, 69, 135, 137, 138, 139],
                'description': 'FTP Services'
            },
            'remote_access': {
                'ports': [22, 23, 3389, 5900, 5901, 5902, 5903],
                'description': 'Remote Access Services'
            },
            'microsoft': {
                'ports': [135, 137, 138, 139, 445, 1433, 3389],
                'description': 'Microsoft Services'
            },
            'development': {
                'ports': [3000, 8000, 8080, 8443, 9000, 9090, 5000, 5001],
                'description': 'Development & Testing'
            },
            'iot_devices': {
                'ports': [1883, 8883, 5683, 8080, 8443, 5000],
                'description': 'IoT & Smart Devices'
            }
        }
        
        # Port servis bilgileri
        self.port_services = {
            20: 'FTP Data',
            21: 'FTP Control',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            67: 'DHCP Server',
            68: 'DHCP Client',
            69: 'TFTP',
            80: 'HTTP',
            110: 'POP3',
            135: 'RPC',
            137: 'NetBIOS Name Service',
            138: 'NetBIOS Datagram Service',
            139: 'NetBIOS Session Service',
            143: 'IMAP',
            161: 'SNMP',
            162: 'SNMP Trap',
            389: 'LDAP',
            443: 'HTTPS',
            445: 'SMB',
            465: 'SMTPS',
            500: 'IKE',
            514: 'Syslog',
            520: 'RIP',
            587: 'SMTP Submission',
            636: 'LDAPS',
            993: 'IMAPS',
            995: 'POP3S',
            1433: 'MSSQL',
            1521: 'Oracle',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5683: 'CoAP',
            5900: 'VNC',
            6379: 'Redis',
            8080: 'HTTP Alternate',
            8443: 'HTTPS Alternate',
            27017: 'MongoDB',
            3000: 'Node.js Default',
            5000: 'Flask Default',
            8000: 'HTTP Dev',
            9000: 'HTTP Admin',
            9090: 'HTTP Admin'
        }
        
    def scan_port(self, port):
        """Tek port tarama"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                # Port açık
                service = self.get_service_info(port)
                banner = self.get_banner(port)
                
                port_info = {
                    'port': port,
                    'status': 'open',
                    'service': service,
                    'banner': banner,
                    'category': self.get_port_category(port),
                    'risk_level': self.assess_port_risk(port, service)
                }
                
                self.open_ports.append(port_info)
                return port_info
                
            sock.close()
            
        except socket.timeout:
            # Port filtered (timeout)
            self.filtered_ports.append(port)
        except Exception:
            # Port closed
            self.closed_ports.append(port)
            
        return None
        
    def get_service_info(self, port):
        """Port servisi bilgisini al"""
        if port in self.port_services:
            return self.port_services[port]
        
        # Yaygın port aralıklarını kontrol et
        if port in range(1, 1024):
            return 'Well-known port'
        elif port in range(1024, 49152):
            return 'Registered port'
        else:
            return 'Dynamic/private port'
            
    def get_banner(self, port):
        """Port banner bilgisini al"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((self.target, port))
            
            # HTTP servisleri için
            if port in [80, 8080, 8000, 3000, 5000, 9000]:
                sock.send(b'GET / HTTP/1.1\r\nHost: ' + self.target.encode() + b'\r\n\r\n')
            elif port in [443, 8443]:
                sock.send(b'GET / HTTP/1.1\r\nHost: ' + self.target.encode() + b'\r\n\r\n')
            elif port == 22:
                # SSH - otomatik banner gönderir
                pass
            elif port == 21:
                # FTP - otomatik banner gönderir
                pass
            elif port == 25:
                # SMTP - otomatik banner gönderir
                pass
            else:
                # Genel veri gönder
                sock.send(b'GET / HTTP/1.1\r\n\r\n')
                
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            # Banner'i temizle
            if len(banner) > 200:
                banner = banner[:200] + '...'
                
            return banner if banner else 'No banner'
            
        except Exception:
            return 'No banner'
            
    def get_port_category(self, port):
        """Port kategorisini belirle"""
        for category, info in self.port_categories.items():
            if port in info['ports']:
                return info['description']
        return 'Other'
        
    def assess_port_risk(self, port, service):
        """Port risk seviyesini değerlendir"""
        high_risk_ports = [21, 23, 135, 139, 445, 1433, 3389, 5900]
        medium_risk_ports = [22, 25, 53, 110, 143, 389, 993, 995, 3306, 5432, 6379, 27017]
        
        if port in high_risk_ports:
            return 'High'
        elif port in medium_risk_ports:
            return 'Medium'
        elif port in [80, 443]:
            return 'Low'
        else:
            return 'Low'
            
    def scan_range(self, start_port, end_port):
        """Port aralığını tara"""
        ports = range(start_port, end_port + 1)
        return self.scan_ports(ports)
        
    def scan_common_ports(self):
        """Yaygın portları tara"""
        common_ports = list(set(sum([info['ports'] for info in self.port_categories.values()], [])))
        return self.scan_ports(common_ports)
        
    def scan_all_ports(self):
        """Tüm portları tara (1-65535)"""
        return self.scan_range(1, 65535)
        
    def scan_ports(self, ports):
        """Port listesini paralel olarak tara"""
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(self.scan_port, port) for port in ports]
            concurrent.futures.wait(futures)
            
        end_time = time.time()
        scan_duration = end_time - start_time
        
        # Sonuçları özetle
        results = {
            'target': self.target,
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'duration': f"{scan_duration:.2f} seconds",
            'total_ports': len(ports),
            'open_ports': len(self.open_ports),
            'closed_ports': len(self.closed_ports),
            'filtered_ports': len(self.filtered_ports),
            'open_ports_details': self.open_ports,
            'scan_summary': self.generate_scan_summary()
        }
        
        return results
        
    def generate_scan_summary(self):
        """Tarama özeti oluştur"""
        summary = {
            'high_risk_ports': [],
            'medium_risk_ports': [],
            'low_risk_ports': [],
            'services_found': {},
            'categories_found': {}
        }
        
        for port_info in self.open_ports:
            risk = port_info['risk_level']
            if risk == 'High':
                summary['high_risk_ports'].append(port_info['port'])
            elif risk == 'Medium':
                summary['medium_risk_ports'].append(port_info['port'])
            else:
                summary['low_risk_ports'].append(port_info['port'])
                
            # Servisler
            service = port_info['service']
            if service not in summary['services_found']:
                summary['services_found'][service] = []
            summary['services_found'][service].append(port_info['port'])
            
            # Kategoriler
            category = port_info['category']
            if category not in summary['categories_found']:
                summary['categories_found'][category] = []
            summary['categories_found'][category].append(port_info['port'])
            
        return summary
        
    def detect_os(self):
        """İşletim sistemi tespiti (basit)"""
        try:
            # TTL değerlerine göre OS tahmini
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW)
            sock.settimeout(2)
            
            # ICMP ping gönder
            sock.sendto(b'', (self.target, 0))
            
            # Cevabı bekle
            try:
                data, addr = sock.recvfrom(1024)
                # TTL değerini al (basit tahmin)
                if len(data) >= 8:
                    ttl = data[8]
                    if ttl <= 64:
                        return 'Linux/Unix'
                    elif ttl <= 128:
                        return 'Windows'
                    else:
                        return 'Cisco/Network Device'
            except:
                pass
                
        except Exception:
            pass
            
        return 'Unknown'
        
    def run_nmap_scan(self, ports=None):
        """Nmap taraması (yüklü ise)"""
        try:
            if ports:
                port_list = ','.join(map(str, ports))
                command = f'nmap -sS -sV -O -p {port_list} {self.target}'
            else:
                command = f'nmap -sS -sV -O {self.target}'
                
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                return self.parse_nmap_output(result.stdout)
            else:
                return {'error': 'Nmap failed: ' + result.stderr}
                
        except subprocess.TimeoutExpired:
            return {'error': 'Nmap scan timeout'}
        except FileNotFoundError:
            return {'error': 'Nmap not found'}
        except Exception as e:
            return {'error': f'Nmap error: {str(e)}'}
            
    def parse_nmap_output(self, output):
        """Nmap çıktısını parse et"""
        results = {
            'target': self.target,
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'open_ports': [],
            'os_guess': 'Unknown',
            'raw_output': output
        }
        
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            
            # Port satırlarını parse et
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_service = parts[0]
                    status = parts[1]
                    service = ' '.join(parts[2:])
                    
                    port_num = int(port_service.split('/')[0])
                    
                    port_info = {
                        'port': port_num,
                        'status': status,
                        'service': service,
                        'banner': '',
                        'category': self.get_port_category(port_num),
                        'risk_level': self.assess_port_risk(port_num, service)
                    }
                    
                    results['open_ports'].append(port_info)
                    
            # OS tahmini
            if 'OS details:' in line:
                results['os_guess'] = line.replace('OS details:', '').strip()
                
        return results
        
    def format_results_text(self, results):
        """Sonuçları metin formatında oluştur"""
        text = f"🔍 PORT TARAMA RAPORU\n"
        text += f"{'='*60}\n\n"
        text += f"Hedef: {results['target']}\n"
        text += f"Tarama Tarihi: {results['scan_time']}\n"
        text += f" Süre: {results['duration']}\n"
        text += f"Toplam Port: {results['total_ports']}\n"
        text += f"Açık Port: {results['open_ports']}\n"
        text += f"Kapalı Port: {results['closed_ports']}\n"
        text += f"Filtrelenmiş Port: {results['filtered_ports']}\n\n"
        
        if 'open_ports_details' in results and results['open_ports_details']:
            text += f"🔴 AÇIK PORTLAR:\n"
            text += f"{'-'*40}\n"
            
            for port_info in results['open_ports_details']:
                risk_emoji = {'High': '🔴', 'Medium': '🟡', 'Low': '🟢'}.get(port_info['risk_level'], '⚪')
                text += f"{risk_emoji} Port {port_info['port']}/{port_info['service']}\n"
                text += f"   Kategori: {port_info['category']}\n"
                text += f"   Risk: {port_info['risk_level']}\n"
                if port_info['banner'] and port_info['banner'] != 'No banner':
                    text += f"   Banner: {port_info['banner'][:100]}\n"
                text += f"{'-'*40}\n"
                
        # Özet bilgiler
        if 'scan_summary' in results:
            summary = results['scan_summary']
            text += f"\n📊 ÖZET:\n"
            text += f"Yüksek Riskli Portlar: {summary['high_risk_ports']}\n"
            text += f"Orta Riskli Portlar: {summary['medium_risk_ports']}\n"
            text += f"Düşük Riskli Portlar: {summary['low_risk_ports']}\n\n"
            
            text += f"🔧 BULUNAN SERVİSLER:\n"
            for service, ports in summary['services_found'].items():
                text += f"• {service}: {ports}\n"
                
        return text
        
    def get_security_recommendations(self, results):
        """Güvenlik önerileri oluştur"""
        recommendations = []
        
        if 'open_ports_details' in results:
            for port_info in results['open_ports_details']:
                port = port_info['port']
                service = port_info['service']
                
                if port == 21:
                    recommendations.append({
                        'port': port,
                        'issue': 'FTP açık',
                        'recommendation': 'FTP yerine SFTP kullanın veya FTP erişimini IP ile kısıtlayın'
                    })
                elif port == 23:
                    recommendations.append({
                        'port': port,
                        'issue': 'Telnet açık',
                        'recommendation': 'Telnet yerine SSH kullanın, Telnet güvensizdir'
                    })
                elif port == 3389:
                    recommendations.append({
                        'port': port,
                        'issue': 'RDP açık',
                        'recommendation': 'RDP erişimini VPN ile kısıtlayın ve güçlü şifreler kullanın'
                    })
                elif port == 445:
                    recommendations.append({
                        'port': port,
                        'issue': 'SMB açık',
                        'recommendation': 'SMB erişimini ağ içi ile kısıtlayın, dışarıya açık olmasın'
                    })
                elif port in [1433, 3306, 5432]:
                    recommendations.append({
                        'port': port,
                        'issue': f'Database ({service}) açık',
                        'recommendation': 'Database erişimini sadece uygulama sunucusu ile kısıtlayın'
                    })
                    
        return recommendations
