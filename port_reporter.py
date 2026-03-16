#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Port Tarama Raporlama Modülü
Port tarama sonuçlarını HTML ve JSON formatında raporlar
"""

import os
from datetime import datetime
import json

class PortReporter:
    def __init__(self, target, scan_results):
        self.target = target
        self.scan_results = scan_results
        self.scan_date = datetime.now().strftime('%d.%m.%Y %H:%M:%S')
        
    def generate_html_report(self):
        """HTML formatında port raporu oluştur"""
        report_filename = f"port_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        report_path = os.path.join(os.getcwd(), "reports", report_filename)
        
        # Reports dizinini oluştur
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        
        # Rapor içeriği
        html_content = self._generate_html_content()
        
        # Raporu kaydet
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        return report_path
        
    def _generate_html_content(self):
        """HTML rapor içeriği oluştur"""
        results = self.scan_results
        
        html = f"""
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Port Tarama Raporu - {self.target}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f8f9fa;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 0 30px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            border-bottom: 4px solid #007bff;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            color: #007bff;
            margin: 0;
            font-size: 2.8em;
        }}
        .header p {{
            color: #666;
            margin: 10px 0 0 0;
            font-size: 1.2em;
        }}
        .summary {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 12px;
            margin-bottom: 30px;
        }}
        .summary h2 {{
            margin-top: 0;
            color: white;
            font-size: 1.8em;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        .summary-item {{
            background: rgba(255,255,255,0.15);
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            backdrop-filter: blur(10px);
        }}
        .summary-item h3 {{
            margin: 0 0 10px 0;
            font-size: 2.5em;
            font-weight: bold;
        }}
        .summary-item p {{
            margin: 0;
            font-size: 1.1em;
        }}
        .section {{
            margin-bottom: 40px;
            border: 1px solid #e9ecef;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }}
        .section-header {{
            padding: 20px;
            font-weight: bold;
            font-size: 1.4em;
            color: white;
        }}
        .section-header.open {{
            background: linear-gradient(135deg, #28a745, #20c997);
        }}
        .section-header.high-risk {{
            background: linear-gradient(135deg, #dc3545, #c82333);
        }}
        .section-header.medium-risk {{
            background: linear-gradient(135deg, #ffc107, #e0a800);
        }}
        .section-header.low-risk {{
            background: linear-gradient(135deg, #17a2b8, #138496);
        }}
        .section-header.summary {{
            background: linear-gradient(135deg, #007bff, #0056b3);
        }}
        .section-content {{
            padding: 25px;
        }}
        .port-item {{
            background: #f8f9fa;
            border-left: 5px solid #28a745;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 0 8px 8px 0;
            transition: transform 0.2s;
        }}
        .port-item:hover {{
            transform: translateX(5px);
            box-shadow: 0 2px 15px rgba(40,167,69,0.2);
        }}
        .port-item.high-risk {{
            border-left-color: #dc3545;
            background: #fff5f5;
        }}
        .port-item.medium-risk {{
            border-left-color: #ffc107;
            background: #fffbf0;
        }}
        .port-item.low-risk {{
            border-left-color: #17a2b8;
            background: #f0fcff;
        }}
        .port-title {{
            font-weight: bold;
            font-size: 1.2em;
            color: #333;
            margin-bottom: 10px;
        }}
        .port-meta {{
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            margin-bottom: 10px;
        }}
        .port-meta-item {{
            background: #e9ecef;
            padding: 5px 10px;
            border-radius: 15px;
            font-size: 0.9em;
        }}
        .risk-high {{
            background: #dc3545;
            color: white;
        }}
        .risk-medium {{
            background: #ffc107;
            color: black;
        }}
        .risk-low {{
            background: #17a2b8;
            color: white;
        }}
        .port-description {{
            margin-bottom: 10px;
            color: #555;
        }}
        .port-banner {{
            background: #e7f3ff;
            border-left: 4px solid #007bff;
            padding: 10px;
            border-radius: 0 5px 5px 0;
            font-family: monospace;
            font-size: 0.9em;
            margin-top: 10px;
            word-break: break-all;
        }}
        .recommendations {{
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 8px;
            padding: 20px;
            margin-top: 30px;
        }}
        .recommendations h2 {{
            color: #856404;
            margin-top: 0;
        }}
        .recommendation-item {{
            background: white;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 5px;
            border-left: 4px solid #ffc107;
        }}
        .recommendation-item h4 {{
            margin: 0 0 10px 0;
            color: #dc3545;
        }}
        .service-distribution {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }}
        .service-item {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #007bff;
        }}
        .service-name {{
            font-weight: bold;
            color: #007bff;
            margin-bottom: 10px;
        }}
        .service-ports {{
            display: flex;
            flex-wrap: wrap;
            gap: 5px;
        }}
        .service-port {{
            background: #007bff;
            color: white;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 0.8em;
        }}
        .no-ports {{
            text-align: center;
            padding: 40px;
            color: #28a745;
            font-size: 1.2em;
            background: #d4edda;
            border-radius: 8px;
            border: 2px solid #c3e6cb;
        }}
        .footer {{
            text-align: center;
            margin-top: 50px;
            padding-top: 30px;
            border-top: 2px solid #e9ecef;
            color: #666;
        }}
        @media (max-width: 768px) {{
            .container {{
                padding: 15px;
            }}
            .summary-grid {{
                grid-template-columns: 1fr;
            }}
            .port-item {{
                padding: 15px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Port Tarama Raporu</h1>
            <p><strong>Hedef:</strong> {self.target}</p>
            <p><strong>Tarih:</strong> {self.scan_date}</p>
        </div>
        
        <div class="summary">
            <h2>📊 Tarama Özeti</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <h3>{results.get('total_ports', 0)}</h3>
                    <p>Toplam Port</p>
                </div>
                <div class="summary-item">
                    <h3>{results.get('open_ports', 0)}</h3>
                    <p>Açık Port</p>
                </div>
                <div class="summary-item">
                    <h3>{results.get('closed_ports', 0)}</h3>
                    <p>Kapalı Port</p>
                </div>
                <div class="summary-item">
                    <h3>{results.get('duration', 'N/A')}</h3>
                    <p>Tarama Süresi</p>
                </div>
            </div>
        </div>
        
        {self._generate_open_ports_section()}
        
        {self._generate_risk_analysis_section()}
        
        {self._generate_service_distribution_section()}
        
        {self._generate_recommendations_section()}
        
        <div class="footer">
            <p>Bu rapor Web Güvenlik Tarama Uygulaması tarafından otomatik olarak oluşturulmuştur.</p>
            <p>Port taraması sonuçları ağ güvenliği analizi için kullanılmalıdır.</p>
            <p>⚠️ Yetkisiz port taraması yasa dışı olabilir. Lütfen sadece kendi ağlarınızda kullanın.</p>
        </div>
    </div>
</body>
</html>
        """
        return html
        
    def _generate_open_ports_section(self):
        """Açık portlar bölümünü oluştur"""
        if 'open_ports_details' not in self.scan_results or not self.scan_results['open_ports_details']:
            return """
            <div class="section">
                <div class="section-header open">
                    🚪 Açık Portlar
                </div>
                <div class="section-content">
                    <div class="no-ports">
                        ✅ Güvenli! Açık port bulunamadı.
                    </div>
                </div>
            </div>
            """
        
        open_ports = self.scan_results['open_ports_details']
        html = f"""
        <div class="section">
            <div class="section-header open">
                🚪 Açık Portlar ({len(open_ports)})
            </div>
            <div class="section-content">
        """
        
        for port_info in open_ports:
            risk_class = f"{port_info['risk_level'].lower()}-risk"
            html += self._format_port_html(port_info, risk_class)
            
        html += "</div></div>"
        return html
        
    def _generate_risk_analysis_section(self):
        """Risk analizi bölümünü oluştur"""
        if 'scan_summary' not in self.scan_results:
            return ""
            
        summary = self.scan_results['scan_summary']
        
        html = """
        <div class="section">
            <div class="section-header summary">
                📈 Risk Analizi
            </div>
            <div class="section-content">
        """
        
        # Risk seviyelerine göre gruplama
        risk_data = {
            'Yüksek Risk': {'class': 'high-risk', 'ports': summary.get('high_risk_ports', [])},
            'Orta Risk': {'class': 'medium-risk', 'ports': summary.get('medium_risk_ports', [])},
            'Düşük Risk': {'class': 'low-risk', 'ports': summary.get('low_risk_ports', [])}
        }
        
        for risk_level, data in risk_data.items():
            if data['ports']:
                html += f"""
                <h4>{risk_level}</h4>
                <div class="port-meta">
                """
                for port in data['ports']:
                    html += f'<span class="port-meta-item {data["class"]}">{port}</span>'
                html += "</div><br>"
        
        html += "</div></div>"
        return html
        
    def _generate_service_distribution_section(self):
        """Servis dağılım bölümünü oluştur"""
        if 'scan_summary' not in self.scan_results:
            return ""
            
        services = self.scan_results['scan_summary'].get('services_found', {})
        
        if not services:
            return ""
            
        html = """
        <div class="section">
            <div class="section-header summary">
                🔧 Servis Dağılımı
            </div>
            <div class="section-content">
                <div class="service-distribution">
        """
        
        for service, ports in services.items():
            html += f"""
            <div class="service-item">
                <div class="service-name">{service}</div>
                <div class="service-ports">
            """
            for port in ports:
                html += f'<span class="service-port">{port}</span>'
            html += "</div></div>"
        
        html += "</div></div>"
        return html
        
    def _generate_recommendations_section(self):
        """Öneriler bölümünü oluştur"""
        from port_scanner import PortScanner
        scanner = PortScanner(self.target)
        recommendations = scanner.get_security_recommendations(self.scan_results)
        
        if not recommendations:
            return """
            <div class="recommendations">
                <h2>🔒 Güvenlik Önerileri</h2>
                <div class="no-ports">
                    ✅ Güvenlik açığı bulunamadı. Sisteminiz güvenli görünüyor!
                </div>
            </div>
            """
        
        html = """
        <div class="recommendations">
            <h2>🔒 Güvenlik Önerileri</h2>
        """
        
        for rec in recommendations:
            html += f"""
            <div class="recommendation-item">
                <h4>Port {rec['port']} - {rec['issue']}</h4>
                <p>{rec['recommendation']}</p>
            </div>
            """
        
        html += "</div>"
        return html
        
    def _format_port_html(self, port_info, risk_class):
        """Port bilgisini HTML formatında göster"""
        html = f"""
        <div class="port-item {risk_class}">
            <div class="port-title">
                Port {port_info['port']}/{port_info['service']}
            </div>
            <div class="port-meta">
                <span class="port-meta-item {risk_class}">{port_info['risk_level']} Risk</span>
                <span class="port-meta-item">🖥️ {port_info['category']}</span>
            </div>
            <div class="port-description">
                Servis: {port_info['service']}
            </div>
        """
        
        if port_info.get('banner') and port_info['banner'] != 'No banner':
            html += f'<div class="port-banner">Banner: {port_info["banner"]}</div>'
            
        html += "</div>"
        return html
        
    def generate_json_report(self):
        """JSON formatında rapor oluştur"""
        report_data = {
            'target': self.target,
            'scan_date': self.scan_date,
            'scan_results': self.scan_results
        }
        
        report_filename = f"port_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report_path = os.path.join(os.getcwd(), "reports", report_filename)
        
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)
            
        return report_path
