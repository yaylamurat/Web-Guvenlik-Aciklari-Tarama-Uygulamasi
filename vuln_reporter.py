#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Güvenlik Açığı Raporlama Modülü
Son güvenlik açıklarını PDF ve HTML formatında raporlar
"""

import os
from datetime import datetime
from vulnerability_db import VulnerabilityDatabase

class VulnerabilityReporter:
    def __init__(self):
        self.vuln_db = VulnerabilityDatabase()
        
    def generate_vulnerability_report(self, format_type='html'):
        """Güvenlik açığı raporu oluştur"""
        if format_type.lower() == 'html':
            return self.generate_html_report()
        elif format_type.lower() == 'json':
            return self.generate_json_report()
        else:
            raise ValueError("Desteklenmeyen format: " + format_type)
            
    def generate_html_report(self):
        """HTML formatında açık raporu oluştur"""
        report_filename = f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
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
        summary = self.vuln_db.get_vulnerability_summary()
        recent_vulns = self.vuln_db.get_recent_vulnerabilities(30)
        critical_vulns = self.vuln_db.get_critical_vulnerabilities()
        
        html = f"""
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Son Güvenlik Açıkları Raporu</title>
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
            border-bottom: 4px solid #dc3545;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            color: #dc3545;
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
        .section-header.critical {{
            background: linear-gradient(135deg, #dc3545, #c82333);
        }}
        .section-header.recent {{
            background: linear-gradient(135deg, #ffc107, #e0a800);
        }}
        .section-header.summary {{
            background: linear-gradient(135deg, #007bff, #0056b3);
        }}
        .section-content {{
            padding: 25px;
        }}
        .vulnerability-item {{
            background: #f8f9fa;
            border-left: 5px solid #dc3545;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 0 8px 8px 0;
            transition: transform 0.2s;
        }}
        .vulnerability-item:hover {{
            transform: translateX(5px);
            box-shadow: 0 2px 15px rgba(220,53,69,0.2);
        }}
        .vulnerability-item.critical {{
            border-left-color: #dc3545;
            background: #fff5f5;
        }}
        .vulnerability-item.high {{
            border-left-color: #fd7e14;
            background: #fff8f3;
        }}
        .vulnerability-item.medium {{
            border-left-color: #ffc107;
            background: #fffbf0;
        }}
        .vulnerability-item.low {{
            border-left-color: #28a745;
            background: #f0fff4;
        }}
        .vuln-title {{
            font-weight: bold;
            font-size: 1.2em;
            color: #333;
            margin-bottom: 10px;
        }}
        .vuln-meta {{
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            margin-bottom: 10px;
        }}
        .vuln-meta-item {{
            background: #e9ecef;
            padding: 5px 10px;
            border-radius: 15px;
            font-size: 0.9em;
        }}
        .severity-critical {{
            background: #dc3545;
            color: white;
        }}
        .severity-high {{
            background: #fd7e14;
            color: white;
        }}
        .severity-medium {{
            background: #ffc107;
            color: black;
        }}
        .severity-low {{
            background: #28a745;
            color: white;
        }}
        .vuln-description {{
            margin-bottom: 10px;
            color: #555;
        }}
        .vuln-solution {{
            background: #e7f3ff;
            border-left: 4px solid #007bff;
            padding: 10px;
            border-radius: 0 5px 5px 0;
            font-weight: 500;
        }}
        .system-distribution {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }}
        .system-item {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #007bff;
        }}
        .system-name {{
            font-weight: bold;
            color: #007bff;
            margin-bottom: 10px;
        }}
        .system-stats {{
            display: flex;
            justify-content: space-between;
            font-size: 0.9em;
        }}
        .footer {{
            text-align: center;
            margin-top: 50px;
            padding-top: 30px;
            border-top: 2px solid #e9ecef;
            color: #666;
        }}
        .no-vulnerabilities {{
            text-align: center;
            padding: 40px;
            color: #28a745;
            font-size: 1.2em;
            background: #d4edda;
            border-radius: 8px;
            border: 2px solid #c3e6cb;
        }}
        @media (max-width: 768px) {{
            .container {{
                padding: 15px;
            }}
            .summary-grid {{
                grid-template-columns: 1fr;
            }}
            .vulnerability-item {{
                padding: 15px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Son Güvenlik Açıkları Raporu</h1>
            <p><strong>Rapor Tarihi:</strong> {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}</p>
        </div>
        
        <div class="summary">
            <h2>📊 Genel Özet</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <h3>{summary['TOTAL']['total']}</h3>
                    <p>Toplam Açık</p>
                </div>
                <div class="summary-item">
                    <h3>{summary['TOTAL']['critical']}</h3>
                    <p>Kritik Açık</p>
                </div>
                <div class="summary-item">
                    <h3>{summary['TOTAL']['high']}</h3>
                    <p>Yüksek Risk</p>
                </div>
                <div class="summary-item">
                    <h3>{len(recent_vulns)}</h3>
                    <p>Son 30 Gün</p>
                </div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-header summary">
                📈 Sistemlere Göre Dağılım
            </div>
            <div class="section-content">
                <div class="system-distribution">
                    {self._generate_system_distribution(summary)}
                </div>
            </div>
        </div>
        
        {self._generate_critical_section(critical_vulns)}
        
        {self._generate_recent_section(recent_vulns)}
        
        <div class="footer">
            <p>Bu rapor Web Güvenlik Tarama Uygulaması tarafından otomatik olarak oluşturulmuştur.</p>
            <p>Güvenlik açıkları veritabanı düzenli olarak güncellenmektedir.</p>
            <p>⚠️ Bu rapor sadece bilgilendirme amaçlıdır. Lütfen profesyonel güvenlik uzmanlarıyla danışın.</p>
        </div>
    </div>
</body>
</html>
        """
        return html
        
    def _generate_system_distribution(self, summary):
        """Sistem dağılım HTML'i oluştur"""
        html = ""
        for system, data in summary.items():
            if system != 'TOTAL':
                html += f"""
                <div class="system-item">
                    <div class="system-name">{system}</div>
                    <div class="system-stats">
                        <span>Toplam: {data['total']}</span>
                        <span>K: {data['critical']}</span>
                        <span>Y: {data['high']}</span>
                        <span>O: {data['medium']}</span>
                        <span>D: {data['low']}</span>
                    </div>
                </div>
                """
        return html
        
    def _generate_critical_section(self, critical_vulns):
        """Kritik açıklar bölümünü oluştur"""
        if not critical_vulns:
            return """
            <div class="section">
                <div class="section-header critical">
                    🚨 Kritik Açıklar
                </div>
                <div class="section-content">
                    <div class="no-vulnerabilities">
                        ✅ Güvenli! Kritik seviyede açık bulunmuyor.
                    </div>
                </div>
            </div>
            """
        
        html = """
        <div class="section">
            <div class="section-header critical">
                🚨 Kritik Açıklar ({len(critical_vulns)})
            </div>
            <div class="section-content">
        """
        
        for vuln in critical_vulns:
            html += self._format_vulnerability_html(vuln)
            
        html += "</div></div>"
        return html
        
    def _generate_recent_section(self, recent_vulns):
        """Son açıklar bölümünü oluştur"""
        if not recent_vulns:
            return """
            <div class="section">
                <div class="section-header recent">
                    🕐 Son 30 Gündeki Açıklar
                </div>
                <div class="section-content">
                    <div class="no-vulnerabilities">
                        ✅ Son 30 günde yeni açık bulunamadı.
                    </div>
                </div>
            </div>
            """
        
        html = f"""
        <div class="section">
            <div class="section-header recent">
                🕐 Son 30 Gündeki Açıklar ({len(recent_vulns)})
            </div>
            <div class="section-content">
        """
        
        for vuln in recent_vulns[:20]:  # İlk 20'yi göster
            html += self._format_vulnerability_html(vuln)
            
        html += "</div></div>"
        return html
        
    def _format_vulnerability_html(self, vuln):
        """Açık bilgisini HTML formatında göster"""
        severity_class = f"severity-{vuln['severity'].lower()}"
        item_class = f"vulnerability-item {vuln['severity'].lower()}"
        
        html = f"""
        <div class="{item_class}">
            <div class="vuln-title">
                [{vuln['id']}] {vuln['title']}
            </div>
            <div class="vuln-meta">
                <span class="vuln-meta-item {severity_class}">{vuln['severity']}</span>
                <span class="vuln-meta-item">🖥️ {vuln['system']}</span>
                <span class="vuln-meta-item">📦 {vuln['version']}</span>
                <span class="vuln-meta-item">📅 {vuln['date']}</span>
            </div>
            <div class="vuln-description">
                <strong>Açıklama:</strong> {vuln['description']}
            </div>
            <div class="vuln-solution">
                <strong>💡 Çözüm:</strong> {vuln['solution']}
            </div>
        </div>
        """
        return html
        
    def generate_json_report(self):
        """JSON formatında rapor oluştur"""
        report_data = {
            'report_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'summary': self.vuln_db.get_vulnerability_summary(),
            'critical_vulnerabilities': self.vuln_db.get_critical_vulnerabilities(),
            'recent_vulnerabilities': self.vuln_db.get_recent_vulnerabilities(30),
            'all_vulnerabilities': self.vuln_db.get_all_vulnerabilities()
        }
        
        report_filename = f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report_path = os.path.join(os.getcwd(), "reports", report_filename)
        
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        
        import json
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)
            
        return report_path
