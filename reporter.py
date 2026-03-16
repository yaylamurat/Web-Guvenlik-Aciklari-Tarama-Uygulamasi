#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Güvenlik Raporlama Modülü
Tarama sonuçlarını HTML ve PDF formatında raporlar
"""

import os
from datetime import datetime
import json

class SecurityReporter:
    def __init__(self, target_url, scan_results):
        self.target_url = target_url
        self.scan_results = scan_results
        self.scan_date = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
        
    def generate_html_report(self):
        """HTML formatında güvenlik raporu oluştur"""
        report_filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
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
        total_vulnerabilities = sum(len(findings) for findings in self.scan_results.values() if findings)
        
        html = f"""
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Güvenlik Raporu - {self.target_url}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            border-bottom: 3px solid #007bff;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            color: #007bff;
            margin: 0;
            font-size: 2.5em;
        }}
        .header p {{
            color: #666;
            margin: 10px 0 0 0;
            font-size: 1.1em;
        }}
        .summary {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
        }}
        .summary h2 {{
            margin-top: 0;
            color: white;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        .summary-item {{
            background: rgba(255,255,255,0.1);
            padding: 15px;
            border-radius: 5px;
            text-align: center;
        }}
        .summary-item h3 {{
            margin: 0 0 10px 0;
            font-size: 2em;
        }}
        .vulnerability-section {{
            margin-bottom: 30px;
            border: 1px solid #ddd;
            border-radius: 8px;
            overflow: hidden;
        }}
        .vulnerability-header {{
            padding: 15px 20px;
            font-weight: bold;
            font-size: 1.2em;
        }}
        .vulnerability-header.high {{
            background-color: #dc3545;
            color: white;
        }}
        .vulnerability-header.medium {{
            background-color: #ffc107;
            color: black;
        }}
        .vulnerability-header.low {{
            background-color: #28a745;
            color: white;
        }}
        .vulnerability-header.safe {{
            background-color: #17a2b8;
            color: white;
        }}
        .vulnerability-content {{
            padding: 20px;
        }}
        .vulnerability-item {{
            background: #f8f9fa;
            border-left: 4px solid #dc3545;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 0 5px 5px 0;
        }}
        .vulnerability-item.safe {{
            border-left-color: #28a745;
            background: #d4edda;
        }}
        .recommendations {{
            background: #e7f3ff;
            border: 1px solid #007bff;
            border-radius: 8px;
            padding: 20px;
            margin-top: 30px;
        }}
        .recommendations h2 {{
            color: #007bff;
            margin-top: 0;
        }}
        .recommendation-item {{
            margin-bottom: 15px;
            padding: 10px;
            background: white;
            border-radius: 5px;
            border-left: 4px solid #007bff;
        }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #666;
        }}
        .severity-badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 0.8em;
            font-weight: bold;
            margin-left: 10px;
        }}
        .severity-high {{
            background-color: #dc3545;
            color: white;
        }}
        .severity-medium {{
            background-color: #ffc107;
            color: black;
        }}
        .severity-low {{
            background-color: #28a745;
            color: white;
        }}
        ul {{
            margin: 10px 0;
            padding-left: 20px;
        }}
        li {{
            margin-bottom: 5px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Web Güvenlik Raporu</h1>
            <p><strong>Hedef:</strong> {self.target_url}</p>
            <p><strong>Tarih:</strong> {self.scan_date}</p>
        </div>
        
        <div class="summary">
            <h2>📊 Özet</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <h3>{total_vulnerabilities}</h3>
                    <p>Toplam Açık</p>
                </div>
                <div class="summary-item">
                    <h3>{len(self.scan_results)}</h3>
                    <p>Kontrol Kategorisi</p>
                </div>
                <div class="summary-item">
                    <h3>{self._get_risk_level()}</h3>
                    <p>Risk Seviyesi</p>
                </div>
            </div>
        </div>
        
        {self._generate_vulnerability_sections()}
        
        <div class="recommendations">
            <h2>🔧 Güvenlik Önerileri</h2>
            {self._generate_recommendations()}
        </div>
        
        <div class="footer">
            <p>Bu rapor Web Güvenlik Tarama Uygulaması tarafından otomatik olarak oluşturulmuştur.</p>
            <p>Raporun doğruluğunu kontrol etmek için manuel testler önerilir.</p>
        </div>
    </div>
</body>
</html>
        """
        return html
        
    def _generate_vulnerability_sections(self):
        """Zafiyet bölümlerini oluştur"""
        sections = ""
        
        category_info = {
            'sql_injection': {
                'title': 'SQL Injection Açıkları',
                'severity': 'high',
                'description': 'SQL Injection, veritabanı sorgularına kötü niyetli SQL kodları enjekte edilerek veritabanına yetkisiz erişim sağlanmasıdır.'
            },
            'xss': {
                'title': 'Cross-Site Scripting (XSS) Açıkları',
                'severity': 'high',
                'description': 'XSS, web sayfalarına kötü niyetli script kodları enjekte edilerek kullanıcı bilgilerinin çalınmasıdır.'
            },
            'csrf': {
                'title': 'Cross-Site Request Forgery (CSRF) Açıkları',
                'severity': 'medium',
                'description': 'CSRF, kullanıcının haberi olmadan istenmeyen işlemlerin yapılmasını sağlayan saldırıdır.'
            },
            'directory_listing': {
                'title': 'Dizin Listeleme Açıkları',
                'severity': 'medium',
                'description': 'Dizin listeleme, web sunucusundaki dosya ve dizinlerin yetkisiz erişime açık olmasıdır.'
            },
            'security_headers': {
                'title': 'Güvenlik Başlığı Eksiklikleri',
                'severity': 'low',
                'description': 'Güvenlik başlıkları, çeşitli web saldırılarına karşı koruma sağlayan HTTP başlıklarıdır.'
            },
            'ssl': {
                'title': 'SSL/TLS Güvenlik Problemleri',
                'severity': 'medium',
                'description': 'SSL/TLS sorunları, veri iletişiminin güvenliğini etkileyen konfigürasyon hatalarıdır.'
            }
        }
        
        for category, findings in self.scan_results.items():
            if category in category_info:
                info = category_info[category]
                severity_class = info['severity']
                
                if findings:
                    header_class = f"vulnerability-header {severity_class}"
                    sections += f"""
                    <div class="vulnerability-section">
                        <div class="{header_class}">
                            {info['title']} <span class="severity-badge severity-{severity_class}">{len(findings)} Açık</span>
                        </div>
                        <div class="vulnerability-content">
                            <p><strong>Açıklama:</strong> {info['description']}</p>
                            <h4>Tespit Edilen Açıklar:</h4>
                    """
                    
                    for finding in findings:
                        sections += f'<div class="vulnerability-item">🔴 {finding}</div>'
                    
                    sections += "</div></div>"
                else:
                    sections += f"""
                    <div class="vulnerability-section">
                        <div class="vulnerability-header safe">
                            {info['title']} <span class="severity-badge severity-low">Güvenli</span>
                        </div>
                        <div class="vulnerability-content">
                            <div class="vulnerability-item safe">✅ Bu kategoride hiç açık bulunamadı.</div>
                        </div>
                    </div>
                    """
        
        return sections
        
    def _generate_recommendations(self):
        """Güvenlik önerileri oluştur"""
        recommendations = ""
        
        all_recommendations = {
            'sql_injection': [
                'Kullanıcı girdilerini her zaman doğrulayın ve temizleyin',
                'Prepared statements ve parameterized queries kullanın',
                'ORM (Object-Relational Mapping) araçlarını tercih edin',
                'Minimum yetki prensibini uygulayın',
                'Veritabanı hata mesajlarını kullanıcıya göstermeyin'
            ],
            'xss': [
                'Kullanıcı girdilerini HTML encode edin',
                'Content Security Policy (CSP) başlığını kullanın',
                'X-XSS-Protection başlığını ekleyin',
                'Input validation ve output encoding uygulayın',
                'Güvenli template engine\'leri kullanın'
            ],
            'csrf': [
                'CSRF token\'ları kullanın',
                'SameSite cookie attribute\'ünü ayarlayın',
                'Önemli işlemler için二次 doğrulama ekleyin',
                'Origin ve Referer başlıklarını kontrol edin',
                'Custom request headers kullanın'
            ],
            'directory_listing': [
                'Web sunucusu konfigürasyonunda dizin listelemeyi devre dışı bırakın',
                'Önemli dosyaları web root dışında tutun',
                'Access control listeleri (ACL) kullanın',
                'Varsayılan konfigürasyonları değiştirin',
                'Dosya izinlerini doğru ayarlayın'
            ],
            'security_headers': [
                'X-Frame-Options başlığını ekleyin',
                'Strict-Transport-Security (HSTS) kullanın',
                'Content-Security-Policy (CSP) yapılandırın',
                'X-Content-Type-Options: nosniff ekleyin',
                'Referrer-Policy başlığını ayarlayın'
            ],
            'ssl': [
                'HTTPS kullanımını zorunlu kılın',
                'SSL sertifikalarını düzenli olarak güncelleyin',
                'Zayıf SSL/TLS versiyonlarını devre dışı bırakın',
                'Perfect Forward Secrecy (PFS) kullanın',
                'OCSP Stapling\'i etkinleştirin'
            ]
        }
        
        for category, findings in self.scan_results.items():
            if findings and category in all_recommendations:
                recommendations += f"<div class='recommendation-item'><h4>{category.replace('_', ' ').title()} için Öneriler:</h4><ul>"
                for rec in all_recommendations[category]:
                    recommendations += f"<li>{rec}</li>"
                recommendations += "</ul></div>"
        
        if not recommendations:
            recommendations = "<p>Tebrikler! Hiç güvenlik açığı bulunamadı. Yine de düzenli güvenlik kontrolleri yapmanız önerilir.</p>"
        
        return recommendations
        
    def _get_risk_level(self):
        """Risk seviyesini belirle"""
        total_vulnerabilities = sum(len(findings) for findings in self.scan_results.values() if findings)
        
        if total_vulnerabilities == 0:
            return "Düşük"
        elif total_vulnerabilities <= 3:
            return "Orta"
        else:
            return "Yüksek"
            
    def generate_json_report(self):
        """JSON formatında rapor oluştur"""
        report_data = {
            'target_url': self.target_url,
            'scan_date': self.scan_date,
            'total_vulnerabilities': sum(len(findings) for findings in self.scan_results.values() if findings),
            'risk_level': self._get_risk_level(),
            'results': self.scan_results
        }
        
        report_filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report_path = os.path.join(os.getcwd(), "reports", report_filename)
        
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)
            
        return report_path
