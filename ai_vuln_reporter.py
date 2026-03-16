#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI Güvenlik Açığı Raporlama Modülü
AI analiz sonuçlarını HTML formatında raporlar
"""

import os
from datetime import datetime
import json

class AIVulnerabilityReporter:
    def __init__(self, ai_results):
        self.ai_results = ai_results
        self.report_date = datetime.now().strftime('%d.%m.%Y %H:%M:%S')
        
    def generate_html_report(self):
        """HTML formatında AI analiz raporu oluştur"""
        report_filename = f"ai_vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
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
        vulnerabilities = self.ai_results.get('vulnerabilities', [])
        
        html = f"""
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🤖 AI Güvenlik Analiz Raporu</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
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
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            margin: -30px -30px 30px -30px;
            padding: 30px;
            border-radius: 15px 15px 0 0;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.8em;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        .header .ai-badge {{
            display: inline-block;
            background: rgba(255,255,255,0.2);
            padding: 5px 15px;
            border-radius: 20px;
            margin-top: 10px;
            font-size: 1.1em;
        }}
        .summary {{
            background: linear-gradient(135deg, #28a745, #20c997);
            color: white;
            padding: 25px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 4px 15px rgba(40,167,69,0.3);
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
            border: 1px solid rgba(255,255,255,0.3);
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
        .section-header.high {{
            background: linear-gradient(135deg, #ffc107, #e0a800);
        }}
        .section-header.medium {{
            background: linear-gradient(135deg, #17a2b8, #138496);
        }}
        .section-header.low {{
            background: linear-gradient(135deg, #6c757d, #5a6268);
        }}
        .section-content {{
            padding: 25px;
        }}
        .vulnerability {{
            background: #f8f9fa;
            border-left: 5px solid #007bff;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 0 8px 8px 0;
            transition: transform 0.2s;
        }}
        .vulnerability:hover {{
            transform: translateX(5px);
            box-shadow: 0 2px 15px rgba(0,123,255,0.2);
        }}
        .vulnerability.critical {{
            border-left-color: #dc3545;
            background: #fff5f5;
        }}
        .vulnerability.high {{
            border-left-color: #ffc107;
            background: #fffbf0;
        }}
        .vulnerability.medium {{
            border-left-color: #17a2b8;
            background: #f0fcff;
        }}
        .vulnerability.low {{
            border-left-color: #6c757d;
            background: #f8f9fa;
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
            gap: 10px;
            margin-bottom: 10px;
        }}
        .vuln-meta-item {{
            background: #e9ecef;
            padding: 5px 10px;
            border-radius: 15px;
            font-size: 0.9em;
        }}
        .cvss-critical {{
            background: #dc3545;
            color: white;
        }}
        .cvss-high {{
            background: #ffc107;
            color: black;
        }}
        .cvss-medium {{
            background: #17a2b8;
            color: white;
        }}
        .cvss-low {{
            background: #6c757d;
            color: white;
        }}
        .vuln-description {{
            margin-bottom: 15px;
            color: #555;
            line-height: 1.6;
        }}
        .vuln-impact {{
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 5px;
            padding: 10px;
            margin-bottom: 10px;
        }}
        .vuln-solution {{
            background: #d4edda;
            border: 1px solid #c3e6cb;
            border-radius: 5px;
            padding: 10px;
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
        .footer {{
            text-align: center;
            margin-top: 50px;
            padding-top: 30px;
            border-top: 2px solid #e9ecef;
            color: #666;
        }}
        .ai-insights {{
            background: linear-gradient(135deg, #ff6b6b, #4ecdc4);
            color: white;
            padding: 25px;
            border-radius: 12px;
            margin-bottom: 30px;
        }}
        .trending-badge {{
            display: inline-block;
            background: #ff6b6b;
            color: white;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.8em;
            margin-left: 10px;
            animation: pulse 2s infinite;
        }}
        @keyframes pulse {{
            0% {{ opacity: 1; }}
            50% {{ opacity: 0.7; }}
            100% {{ opacity: 1; }}
        }}
        @media (max-width: 768px) {{
            .container {{
                padding: 15px;
            }}
            .summary-grid {{
                grid-template-columns: 1fr;
            }}
            .vulnerability {{
                padding: 15px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🤖 AI Güvenlik Analiz Raporu</h1>
            <div class="ai-badge">Yapay Zeka Destekli Analiz</div>
            <p style="margin: 10px 0 0 0; opacity: 0.9;">
                <strong>Tarih:</strong> {self.report_date} | 
                <strong>Analiz Süresi:</strong> {self.ai_results.get('days_analyzed', 'N/A')} gün
            </p>
        </div>
        
        <div class="summary">
            <h2>📊 Analiz Özeti</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <h3>{len(vulnerabilities)}</h3>
                    <p>Toplam Açık</p>
                </div>
                <div class="summary-item">
                    <h3>{len([v for v in vulnerabilities if v.get('severity', '').lower() == 'critical'])}</h3>
                    <p>Kritik Açık</p>
                </div>
                <div class="summary-item">
                    <h3>{len([v for v in vulnerabilities if v.get('severity', '').lower() == 'high'])}</h3>
                    <p>Yüksek Risk</p>
                </div>
                <div class="summary-item">
                    <h3>{self.ai_results.get('scan_date', 'N/A').split(' ')[1]}</h3>
                    <p>Analiz Saati</p>
                </div>
            </div>
        </div>
        
        {self._generate_ai_insights_section()}
        
        {self._generate_vulnerabilities_section()}
        
        <div class="footer">
            <p>Bu rapor Yapay Zeka destekli güvenlik analizi ile otomatik olarak oluşturulmuştur.</p>
            <p>🤖 NVIDIA AI API kullanılarak güncel siber güvenlik açıkları analiz edilmiştir.</p>
            <p>⚠️ Bu rapor sadece bilgilendirme amaçlıdır. Profesyonel güvenlik uzmanlarıyla teyit edin.</p>
        </div>
    </div>
</body>
</html>
        """
        return html
        
    def _generate_ai_insights_section(self):
        """AI içgörüleri bölümünü oluştur"""
        vulnerabilities = self.ai_results.get('vulnerabilities', [])
        
        if not vulnerabilities:
            return """
            <div class="ai-insights">
                <h2>🎯 AI İçgörüleri</h2>
                <p style="font-size: 1.1em; margin-bottom: 0;">✅ Harika haber! Analiz edilen sistemlerde güncel güvenlik açığı bulunamadı.</p>
                <p style="margin-top: 10px;">Bu, sistemlerinizin güncel ve güvenli olduğunu gösteriyor.</p>
            </div>
            """
        
        # En yaygın sistemleri belirle
        affected_systems = {}
        for vuln in vulnerabilities:
            for system in vuln.get('affected_systems', []):
                affected_systems[system] = affected_systems.get(system, 0) + 1
        
        most_affected = sorted(affected_systems.items(), key=lambda x: x[1], reverse=True)[:3]
        
        # Exploit durumunu analiz et
        exploitable = len([v for v in vulnerabilities if v.get('exploit_status', '').lower() in ['public', 'poc']])
        
        insights_html = """
        <div class="ai-insights">
            <h2>🎯 AI İçgörüleri</h2>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px;">
                <div>
                    <h4>🔥 En Çok Etkilenen Sistemler:</h4>
                    <ul style="margin: 10px 0; padding-left: 20px;">
        """
        
        for system, count in most_affected:
            insights_html += f"<li><strong>{system}:</strong> {count} açık</li>"
        
        insights_html += f"""
                    </ul>
                </div>
                <div>
                    <h4>⚡ Exploit Durumu:</h4>
                    <p style="margin: 10px 0;">
                        <span style="color: {'#dc3545' if exploitable > 0 else '#28a745'}; font-weight: bold;">
                            {exploitable} açık ({(exploitable/len(vulnerabilities)*100):.1f}%)
                        </span>
                        aktif exploit'e sahip
                    </p>
                </div>
                <div>
                    <h4>🛡️ Önceliklendirme Önerisi:</h4>
                    <p style="margin: 10px 0;">
                        {self._get_priority_recommendation(vulnerabilities)}
                    </p>
                </div>
            </div>
        </div>
        """
        
        return insights_html
        
    def _generate_vulnerabilities_section(self):
        """Açıklar bölümünü oluştur"""
        vulnerabilities = self.ai_results.get('vulnerabilities', [])
        
        if not vulnerabilities:
            return """
            <div class="section">
                <div class="section-header" style="background: linear-gradient(135deg, #28a745, #20c997);">
                    ✅ Güvenlik Durumu
                </div>
                <div class="section-content">
                    <div class="no-vulnerabilities">
                        🛡️ Güvenli! Analiz edilen sistemlerde güncel güvenlik açığı bulunamadı.
                    </div>
                </div>
            </div>
            """
        
        # Açıkları severity'e göre grupla
        critical_vulns = [v for v in vulnerabilities if v.get('severity', '').lower() == 'critical']
        high_vulns = [v for v in vulnerabilities if v.get('severity', '').lower() == 'high']
        medium_vulns = [v for v in vulnerabilities if v.get('severity', '').lower() == 'medium']
        low_vulns = [v for v in vulnerabilities if v.get('severity', '').lower() == 'low']
        
        html = ""
        
        # Kritik açıklar
        if critical_vulns:
            html += self._create_vulnerability_section("🚨 KRİTİK AÇIKLAR", critical_vulns, "critical")
        
        # Yüksek riskli açıklar
        if high_vulns:
            html += self._create_vulnerability_section("⚠️ YÜKSEK RİSKLİ AÇIKLAR", high_vulns, "high")
        
        # Orta riskli açıklar
        if medium_vulns:
            html += self._create_vulnerability_section("🟡 ORTA RİSKLİ AÇIKLAR", medium_vulns, "medium")
        
        # Düşük riskli açıklar
        if low_vulns:
            html += self._create_vulnerability_section("🟢 DÜŞÜK RİSKLİ AÇIKLAR", low_vulns, "low")
        
        return html
        
    def _create_vulnerability_section(self, title, vulnerabilities, severity_class):
        """Açıklar bölümü oluştur"""
        html = f"""
        <div class="section">
            <div class="section-header {severity_class}">
                {title} ({len(vulnerabilities)})
            </div>
            <div class="section-content">
        """
        
        for vuln in vulnerabilities:
            html += self._format_vulnerability_html(vuln, severity_class)
            
        html += "</div></div>"
        return html
        
    def _format_vulnerability_html(self, vuln, severity_class):
        """Açık bilgisini HTML formatında göster"""
        cve_id = vuln.get('cve_id', 'N/A')
        title = vuln.get('title', 'Başlık yok')
        cvss_score = vuln.get('cvss_score', 'N/A')
        severity = vuln.get('severity', 'Unknown')
        published_date = vuln.get('published_date', 'N/A')
        description = vuln.get('description', 'Açıklama yok')
        impact_type = vuln.get('impact_type', 'Bilinmiyor')
        exploit_status = vuln.get('exploit_status', 'Bilinmiyor')
        patch_status = vuln.get('patch_status', 'Bilinmiyor')
        solution = vuln.get('solution', 'Çözüm önerisi yok')
        affected_systems = vuln.get('affected_systems', [])
        references = vuln.get('references', [])
        
        # CVSS rengini belirle
        cvss_class = "cvss-low"
        if isinstance(cvss_score, (int, float)):
            if cvss_score >= 9.0:
                cvss_class = "cvss-critical"
            elif cvss_score >= 7.0:
                cvss_class = "cvss-high"
            elif cvss_score >= 4.0:
                cvss_class = "cvss-medium"
        
        html = f"""
        <div class="vulnerability {severity_class}">
            <div class="vuln-title">
                {cve_id} - {title}
                {self._get_trending_badge(vuln)}
            </div>
            <div class="vuln-meta">
                <span class="vuln-meta-item {cvss_class}">CVSS: {cvss_score}</span>
                <span class="vuln-meta-item">📅 {published_date}</span>
                <span class="vuln-meta-item">🎯 {impact_type}</span>
                <span class="vuln-meta-item">{'🔓' if exploit_status.lower() in ['public', 'poc'] else '🔒'} {exploit_status}</span>
            </div>
            
            <div class="vuln-description">
                <strong>Açıklama:</strong> {description}
            </div>
            
            <div class="vuln-impact">
                <strong>Etkilenen Sistemler:</strong> {', '.join(affected_systems) if affected_systems else 'Belirtilmemiş'}
            </div>
            
            <div class="vuln-solution">
                <strong>Yama Durumu:</strong> {patch_status}<br>
                <strong>Çözüm Önerisi:</strong> {solution}
            </div>
        """
        
        # Referansları ekle
        if references:
            html += """
            <div style="margin-top: 15px;">
                <strong>Referanslar:</strong><br>
                <div style="display: flex; flex-wrap: wrap; gap: 10px; margin-top: 5px;">
            """
            for ref in references[:3]:  # İlk 3 referans
                html += f'<a href="{ref}" target="_blank" style="background: #007bff; color: white; padding: 3px 8px; border-radius: 10px; text-decoration: none; font-size: 0.8em;">📄 Kaynak</a>'
            html += "</div></div>"
        
        html += "</div>"
        return html
        
    def _get_trending_badge(self, vuln):
        """Trending badge'i oluştur"""
        # Eğer exploit durumu public ise trending olarak işaretle
        if vuln.get('exploit_status', '').lower() in ['public', 'poc']:
            return '<span class="trending-badge">🔥 TRENDING</span>'
        return ""
        
    def _get_priority_recommendation(self, vulnerabilities):
        """Önceliklendirme önerisi oluştur"""
        critical_count = len([v for v in vulnerabilities if v.get('severity', '').lower() == 'critical'])
        high_count = len([v for v in vulnerabilities if v.get('severity', '').lower() == 'high'])
        
        if critical_count > 0:
            return f"🚨 <strong>Acil öncelik:</strong> {critical_count} kritik açık tespit edildi. Bu açıklar derhal yamanmalıdır."
        elif high_count > 3:
            return f"⚠️ <strong>Yüksek öncelik:</strong> {high_count} yüksek riskli açık bulunuyor. 24 saat içinde yama önerilir."
        else:
            return "✅ <strong>Normal öncelik:</strong> Düzenli yama takvimi önerilir."

def generate_ai_report(ai_results):
    """AI raporu oluştur"""
    reporter = AIVulnerabilityReporter(ai_results)
    return reporter.generate_html_report()
