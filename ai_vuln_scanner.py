#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Yapay Zeka Destekli Güvenlik Açığı Tarayıcısı
NVIDIA API kullanarak son siber güvenlik açıklarını araştırır
"""

import requests
import base64
import json
from datetime import datetime, timedelta
import re

class AIVulnerabilityScanner:
    def __init__(self):
        self.invoke_url = "https://integrate.api.nvidia.com/v1/chat/completions"
        self.api_key = "nvapi-KG **********" //API ANAHTARINIZI BURAYA EKLEMENİZ GEREKİYOR.
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        
    def get_recent_vulnerabilities(self, days=30, categories=None):
        """Son günlerdeki güvenlik açıklarını AI ile araştır"""
        
        if categories is None:
            categories = [
                "WordPress", "Joomla", "Drupal", "Apache", "Nginx", 
                "PHP", "MySQL", "MariaDB", "PostgreSQL", "MongoDB",
                "Redis", "Docker", "Kubernetes", "Linux", "Windows",
                "MSSQL", "Oracle", "Cisco", "Juniper", "Palo Alto", "Fortinet"
            ]
        
        prompt = f"""
        Son {days} gün içinde çıkan en kritik siber güvenlik açıklarını araştır ve analiz et.
        
        Özellikle şu sistemlere odaklan:
        {', '.join(categories)}
        
        Her açıklık için şu bilgileri ver:
        1. CVE numarası
        2. Etkilenen sistem/versiyon
        3. CVSS skor ve seviyesi (Critical/High/Medium/Low)
        4. Açıklamanın yayınlanma tarihi
        5. Açığın kısa açıklaması
        6. Etki alanı (Remote Code Execution, SQL Injection, XSS, vb.)
        7. Exploit durumu (Public/Proof of Concept/None)
        8. Yama durumu (Available/In Development/Not Available)
        9. Kısa çözüm önerisi
        10. Referans linkleri (CVE, vendor advisory, exploit-db)
        
        Format:
        {{
            "cve_id": "CVE-YYYY-NNNN",
            "title": "Açık başlığı",
            "affected_systems": ["Sistem1", "Sistem2"],
            "cvss_score": 9.8,
            "severity": "Critical",
            "published_date": "2024-03-13",
            "description": "Detaylı açıklama",
            "impact_type": "Remote Code Execution",
            "exploit_status": "Public",
            "patch_status": "Available",
            "solution": "Kısa çözüm önerisi",
            "references": ["https://cve.mitre.org/...", "https://nvd.nist.gov/..."]
        }}
        
        Lütfen JSON formatında, geçerli ve doğrulanabilir bilgilerle yanıt ver.
        En kritik ve önemli açıklara öncelik ver.
        """
        
        try:
            payload = {
                "model": "qwen/qwen3.5-122b-a10b",
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 16384,
                "temperature": 0.60,
                "top_p": 0.95,
                "stream": False,
                "chat_template_kwargs": {"enable_thinking": True},
            }
            
            response = requests.post(self.invoke_url, headers=self.headers, json=payload, timeout=120)
            response.raise_for_status()
            
            result = response.json()
            content = result.get('choices', [{}])[0].get('message', {}).get('content', '')
            
            # JSON içeriğini çıkar
            vulnerabilities = self.parse_ai_response(content)
            
            return {
                'success': True,
                'vulnerabilities': vulnerabilities,
                'total_count': len(vulnerabilities),
                'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'days_analyzed': days
            }
            
        except requests.exceptions.Timeout:
            return {
                'success': False,
                'error': 'API isteği zaman aşımına uğradı. Lütfen internet bağlantınızı kontrol edin ve tekrar deneyin.',
                'vulnerabilities': []
            }
        except requests.exceptions.ConnectionError:
            return {
                'success': False,
                'error': 'İnternet bağlantısı hatası. Lütfen ağ bağlantınızı kontrol edin.',
                'vulnerabilities': []
            }
        except requests.exceptions.RequestException as e:
            return {
                'success': False,
                'error': f'API isteği başarısız: {str(e)}',
                'vulnerabilities': []
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Analiz hatası: {str(e)}',
                'vulnerabilities': []
            }
    
    def parse_ai_response(self, content):
        """AI yanıtından JSON verilerini çıkar"""
        vulnerabilities = []
        
        try:
            # JSON bloklarını bul
            json_pattern = r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}'
            matches = re.findall(json_pattern, content, re.DOTALL)
            
            for match in matches:
                try:
                    vuln = json.loads(match)
                    # Gerekli alanları kontrol et
                    if self.validate_vulnerability(vuln):
                        vulnerabilities.append(vuln)
                except json.JSONDecodeError:
                    continue
                    
        except Exception:
            # Eğer regex çalışmazsa, manuel parse dene
            try:
                # İlk ve son { } arasını al
                start = content.find('{')
                end = content.rfind('}') + 1
                if start != -1 and end > start:
                    json_str = content[start:end]
                    vuln = json.loads(json_str)
                    if self.validate_vulnerability(vuln):
                        vulnerabilities.append(vuln)
            except:
                pass
        
        return vulnerabilities
    
    def validate_vulnerability(self, vuln):
        """Açıklık verisini doğrula"""
        required_fields = ['cve_id', 'title', 'cvss_score', 'severity', 'published_date']
        return all(field in vuln for field in required_fields)
    
    def get_vulnerability_details(self, cve_id):
        """Belirli bir CVE hakkında detaylı bilgi al"""
        prompt = f"""
        {cve_id} numaralı güvenlik açığı hakkında detaylı analiz yap.
        
        Şu bilgileri ver:
        1. Teknik detaylar ve açığın nasıl çalıştığı
        2. Etkilenen tüm versiyonlar
        3. Kötüye kullanım senaryoları
        4. Tespit yöntemleri
        5. Kısa ve uzun vadeli çözümler
        6. İlgili güvenlik duyuruları
        7. Aktif exploit'ler ve PoC'ler
        8. Risk değerlendirmesi ve öncelik seviyesi
        
        Lütfen teknik olarak doğru ve güncel bilgiler ver.
        """
        
        try:
            payload = {
                "model": "qwen/qwen3.5-122b-a10b",
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 4096,
                "temperature": 0.30,
                "top_p": 0.90,
                "stream": False,
            }
            
            response = requests.post(self.invoke_url, headers=self.headers, json=payload, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            content = result.get('choices', [{}])[0].get('message', {}).get('content', '')
            
            return {
                'success': True,
                'cve_id': cve_id,
                'detailed_analysis': content,
                'analysis_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Detay analizi başarısız: {str(e)}',
                'cve_id': cve_id
            }
    
    def get_trending_vulnerabilities(self):
        """Trend olan güvenlik açıklarını araştır"""
        prompt = """
        Son 7 günde en çok konuşulan ve aktif olarak exploit edilen güvenlik açıklarını araştır.
        
        Özellikle şu kriterlere göre analiz yap:
        1. Aktif exploit'lerin varlığı
        2. Sosyal medya ve güvenlik forumlarındaki tartışma seviyesi
        3. Kurumsal etkisi ve kritikliği
        4. Yama durumu ve aciliyeti
        
        Her açıklık için:
        - Trend seviyesi (Hot/Trending/Warm/Cold)
        - Aktif exploit sayısı
        - Tartışma platformları
        - Aciliyet seviyesi
        
        JSON formatında yanıt ver.
        """
        
        try:
            payload = {
                "model": "qwen/qwen3.5-122b-a10b",
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 8192,
                "temperature": 0.50,
                "top_p": 0.95,
                "stream": False,
            }
            
            response = requests.post(self.invoke_url, headers=self.headers, json=payload, timeout=90)
            response.raise_for_status()
            
            result = response.json()
            content = result.get('choices', [{}])[0].get('message', {}).get('content', '')
            
            vulnerabilities = self.parse_ai_response(content)
            
            return {
                'success': True,
                'vulnerabilities': vulnerabilities,
                'trend_analysis': True,
                'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
        except requests.exceptions.Timeout:
            return {
                'success': False,
                'error': 'Trend analizi zaman aşımına uğradı. Lütfen daha sonra tekrar deneyin.',
                'vulnerabilities': []
            }
        except requests.exceptions.ConnectionError:
            return {
                'success': False,
                'error': 'İnternet bağlantısı hatası. Lütfen ağ bağlantınızı kontrol edin.',
                'vulnerabilities': []
            }
        except requests.exceptions.RequestException as e:
            return {
                'success': False,
                'error': f'Trend analizi başarısız: {str(e)}',
                'vulnerabilities': []
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Trend analizi hatası: {str(e)}',
                'vulnerabilities': []
            }
    
    def get_patch_recommendations(self, cve_ids):
        """CVE listesi için yama önerileri al"""
        prompt = f"""
        Bu CVE listesi için kapsamlı yama ve mitigasyon önerileri hazırla:
        {', '.join(cve_ids)}
        
        Her CVE için:
        1. Mevcut yama versiyonları ve linkleri
        2. Geçici mitigasyon adımları
        3. Yapılandırma değişiklikleri
        4. İzleme ve tespit yöntemleri
        5. Yama öncesi ve sonrası adımlar
        6. Test ve deployment önerileri
        7. Rollback planları
        
        Önceliklendirilmiş ve eyleme geçirilebilir öneriler sun.
        """
        
        try:
            payload = {
                "model": "qwen/qwen3.5-122b-a10b",
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 12288,
                "temperature": 0.20,
                "top_p": 0.85,
                "stream": False,
            }
            
            response = requests.post(self.invoke_url, headers=self.headers, json=payload, timeout=120)
            response.raise_for_status()
            
            result = response.json()
            content = result.get('choices', [{}])[0].get('message', {}).get('content', '')
            
            return {
                'success': True,
                'patch_recommendations': content,
                'cve_count': len(cve_ids),
                'analysis_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
        except requests.exceptions.Timeout:
            return {
                'success': False,
                'error': 'Yama önerileri zaman aşımına uğradı. Lütfen daha sonra tekrar deneyin.'
            }
        except requests.exceptions.ConnectionError:
            return {
                'success': False,
                'error': 'İnternet bağlantısı hatası. Lütfen ağ bağlantınızı kontrol edin.'
            }
        except requests.exceptions.RequestException as e:
            return {
                'success': False,
                'error': f'Yama önerileri alınamadı: {str(e)}'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Yama analizi hatası: {str(e)}'
            }

# Test fonksiyonu
def test_ai_scanner():
    """AI tarayıcısını test et"""
    scanner = AIVulnerabilityScanner()
    
    print("🤖 AI Güvenlik Açığı Tarayıcısı Testi")
    print("="*50)
    
    # Son açıkları al
    print("\n📡 Son güvenlik açıkları alınıyor...")
    result = scanner.get_recent_vulnerabilities(days=7, categories=["WordPress", "Apache", "PHP"])
    
    if result['success']:
        print(f"✅ {result['total_count']} açık bulundu")
        for i, vuln in enumerate(result['vulnerabilities'][:3], 1):
            print(f"\n{i}. {vuln.get('cve_id', 'N/A')} - {vuln.get('title', 'N/A')}")
            print(f"   Severity: {vuln.get('severity', 'N/A')} | CVSS: {vuln.get('cvss_score', 'N/A')}")
    else:
        print(f"❌ Hata: {result['error']}")
    
    # Trend olan açıklar
    print("\n🔥 Trend olan açıklar alınıyor...")
    trending = scanner.get_trending_vulnerabilities()
    
    if trending['success']:
        print(f"✅ {trending['vulnerabilities']} trend açık bulundu")
    else:
        print(f"❌ Hata: {trending['error']}")

if __name__ == "__main__":
    test_ai_scanner()
