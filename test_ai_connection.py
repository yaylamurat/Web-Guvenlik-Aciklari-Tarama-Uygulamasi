#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI Güvenlik Analizi Test Script'i
API bağlantısını ve zaman aşımı sorunlarını test etmek için
"""

import time
import requests
import json
from datetime import datetime
from ai_vuln_scanner import AIVulnerabilityScanner

def test_connection():
    """Temel bağlantı testi"""
    print("🔗 NVIDIA API Bağlantı Testi")
    print("="*50)
    
    scanner = AIVulnerabilityScanner()
    
    # Basit test isteği
    try:
        payload = {
            "model": "qwen/qwen3.5-122b-a10b",
            "messages": [{"role": "user", "content": "Merhaba, bağlantı testi"}],
            "max_tokens": 100,
            "temperature": 0.1,
            "stream": False,
        }
        
        print("📡 API isteği gönderiliyor...")
        start_time = time.time()
        
        response = requests.post(
            scanner.invoke_url, 
            headers=scanner.headers, 
            json=payload, 
            timeout=30
        )
        
        end_time = time.time()
        response_time = end_time - start_time
        
        print(f"✅ Bağlantı başarılı!")
        print(f"⏱️ Yanıt süresi: {response_time:.2f} saniye")
        print(f"📊 Status kodu: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            content = result.get('choices', [{}])[0].get('message', {}).get('content', '')
            print(f"📝 Yanıt: {content[:100]}...")
            
        return True
        
    except requests.exceptions.Timeout:
        print("❌ Zaman aşımı hatası!")
        print("💡 Çözüm: Timeout süresini artırın veya internet bağlantınızı kontrol edin")
        return False
        
    except requests.exceptions.ConnectionError:
        print("❌ Bağlantı hatası!")
        print("💡 Çözüm: İnternet bağlantınızı veya DNS ayarlarınızı kontrol edin")
        return False
        
    except Exception as e:
        print(f"❌ Genel hata: {str(e)}")
        return False

def test_small_analysis():
    """Küçük analiz testi"""
    print("\n🧪 Küçük Analiz Testi")
    print("="*50)
    
    scanner = AIVulnerabilityScanner()
    
    try:
        print("📡 Küçük analiz başlatılıyor (WordPress, son 3 gün)...")
        start_time = time.time()
        
        result = scanner.get_recent_vulnerabilities(
            days=3, 
            categories=["WordPress"]
        )
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"⏱️ Analiz süresi: {duration:.2f} saniye")
        
        if result['success']:
            vulns = result.get('vulnerabilities', [])
            print(f"✅ Analiz başarılı! {len(vulns)} açık bulundu")
            
            if vulns:
                print("📋 Bulunan açıklar:")
                for i, vuln in enumerate(vulns[:3], 1):
                    cve = vuln.get('cve_id', 'N/A')
                    title = vuln.get('title', 'Başlık yok')
                    print(f"  {i}. {cve} - {title[:50]}...")
        else:
            print(f"❌ Analiz başarısız: {result.get('error', 'Bilinmeyen hata')}")
            
        return result['success']
        
    except Exception as e:
        print(f"❌ Test hatası: {str(e)}")
        return False

def test_timeout_scenarios():
    """Farklı timeout senaryolarını test et"""
    print("\n⏱️ Timeout Senaryoları Testi")
    print("="*50)
    
    scanner = AIVulnerabilityScanner()
    
    # Test senaryoları
    test_cases = [
        {"days": 1, "categories": ["WordPress"], "expected_time": 30},
        {"days": 7, "categories": ["WordPress", "Apache"], "expected_time": 60},
        {"days": 30, "categories": ["WordPress", "Apache", "PHP"], "expected_time": 120},
    ]
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n🧪 Test {i}: {test_case['days']} gün, {len(test_case['categories'])} sistem")
        
        try:
            start_time = time.time()
            
            result = scanner.get_recent_vulnerabilities(
                days=test_case['days'],
                categories=test_case['categories']
            )
            
            end_time = time.time()
            duration = end_time - start_time
            
            if result['success']:
                print(f"✅ Başarılı - {duration:.2f}s (beklenen: ~{test_case['expected_time']}s)")
            else:
                print(f"❌ Başarısız - {result.get('error', 'Hata')}")
                
        except Exception as e:
            print(f"❌ Hata: {str(e)}")

def main():
    """Ana test fonksiyonu"""
    print("🤖 AI Güvenlik Analizi Test Aracı")
    print("="*60)
    print(f"📅 Test Tarihi: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}")
    print()
    
    # 1. Bağlantı testi
    if not test_connection():
        print("\n❌ Temel bağlantı testi başarısız!")
        print("Lütfen internet bağlantınızı ve API anahtarınızı kontrol edin.")
        return
    
    # 2. Küçük analiz testi
    if not test_small_analysis():
        print("\n⚠️ Küçük analiz testi başarısız!")
        print("Bu durum API limitleri veya geçici sorunlar olabilir.")
    
    # 3. Timeout senaryoları
    test_timeout_scenarios()
    
    print("\n" + "="*60)
    print("📋 Test Özeti:")
    print("✅ Bağlantı testi tamamlandı")
    print("✅ Küçük analiz testi tamamlandı") 
    print("✅ Timeout senaryoları test edildi")
    print("\n💡 Öneriler:")
    print("1. Zaman aşımı hatası alırsanız, daha kısa periyotlar kullanın")
    print("2. Daha az sistem seçerek analiz süresini kısaltın")
    print("3. İnternet bağlantınızın stabil olduğundan emin olun")
    print("4. API limitlerini aşmamaya dikkat edin")

if __name__ == "__main__":
    main()
