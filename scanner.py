#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web Güvenlik Tarayıcı Modülü
SQL Injection, XSS, CSRF gibi güvenlik açıklarını tespit eder
"""

import requests
import re
import urllib.parse
from urllib.parse import urljoin, urlparse
import ssl
import socket
from bs4 import BeautifulSoup
import time
import random

class WebSecurityScanner:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.results = {}
        
    def scan_all(self, options):
        """T seçilen tüm taramaları yap"""
        results = {}
        
        # Önce siteye erişilebilirlik kontrolü yap
        if not self.check_site_accessibility():
            return {'error': ['Siteye ulaşılamıyor! Lütfen URL\'nin doğru ve sitenin açık olduğundan emin olun.']}
        
        if options.get('sql_injection', True):
            results['sql_injection'] = self.check_sql_injection()
            
        if options.get('xss', True):
            results['xss'] = self.check_xss()
            
        if options.get('csrf', True):
            results['csrf'] = self.check_csrf()
            
        if options.get('directory_listing', True):
            results['directory_listing'] = self.check_directory_listing()
            
        if options.get('security_headers', True):
            results['security_headers'] = self.check_security_headers()
            
        if options.get('ssl_check', True):
            results['ssl'] = self.check_ssl_security()
            
        return results
        
    def check_sql_injection(self):
        """SQL Injection açıklarını kontrol et"""
        vulnerabilities = []
        
        try:
            # Formları bul
            forms = self.get_forms()
            
            for form in forms:
                form_url = urljoin(self.base_url, form.get('action', ''))
                method = form.get('method', 'get').lower()
                
                # SQL injection payload'ları
                sql_payloads = [
                    "' OR '1'='1",
                    "' OR '1'='1' --",
                    "' OR '1'='1' /*",
                    "admin'--",
                    "admin' /*",
                    "' OR 'x'='x",
                    "1' OR '1'='1' --",
                    "x'; DROP TABLE users; --"
                ]
                
                inputs = form.find_all(['input', 'textarea'])
                if not inputs:
                    continue
                    
                for payload in sql_payloads:
                    data = {}
                    for input_tag in inputs:
                        input_name = input_tag.get('name')
                        if input_name:
                            data[input_name] = payload
                            
                    try:
                        if method == 'post':
                            response = self.session.post(form_url, data=data, timeout=10)
                        else:
                            response = self.session.get(form_url, params=data, timeout=10)
                            
                        # SQL error mesajlarını kontrol et
                        sql_errors = [
                            "sql syntax",
                            "mysql_fetch",
                            "ora-",
                            "microsoft ole db",
                            "odbc drivers error",
                            "java.sql.sqlexception",
                            "postgresql query failed"
                        ]
                        
                        response_text = response.text.lower()
                        for error in sql_errors:
                            if error in response_text:
                                vulnerabilities.append(f"SQL Injection tespit edildi - Form: {form_url}, Payload: {payload}")
                                break
                                
                    except Exception:
                        continue
                        
            # URL parametrelerini kontrol et
            parsed_url = urlparse(self.base_url)
            if parsed_url.query:
                query_params = urllib.parse.parse_qs(parsed_url.query)
                for param in query_params:
                    for payload in sql_payloads:
                        test_url = self.base_url.replace(f"{param}={query_params[param][0]}", f"{param}={payload}")
                        try:
                            response = self.session.get(test_url, timeout=10)
                            if any(error in response.text.lower() for error in sql_errors):
                                vulnerabilities.append(f"SQL Injection tespit edildi - URL: {test_url}")
                                break
                        except Exception:
                            continue
                            
        except Exception as e:
            vulnerabilities.append(f"SQL Injection kontrolü sırasında hata: {str(e)}")
            
        return vulnerabilities
        
    def check_xss(self):
        """XSS açıklarını kontrol et"""
        vulnerabilities = []
        
        try:
            forms = self.get_forms()
            
            # XSS payload'ları
            xss_payloads = [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "<svg onload=alert('XSS')>",
                "';alert('XSS');//",
                "<iframe src=javascript:alert('XSS')>"
            ]
            
            for form in forms:
                form_url = urljoin(self.base_url, form.get('action', ''))
                method = form.get('method', 'get').lower()
                
                inputs = form.find_all(['input', 'textarea'])
                if not inputs:
                    continue
                    
                for payload in xss_payloads:
                    data = {}
                    for input_tag in inputs:
                        input_name = input_tag.get('name')
                        if input_name and input_tag.get('type') != 'hidden':
                            data[input_name] = payload
                            
                    try:
                        if method == 'post':
                            response = self.session.post(form_url, data=data, timeout=10)
                        else:
                            response = self.session.get(form_url, params=data, timeout=10)
                            
                        # Payload'ın response'ta olup olmadığını kontrol et
                        if payload in response.text:
                            vulnerabilities.append(f"XSS açığı tespit edildi - Form: {form_url}, Payload: {payload}")
                            
                    except Exception:
                        continue
                        
        except Exception as e:
            vulnerabilities.append(f"XSS kontrolü sırasında hata: {str(e)}")
            
        return vulnerabilities
        
    def check_csrf(self):
        """CSRF açıklarını kontrol et"""
        vulnerabilities = []
        
        try:
            forms = self.get_forms()
            
            for form in forms:
                form_action = form.get('action', '')
                form_method = form.get('method', 'get').lower()
                
                # Sadece POST formlarını kontrol et
                if form_method != 'post':
                    continue
                    
                # CSRF token'ı ara
                csrf_found = False
                inputs = form.find_all('input')
                
                for input_tag in inputs:
                    input_name = input_tag.get('name', '').lower()
                    input_type = input_tag.get('type', '').lower()
                    
                    # CSRF token isimleri
                    csrf_names = ['csrf', 'token', '_token', 'authenticity_token', 'csrf_token']
                    
                    if any(csrf_name in input_name for csrf_name in csrf_names):
                        csrf_found = True
                        break
                        
                if not csrf_found:
                    form_url = urljoin(self.base_url, form_action)
                    vulnerabilities.append(f"CSRF açığı tespit edildi - Token bulunamadı: {form_url}")
                    
        except Exception as e:
            vulnerabilities.append(f"CSRF kontrolü sırasında hata: {str(e)}")
            
        return vulnerabilities
        
    def check_directory_listing(self):
        """Dizin listeleme açıklarını kontrol et"""
        vulnerabilities = []
        
        try:
            # Yaygın dizinleri kontrol et
            common_dirs = [
                '/admin/',
                '/backup/',
                '/logs/',
                '/temp/',
                '/uploads/',
                '/images/',
                '/css/',
                '/js/',
                '/config/',
                '/database/',
                '/includes/',
                '/lib/',
                '/vendor/'
            ]
            
            for directory in common_dirs:
                url = urljoin(self.base_url, directory)
                try:
                    response = self.session.get(url, timeout=10)
                    
                    # Dizin listeleme belirtileri
                    listing_indicators = [
                        "index of",
                        "directory listing",
                        "parent directory",
                        "<pre>",
                        "name    last modified"
                    ]
                    
                    response_text = response.text.lower()
                    if any(indicator in response_text for indicator in listing_indicators):
                        vulnerabilities.append(f"Dizin listeleme açığı: {url}")
                        
                except Exception:
                    continue
                    
        except Exception as e:
            vulnerabilities.append(f"Dizin listeleme kontrolü sırasında hata: {str(e)}")
            
        return vulnerabilities
        
    def check_security_headers(self):
        """Güvenlik başlıklarını kontrol et"""
        vulnerabilities = []
        
        try:
            response = self.session.get(self.base_url, timeout=10)
            headers = response.headers
            
            # Önemli güvenlik başlıkları
            security_headers = {
                'X-Frame-Options': 'Clickjacking saldırılarını önler',
                'X-XSS-Protection': 'XSS filtrelemesi sağlar',
                'X-Content-Type-Options': 'MIME type sniffing önler',
                'Strict-Transport-Security': 'HTTPS kullanımını zorunlu kılar',
                'Content-Security-Policy': 'İçerik güvenlik politikası belirler',
                'Referrer-Policy': 'Referrer bilgilerini kontrol eder'
            }
            
            for header, description in security_headers.items():
                if header not in headers:
                    vulnerabilities.append(f"Eksik güvenlik başlığı: {header} - {description}")
                    
        except Exception as e:
            vulnerabilities.append(f"Güvenlik başlıkları kontrolü sırasında hata: {str(e)}")
            
        return vulnerabilities
        
    def check_ssl_security(self):
        """SSL/TLS güvenliğini kontrol et"""
        vulnerabilities = []
        
        try:
            parsed_url = urlparse(self.base_url)
            hostname = parsed_url.netloc.split(':')[0]
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
            
            if parsed_url.scheme != 'https':
                vulnerabilities.append("Site HTTPS kullanmıyor - Trafik şifrelenmiyor")
                return vulnerabilities
                
            # SSL sertifikası kontrolü
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Sertifika geçerliliği kontrolü
                    import datetime
                    not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if not_after < datetime.datetime.now():
                        vulnerabilities.append("SSL sertifikasının süresi dolmuş")
                        
                    # Zayıf SSL/TLS versiyonları kontrolü
                    ssl_version = ssock.version()
                    if ssl_version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        vulnerabilities.append(f"Zayıf SSL/TLS versiyonu kullanılıyor: {ssl_version}")
                        
        except Exception as e:
            vulnerabilities.append(f"SSL kontrolü sırasında hata: {str(e)}")
            
        return vulnerabilities
        
    def get_forms(self):
        """Sayfadaki tüm formları getir"""
        try:
            response = self.session.get(self.base_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            return soup.find_all('form')
        except Exception:
            return []
            
    def check_site_accessibility(self):
        """Siteye erişilebilirlik kontrolü yap"""
        try:
            response = self.session.get(self.base_url, timeout=15)
            return response.status_code == 200
        except requests.exceptions.ConnectionError:
            return False
        except requests.exceptions.Timeout:
            return False
        except requests.exceptions.RequestException:
            return False
        except Exception:
            return False
