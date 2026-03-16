#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web Güvenlik Tarama Uygulaması
Windows için eklentisiz web sitesi güvenlik açığı tarayıcısı
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import json
import os
from datetime import datetime
from scanner import WebSecurityScanner
from reporter import SecurityReporter
from vulnerability_db import VulnerabilityDatabase
from vuln_reporter import VulnerabilityReporter
from port_scanner import PortScanner
from port_reporter import PortReporter
from nmap_installer import NmapInstaller
from ai_vuln_scanner import AIVulnerabilityScanner
from ai_vuln_reporter import generate_ai_report

class WebSecurityApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Web Güvenlik Tarama Uygulaması v1.0")
        self.root.geometry("1000x700")
        self.root.resizable(True, True)
        
        # Temel değişkenler
        self.scanner = None
        self.is_scanning = False
        self.vuln_db = VulnerabilityDatabase()
        self.ai_scanner = AIVulnerabilityScanner()
        
        # GUI oluştur
        self.setup_gui()
        
    def setup_gui(self):
        # Ana frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Hedef URL giriş
        url_frame = ttk.LabelFrame(main_frame, text="Hedef Web Sitesi", padding="10")
        url_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(url_frame, text="URL:").grid(row=0, column=0, sticky=tk.W)
        self.url_entry = ttk.Entry(url_frame, width=60)
        self.url_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(10, 0))
        self.url_entry.insert(0, "https://")
        
        # Tarama seçenekleri
        options_frame = ttk.LabelFrame(main_frame, text="Tarama Seçenekleri", padding="10")
        options_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.sql_injection_var = tk.BooleanVar(value=True)
        self.xss_var = tk.BooleanVar(value=True)
        self.csrf_var = tk.BooleanVar(value=True)
        self.directory_listing_var = tk.BooleanVar(value=True)
        self.security_headers_var = tk.BooleanVar(value=True)
        self.ssl_check_var = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(options_frame, text="SQL Injection Açıkları", variable=self.sql_injection_var).grid(row=0, column=0, sticky=tk.W, padx=(0, 20))
        ttk.Checkbutton(options_frame, text="XSS Açıkları", variable=self.xss_var).grid(row=0, column=1, sticky=tk.W, padx=(0, 20))
        ttk.Checkbutton(options_frame, text="CSRF Açıkları", variable=self.csrf_var).grid(row=0, column=2, sticky=tk.W)
        ttk.Checkbutton(options_frame, text="Dizin Listeleme", variable=self.directory_listing_var).grid(row=1, column=0, sticky=tk.W, padx=(0, 20), pady=(5, 0))
        ttk.Checkbutton(options_frame, text="Güvenlik Başlıkları", variable=self.security_headers_var).grid(row=1, column=1, sticky=tk.W, padx=(0, 20), pady=(5, 0))
        ttk.Checkbutton(options_frame, text="SSL/TLS Kontrolü", variable=self.ssl_check_var).grid(row=1, column=2, sticky=tk.W, pady=(5, 0))
        
        # Butonlar
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=(0, 10))
        
        self.scan_button = ttk.Button(button_frame, text="Taramayı Başlat", command=self.start_scan)
        self.scan_button.grid(row=0, column=0, padx=(0, 10))
        
        self.report_button = ttk.Button(button_frame, text="Rapor Oluştur", command=self.generate_report, state=tk.DISABLED)
        self.report_button.grid(row=0, column=1, padx=(0, 10))
        
        self.vuln_button = ttk.Button(button_frame, text="Son Açıklar", command=self.show_vulnerabilities)
        self.vuln_button.grid(row=0, column=2, padx=(0, 10))
        
        self.ai_vuln_button = ttk.Button(button_frame, text="🤖 AI Analiz", command=self.show_ai_vulnerabilities)
        self.ai_vuln_button.grid(row=0, column=3, padx=(0, 10))
        
        self.ai_report_button = ttk.Button(button_frame, text="📊 AI Raporu", command=self.generate_ai_report, state=tk.DISABLED)
        self.ai_report_button.grid(row=0, column=4, padx=(0, 10))
        
        self.vuln_report_button = ttk.Button(button_frame, text="Açık Raporu", command=self.generate_vulnerability_report)
        self.vuln_report_button.grid(row=0, column=5, padx=(0, 10))
        
        self.port_scan_button = ttk.Button(button_frame, text="Port Taraması", command=self.start_port_scan)
        self.port_scan_button.grid(row=0, column=6, padx=(0, 10))
        
        self.port_report_button = ttk.Button(button_frame, text="Port Raporu", command=self.generate_port_report, state=tk.DISABLED)
        self.port_report_button.grid(row=0, column=7, padx=(0, 10))
        
        self.clear_button = ttk.Button(button_frame, text="Temizle", command=self.clear_results)
        self.clear_button.grid(row=0, column=8)
        
        # İlerleme çubuğu
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Sonuç alanı
        results_frame = ttk.LabelFrame(main_frame, text="Tarama Sonuçları", padding="10")
        results_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.results_text = scrolledtext.ScrolledText(results_frame, width=100, height=25, wrap=tk.WORD)
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Grid konfigürasyonu
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(4, weight=1)
        url_frame.columnconfigure(1, weight=1)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        
    def start_scan(self):
        if self.is_scanning:
            messagebox.showwarning("Uyarı", "Tarama zaten devam ediyor!")
            return
            
        url = self.url_entry.get().strip()
        if not url or url == "https://":
            messagebox.showerror("Hata", "Lütfen geçerli bir URL girin!")
            return
            
        self.is_scanning = True
        self.scan_button.config(state=tk.DISABLED)
        self.report_button.config(state=tk.DISABLED)
        self.progress.start()
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"Tarama başlatılıyor: {url}\n")
        self.results_text.insert(tk.END, "="*50 + "\n\n")
        
        # Tarama seçeneklerini hazırla
        scan_options = {
            'sql_injection': self.sql_injection_var.get(),
            'xss': self.xss_var.get(),
            'csrf': self.csrf_var.get(),
            'directory_listing': self.directory_listing_var.get(),
            'security_headers': self.security_headers_var.get(),
            'ssl_check': self.ssl_check_var.get()
        }
        
        # Taramayı ayrı thread'de başlat
        thread = threading.Thread(target=self.perform_scan, args=(url, scan_options))
        thread.daemon = True
        thread.start()
        
    def perform_scan(self, url, scan_options):
        try:
            self.scanner = WebSecurityScanner(url)
            results = self.scanner.scan_all(scan_options)
            
            # Sonuçları GUI'de göster
            self.root.after(0, self.display_results, results)
            
        except Exception as e:
            self.root.after(0, self.show_error, str(e))
            
    def display_results(self, results):
        self.progress.stop()
        self.is_scanning = False
        self.scan_button.config(state=tk.NORMAL)
        
        # Eğer siteye ulaşılamıyorsa rapor butonunu aktif etme
        if 'error' in results:
            self.report_button.config(state=tk.DISABLED)
        else:
            self.report_button.config(state=tk.NORMAL)
        
        self.results_text.insert(tk.END, "TARAMA TAMAMLANDI\n")
        self.results_text.insert(tk.END, "="*50 + "\n\n")
        
        # Sonuçları formatla ve göster
        for category, findings in results.items():
            if category == 'error':
                # Hata mesajını özel formatla göster
                self.results_text.insert(tk.END, f"❌ HATA:\n", "error")
                for finding in findings:
                    self.results_text.insert(tk.END, f"  • {finding}\n", "error")
                self.results_text.insert(tk.END, "\n")
            elif findings:
                self.results_text.insert(tk.END, f"🔴 {category.upper()} AÇIKLARI:\n", "header")
                for finding in findings:
                    self.results_text.insert(tk.END, f"  • {finding}\n", "vulnerability")
                self.results_text.insert(tk.END, "\n")
            else:
                self.results_text.insert(tk.END, f"✅ {category.upper()}: Açık bulunamadı\n", "safe")
                self.results_text.insert(tk.END, "\n")
        
        # Özet bilgi
        if 'error' not in results:
            total_vulnerabilities = sum(len(f) for f in results.values() if f)
            self.results_text.insert(tk.END, f"ÖZET: Toplam {total_vulnerabilities} potansiyel açık bulundu.\n", "summary")
        
        # Text formatlama
        self.results_text.tag_config("header", foreground="red", font=("Arial", 10, "bold"))
        self.results_text.tag_config("vulnerability", foreground="orange")
        self.results_text.tag_config("safe", foreground="green")
        self.results_text.tag_config("summary", foreground="blue", font=("Arial", 10, "bold"))
        self.results_text.tag_config("error", foreground="red", font=("Arial", 10, "bold"))
        
        # Sonuçları kaydet
        self.last_results = results
        
    def generate_report(self):
        if not hasattr(self, 'last_results'):
            messagebox.showerror("Hata", "Önce bir tarama yapın!")
            return
            
        # Eğer hata varsa rapor oluşturma
        if 'error' in self.last_results:
            messagebox.showerror("Hata", "Siteye ulaşılamadığı için rapor oluşturulamıyor!")
            return
            
        try:
            reporter = SecurityReporter(self.url_entry.get(), self.last_results)
            report_file = reporter.generate_html_report()
            messagebox.showinfo("Başarılı", f"Rapor oluşturuldu: {report_file}")
        except Exception as e:
            messagebox.showerror("Hata", f"Rapor oluşturulamadı: {str(e)}")
            
    def clear_results(self):
        self.results_text.delete(1.0, tk.END)
        self.last_results = None
        self.last_port_results = None
        self.last_ai_results = None
        self.report_button.config(state=tk.DISABLED)
        self.port_report_button.config(state=tk.DISABLED)
        self.ai_report_button.config(state=tk.DISABLED)
        
    def show_error(self, error_msg):
        self.progress.stop()
        self.is_scanning = False
        self.scan_button.config(state=tk.NORMAL)
        self.results_text.insert(tk.END, f"HATA: {error_msg}\n", "error")
        self.results_text.tag_config("error", foreground="red", font=("Arial", 10, "bold"))
        
    def show_vulnerabilities(self):
        """Son güvenlik açıklarını göster"""
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "🔒 SON GÜVENLİK AÇIKLARI LİSTESİ\n")
        self.results_text.insert(tk.END, "="*60 + "\n\n")
        
        # Özet bilgileri göster
        summary = self.vuln_db.get_vulnerability_summary()
        self.results_text.insert(tk.END, "📊 ÖZET BİLGİLER:\n", "header")
        self.results_text.insert(tk.END, f"Toplam Açık Sayısı: {summary['TOTAL']['total']}\n", "summary")
        self.results_text.insert(tk.END, f"Kritik: {summary['TOTAL']['critical']} | Yüksek: {summary['TOTAL']['high']} | Orta: {summary['TOTAL']['medium']} | Düşük: {summary['TOTAL']['low']}\n\n", "summary")
        
        # Sistemlere göre dağılım
        self.results_text.insert(tk.END, "📈 SİSTEMLERE GÖRE DAĞILIM:\n", "header")
        for system, data in summary.items():
            if system != 'TOTAL':
                self.results_text.insert(tk.END, f"• {system}: {data['total']} açık (K:{data['critical']} Y:{data['high']} O:{data['medium']} D:{data['low']})\n", "info")
        self.results_text.insert(tk.END, "\n")
        
        # Son 30 günlük açıklar
        recent_vulns = self.vuln_db.get_recent_vulnerabilities(30)
        if recent_vulns:
            self.results_text.insert(tk.END, "🕐 SON 30 GÜNDEKİ AÇIKLAR:\n", "header")
            for vuln in recent_vulns[:10]:  # İlk 10'u göster
                self.results_text.insert(tk.END, self.vuln_db.format_vulnerability_text(vuln), "vulnerability")
        else:
            self.results_text.insert(tk.END, "Son 30 günde yeni açık bulunamadı.\n\n", "safe")
        
        # Kritik açıklar
        critical_vulns = self.vuln_db.get_critical_vulnerabilities()
        if critical_vulns:
            self.results_text.insert(tk.END, "🚨 KRİTİK AÇIKLAR:\n", "critical")
            for vuln in critical_vulns:
                self.results_text.insert(tk.END, self.vuln_db.format_vulnerability_text(vuln), "critical")
        
        # Format ayarları
        self.results_text.tag_config("header", foreground="blue", font=("Arial", 11, "bold"))
        self.results_text.tag_config("summary", foreground="purple", font=("Arial", 10, "bold"))
        self.results_text.tag_config("info", foreground="darkblue")
        self.results_text.tag_config("vulnerability", foreground="red")
        self.results_text.tag_config("critical", foreground="red", font=("Arial", 10, "bold"))
        self.results_text.tag_config("safe", foreground="green", font=("Arial", 10, "bold"))
        
    def generate_vulnerability_report(self):
        """Güvenlik açığı raporu oluştur"""
        try:
            reporter = VulnerabilityReporter()
            report_file = reporter.generate_html_report()
            messagebox.showinfo("Başarılı", f"Güvenlik açığı raporu oluşturuldu: {report_file}")
        except Exception as e:
            messagebox.showerror("Hata", f"Rapor oluşturulamadı: {str(e)}")
            
    def show_ai_vulnerabilities(self):
        """AI destekli güvenlik açıklarını göster"""
        self.show_ai_vulnerability_options()
        
    def show_ai_vulnerability_options(self):
        """AI analiz seçeneklerini ana ekranda göster"""
        # Sonuç alanını temizle
        self.results_text.delete(1.0, tk.END)
        
        # AI analiz seçeneklerini sonuç alanına ekle
        self.results_text.insert(tk.END, f"🤖 AI Güvenlik Analizi Seçenekleri\n")
        self.results_text.insert(tk.END, f"Yapay zeka ile güncel siber güvenlik açıklarını araştırın\n")
        self.results_text.insert(tk.END, "="*50 + "\n\n")
        
        # Analiz tipi seçimi frame'i
        analysis_frame = ttk.Frame(self.results_text)
        self.results_text.window_create(tk.END, window=analysis_frame)
        
        analysis_label = ttk.Label(analysis_frame, text="Analiz Tipi:", font=("Arial", 10, "bold"))
        analysis_label.grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        
        analysis_type = tk.StringVar(value="recent")
        ttk.Radiobutton(analysis_frame, text="Son Açıklar (30 gün)", variable=analysis_type, value="recent").grid(row=0, column=1, sticky=tk.W, padx=(0, 15))
        ttk.Radiobutton(analysis_frame, text="Trend Olanlar", variable=analysis_type, value="trending").grid(row=0, column=2, sticky=tk.W, padx=(0, 15))
        ttk.Radiobutton(analysis_frame, text="Özel Sistemler", variable=analysis_type, value="custom").grid(row=0, column=3, sticky=tk.W, padx=(0, 15))
        
        # Sistem seçimi frame'i
        system_frame = ttk.Frame(self.results_text)
        self.results_text.window_create(tk.END, window=system_frame)
        
        system_label = ttk.Label(system_frame, text="Sistemler:", font=("Arial", 10, "bold"))
        system_label.grid(row=0, column=0, sticky=tk.W, padx=(0, 10), pady=(10, 0))
        
        # Checkbox'lar için değişkenler
        system_vars = {}
        systems = [
            ("WordPress", "wordpress"), ("Joomla", "joomla"), ("Drupal", "drupal"),
            ("Apache", "apache"), ("Nginx", "nginx"), ("PHP", "php"),
            ("MySQL", "mysql"), ("MariaDB", "mariadb"), ("PostgreSQL", "postgresql"),
            ("MongoDB", "mongodb"), ("Redis", "redis"), ("Docker", "docker"),
            ("Kubernetes", "kubernetes"), ("Linux", "linux"), ("Windows", "windows"),
            ("MSSQL", "mssql"), ("Oracle", "oracle")
        ]
        
        for i, (name, key) in enumerate(systems):
            var = tk.BooleanVar(value=True if i < 10 else False)  # İlk 10 sistem seçili
            system_vars[key] = var
            cb = ttk.Checkbutton(system_frame, text=name, variable=var)
            cb.grid(row=(i // 3), column=(i % 3) + 1, sticky=tk.W, padx=(0, 15), pady=(10, 0))
        
        # Gün seçimi frame'i
        days_frame = ttk.Frame(self.results_text)
        self.results_text.window_create(tk.END, window=days_frame)
        
        days_label = ttk.Label(days_frame, text="Analiz Periyodu:", font=("Arial", 10, "bold"))
        days_label.grid(row=0, column=0, sticky=tk.W, padx=(0, 10), pady=(10, 0))
        
        days_var = tk.StringVar(value="7")
        ttk.Label(days_frame, text="Son").grid(row=0, column=1, sticky=tk.W, padx=(0, 5), pady=(10, 0))
        days_entry = ttk.Entry(days_frame, textvariable=days_var, width=5)
        days_entry.grid(row=0, column=2, padx=(0, 5), pady=(10, 0))
        ttk.Label(days_frame, text="gün").grid(row=0, column=3, sticky=tk.W, pady=(10, 0))
        
        # Butonlar frame'i
        button_frame = ttk.Frame(self.results_text)
        self.results_text.window_create(tk.END, window=button_frame)
        
        def start_ai_analysis():
            analysis_value = analysis_type.get()
            
            # Seçili sistemleri belirle
            selected_systems = []
            for key, var in system_vars.items():
                if var.get():
                    selected_systems.append(key.title())
            
            if not selected_systems:
                messagebox.showerror("Hata", "Lütfen en az bir sistem seçin!")
                return
            
            try:
                days = int(days_var.get())
                if days < 1 or days > 90:
                    messagebox.showerror("Hata", "Gün sayısı 1-90 arasında olmalıdır!")
                    return
            except ValueError:
                messagebox.showerror("Hata", "Lütfen geçerli bir gün sayısı girin!")
                return
            
            self.perform_ai_analysis(analysis_value, selected_systems, days)
        
        ttk.Button(button_frame, text="🚀 Analizi Başlat", command=start_ai_analysis).grid(row=0, column=0, padx=(0, 10), pady=(15, 0))
        ttk.Button(button_frame, text="❌ İptal", command=self.clear_ai_options).grid(row=0, column=1, pady=(15, 0))
        
    def clear_ai_options(self):
        """AI analiz seçeneklerini temizle"""
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "AI güvenlik analizi iptal edildi.\n")
        
    def perform_ai_analysis(self, analysis_type, systems, days):
        """AI analizini gerçekleştir"""
        self.is_scanning = True
        self.ai_vuln_button.config(state=tk.DISABLED)
        self.progress.start()
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"🤖 AI Güvenlik Analizi Başlatılıyor...\n")
        self.results_text.insert(tk.END, f"Analiz Tipi: {analysis_type}\n")
        self.results_text.insert(tk.END, f"Sistemler: {', '.join(systems)}\n")
        self.results_text.insert(tk.END, f"Periyot: Son {days} gün\n")
        self.results_text.insert(tk.END, "="*50 + "\n\n")
        self.results_text.insert(tk.END, "⏳ Yapay zeka analiz çalışıyor, bu işlem birkaç dakika sürebilir...\n\n")
        
        # Analizi ayrı thread'de başlat
        thread = threading.Thread(target=self.run_ai_analysis, args=(analysis_type, systems, days))
        thread.daemon = True
        thread.start()
        
    def run_ai_analysis(self, analysis_type, systems, days):
        """AI analizini çalıştır"""
        try:
            if analysis_type == "recent":
                result = self.ai_scanner.get_recent_vulnerabilities(days=days, categories=systems)
            elif analysis_type == "trending":
                result = self.ai_scanner.get_trending_vulnerabilities()
            else:  # custom
                result = self.ai_scanner.get_recent_vulnerabilities(days=days, categories=systems)
            
            self.root.after(0, lambda: self.display_ai_results(result))
            
        except Exception as e:
            self.root.after(0, lambda: self.show_ai_error(str(e)))
            
    def display_ai_results(self, result):
        """AI analiz sonuçlarını göster"""
        self.progress.stop()
        self.is_scanning = False
        self.ai_vuln_button.config(state=tk.NORMAL)
        
        if not result['success']:
            self.results_text.insert(tk.END, f"HATA: {result['error']}\n", "error")
            self.results_text.tag_config("error", foreground="red", font=("Arial", 10, "bold"))
            return
        
        vulnerabilities = result.get('vulnerabilities', [])
        
        if not vulnerabilities:
            self.results_text.insert(tk.END, "🔍 AI analizi tamamlandı, ancak yeni güvenlik açığı bulunamadı.\n", "info")
            self.results_text.insert(tk.END, "Bu iyi bir haber! Sistemleriniz güncel görünüyor.\n", "success")
            self.results_text.tag_config("info", foreground="blue")
            self.results_text.tag_config("success", foreground="green", font=("Arial", 10, "bold"))
            return
        
        # Sonuçları göster
        self.results_text.insert(tk.END, f"🎯 AI Analizi Tamamlandı!\n", "header")
        self.results_text.insert(tk.END, f"📊 Toplam {len(vulnerabilities)} güvenlik açığı bulundu\n", "summary")
        self.results_text.insert(tk.END, f"📅 Tarih: {result.get('scan_date', 'N/A')}\n\n", "info")
        
        # Açıkları kategorize et
        critical_vulns = [v for v in vulnerabilities if v.get('severity', '').lower() == 'critical']
        high_vulns = [v for v in vulnerabilities if v.get('severity', '').lower() == 'high']
        medium_vulns = [v for v in vulnerabilities if v.get('severity', '').lower() == 'medium']
        
        # Kritik açıklar
        if critical_vulns:
            self.results_text.insert(tk.END, "🚨 KRİTİK AÇIKLAR:\n", "critical")
            for vuln in critical_vulns[:5]:  # İlk 5 kritik açık
                self.display_ai_vulnerability(vuln, "critical")
        
        # Yüksek riskli açıklar
        if high_vulns:
            self.results_text.insert(tk.END, "\n⚠️ YÜKSEK RİSKLİ AÇIKLAR:\n", "high")
            for vuln in high_vulns[:5]:  # İlk 5 yüksek açık
                self.display_ai_vulnerability(vuln, "high")
        
        # Orta riskli açıklar
        if medium_vulns:
            self.results_text.insert(tk.END, "\n🟡 ORTA RİSKLİ AÇIKLAR:\n", "medium")
            for vuln in medium_vulns[:3]:  # İlk 3 orta açık
                self.display_ai_vulnerability(vuln, "medium")
        
        # Format ayarları
        self.results_text.tag_config("header", foreground="blue", font=("Arial", 11, "bold"))
        self.results_text.tag_config("summary", foreground="purple", font=("Arial", 10, "bold"))
        self.results_text.tag_config("info", foreground="darkblue")
        self.results_text.tag_config("critical", foreground="red", font=("Arial", 10, "bold"))
        self.results_text.tag_config("high", foreground="orange", font=("Arial", 10, "bold"))
        self.results_text.tag_config("medium", foreground="goldenrod", font=("Arial", 10, "bold"))
        
        # Sonuçları kaydet
        self.last_ai_results = result
        
        # AI rapor butonunu aktif et
        if hasattr(self, 'ai_report_button'):
            self.ai_report_button.config(state=tk.NORMAL)
        
    def generate_ai_report(self):
        """AI analiz raporu oluştur"""
        if not hasattr(self, 'last_ai_results'):
            messagebox.showerror("Hata", "Önce bir AI güvenlik analizi yapın!")
            return
            
        try:
            report_file = generate_ai_report(self.last_ai_results)
            messagebox.showinfo("Başarılı", f"AI analiz raporu oluşturuldu: {report_file}")
        except Exception as e:
            messagebox.showerror("Hata", f"AI raporu oluşturulamadı: {str(e)}")
        
    def display_ai_vulnerability(self, vuln, severity_tag):
        """AI bulunan açığı göster"""
        cve_id = vuln.get('cve_id', 'N/A')
        title = vuln.get('title', 'Başlık yok')
        cvss_score = vuln.get('cvss_score', 'N/A')
        affected = ', '.join(vuln.get('affected_systems', []))[:50]
        exploit_status = vuln.get('exploit_status', 'Bilinmiyor')
        
        self.results_text.insert(tk.END, f"\n🔸 {cve_id} - {title}\n", severity_tag)
        self.results_text.insert(tk.END, f"   CVSS: {cvss_score} | Etkilenen: {affected}\n", "info")
        self.results_text.insert(tk.END, f"   Exploit: {exploit_status}\n", "info")
        
    def show_ai_error(self, error_msg):
        """AI hatası göster"""
        self.progress.stop()
        self.is_scanning = False
        self.ai_vuln_button.config(state=tk.NORMAL)
        self.results_text.insert(tk.END, f"AI analiz hatası: {error_msg}\n", "error")
        self.results_text.insert(tk.END, "\n💡 Çözüm Önerileri:\n", "info")
        self.results_text.insert(tk.END, "1. İnternet bağlantınızı kontrol edin\n", "info")
        self.results_text.insert(tk.END, "2. Daha sonra tekrar deneyin\n", "info")
        self.results_text.insert(tk.END, "3. Daha kısa bir periyot seçin (örn: 3 gün)\n", "info")
        self.results_text.insert(tk.END, "4. Daha az sistem seçerek tekrar deneyin\n", "info")
        self.results_text.tag_config("error", foreground="red", font=("Arial", 10, "bold"))
        self.results_text.tag_config("info", foreground="blue")
            
    def start_port_scan(self):
        """Port taraması başlat"""
        if self.is_scanning:
            messagebox.showwarning("Uyarı", "Tarama zaten devam ediyor!")
            return
            
        url = self.url_entry.get().strip()
        if not url or url == "https://":
            messagebox.showerror("Hata", "Lütfen geçerli bir URL veya IP adresi girin!")
            return
            
        # URL'den domain/IP çıkar
        target = self.extract_target_from_url(url)
        if not target:
            messagebox.showerror("Hata", "Geçerli bir hedef belirlenemedi!")
            return
            
        # Port tarama seçeneklerini ana ekranda göster
        self.show_port_scan_options_inline(target)
        
    def extract_target_from_url(self, url):
        """URL'den hedef domain/IP çıkar"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc.split(':')[0]  # Port numarasını kaldır
        except Exception:
            # Eğer IP adresi ise doğrudan döndür
            return url if self.is_valid_ip(url) else None
            
    def is_valid_ip(self, ip):
        """IP adresi geçerliliğini kontrol et"""
        try:
            parts = ip.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except Exception:
            return False
            
    def show_port_scan_options_inline(self, target):
        """Port tarama seçeneklerini ana ekranda göster"""
        # Sonuç alanını temizle
        self.results_text.delete(1.0, tk.END)
        
        # Port tarama seçeneklerini sonuç alanına ekle
        self.results_text.insert(tk.END, f"🔍 Port Tarama Seçenekleri\n")
        self.results_text.insert(tk.END, f"Hedef: {target}\n")
        self.results_text.insert(tk.END, "="*50 + "\n\n")
        
        # Tarama tipi seçimi frame'i
        scan_frame = ttk.Frame(self.results_text)
        self.results_text.window_create(tk.END, window=scan_frame)
        
        scan_label = ttk.Label(scan_frame, text="Tarama Tipi:", font=("Arial", 10, "bold"))
        scan_label.grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        
        scan_type = tk.StringVar(value="common")
        ttk.Radiobutton(scan_frame, text="Yaygın Portlar", variable=scan_type, value="common").grid(row=0, column=1, sticky=tk.W, padx=(0, 15))
        ttk.Radiobutton(scan_frame, text="Web Portları", variable=scan_type, value="web").grid(row=0, column=2, sticky=tk.W, padx=(0, 15))
        ttk.Radiobutton(scan_frame, text="Tüm Portlar", variable=scan_type, value="all").grid(row=0, column=3, sticky=tk.W, padx=(0, 15))
        ttk.Radiobutton(scan_frame, text="Özel Aralık", variable=scan_type, value="custom").grid(row=0, column=4, sticky=tk.W)
        
        # Özel aralık frame'i
        custom_frame = ttk.Frame(self.results_text)
        self.results_text.window_create(tk.END, window=custom_frame)
        
        ttk.Label(custom_frame, text="Özel Aralık:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10), pady=(10, 0))
        
        ttk.Label(custom_frame, text="Başlangıç:").grid(row=0, column=1, sticky=tk.W, padx=(0, 5), pady=(10, 0))
        start_entry = ttk.Entry(custom_frame, width=8)
        start_entry.grid(row=0, column=2, padx=(0, 10), pady=(10, 0))
        start_entry.insert(0, "1")
        
        ttk.Label(custom_frame, text="Bitiş:").grid(row=0, column=3, sticky=tk.W, padx=(0, 5), pady=(10, 0))
        end_entry = ttk.Entry(custom_frame, width=8)
        end_entry.grid(row=0, column=4, padx=(0, 10), pady=(10, 0))
        end_entry.insert(0, "1000")
        
        # Nmap seçenekleri frame'i
        nmap_frame = ttk.Frame(self.results_text)
        self.results_text.window_create(tk.END, window=nmap_frame)
        
        use_nmap = tk.BooleanVar(value=False)
        nmap_checkbox = ttk.Checkbutton(nmap_frame, text="Nmap kullan (daha hızlı)", variable=use_nmap)
        nmap_checkbox.grid(row=0, column=0, sticky=tk.W, pady=(10, 0))
        
        nmap_status_label = ttk.Label(nmap_frame, text="Nmap durumu kontrol ediliyor...")
        nmap_status_label.grid(row=0, column=1, sticky=tk.W, padx=(20, 0), pady=(10, 0))
        
        # Nmap durumunu kontrol et
        def check_nmap_status():
            installer = NmapInstaller()
            if installer.check_nmap_installed():
                nmap_status_label.config(text=f"✅ Nmap yüklü - {installer.get_nmap_version()}")
                use_nmap.set(True)
            else:
                nmap_status_label.config(text="❌ Nmap yüklü değil")
                use_nmap.set(False)
                # Kurulum butonu ekle
                install_button = ttk.Button(nmap_frame, text="Nmap'i Yükle", 
                                         command=lambda: self.install_nmap_direct())
                install_button.grid(row=1, column=0, sticky=tk.W, pady=(5, 0))
        
        # Butonlar frame'i
        button_frame = ttk.Frame(self.results_text)
        self.results_text.window_create(tk.END, window=button_frame)
        
        def start_scan():
            scan_type_value = scan_type.get()
            
            if scan_type_value == "custom":
                try:
                    start_port = int(start_entry.get())
                    end_port = int(end_entry.get())
                    if start_port < 1 or end_port > 65535 or start_port > end_port:
                        messagebox.showerror("Hata", "Geçersiz port aralığı!")
                        return
                except ValueError:
                    messagebox.showerror("Hata", "Lütfen geçerli port numaraları girin!")
                    return
                    
            # Nmap kontrolü ve kurulum
            use_nmap_value = use_nmap.get()
            if use_nmap_value:
                installer = NmapInstaller()
                if not installer.check_nmap_installed():
                    result = messagebox.askyesno(
                        "Nmap Kurulumu",
                        "Nmap yüklü değil. Otomatik olarak kurulmasını ister misiniz?\n\n"
                        "Bu işlem birkaç dakika sürebilir."
                    )
                    if result:
                        self.install_nmap_and_scan(target, scan_type_value, use_nmap_value, 
                                                 start_port if scan_type_value == "custom" else None,
                                                 end_port if scan_type_value == "custom" else None)
                        return
                    else:
                        use_nmap_value = False
                        
            self.perform_port_scan(target, scan_type_value, use_nmap_value, 
                                 start_port if scan_type_value == "custom" else None,
                                 end_port if scan_type_value == "custom" else None)
        
        ttk.Button(button_frame, text="🚀 Taramayı Başlat", command=start_scan).grid(row=0, column=0, padx=(0, 10), pady=(10, 0))
        ttk.Button(button_frame, text="❌ İptal", command=self.clear_port_options).grid(row=0, column=1, pady=(10, 0))
        
        # Nmap durumunu kontrol et
        self.root.after(100, check_nmap_status)
        
    def clear_port_options(self):
        """Port tarama seçeneklerini temizle"""
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "Port taraması iptal edildi.\n")
        
    def install_nmap_direct(self):
        """Doğrudan Nmap kurulumu başlat"""
        result = messagebox.askyesno(
            "Nmap Kurulumu",
            "Nmap'i otomatik olarak kurmak istiyor musunuz?\n\n"
            "Bu işlem birkaç dakika sürebilir ve internet bağlantısı gerektirir.\n"
            "Kurulum sonrası port taraması daha hızlı ve detaylı olacaktır."
        )
        
        if result:
            # Kurulum penceresini kapat
            self.show_nmap_installation_dialog()
            
    def show_nmap_installation_dialog(self):
        """Nmap kurulum diyaloğu göster"""
        install_window = tk.Toplevel(self.root)
        install_window.title("Nmap Kurulumu")
        install_window.geometry("600x400")
        install_window.resizable(False, False)
        
        # Kurulum bilgisi
        info_frame = ttk.LabelFrame(install_window, text="Kurulum Bilgisi", padding="10")
        info_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(info_frame, text="Nmap profesyonel ağ tarama aracıdır.").pack(anchor=tk.W)
        ttk.Label(info_frame, text="Kurulum adımları:").pack(anchor=tk.W, pady=(10, 5))
        ttk.Label(info_frame, text="1. Nmap resmi sitesinden indirilecek").pack(anchor=tk.W, padx=(20, 0))
        ttk.Label(info_frame, text="2. Sessiz kurulum yapılacak").pack(anchor=tk.W, padx=(20, 0))
        ttk.Label(info_frame, text="3. Sistem PATH'ine eklenecek").pack(anchor=tk.W, padx=(20, 0))
        
        # İlerleme alanı
        progress_frame = ttk.LabelFrame(install_window, text="Kurulum İlerlemesi", padding="10")
        progress_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        progress_text = scrolledtext.ScrolledText(progress_frame, width=70, height=15, wrap=tk.WORD)
        progress_text.pack(fill=tk.BOTH, expand=True)
        
        progress_bar = ttk.Progressbar(install_window, mode='indeterminate')
        progress_bar.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        # Butonlar
        button_frame = ttk.Frame(install_window)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        def start_installation():
            progress_bar.start()
            progress_text.insert(tk.END, "🔧 Nmap kurulumu başlatılıyor...\n\n")
            
            # Kurulumu ayrı thread'de başlat
            thread = threading.Thread(target=self.run_nmap_installation_with_ui, 
                                    args=(progress_text, progress_bar, install_window))
            thread.daemon = True
            thread.start()
            
        ttk.Button(button_frame, text="Kurulumu Başlat", command=start_installation).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="İptal", command=install_window.destroy).pack(side=tk.LEFT)
        
    def run_nmap_installation_with_ui(self, progress_text, progress_bar, install_window):
        """UI ile Nmap kurulumu çalıştır"""
        try:
            installer = NmapInstaller()
            
            def update_message(msg):
                install_window.after(0, lambda: progress_text.insert(tk.END, f"{msg}\n"))
                install_window.after(0, lambda: progress_text.see(tk.END))
                
            update_message("Nmap indiriliyor...")
            if not installer.download_nmap():
                install_window.after(0, lambda: self.show_install_error(progress_text, "Nmap indirilemedi!"))
                return
                
            update_message("Nmap kuruluyor...")
            if not installer.install_nmap_silent():
                install_window.after(0, lambda: self.show_install_error(progress_text, "Nmap kurulamadı!"))
                return
                
            update_message("Nmap PATH'e ekleniyor...")
            installer.add_to_path()
            
            update_message("✅ Nmap başarıyla kuruldu!")
            update_message(f"Versiyon: {installer.get_nmap_version()}")
            update_message("\nPort taraması penceresini kapatıp tekrar açabilirsiniz.")
            
            progress_bar.stop()
            install_window.after(2000, install_window.destroy)
            
        except Exception as e:
            install_window.after(0, lambda: self.show_install_error(progress_text, f"Kurulum hatası: {str(e)}"))
            
    def show_install_error(self, progress_text, error_msg):
        """Kurulum hatası göster"""
        progress_text.insert(tk.END, f"\n❌ HATA: {error_msg}\n", "error")
        progress_text.insert(tk.END, "\nPython port tarayıcısı ile devam edebilirsiniz.\n", "info")
        progress_text.tag_config("error", foreground="red", font=("Arial", 10, "bold"))
        progress_text.tag_config("info", foreground="blue")

    def install_nmap_and_scan(self, target, scan_type, use_nmap, start_port, end_port):
        """Nmap'i kur ve taramayı başlat"""
        self.is_scanning = True
        self.port_scan_button.config(state=tk.DISABLED)
        self.progress.start()
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "🔧 Nmap kurulumu başlatılıyor...\n")
        self.results_text.insert(tk.END, "Bu işlem birkaç dakika sürebilir.\n")
        self.results_text.insert(tk.END, "="*50 + "\n\n")
        
        # Kurulumu ayrı thread'de başlat
        thread = threading.Thread(target=self.run_nmap_installation, 
                                args=(target, scan_type, use_nmap, start_port, end_port))
        thread.daemon = True
        thread.start()
        
    def run_nmap_installation(self, target, scan_type, use_nmap, start_port, end_port):
        """Nmap kurulumunu çalıştır"""
        try:
            installer = NmapInstaller()
            
            def update_progress(message):
                self.root.after(0, lambda: self.results_text.insert(tk.END, f"{message}\n"))
                
            update_progress("Nmap indiriliyor...")
            if not installer.download_nmap():
                self.root.after(0, lambda: self.show_nmap_error("Nmap indirilemedi!"))
                return
                
            update_progress("Nmap kuruluyor...")
            if not installer.install_nmap_silent():
                self.root.after(0, lambda: self.show_nmap_error("Nmap kurulamadı!"))
                return
                
            update_progress("Nmap PATH'e ekleniyor...")
            installer.add_to_path()
            
            update_progress("✅ Nmap başarıyla kuruldu!")
            update_progress(f"Versiyon: {installer.get_nmap_version()}")
            update_progress("\nPort taraması başlatılıyor...\n")
            
            # Kurulum başarılı, taramayı başlat
            self.root.after(1000, lambda: self.perform_port_scan(target, scan_type, True, start_port, end_port))
            
        except Exception as e:
            self.root.after(0, lambda: self.show_nmap_error(f"Kurulum hatası: {str(e)}"))
            
    def show_nmap_error(self, error_msg):
        """Nmap hatası göster"""
        self.progress.stop()
        self.is_scanning = False
        self.port_scan_button.config(state=tk.NORMAL)
        self.results_text.insert(tk.END, f"HATA: {error_msg}\n", "error")
        self.results_text.insert(tk.END, "\nPython port tarayıcısı ile devam etmek isterseniz tekrar deneyin.\n", "info")
        self.results_text.tag_config("error", foreground="red", font=("Arial", 10, "bold"))
        self.results_text.tag_config("info", foreground="blue")
        
    def perform_port_scan(self, target, scan_type, use_nmap, start_port=None, end_port=None):
        """Port taraması gerçekleştir"""
        self.is_scanning = True
        self.port_scan_button.config(state=tk.DISABLED)
        self.progress.start()
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"🔍 Port taraması başlatılıyor: {target}\n")
        self.results_text.insert(tk.END, f"Tarama tipi: {scan_type}\n")
        self.results_text.insert(tk.END, "="*50 + "\n\n")
        
        # Taramayı ayrı thread'de başlat
        thread = threading.Thread(target=self.run_port_scan, args=(target, scan_type, use_nmap, start_port, end_port))
        thread.daemon = True
        thread.start()
        
    def run_port_scan(self, target, scan_type, use_nmap, start_port, end_port):
        """Port taramasını çalıştır"""
        try:
            if use_nmap:
                # Nmap ile tarama dene
                nmap_results = self.run_nmap_scan(target, scan_type, start_port, end_port)
                if 'error' not in nmap_results:
                    self.root.after(0, self.display_port_results, nmap_results)
                    return
                    
            # Python port scanner ile tara
            scanner = PortScanner(target)
            
            if scan_type == "common":
                results = scanner.scan_common_ports()
            elif scan_type == "web":
                results = scanner.scan_range(1, 1024)
            elif scan_type == "all":
                results = scanner.scan_all_ports()
            elif scan_type == "custom":
                results = scanner.scan_range(start_port, end_port)
            else:
                results = scanner.scan_common_ports()
                
            self.root.after(0, self.display_port_results, results)
            
        except Exception as e:
            self.root.after(0, self.show_port_error, str(e))
            
    def run_nmap_scan(self, target, scan_type, start_port, end_port):
        """Nmap taraması çalıştır"""
        try:
            scanner = PortScanner(target)
            
            if scan_type == "common":
                common_ports = list(set(sum([info['ports'] for info in scanner.port_categories.values()], [])))
                return scanner.run_nmap_scan(common_ports)
            elif scan_type == "web":
                return scanner.run_nmap_scan(range(1, 1025))
            elif scan_type == "all":
                return scanner.run_nmap_scan()
            elif scan_type == "custom":
                return scanner.run_nmap_scan(range(start_port, end_port + 1))
            else:
                return scanner.run_nmap_scan()
                
        except Exception as e:
            return {'error': str(e)}
            
    def display_port_results(self, results):
        """Port tarama sonuçlarını göster"""
        self.progress.stop()
        self.is_scanning = False
        self.port_scan_button.config(state=tk.NORMAL)
        
        if 'error' in results:
            self.results_text.insert(tk.END, f"HATA: {results['error']}\n", "error")
            self.results_text.tag_config("error", foreground="red", font=("Arial", 10, "bold"))
            return
            
        # Port rapor butonunu aktif et
        self.port_report_button.config(state=tk.NORMAL)
            
        # Sonuçları formatla
        formatted_results = PortScanner(results['target']).format_results_text(results)
        self.results_text.insert(tk.END, formatted_results, "port")
        
        # Güvenlik önerileri
        recommendations = PortScanner(results['target']).get_security_recommendations(results)
        if recommendations:
            self.results_text.insert(tk.END, "\n🔒 GÜVENLİK ÖNERİLERİ:\n", "recommendations")
            self.results_text.insert(tk.END, "-"*40 + "\n", "recommendations")
            for rec in recommendations:
                self.results_text.insert(tk.END, f"Port {rec['port']} ({rec['issue']}):\n", "warning")
                self.results_text.insert(tk.END, f"  → {rec['recommendation']}\n\n", "solution")
                
        # Format ayarları
        self.results_text.tag_config("port", foreground="blue")
        self.results_text.tag_config("recommendations", foreground="purple", font=("Arial", 10, "bold"))
        self.results_text.tag_config("warning", foreground="orange")
        self.results_text.tag_config("solution", foreground="green")
        
        # Sonuçları kaydet
        self.last_port_results = results
        
    def show_port_error(self, error_msg):
        """Port tarama hatası göster"""
        self.progress.stop()
        self.is_scanning = False
        self.port_scan_button.config(state=tk.NORMAL)
        self.port_report_button.config(state=tk.DISABLED)
        self.results_text.insert(tk.END, f"Port tarama hatası: {error_msg}\n", "error")
        self.results_text.tag_config("error", foreground="red", font=("Arial", 10, "bold"))
        
    def generate_port_report(self):
        """Port tarama raporu oluştur"""
        if not hasattr(self, 'last_port_results'):
            messagebox.showerror("Hata", "Önce bir port taraması yapın!")
            return
            
        try:
            reporter = PortReporter(self.last_port_results['target'], self.last_port_results)
            report_file = reporter.generate_html_report()
            messagebox.showinfo("Başarılı", f"Port tarama raporu oluşturuldu: {report_file}")
        except Exception as e:
            messagebox.showerror("Hata", f"Rapor oluşturulamadı: {str(e)}")

def main():
    root = tk.Tk()
    app = WebSecurityApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
