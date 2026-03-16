#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nmap Otomatik Yükleyici
Windows için Nmap'i otomatik olarak indirir ve kurar
"""

import os
import sys
import requests
import subprocess
import tempfile
import zipfile
from pathlib import Path
import shutil

class NmapInstaller:
    def __init__(self):
        self.nmap_url = "https://nmap.org/dist/nmap-7.92-setup.exe"
        self.nmap_installer_name = "nmap-7.92-setup.exe"
        self.temp_dir = tempfile.gettempdir()
        self.installer_path = os.path.join(self.temp_dir, self.nmap_installer_name)
        
    def check_nmap_installed(self):
        """Nmap yüklü mü kontrol et"""
        try:
            # Nmap komutunu kontrol et
            result = subprocess.run(['nmap', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
            
    def download_nmap(self):
        """Nmap'i indir"""
        try:
            print("Nmap indiriliyor...")
            response = requests.get(self.nmap_url, stream=True, timeout=30)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            
            with open(self.installer_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total_size > 0:
                            percent = (downloaded / total_size) * 100
                            print(f"\rİndiriliyor: {percent:.1f}%", end='')
            
            print(f"\nNmap başarıyla indirildi: {self.installer_path}")
            return True
            
        except requests.exceptions.Timeout:
            print("İndirme zaman aşımına uğradı. İnternet bağlantınızı kontrol edin.")
            return False
        except requests.exceptions.RequestException as e:
            print(f"İndirme hatası: {str(e)}")
            return False
        except Exception as e:
            print(f"Beklenmedik hata: {str(e)}")
            return False
            
    def install_nmap_silent(self):
        """Nmap'i sessiz kur"""
        try:
            print("Nmap kuruluyor...")
            
            # Sessiz kurulum parametreleri
            install_args = [
                self.installer_path,
                '/S',  # Sessiz kurulum
                '/D=C:\\Program Files (x86)\\Nmap'  # Kurulum dizini
            ]
            
            result = subprocess.run(install_args, capture_output=True, timeout=300)
            
            if result.returncode == 0:
                print("Nmap başarıyla kuruldu.")
                # PATH'e ekle
                self.add_to_path()
                return True
            else:
                print(f"Kurulum hatası: {result.stderr.decode()}")
                return False
                
        except subprocess.TimeoutExpired:
            print("Kurulum zaman aşımına uğradı.")
            return False
        except Exception as e:
            print(f"Kurulum hatası: {str(e)}")
            return False
            
    def add_to_path(self):
        """Nmap'i PATH'e ekle"""
        try:
            nmap_path = r"C:\Program Files (x86)\Nmap"
            
            # Mevcut PATH'i al
            current_path = os.environ.get('PATH', '')
            
            if nmap_path not in current_path:
                # PATH'e ekle
                new_path = f"{current_path};{nmap_path}"
                os.environ['PATH'] = new_path
                
                # Kalıcı olarak ekle (kayıt defteri)
                try:
                    import winreg
                    key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, 
                                         r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment")
                    winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, new_path)
                    winreg.CloseKey(key)
                except:
                    pass  # Kayıt defteri hatası olsa da devam et
                    
                print("Nmap PATH'e eklendi.")
                
        except Exception as e:
            print(f"PATH ekleme hatası: {str(e)}")
            
    def cleanup(self):
        """Geçici dosyaları temizle"""
        try:
            if os.path.exists(self.installer_path):
                os.remove(self.installer_path)
                print("Geçici dosyalar temizlendi.")
        except Exception:
            pass
            
    def install(self):
        """Nmap'i indir ve kur"""
        print("Nmap kurulumu başlatılıyor...")
        
        # Zaten yüklü mü kontrol et
        if self.check_nmap_installed():
            print("Nmap zaten yüklü.")
            return True
            
        # İndir
        if not self.download_nmap():
            return False
            
        # Kur
        if not self.install_nmap_silent():
            return False
            
        # Temizle
        self.cleanup()
        
        # Kurulumu kontrol et
        if self.check_nmap_installed():
            print("Nmap başarıyla kuruldu ve kullanıma hazır.")
            return True
        else:
            print("Nmap kurulumu başarısız oldu.")
            return False
            
    def get_nmap_version(self):
        """Nmap versiyonunu al"""
        try:
            result = subprocess.run(['nmap', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                first_line = result.stdout.split('\n')[0]
                return first_line
        except:
            pass
        return "Bilinmeyen versiyon"

def install_nmap_if_needed():
    """Nmap gerekliyse kur"""
    installer = NmapInstaller()
    
    if not installer.check_nmap_installed():
        print("Nmap bulunamadı, otomatik kurulum başlatılıyor...")
        return installer.install()
    else:
        print(f"Nmap zaten yüklü: {installer.get_nmap_version()}")
        return True

if __name__ == "__main__":
    if install_nmap_if_needed():
        print("Nmap kullanıma hazır!")
        sys.exit(0)
    else:
        print("Nmap kurulumu başarısız oldu.")
        sys.exit(1)
