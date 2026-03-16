# Web Güvenlik Tarama Uygulaması

Windows için eklentisiz web sitesi ve web uygulaması güvenlik açığı tarayıcısı.

## Özellikler

### 🛡️ Web Sitesi Taraması
- **SQL Injection Tespiti**: Veritabanı enjeksiyon açıklarını tarar
- **XSS Tespiti**: Cross-Site Scripting açıklarını tespit eder
- **CSRF Tespiti**: Cross-Site Request Forgery zafiyetlerini kontrol eder
- **Dizin Listeleme**: Yetkisiz dizin erişimlerini bulur
- **Güvenlik Başlıkları**: HTTP güvenlik başlıklarını kontrol eder
- **SSL/TLS Kontrolü**: Sertifika güvenliğini denetler

### 🔒 Son Güvenlik Açıkları Veritabanı
- **WordPress**: Son güvenlik açıkları ve versiyon bilgileri
- **Joomla**: Güncel zafiyetler ve çözüm önerileri
- **Apache**: Web sunucu güvenlik açıkları
- **PHP**: Programlama dili güvenlik zafiyetleri
- **MySQL**: Veritabanı güvenlik açıkları
- **MariaDB**: Veritabanı güvenlik sorunları

### 📊 Raporlama
- **Site Tarama Raporu**: HTML formatında detaylı analiz
- **Güvenlik Açığı Raporu**: Son CVE açıklarının listesi
- **Port Tarama Raporu**: Açık portların analizi
- **JSON Export**: Programatik kullanım için yapısal veri

### 🤖 Yapay Zeka Analizi
- **AI Destekli Tarama**: NVIDIA API ile güncel CVE açıkları
- **Gerçek Zamanlı Analiz**: Son 30 gün içindeki güvenlik açıkları
- **Trend Analizi**: Aktif exploit'li ve popüler açıklar
- **Sistem Bazlı**: WordPress, Apache, PHP, Docker, MSSQL, Oracle gibi 17+ sistem
- **CVSS Skorlama**: Otomatik risk seviyesi belirleme
- **AI Raporlama**: Detaylı HTML raporları

### 🔍 Kapsamlı Port Taraması
- **Yaygın Portlar**: Web, FTP, SSH, veritabanı portları
- **Tüm Portlar**: 1-65535 arası tam tarama
- **Özel Aralık**: Belirli port aralıklarında tarama
- **Nmap Entegrasyonu**: Yüklü ise Nmap kullanımı
- **Servis Tespiti**: Port servislerini ve banner'ları algılama
- **Risk Analizi**: Port risk seviyelerini değerlendirme

## Kurulum

### Gereksinimler
- Python 3.7 veya üzeri
- Windows işletim sistemi

### Adım 1: Python'u Yükleyin
Eğer sisteminizde Python yüklü değilse:
1. [python.org](https://www.python.org/downloads/) adresinden Python'u indirin
2. Kurulum sırasında "Add Python to PATH" seçeneğini işaretleyin
3. Kurulumu tamamlayın

### Adım 2: Uygulamayı İndirin
Bu repository'i bilgisayarınıza indirin veya ZIP olarak download edin.

### Adım 3: Gerekli Paketleri Yükleyin
Komut istemini (CMD) açın ve uygulama dizinine gidin:
```cmd
cd WindAiTarama
```

Gerekli paketleri yükleyin:
```cmd
pip install -r requirements.txt
```

## Kullanım

### Uygulamayı Çalıştırma
Uygulamayı başlatmak için:
```cmd
python main.py
```

### Tarama Yapma
1. **URL Girin**: Taramak istediğiniz web sitesinin URL'sini girin
2. **Tarama Seçeneklerini Belirleyin**: Hangi açıkların taranacağını seçin
3. **Taramayı Başlatın**: "Taramayı Başlat" butonuna tıklayın
4. **Sonuçları İnceleyin**: Tarama sonuçları gerçek zamanlı olarak görüntülenir
5. **Rapor Oluşturun**: "Rapor Oluştur" butonuyla detaylı rapor indirin

### Son Güvenlik Açıklarını Görüntüleme
1. **"Son Açıklar" Butonu**: Güncel güvenlik açıklarını listeler
2. **Sistem Dağılımı**: WordPress, Joomla, Apache gibi sistemlere göre gruplama
3. **Kritik Açıklar**: Yüksek riskli CVE açıkları
4. **"Açık Raporu" Butonu**: Detaylı HTML raporu indirin

### AI Güvenlik Analizi Yapma
1. **"🤖 AI Analiz" Butonu**: Yapay zeka analiz seçeneklerini açar
2. **Analiz Tipi**: Son açıklar, trend olanlar, özel sistemler
3. **Sistem Seçimi**: 17+ sistemden istediklerinizi seçin
4. **Periyot Belirleme**: 1-90 gün arası analiz periyodu
5. **"📊 AI Raporu" Butonu**: Detaylı AI analiz raporu indirin

### Port Taraması Yapma
1. **"Port Taraması" Butonu**: Port tarama seçeneklerini açar
2. **Hedef Belirleme**: URL veya IP adresi girin
3. **Tarama Tipi**: Yaygın portlar, web portları, tüm portlar veya özel aralık
4. **Nmap Seçeneği**: Yüklü ise Nmap ile gelişmiş tarama
5. **"Port Raporu" Butonu**: Detaylı port tarama raporu indirin

## Tarama Türleri

### 🔴 Yüksek Riskli Açıklar
- **SQL Injection**: Veritabanına yetkisiz erişim
- **XSS**: Kullanıcı oturumlarını çalma

### 🟡 Orta Riskli Açıklar
- **CSRF**: Kullanıcı hesaplarını ele geçirme
- **Dizin Listeleme**: Dosya erişim açıkları
- **SSL/TLS**: Şifreleme zafiyetleri

### 🟢 Düşük Riskli Açıklar
- **Güvenlik Başlıkları**: Ek koruma katmanları

### 🔍 Port Risk Seviyeleri
- **🔴 Yüksek Risk**: Telnet, FTP, RDP, SMB, Database portları
- **🟡 Orta Risk**: SSH, SMTP, DNS, LDAP, Development portları
- **🟢 Düşük Risk**: HTTP, HTTPS, standart web servisleri

## Raporlama

Uygulama şu rapor formatlarını destekler:
- **Site Tarama Raporu**: Detaylı, görsel rapor (tarayıcıda açılabilir)
- **Güvenlik Açığı Raporu**: Son CVE açıklarının analizi
- **AI Analiz Raporu**: Yapay zeka destekli güvenlik analizi
- **Port Tarama Raporu**: Açık portların detaylı analizi
- **JSON Raporu**: Programatik analiz için yapısal veri

### 📊 Desteklenen Sistemler
- **Web Platformları**: WordPress, Joomla, Drupal
- **Web Sunucular**: Apache, Nginx
- **Programlama**: PHP
- **Veritabanları**: MySQL, MariaDB, PostgreSQL, MongoDB, Redis, MSSQL, Oracle
- **DevOps**: Docker, Kubernetes
- **İşletim Sistemleri**: Linux, Windows

Raporlar `reports` klasöründe otomatik olarak oluşturulur.

## 🗂️ Dosya Yapısı

```
WindAiTarama/
├── main.py              # Ana GUI uygulaması
├── scanner.py           # Web sitesi tarama motoru
├── reporter.py          # Site tarama raporlama
├── vulnerability_db.py  # Güvenlik açığı veritabanı
├── vuln_reporter.py     # Açık raporlama sistemi
├── port_scanner.py      # Port tarama motoru
├── port_reporter.py     # Port tarama raporlama
├── nmap_installer.py    # Nmap otomatik kurulum
├── ai_vuln_scanner.py   # AI destekli güvenlik analizi
├── ai_vuln_reporter.py  # AI analiz raporlama
├── requirements.txt     # Python bağımlılıkları
├── run.bat             # Windows başlatma script'i
├── README.md           # Kullanım kılavuzu
└── reports/            # Oluşturulan raporlar
```

## Güvenlik Uyarısı

⚠️ **ÖNEMLİ**: Bu araç sadece eğitim ve test amaçlıdır.
- Yalnızca kendi siteleriniz veya izin aldığınız siteler için kullanın
- Yasalara aykırı kullanımdan kullanıcı sorumludur
- Tarama sonuçlarını profesyonel güvenlik uzmanlarıyla teyit edin
- **Port taraması sadece kendi ağınızda veya izin verilen sistemlerde kullanılmalıdır**

## Teknik Özellikler

- **Platform**: Windows
- **Dil**: Python 3
- **GUI**: Tkinter
- **Ağ**: Requests kütüphanesi
- **HTML Parsing**: BeautifulSoup4
- **Raporlama**: HTML, JSON

## Sıkça Sorulan Sorular

### S: Uygulama çalışmıyor?
C: Python ve gerekli paketlerin doğru kurulduğundan emin olun.

### S: Tarama çok uzun sürüyor?
C: Büyük sitelerde tarama süresi uzayabilir. Lütfen bekleyin.

### S: Yanlış pozitif sonuçlar alıyorum?
C: Otomatik tarama tools'ları yanlış pozitif verebilir. Manuel kontrol önerilir.

### S: HTTPS olmayan siteleri tarayabilir miyim?
C: Evet, ancak SSL kontrolü yapılamaz.

## Destek ve Katkı

- Hata bildirimleri için GitHub Issues kullanın
- Katkı yapmak için pull request gönderebilirsiniz
- Güvenlik sorunları için özel iletişim kurun

## Lisans

Bu proje MIT Lisansı altında dağıtılmaktadır.

## Sürüm Geçmişi

### v1.3.0
- ✅ Yapay zeka destekli güvenlik analizi eklendi
- ✅ NVIDIA API entegrasyonu ile gerçek zamanlı CVE taraması
- ✅ AI destekli trend ve exploit analizi
- ✅ 17+ sistem için özel analiz seçenekleri
- ✅ AI analiz raporlama sistemi
- ✅ Otomatik önceliklendirme ve içgörüler

### v1.2.0
- ✅ Kapsamlı port tarama özelliği eklendi
- ✅ 1-65535 arası port tarama desteği
- ✅ Port servisi ve banner tespiti
- ✅ Risk seviyesi analizi
- ✅ Nmap entegrasyonu (isteğe bağlı)
- ✅ Port tarama raporlama

### v1.1.0
- ✅ Son güvenlik açıkları veritabanı eklendi
- ✅ WordPress, Joomla, Apache, PHP, MySQL, MariaDB desteği
- ✅ CVE açıklarını listeleme özelliği
- ✅ Güvenlik açığı raporu oluşturma
- ✅ Site erişim kontrolü ve hata mesajları

### v1.0.0
- İlk sürüm
- Temel güvenlik tarama özellikleri
- HTML raporlama
- Windows GUI arayüzü

---

**Güvenli İnternet İçin Tarayın, Korunun!** 🛡️
