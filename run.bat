@echo off
echo Web Guvenlik Tarama Uygulamasi Baslatiliyor...
echo.
echo Python kontrol ediliyor...
python --version >nul 2>&1
if errorlevel 1 (
    echo HATA: Python yuklu degil!
    echo Lutfen once Python'u kurun: https://www.python.org/downloads/
    pause
    exit /b 1
)

echo Python bulundu.
echo.
echo Gerekli paketler kontrol ediliyor...
pip show requests >nul 2>&1
if errorlevel 1 (
    echo Gerekli paketler yukleniyor...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo HATA: Paketler yuklenemedi!
        pause
        exit /b 1
    )
)

echo.
echo Uygulama baslatiliyor...
python main.py

if errorlevel 1 (
    echo.
    echo Uygulama calisirken bir hata olustu!
    pause
)
