# Asset Management Service

Gelişmiş ağ varlık keşfi ve güvenlik tarama sistemi.

## Özellikler

### 🔍 Ağ Keşfi
- **ARP Tarama**: Yerel ağdaki cihazları keşfetme
- **Port Tarama**: Açık portları ve servisleri tespit etme
- **Ping Tarama**: ARP başarısız olduğunda fallback
- **MAC Vendor Lookup**: Cihaz üreticilerini API ile belirleme

### 🖥️ İşletim Sistemi Tespiti
- **Port Tabanlı OS Tespiti**: Açık portlara göre basit ama etkili OS tespiti
  - NetBIOS/RDP portları → Windows
  - mDNS/AirPlay portları → macOS/iOS  
  - SSH (NetBIOS olmadan) → Linux/Unix

### 🔐 Güvenlik Tarama
- **Credential Testing**: SSH, FTP, HTTP, Redis, RDP için default credential testi
- **Vulnerable Services**: Güvenlik açığı bulunan servisleri işaretleme
- **Default Credentials Database**: 40+ yaygın default credential

### 📸 Web Servis Analizi
- **Otomatik Screenshot**: HTTP/HTTPS servisleri için otomatik ekran görüntüsü
- **Web Service Detection**: Web portalları, admin panelleri tespit
- **Headless Browser**: Chrome/Chromium ile gerçek sayfa renderı

### 📊 API & Web Interface
- **RESTful API**: JSON formatında veri erişimi
- **PHP Web UI**: Modern, responsive web arayüzü
- **Real-time Updates**: Anlık tarama sonuçları

## Kurulum & Çalıştırma

### Gereksinimler
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install golang-go chromium-browser

# CentOS/RHEL
sudo yum install golang chromium
```

### Build
```bash
# Ana daemon
go build -o asset-daemon asset-daemon.go

# API server
go build -o bin/api-server cmd/server/main.go
```

### Yapılandırma
`config.json` dosyasını düzenleyin:
```json
{
  "network": {
    "default_cidr": "192.168.1.0/24"  // Kendi ağınıza göre ayarlayın
  }
}
```

### Çalıştırma

#### 1. Daemon Modu (Arka Plan)
```bash
sudo ./asset-daemon -config config.json
```

#### 2. Manuel Tarama
```bash
sudo ./asset-daemon -config config.json -scan-once
```

#### 3. API Server
```bash
./bin/api-server -port 8080
```

### Web Interface
```bash
# PHP built-in server
php -S localhost:8000 assets-ui.php

# Nginx/Apache ile
# assets-ui.php dosyasını web root'a kopyalayın
```

## Kullanım

### Web Interface
1. `http://localhost:8000` adresini açın
2. Keşfedilen cihazları görüntüleyin
3. Credential test sonuçlarını inceleyin
4. Screenshot'ları görüntüleyin

### API Endpoints
```bash
# Tüm assets
curl http://localhost:8080/api/assets

# Güvenlik raporu
curl http://localhost:8080/api/security-report

# Sistem durumu
curl http://localhost:8080/api/status
```

## Çıktı Formatı

### assets.json
```json
{
  "timestamp": "2025-01-15 10:30:45",
  "total_hosts": 15,
  "scan_time": "45.2s",
  "assets": [
    {
      "ip": "192.168.1.100",
      "hostname": "router.local",
      "mac": "aa:bb:cc:dd:ee:ff",
      "vendor": "Cisco Systems",
      "open_ports": [
        {
          "port": 22,
          "protocol": "tcp",
          "state": "open",
          "service": "SSH"
        }
      ],
      "device_info": {
        "os_family": "Linux/Unix",
        "device_type": "server",
        "manufacturer": "Cisco Systems"
      },
      "credential_results": [
        {
          "service": "ssh",
          "port": 22,
          "username": "admin",
          "password": "admin",
          "success": true
        }
      ],
      "screenshot_results": [
        {
          "url": "http://192.168.1.100",
          "success": true,
          "filename": "screenshot_192.168.1.100_80.png"
        }
      ],
      "has_default_creds": true,
      "has_web_services": true
    }
  ]
}
```

## Linux'ta Test Etme

### 1. Hızlı Test
```bash
# Sadece localhost tarama
sudo ./asset-daemon -config config.json -target 127.0.0.1/32 -scan-once

# Küçük ağ tarama
sudo ./asset-daemon -config config.json -target 192.168.1.0/28 -scan-once
```

### 2. Full Network Scan
```bash
# Tüm yerel ağı tara
sudo ./asset-daemon -config config.json -scan-once

# Sonuçları kontrol et
cat assets.json | jq '.'
```

### 3. Debug Modu
```bash
# Verbose output ile
sudo ./asset-daemon -config config.json -debug -scan-once
```

### 4. Credential Testing
```bash
# Sadece credential test
sudo ./asset-daemon -config config.json -credentials-only -scan-once

# Custom credential file
sudo ./asset-daemon -config config.json -credentials static/my_creds.txt -scan-once
```

## Sorun Giderme

### ARP Tarama Sorunları
```bash
# Interface kontrol
ip link show

# Raw socket permission
sudo setcap cap_net_raw=+ep ./asset-daemon
```

### Port Tarama Sorunları
```bash
# Firewall kontrol
sudo ufw status
sudo iptables -L

# Çok fazla connection için
echo 'net.core.somaxconn = 1024' | sudo tee -a /etc/sysctl.conf
```

### Screenshot Sorunları
```bash
# Chromium kurulum kontrol
which chromium-browser
which google-chrome

# Headless test
chromium-browser --headless --disable-gpu --dump-dom https://google.com
```

## Güvenlik Notları

⚠️ **Bu araç sadece kendi ağınızda veya yetkili olduğunuz sistemlerde kullanılmalıdır!**

- Default credential test'i sadece güvenlik değerlendirmesi içindir
- Production ortamında kullanmadan önce test edin
- Ağ trafiğini izlemek için uygun izinlere sahip olun
- Screenshot özelliği hassas bilgileri saklayabilir

## Performans İpuçları

- Büyük ağlarda worker sayısını artırın
- Timeout değerlerini ağ durumuna göre ayarlayın
- SSD kullanın (screenshot için)
- RAM: En az 512MB önerilir

## Lisans

Bu proje test ve eğitim amaçlıdır. Ticari kullanım için geliştiriciye başvurun.
