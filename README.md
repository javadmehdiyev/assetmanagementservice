# Asset Management Daemon

@gereksinim'e göre yapılmış basit asset management daemon servisi.

## 🎯 Özellikler (Requirements)

1. **Dosya tabanlı IP blok tarama** - `list.txt` dosyasından IP blokları okur
2. **Yerel network taraması** - Otomatik yerel ağ tespiti ve tarama  
3. **Arka planda çalışan servis** - Daemon olarak sürekli çalışır
4. **JSON konfigürasyon** - `config.json` dosyasından ayarları okur
5. **Asset Management** - Bulunan varlıkları JSON olarak kaydeder
6. **Otomasyon** - Otomatik başlatma ve sürekli çalışma

## 🚀 Hızlı Başlangıç

```bash
# Test et
go run test-daemon.go

# Daemon'u çalıştır
go run asset-daemon.go
```

## 📁 Dosyalar

- `asset-daemon.go` - Ana daemon servisi
- `test-daemon.go` - Test programı  
- `config.json` - Konfigürasyon dosyası
- `list.txt` - Taranacak IP blokları
- `assets.json` - Bulunan varlıklar (çıktı)

## ⚙️ Konfigürasyon

```json
{
  "service": {
    "name": "Asset Management Service",
    "scan_interval": "5m"
  },
  "network": {
    "interface": "auto",
    "default_cidr": "192.168.123.0/24",
    "scan_local_network": true,
    "scan_file_list": true
  },
  "arp": {
    "enabled": true,
    "timeout": "1s",
    "workers": 10
  },
  "files": {
    "ip_list_file": "list.txt",
    "output_file": "assets.json"
  }
}
```

## 📋 list.txt Formatı

```
# Yorumlar # ile başlar
192.168.1.0/24
10.0.0.0/24
8.8.8.8
```

## 📄 JSON Çıktı

```json
{
  "timestamp": "2024-01-01 12:00:00",
  "total_hosts": 3,
  "scan_time": "2.5s",
  "assets": [
    {
      "ip": "192.168.1.1",
      "mac": "aa:bb:cc:dd:ee:ff",
      "vendor": "Vendor Name",
      "discovery_method": "ARP"
    }
  ]
}
```

## 🛠️ Kullanım

### Test Modu
```bash
go run test-daemon.go
```

### Daemon Modu  
```bash
go run asset-daemon.go
```

### Durdurma
```bash
Ctrl+C
```

## 🏗️ Mimari

- **Basit ve hızlı** - Karmaşık özellikler kaldırıldı
- **ARP + TCP tarama** - Yerel ağ için ARP, uzak ağlar için TCP
- **JSON tabanlı** - Kolay entegrasyon
- **Daemon ready** - Başka uygulamalar tarafından kullanılabilir

## 📊 Performans

- Yerel ağ tarama: ~30 saniye (254 IP)
- JSON çıktı: Anlık
- Bellek kullanımı: Minimal
- CPU kullanımı: Düşük 