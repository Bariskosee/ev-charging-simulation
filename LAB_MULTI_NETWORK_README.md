# 🔌 EV Charging Simulation - Multi-Network Lab Deployment

## ✅ "Different Networks" Gereksinimi Karşılandı!

Bu proje, Docker kullanarak **4 farklı izole ağ** üzerinde çalışan dağıtık bir EV şarj simülasyonu sunmaktadır.

---

## 🌐 Network Mimarisi

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    BACKEND NETWORK (172.30.0.0/24)                          │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌───────────┐  │
│  │    Kafka     │    │  EV-Central  │    │  EV-Registry │    │ Weather   │  │
│  │ 172.30.0.10  │    │ 172.30.0.20  │    │ 172.30.0.30  │    │172.30.0.40│  │
│  └──────────────┘    └──────────────┘    └──────────────┘    └───────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
         │                    │
         │ (Message Broker)   │ (Gateway)
         ▼                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                   CHARGING NETWORK (172.31.0.0/24)                          │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐               │
│  │ CP-001  │ │ CP-002  │ │ CP-003  │ │ CP-004  │ │ CP-005  │               │
│  │  .101   │ │  .102   │ │  .103   │ │  .104   │ │  .105   │               │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘               │
└─────────────────────────────────────────────────────────────────────────────┘
         │
         │ (Health Check)
         ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                  MONITORING NETWORK (172.32.0.0/24)                         │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐               │
│  │Monitor-1│ │Monitor-2│ │Monitor-3│ │Monitor-4│ │Monitor-5│               │
│  │  .101   │ │  .102   │ │  .103   │ │  .104   │ │  .105   │               │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘               │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                   CUSTOMER NETWORK (172.33.0.0/24)                          │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐               │
│  │  Alice  │ │   Bob   │ │ Charlie │ │  David  │ │   Eve   │               │
│  │  .101   │ │  .102   │ │  .103   │ │  .104   │ │  .105   │               │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘               │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Hızlı Başlangıç

### Sistemi Başlat
```bash
# Multi-network yapılandırmasını başlat
docker-compose -f docker-compose.multi-network.yml up -d

# Network demo'sunu çalıştır
./lab-network-demo.sh
```

### Sistemi Durdur
```bash
docker-compose -f docker-compose.multi-network.yml down
```

---

## 🔒 Network İzolasyonu

| Kaynak Network | Hedef Network | Erişim | Açıklama |
|----------------|---------------|--------|----------|
| Customer → Charging | ❌ BLOCKED | Driver'lar doğrudan CP'lere erişemez |
| Customer → Backend | ✅ Allowed | Driver'lar Central API'ye erişebilir |
| Charging → Backend | ✅ Allowed | CP'ler Kafka'ya mesaj gönderebilir |
| Monitoring → Charging | ✅ Allowed | Monitor'lar CP health check yapabilir |

---

## 📊 Lab Sunumu İçin Demo Komutları

### 1. Network'leri Göster
```bash
docker network ls | grep ev-charging-simulation-8
```

### 2. Her Network'teki Container'ları Göster
```bash
# Backend network
docker network inspect ev-charging-simulation-8_backend-network \
  --format '{{range .Containers}}{{.Name}}: {{.IPv4Address}}{{"\n"}}{{end}}'

# Charging network  
docker network inspect ev-charging-simulation-8_charging-network \
  --format '{{range .Containers}}{{.Name}}: {{.IPv4Address}}{{"\n"}}{{end}}'

# Customer network
docker network inspect ev-charging-simulation-8_customer-network \
  --format '{{range .Containers}}{{.Name}}: {{.IPv4Address}}{{"\n"}}{{end}}'
```

### 3. İzolasyon Testi
```bash
# Driver'dan CP'ye erişim denemesi (başarısız olmalı)
docker exec ev-driver-alice nc -zv 172.31.0.101 8001 2>&1 || echo "✅ İzolasyon çalışıyor!"
```

### 4. Dashboard'lara Erişim
- **Central Dashboard**: http://localhost:8000
- **Driver Alice**: http://localhost:8100
- **Registry API**: http://localhost:8080

---

## 🎯 Lab Sunumu Senaryosu

### Senaryo: "Farklı Ağlarda Dağıtık Sistem"

1. **Network Yapısını Göster** (2 dk)
   ```bash
   ./lab-network-demo.sh
   ```

2. **Central Dashboard'u Aç** (1 dk)
   - http://localhost:8000 adresini tarayıcıda aç
   - 5 CP'nin durumunu göster

3. **Driver Dashboard'dan Şarj Başlat** (2 dk)
   - http://localhost:8100 adresini aç
   - "Request Charging" butonuna tıkla
   - Mesajın Kafka üzerinden CP'ye gittiğini açıkla

4. **Log'ları İzle** (2 dk)
   ```bash
   # Farklı terminallerde
   docker logs -f ev-driver-alice
   docker logs -f ev-cp-e-1
   docker logs -f ev-central
   ```

5. **Network İzolasyonunu Kanıtla** (1 dk)
   ```bash
   # Driver, CP'nin IP'sine erişemez
   docker exec ev-driver-alice timeout 2 nc -zv 172.31.0.101 8001 || echo "Blocked!"
   ```

---

## 📁 Dosya Yapısı

```
ev-charging-simulation-8/
├── docker-compose.yml                    # Tek network (eski)
├── docker-compose.multi-network.yml      # 4 farklı network (LAB İÇİN)
├── lab-network-demo.sh                   # Lab sunumu demo script
├── LAB_MULTI_NETWORK_README.md           # Bu dosya
└── ...
```

---

## ⚠️ Notlar

1. **Ping komutu yok**: Docker imajlarında `ping` yüklü değil, ama `nc` (netcat) ile port kontrolü yapılabilir.

2. **Kafka Bridge**: Kafka tüm network'lerde mevcut çünkü mesaj broker'ı olarak görev yapıyor.

3. **Central Gateway**: Central, hem backend hem customer network'te bulunuyor çünkü API gateway rolü var.

---

## 🎓 Hocanıza Açıklama

> "Bu projede Docker ile 4 farklı izole network oluşturduk:
> 
> 1. **Backend Network** (172.30.x.x) - Altyapı servisleri
> 2. **Charging Network** (172.31.x.x) - Şarj istasyonları
> 3. **Monitoring Network** (172.32.x.x) - İzleme servisleri
> 4. **Customer Network** (172.33.x.x) - Müşteri uygulamaları
> 
> Bu yapı gerçek dünya senaryosunu simüle ediyor: müşteriler doğrudan şarj istasyonlarına erişemiyor, 
> tüm iletişim Kafka message broker üzerinden yapılıyor."

---

## ✨ Sonuç

✅ **4 farklı Docker network** kuruldu  
✅ **Network izolasyonu** sağlandı  
✅ **Cross-network iletişim** Kafka ile yapılıyor  
✅ **Gerçek dünya senaryosu** simüle edildi  
✅ **Tek MacBook'ta** tüm sistem çalışıyor  
