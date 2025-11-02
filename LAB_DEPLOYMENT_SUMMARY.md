# 🎓 EV Charging Simulation - 3 Windows Bilgisayar Laboratuvar Dağıtım Kılavuzu


## 📊 Sistem Yapısı

### Toplam Servis Sayısı: **17 Servis**

```
┌─────────────────────────────────────────────────────────┐
│  Makine 1 (Ana Sunucu)                                  │
│  - 1 Kafka Broker                                       │
│  - 1 Central Controller (Dashboard + TCP)              │
│  Toplam: 2 servis                                       │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│  Makine 2 (Lab PC 1 - Şarj İstasyonları)               │
│  - 5 CP Engine (CP-001 to CP-005)                      │
│  - 5 CP Monitor (Health Checking)                      │
│  Toplam: 10 servis                                      │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│  Makine 3 (Lab PC 2 - Sürücüler)                       │
│  - 5 Driver İstemcisi (Alice, Bob, Charlie, David, Eve)│
│  Toplam: 5 servis                                       │
└─────────────────────────────────────────────────────────┘
```

---

## ⚡ Şarj İstasyonu Detayları (5 CP)

| CP ID  | Güç (kW) | Fiyat (€/kWh) | Port | Açıklama        |
|--------|----------|---------------|------|-----------------|
| CP-001 | 22.0     | 0.30          | 8001 | Standart AC     |
| CP-002 | 50.0     | 0.35          | 8002 | Hızlı DC        |
| CP-003 | 43.0     | 0.32          | 8003 | Orta Seviye     |
| CP-004 | 150.0    | 0.40          | 8004 | Ultra Hızlı DC  |
| CP-005 | 7.2      | 0.28          | 8005 | Yavaş AC (Gece) |

---

## 🚗 Sürücü Detayları (5 Driver)

| Sürücü ID      | Dashboard Port | İstek Aralığı | Davranış Profili      |
|----------------|----------------|---------------|-----------------------|
| driver-alice   | 8100           | 120 saniye    | Dengeli kullanım      |
| driver-bob     | 8101           | 60 saniye     | Sakin kullanıcı       |
| driver-charlie | 8102           | 30 saniye     | Ara sıra kullanım     |
| driver-david   | 8103           | 15 saniye     | Hafta sonu kullanıcı  |
| driver-eve     | 8104           | 10 saniye     | Yoğun kullanım (Taksi)|

---


### Gerekli Portlar:
- **Makine 1**: 9092 (Kafka), 8000 (Dashboard), 9999 (TCP)
- **Makine 2**: Dış bağlantı yok (sadece outbound) - 5 CP Engine + 5 Monitor
- **Makine 3**: 8100-8104 (5 Driver dashboards - Alice, Bob, Charlie, David, Eve)

---

## 🚀 Kurulum Adımları

**Tüm 3 makinede aynı adımları takip edin:**

**Seçenek 1: Git ile (ÖNERİLİR):**

```powershell
# PowerShell'de (Normal kullanıcı - yönetici değil)

# 1. Git kurulu mu kontrol et
git --version
# Eğer "command not found" hatası alırsanız Git kurun:
# https://git-scm.com/download/win

# 2. Projeyi klonlayın
cd C:\Users\$env:USERNAME\Desktop
git clone https://github.com/Bariskosee/ev-charging-simulation.git

# 3. Proje klasörüne girin
cd ev-charging-simulation

# 4. Dosyaların indiğini doğrulayın
ls
# Göreceksiniz: docker/, evcharging/, docker-compose.yml, README.md, vb.
```

**Seçenek 2: ZIP ile (Git yoksa):**

```powershell
# 1. Web tarayıcısında bu adresi açın:
# https://github.com/Bariskosee/ev-charging-simulation/archive/refs/heads/main.zip

# 2. ZIP dosyasını indirin (Downloads klasörüne)

# 3. ZIP'i masaüstüne çıkarın:
# Downloads klasöründe ev-charging-simulation-main.zip'e sağ tık
# "Extract All" → Destination: Desktop → Extract

# 4. PowerShell'de klasöre gidin
cd C:\Users\$env:USERNAME\Desktop\ev-charging-simulation-main

# 5. Dosyaların varlığını doğrulayın
ls
```

**✅ Başarılı İndirme İşaretleri:**
- Masaüstünde `ev-charging-simulation` klasörü var
- İçinde `docker/`, `evcharging/`, `docker-compose.yml` var
- PowerShell'de `cd ev-charging-simulation` komutu çalışıyor

---

#### Adım 0.3: Ağ Bağlantısını Test Etme

**Her makinede ağ bağlantısını test edin:**

**PowerShell'de:**
```powershell
# 1. Kendi IP adresinizi öğrenin
(Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "Ethernet*" | Where-Object {$_.IPAddress -like "192.168.*" -or $_.IPAddress -like "10.*"}).IPAddress

# Örnek çıktı:
# 192.168.1.101  (Makine 1)
# 192.168.1.102  (Makine 2)
# 192.168.1.103  (Makine 3)

# 2. IP'yi not edin (kağıda yazın veya WhatsApp'ta paylaşın)
```

**Ağ testi (Tüm makineler hazır olduktan sonra):**
```powershell
# Her makineden diğer makinelere ping atın:

# Örnek: Makine 2'den Makine 1'e ping
ping 192.168.1.101


---

### 1️⃣ Makine 1 Kurulumu (Ana Sunucu)

> **🎯 Amaç:** Kafka ve Central Controller başlatmak, IP adresini diğer makinelere vermek

#### Adım 1.1: IPv4 Adresini Bul

**PowerShell'de (ÖNERİLİR):**
```powershell
# Ethernet bağlantısının IPv4 adresini bul
(Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "Ethernet*" | Where-Object {$_.IPAddress -like "192.168.*" -or $_.IPAddress -like "10.*"}).IPAddress
```

**Command Prompt'ta (Alternatif):**
```cmd
ipconfig | findstr /i "IPv4"
```

**Örnek Çıktı:**
```
192.168.1.105
```

---


#### Adım 1.3: Windows Firewall Yapılandırması

**PowerShell'i Yönetici Olarak Aç:**
1. Başlat menüsünde "PowerShell" ara
2. Sağ tık → "Run as Administrator"

**Gerekli portları aç:**
```powershell
# Kafka için port 9092'yi aç
New-NetFirewallRule -DisplayName "EV Charging - Kafka Port 9092" -Direction Inbound -LocalPort 9092 -Protocol TCP -Action Allow

# Central Dashboard için port 8000'i aç
New-NetFirewallRule -DisplayName "EV Charging - Central Dashboard 8000" -Direction Inbound -LocalPort 8000 -Protocol TCP -Action Allow

# TCP Server için port 9999'u aç
New-NetFirewallRule -DisplayName "EV Charging - TCP Server 9999" -Direction Inbound -LocalPort 9999 -Protocol TCP -Action Allow
```

**Firewall kurallarını doğrula:**
```powershell
# Kuralların eklendiğini kontrol et
Get-NetFirewallRule -DisplayName "EV Charging*" | Select-Object DisplayName, Enabled, Direction
```

**Alternatif: Windows GUI İle:**
1. `Control Panel` → `Windows Defender Firewall` → `Advanced Settings`
2. `Inbound Rules` → `New Rule`
3. `Port` seç → `TCP` → `9092, 8000, 9999` portlarını ekle
4. `Allow the connection` → `Apply`

---

#### Adım 1.4: Servisleri Başlat

**PowerShell'de (Normal kullanıcı - yönetici değil):**

```powershell
# IPv4 adresini environment variable olarak ayarla
$env:KAFKA_ADVERTISED_HOST = "192.168.1.105"  # ⬅️ KENDİ IP'NİZİ YAZIN!

# Kafka'yı başlat
docker compose up -d kafka

# Kafka'nın hazır olmasını bekle (30 saniye)
Start-Sleep -Seconds 30

# Kafka'nın başarıyla başladığını kontrol et
docker logs ev-kafka | Select-String "started (kafka.server.KafkaRaftServer)"

# Central Controller'ı başlat
docker compose up -d ev-central

# Servislerin durumunu kontrol et
docker compose ps
```

**Beklenen Çıktı:**
```
NAME          IMAGE                     STATUS         PORTS
ev-kafka      apache/kafka:3.7.0        Up (healthy)   0.0.0.0:9092->9092/tcp
ev-central    ev-charging-...-central   Up             0.0.0.0:8000->8000/tcp, 0.0.0.0:9999->9999/tcp
```

---

#### Adım 1.5: Sistem Sağlığını Doğrula

**PowerShell'de:**
```powershell
# Central Dashboard'u kontrol et
Invoke-WebRequest -Uri "http://localhost:8000/health" | Select-Object -ExpandProperty Content

# Kafka bağlantısını test et
docker exec ev-kafka kafka-broker-api-versions.sh --bootstrap-server localhost:9092
```

**Beklenen Sağlık Durumu:**
```json
{
  "status": "healthy",
  "service": "ev-central",
  "kafka_producer": "connected",
  "kafka_consumer": "connected",
  "timestamp": "2025-10-28T..."
}
```

---

#### Adım 1.6: IP Adresini Paylaş

**PowerShell'de:**
```powershell
Write-Host "==================================="
Write-Host "Kafka ve Central IP: $env:KAFKA_ADVERTISED_HOST"
Write-Host "Dashboard URL: http://$env:KAFKA_ADVERTISED_HOST:8000"
Write-Host "==================================="
Write-Host "Bu IP'yi diğer 2 makineye verin!"
```

---

### 2️⃣ Makine 2 Kurulumu (Charging Points)

> **🎯 Amaç:** 5 CP Engine + 5 CP Monitor başlatmak (toplam 10 servis)  
> **📋 Gerekli Bilgi:** Makine 1'in IP adresi (öğretmenden alınacak)

#### Adım 2.1: Makine 1'den IP Adresini Alma

**Öğretmenden/Makine 1'den şu bilgileri alın:**
```
Makine 1 IP: 192.168.1.105  (Örnek - kendi IP'nizi kullanın)
```

---

#### Adım 2.2: Environment Variables Ayarlama

**PowerShell'de (Makine 2'de):**

```powershell
# Makine 1'den aldığınız IP adresini buraya yazın
$env:KAFKA_BOOTSTRAP = "192.168.1.105:9092"      # ⬅️ Makine 1 IP'yi buraya
$env:CENTRAL_HOST = "192.168.1.105"              # ⬅️ Makine 1 IP'yi buraya
$env:CENTRAL_PORT = "8000"

# Ayarlandığını doğrula
Write-Host "✅ Environment Variables Ayarlandı:" -ForegroundColor Green
Write-Host "   KAFKA_BOOTSTRAP = $env:KAFKA_BOOTSTRAP"
Write-Host "   CENTRAL_HOST = $env:CENTRAL_HOST"
Write-Host "   CENTRAL_PORT = $env:CENTRAL_PORT"
```

**Beklenen Çıktı:**
```
✅ Environment Variables Ayarlandı:
   KAFKA_BOOTSTRAP = 192.168.1.105:9092
   CENTRAL_HOST = 192.168.1.105
   CENTRAL_PORT = 8000
```

---

#### Adım 2.3: Bağlantı Testleri (ÖNEMLİ!)

**Bu adım çok önemli - servisleri başlatmadan önce bağlantıyı test edin!**

**PowerShell'de:**
```powershell
Write-Host "🔍 Makine 1'e bağlantı test ediliyor..." -ForegroundColor Cyan

# Test 1: Kafka portuna erişim (9092)
Write-Host "`n1️⃣  Kafka (port 9092) testi:" -ForegroundColor Yellow
Test-NetConnection -ComputerName $env:CENTRAL_HOST -Port 9092

# Test 2: Central HTTP portuna erişim (8000)
Write-Host "`n2️⃣  Central HTTP (port 8000) testi:" -ForegroundColor Yellow
Test-NetConnection -ComputerName $env:CENTRAL_HOST -Port 8000

# Test 3: Central health endpoint
Write-Host "`n3️⃣  Central health endpoint testi:" -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "http://$($env:CENTRAL_HOST):8000/health" -UseBasicParsing
    Write-Host "   ✅ Central erişilebilir! Status: $($response.StatusCode)" -ForegroundColor Green
} catch {
    Write-Host "   ❌ Central erişilemiyor! Hata: $_" -ForegroundColor Red
    Write-Host "   🔧 Makine 1'de firewall ayarlarını kontrol edin!" -ForegroundColor Yellow
}
```

**✅ Başarılı Bağlantı İşaretleri:**
```
TcpTestSucceeded : True  (her iki port için)
✅ Central erişilebilir! Status: 200
```

**❌ Eğer TcpTestSucceeded : False ise:**
1. Makine 1'de firewall kurallarını kontrol edin
2. IP adresinin doğru olduğunu onaylayın
3. Makine 1'de servislerin çalıştığını kontrol edin (`docker ps`)
4. Öğretmene/lab sorumlusuna danışın

---

#### Adım 2.4: Docker Network Oluşturma (KRİTİK ADIM!)

**⚠️ ÖNEMLİ:** Bu network olmazsa CP'ler Central'a kayıt olamaz!
docker network ls | Select-String "evcharging-network"

# Eğer yoksa oluştur (Makine 1'deki ile aynı isimde olmalı)
docker network create ev-charging-simulation-1_evcharging-network

# Network'ü doğrula
docker network inspect ev-charging-simulation-1_evcharging-network
```

**⚠️ ÖNEMLİ:** Bu network Makine 1'de otomatik oluşur ama Makine 2 ve 3'te manuel oluşturulmalı!

---

#### Adım 2.4: Charging Point Servislerini Başlat

**PowerShell Script ile (ÖNERİLİR):**
```powershell
# Quick deployment script kullan (otomatik bağlantı testi dahil)
.\deploy-lab-cp.ps1
```

**Manuel PowerShell:**
```powershell
# Environment variables'ların ayarlandığından emin olun
Write-Host "KAFKA_BOOTSTRAP: $env:KAFKA_BOOTSTRAP"
Write-Host "CENTRAL_HOST: $env:CENTRAL_HOST"

# 5 CP Engine ve 5 Monitor servisini başlat (toplamda 10 servis)
docker compose -f docker/docker-compose.remote-kafka.yml up -d `
  ev-cp-e-1 ev-cp-e-2 ev-cp-e-3 ev-cp-e-4 ev-cp-e-5 `
  ev-cp-m-1 ev-cp-m-2 ev-cp-m-3 ev-cp-m-4 ev-cp-m-5

# Servislerin durumunu kontrol et (10 servis görmelisiniz)
docker compose -f docker/docker-compose.remote-kafka.yml ps

# Tüm CP'lerin çalıştığını doğrula
docker ps --filter "name=ev-cp" --format "table {{.Names}}\t{{.Status}}"
```
Way to add monitor and engine manually
```powershell
# recipe for monitor and engine - run only once
docker build -t ev-cp-engine:latest -f docker/Dockerfile.cp_e ..
docker build -t ev-cp-monitor:latest -f docker/Dockerfile.cp_m ..

Here it is necessary 
docker run -d `
  --name ev-cp-e-NUMBER `
  --network evcharging-network `
  -e CP_ENGINE_KAFKA_BOOTSTRAP="$env:KAFKA_BOOTSTRAP" `
  -e CP_ENGINE_CP_ID="CP-NUMBER" `
  -e CP_ENGINE_HEALTH_PORT=NEXT_PORT `
  -e CP_ENGINE_LOG_LEVEL=INFO `
  -e CP_ENGINE_KW_RATE=VALUE1 `
  -e CP_ENGINE_EURO_RATE=VALUE2 `
  -e CP_ENGINE_TELEMETRY_INTERVAL=1.0 `
  -p NEXT_PORT:NEXT_PORT `
  ev-cp-engine:latest

docker run -d `
  --name ev-cp-m-NUMBER `
  --network evcharging-network `
  -e CP_MONITOR_CP_ID="CP-NUMBER" `
  -e CP_MONITOR_CP_E_HOST="ev-cp-e-NUMBER" `
  -e CP_MONITOR_CP_E_PORT=NEXT_PORT `
  -e CP_MONITOR_CENTRAL_HOST="$env:CENTRAL_HOST" `
  -e CP_MONITOR_CENTRAL_PORT="$env:CENTRAL_PORT" `
  -e CP_MONITOR_HEALTH_INTERVAL=2.0 `
  -e CP_MONITOR_LOG_LEVEL=INFO `
  -e CP_MONITOR_KAFKA_BOOTSTRAP="$env:KAFKA_BOOTSTRAP" `
  ev-cp-monitor:latest

```

**Beklenen Çıktı:** 10 container (5 engine + 5 monitor) "Up" durumda olmalı

---

#### Adım 2.4: CP Loglarını Kontrol Et

**PowerShell'de:**
```powershell
# CP Engine başarıyla başladı mı?
docker logs ev-cp-e-1 | Select-String "started successfully|ACTIVATED"

# CP Monitor çalışıyor mu?
docker logs ev-cp-m-1 | Select-String "heartbeat|Monitoring CP-001"
```

**Beklenen CP Engine Logları:**
```
✅ Kafka producer started: 192.168.1.105:9092
✅ Kafka consumer started: topics=['central.commands']
✅ CP CP-001: CPState.DISCONNECTED + CPEvent.CONNECT -> CPState.ACTIVATED
✅ CP Engine CP-001 started successfully
```

**Beklenen Monitor Logları:**
```
✅ Monitoring CP-001 at ev-cp-e-1:8001
✅ Central heartbeat sent successfully
✅ Health check: CP-001 is HEALTHY
```

---

#### Adım 2.5: Makine 1'den CP'leri Doğrula

**Makine 1'de (Ana Bilgisayar) PowerShell:**
```powershell
# Dashboard'dan CP'leri kontrol et
Invoke-WebRequest -Uri "http://localhost:8000/cp" | ConvertFrom-Json | Select-Object -ExpandProperty charging_points
```

**CP-001 to CP-005 görmelisiniz! (Toplamda 5 CP + 5 Monitor = 10 servis)** 🎉

---

### 3️⃣ Makine 3 Kurulumu (Drivers)

> **🎯 Amaç:** 5 Driver istemcisi başlatmak (Alice, Bob, Charlie, David, Eve)  
> **📋 Gerekli Bilgi:** Makine 1'in IP adresi + CP'lerin hazır olması (Makine 2'den)

#### Adım 3.1: Makine 1'den IP Adresini Alma


**Makine 2'nin hazır olduğundan emin olun!**
- Makine 2'de 10 CP servisi çalışıyor olmalı
- Makine 1 dashboard'unda 5 CP görünüyor olmalı

---

#### Adım 3.2: Environment Variables Ayarlama

**PowerShell'de (Makine 3'te):**

```powershell
# Makine 1'den aldığınız IP adresini buraya yazın
$env:KAFKA_BOOTSTRAP = "192.168.1.105:9092"              # ⬅️ Makine 1 IP'yi buraya
$env:CENTRAL_HTTP_URL = "http://192.168.1.105:8000"      # ⬅️ Makine 1 IP'yi buraya

# Ayarlandığını doğrula
Write-Host "✅ Environment Variables Ayarlandı:" -ForegroundColor Green
Write-Host "   KAFKA_BOOTSTRAP = $env:KAFKA_BOOTSTRAP"
Write-Host "   CENTRAL_HTTP_URL = $env:CENTRAL_HTTP_URL"
```

**Beklenen Çıktı:**
```
✅ Environment Variables Ayarlandı:
   KAFKA_BOOTSTRAP = 192.168.1.105:9092
   CENTRAL_HTTP_URL = http://192.168.1.105:8000
```

---

#### Adım 3.3: Bağlantı Testleri

**PowerShell'de:**
```powershell
Write-Host "🔍 Makine 1'e bağlantı test ediliyor..." -ForegroundColor Cyan

# Test 1: Central health endpoint
Write-Host "`n1️⃣  Central health endpoint testi:" -ForegroundColor Yellow
try {
    $health = Invoke-WebRequest -Uri "$env:CENTRAL_HTTP_URL/health" -UseBasicParsing | ConvertFrom-Json
    Write-Host "   ✅ Central erişilebilir! Status: $($health.status)" -ForegroundColor Green
} catch {
    Write-Host "   ❌ Central erişilemiyor!" -ForegroundColor Red
    exit 1
}

# Test 2: CP'lerin varlığını kontrol et (ÖNEMLİ!)
Write-Host "`n2️⃣  Mevcut CP'leri kontrol ediliyor:" -ForegroundColor Yellow
try {
    $cps = Invoke-WebRequest -Uri "$env:CENTRAL_HTTP_URL/cp" -UseBasicParsing | ConvertFrom-Json
    $cpCount = $cps.charging_points.Count
    
    if ($cpCount -gt 0) {
        Write-Host "   ✅ $cpCount adet CP bulundu!" -ForegroundColor Green
        $cps.charging_points | Select-Object cp_id, engine_state | Format-Table
    } else {
        Write-Host "   ⚠️  Hiç CP bulunamadı! Makine 2'de CP'lerin çalıştığından emin olun!" -ForegroundColor Yellow
        Write-Host "   💡 Makine 2'de .\deploy-lab-cp.ps1 script'ini çalıştırın" -ForegroundColor Cyan
    }
} catch {
    Write-Host "   ❌ CP listesi alınamadı!" -ForegroundColor Red
}

# Test 3: Kafka bağlantısı
Write-Host "`n3️⃣  Kafka bağlantı testi:" -ForegroundColor Yellow
$kafkaHost = $env:KAFKA_BOOTSTRAP -split ':' | Select-Object -First 1
$kafkaPort = $env:KAFKA_BOOTSTRAP -split ':' | Select-Object -Last 1
Test-NetConnection -ComputerName $kafkaHost -Port $kafkaPort
```

**✅ Başarılı Bağlantı İşaretleri:**
- Central health: status = "healthy"
- CP sayısı: 5 adet (CP-001 to CP-005)
- Kafka: TcpTestSucceeded : True

---

#### Adım 3.4: Docker Network Oluşturma

**PowerShell'de:**
```powershell
Write-Host "🌐 Docker network kontrol ediliyor..." -ForegroundColor Cyan

# Network var mı kontrol et
$networkExists = docker network ls | Select-String "ev-charging-simulation-1_evcharging-network"

if (-not $networkExists) {
    Write-Host "   Network yok, oluşturuluyor..." -ForegroundColor Yellow
    docker network create ev-charging-simulation-1_evcharging-network
    Write-Host "   ✅ Network oluşturuldu" -ForegroundColor Green
} else {
    Write-Host "   ✅ Network zaten mevcut" -ForegroundColor Green
}
```

---

#### Adım 3.5: Driver Servislerini Başlatma

**YÖNTEM 1: Script ile (ÖNERİLİR - Otomatik Diagnostic Dahil):**

```powershell
# Proje klasöründe olduğunuzdan emin olun
cd C:\Users\$env:USERNAME\Desktop\ev-charging-simulation

# Deploy script'ini çalıştırın
.\deploy-lab-driver.ps1
```
```powershell
# run this first to create a recipe for the image
docker build -t ev-driver:latest -f docker/Dockerfile.driver ..

# creates an actual image. It is necessary to replace NAME and NEXT_PORT with actual values
docker run -d --name ev-driver-NAME `
  --network evcharging-network `
  -e DRIVER_DRIVER_ID=driver-NAME `
  -e DRIVER_KAFKA_BOOTSTRAP=$env:KAFKA_BOOTSTRAP `
  -e DRIVER_CENTRAL_HTTP_URL=$env:CENTRAL_HTTP_URL `
  -p NEXT_PORT:NEXT_PORT `
  ev-driver:latest

```

**Script ne yapar:**
- ✅ Environment variables'ları kontrol eder
- ✅ Bağlantıyı test eder
- ✅ Network'ü oluşturur (yoksa)
- ✅ 5 Driver servisini başlatır
- ✅ Driver startup durumunu doğrular
- ✅ Sorun varsa diagnostic komutlar gösterir

**YÖNTEM 2: Manuel Docker Compose (Alternatif):**

**PowerShell Script ile (ÖNERİLİR):**
```powershell
# Quick deployment script kullan (otomatik bağlantı testi dahil)
.\deploy-lab-driver.ps1
```

**Manuel PowerShell:**
```powershell
# 5 Driver servisini başlat (Alice, Bob, Charlie, David, Eve)
docker compose -f docker/docker-compose.remote-kafka.yml up -d `
  ev-driver-alice ev-driver-bob ev-driver-charlie ev-driver-david ev-driver-eve

# Servislerin durumunu kontrol et (5 driver görmelisiniz)
docker compose -f docker/docker-compose.remote-kafka.yml ps

# Tüm driver'ların çalıştığını doğrula
docker ps --filter "name=ev-driver" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

**Beklenen Çıktı:** 5 container "Up" durumda, portlar 8100-8104 mapped olmalı

---

#### Adım 3.4: Windows Firewall (Driver Dashboards için - Opsiyonel)

Eğer driver dashboard'larına diğer bilgisayarlardan erişmek isterseniz (örneğin öğretmen herkesi izlemek istiyorsa):

**PowerShell (Yönetici olarak):**
```powershell
# Driver dashboard portlarını aç (8100-8104)
New-NetFirewallRule -DisplayName "EV Charging - Driver Dashboards" -Direction Inbound -LocalPort 8100-8104 -Protocol TCP -Action Allow
```

**Not:** Genellikle gerekli değildir - sadece localhost'tan erişilir.

---

#### Adım 3.5: Driver Loglarını Kontrol Et

**PowerShell'de:**
```powershell
# Driver başarıyla başladı mı?
docker logs ev-driver-alice | Select-String "started|requested charging|ACCEPTED"
```

**Beklenen Driver Logları:**
```
✅ Starting Driver client: driver-alice
✅ Kafka producer started: 192.168.1.105:9092
✅ Kafka consumer started: topics=['driver.updates']
✅ Driver driver-alice started successfully
✅ 📤 Driver driver-alice requested charging at CP-001
✅ ✅ ACCEPTED | Request accepted, starting charging
✅ 🔋 IN_PROGRESS | Charging: 22.0 kW, €0.02
```

---

#### Adım 3.6: Driver Dashboard'lara Erişim

**PowerShell'de:**
```powershell
# Tüm driver dashboard'larını browser'da aç
Start-Process "http://localhost:8100"  # Alice
Start-Process "http://localhost:8101"  # Bob
Start-Process "http://localhost:8102"  # Charlie
Start-Process "http://localhost:8103"  # David
Start-Process "http://localhost:8104"  # Eve

# Veya API üzerinden hepsini kontrol et
@(8100, 8101, 8102, 8103, 8104) | ForEach-Object {
    Write-Host "`nDriver Dashboard Port $_:"
    Invoke-WebRequest -Uri "http://localhost:$_/health" | ConvertFrom-Json
}
```

---

## 🎯 4️⃣ Son Doğrulama ve Test (Tüm Makineler)

---

### Adım 4.2: Uçtan Uca Test Senaryosu


**1️⃣ Makine 1'de: Dashboard'u Açın**
```powershell
# Browser'da aç
Start-Process "http://localhost:8000"
```

**Ne Görmeli:**
- ✅ 5 CP (CP-001 to CP-005) listede
- ✅ Her CP'nin state'i "ACTIVATED"
- ✅ "Active Sessions" bölümünde şarj sessionları

**2️⃣ Makine 3'te: Bir Driver Dashboard'u Açın**
```powershell
# Alice'in dashboard'unu aç
Start-Process "http://localhost:8100"
```

**Ne Görmeli:**
- ✅ "Current Charging Session" bölümü dolu
- ✅ CP ID (örn: CP-002)
- ✅ Charging progress bar ilerliyor
- ✅ Energy, Cost, Duration bilgileri güncelleniyor

**3️⃣ Makine 2'de: CP Loglarını İzleyin**
```powershell
# CP-001'in real-time loglarını izleyin
docker logs -f ev-cp-e-001

# Göreceksiniz:
# - State transitions (ACTIVATED → CHARGING)
# - Telemetry messages (energy, power, cost)
# - Session complete events
```

**4️⃣ Tüm Makinelerde: Log Akışını Gözlemleyin**

**Makine 1:**
```powershell
docker logs -f ev-central | Select-String "session|charge"
```

**Makine 2 (ayrı terminal):**
```powershell
docker logs -f ev-cp-e-001 | Select-String "CHARGING|telemetry"
```

**Makine 3 (ayrı terminal):**
```powershell
docker logs -f ev-driver-alice | Select-String "ACCEPTED|IN_PROGRESS|COMPLETED"
```

**✅ Başarı Kriterleri:**
- Central dashboard'da sessionlar görünüyor
- CP loglarında telemetry mesajları akıyor
- Driver dashboard'unda progress bar ilerliyor
- Tüm 3 makine logları eşzamanlı güncelleniyor

---

### Adım 4.3: Test Senaryosu - CP Crash ve Recovery

**Fault tolerance'ı test edelim:**

**Makine 2'de:**
```powershell
Write-Host "🔧 CP-003'ü crash ettiriyoruz..." -ForegroundColor Yellow

# CP-003 Engine'i durdur
docker stop ev-cp-e-003

Write-Host "⏳ 30 saniye bekleyin..." -ForegroundColor Cyan
Start-Sleep -Seconds 30
```

**Makine 1'de: Dashboard'u kontrol edin**
- CP-003'ün state'i "FAULTY" olmalı
- Diğer 4 CP hala "ACTIVATED" olmalı
- Sistem çalışmaya devam etmeli

**Makine 2'de: Recovery**
```powershell
Write-Host "🔧 CP-003'ü recover ediyoruz..." -ForegroundColor Green

# CP-003'ü yeniden başlat
docker start ev-cp-e-003

Write-Host "⏳ 10 saniye bekleyin..." -ForegroundColor Cyan
Start-Sleep -Seconds 10
```

**Makine 1'de: Dashboard'u tekrar kontrol edin**
- CP-003'ün state'i "FAULTY" → "ACTIVATED" olmalı
- Sistem tamamen geri dönmüş olmalı

**✅ Test Başarılı:**
- CP crash'i sistem çökmesine neden olmadı
- Diğer CP'ler etkilenmedi
- Recovery otomatik oldu

---

### Adım 4.4: Performans Gözlemi

**Makine 1'de: Sistem istatistiklerini görün**

```powershell
Write-Host "📊 SİSTEM İSTATİSTİKLERİ" -ForegroundColor Cyan
Write-Host "=======================" -ForegroundColor Cyan

# CP durumları
$cps = Invoke-WebRequest -Uri "http://localhost:8000/cp" -UseBasicParsing | ConvertFrom-Json | Select-Object -ExpandProperty charging_points

Write-Host "`n🔋 CP DURUMU:" -ForegroundColor Yellow
$cps | Select-Object cp_id, state, engine_state, kw_rate | Format-Table

Write-Host "`n📈 ÖZET:" -ForegroundColor Yellow
Write-Host "   Toplam CP: $($cps.Count)"
Write-Host "   Aktif: $(($cps | Where-Object {$_.engine_state -eq 'ACTIVATED'}).Count)"
Write-Host "   Şarj Yapan: $(($cps | Where-Object {$_.state -eq 'CHARGING'}).Count)"

# Container resource kullanımı
Write-Host "`n💻 RESOURCE KULLANIMI:" -ForegroundColor Yellow
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" --filter "name=ev-"
```

---

## ✅ Son Kontrol Listesi (Başarı Kriterleri)

Aşağıdaki tüm maddeleri kontrol edin:


### Şimdi Ne Yapabilirsiniz:

1
2. **Test Senaryoları:**
   - CP crash simülasyonu (`docker stop ev-cp-e-XXX`)
   - Yeni CP ekleme (`.\add-cp.ps1 11 150.0 0.40`)
   - Yeni driver ekleme (`.\add-driver.ps1 frank 8105`)



---

## ✅ Doğrulama Kontrol Listesi

### Makine 1 Kontrolleri:

**PowerShell:**
```powershell
# ✅ Kafka çalışıyor mu?
docker ps --filter "name=ev-kafka"

# ✅ Central çalışıyor mu?
docker ps --filter "name=ev-central"

# ✅ Kafka external'den erişilebilir mi?
docker exec ev-kafka kafka-broker-api-versions.sh --bootstrap-server localhost:9092

# ✅ CP'ler kaydedildi mi? (5 adet olmalı)
$cps = Invoke-WebRequest -Uri "http://localhost:8000/cp" | ConvertFrom-Json | Select-Object -ExpandProperty charging_points
Write-Host "Toplam CP Sayısı: $($cps.Count)"
$cps | Select-Object cp_id, state, engine_state, kw_rate | Format-Table
```

---

### Makine 2 Kontrolleri:

**PowerShell:**
```powershell
# ✅ CP Engine'ler çalışıyor mu?
docker ps --filter "name=ev-cp-e"

# ✅ CP Monitor'ler çalışıyor mu?
docker ps --filter "name=ev-cp-m"

# ✅ Kafka'ya bağlandılar mı?
docker logs ev-cp-e-001 | Select-String "Kafka producer started"
docker logs ev-cp-m-001 | Select-String "heartbeat sent successfully"
```

---

### Makine 3 Kontrolleri:

**PowerShell:**
```powershell
# ✅ Driver'lar çalışıyor mu?
docker ps --filter "name=ev-driver"

# ✅ Alice Kafka'ya bağlandı mı?
docker logs ev-driver-alice | Select-String "Kafka producer started"

# ✅ Alice şarj isteği gönderiyor mu?
docker logs ev-driver-alice | Select-String "requested charging"

# ✅ Dashboard'lar erişilebilir mi?
@(8100, 8101, 8102, 8103, 8104) | ForEach-Object {
    Write-Host "`nPort $_:"
    (Invoke-WebRequest -Uri "http://localhost:$_/health" | ConvertFrom-Json).status
}
```

---

## 🎯 Test Senaryoları

### Senaryo 1: Normal İşleyiş (Gözlem)
**Amaç:** Sistemin otonom çalıştığını doğrula

1. **Makine 1**: Dashboard'u aç → `http://localhost:8000`
2. **Makine 2**: CP loglarını izle → `docker logs -f ev-cp-e-1`
3. **Makine 3**: Driver loglarını izle → `docker logs -f ev-driver-alice`

**Beklenen Sonuç:**
- Dashboard'da 5 CP ACTIVATED durumda
- Driver'lar sürekli şarj isteği gönderiyor
- CP'ler şarj session'larını başlatıyor ve telemetri gönderiyor

---

### Senaryo 2: CP Fault Injection
**Amaç:** Fault tolerance mekanizmalarını test et

**PowerShell:**
```powershell
# Makine 2'de bir CP'yi crash et
docker stop ev-cp-e-003

# Bekle: 30 saniye
Start-Sleep -Seconds 30

# Makine 1'de Dashboard'dan gözlemle:
# CP-003 durumu: ACTIVATED → FAULTY

# Makine 2'de recover et:
docker start ev-cp-e-003

# Bekle: 10 saniye
Start-Sleep -Seconds 10

# Makine 1'de Dashboard'dan gözlemle:
# CP-003 durumu: FAULTY → ACTIVATED
```

# Makine 1'de dashboard'dan gözlemle
# CP-003 durumu FAULTY olacak

# 30 saniye bekle, sonra recover et
Start-Sleep -Seconds 30
docker start ev-cp-e-3
```

---

### Senaryo 3: Eşzamanlı Şarj Testleri
**Amaç:** 5 driver'ın aynı anda farklı CP'lerde şarj yapabildiğini göster

**PowerShell:**
```powershell
# Makine 3'te tüm driver'ların loglarını izle (ayrı terminal pencerelerinde):
docker logs -f ev-driver-alice
docker logs -f ev-driver-bob
docker logs -f ev-driver-charlie
docker logs -f ev-driver-david
docker logs -f ev-driver-eve

# Veya hepsini birden görmek için:
Get-Process | Where-Object {$_.Name -eq "powershell"} | ForEach-Object {
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "docker logs -f ev-driver-alice"
}

# Makine 1'de Dashboard'dan gözlemle:
# - 5 aktif session aynı anda
# - Farklı CP'ler farklı güç seviyeleri gösteriyor
# - Her driver kendi dashboard'unda charging progress gösteriyor
```

---

### Senaryo 4: Load Testing
**Amaç:** Sistemi yük altında test et

**PowerShell:**
```powershell
# Makine 3'te driver'ları daha agresif yapabilirsin:
# docker-compose.remote-kafka.yml'de interval'ları düşür (örn: 2.0 saniye)

# Veya daha fazla driver ekle:
docker compose -f docker/docker-compose.remote-kafka.yml up -d --scale ev-driver-alice=3
```

---

