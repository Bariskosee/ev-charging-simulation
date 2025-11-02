# PowerShell script to dynamically add a new Charging Point at runtime
# Usage: .\add-cp.ps1 <cp_number> [kw_rate] [euro_rate]
#
# Example: .\add-cp.ps1 11 150.0 0.40

param(
    [Parameter(Mandatory=$true)]
    [int]$CpNumber,
    
    [Parameter(Mandatory=$false)]
    [double]$KwRate = 22.0,
    
    [Parameter(Mandatory=$false)]
    [double]$EuroRate = 0.30
)

$ErrorActionPreference = "Stop"

# Configuration
$CpId = "CP-{0:D3}" -f $CpNumber
$HealthPort = 8000 + $CpNumber

# Get environment variables or use defaults
$KafkaBootstrap = if ($env:KAFKA_BOOTSTRAP) { $env:KAFKA_BOOTSTRAP } else { "kafka:9092" }
$CentralHost = if ($env:CENTRAL_HOST) { $env:CENTRAL_HOST } else { "ev-central" }
$CentralPort = if ($env:CENTRAL_PORT) { $env:CENTRAL_PORT } else { "8000" }

Write-Host ""
Write-Host " Adding New Charging Point" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan
Write-Host "CP ID:        $CpId"
Write-Host "CP Number:    $CpNumber"
Write-Host "Power Rate:   $KwRate kW"
Write-Host "Price:        €$EuroRate/kWh"
Write-Host "Health Port:  $HealthPort"
Write-Host "Kafka:        $KafkaBootstrap"
Write-Host ""

# Create docker-compose override file
$OverrideFile = "docker-compose.cp-$CpNumber.yml"
$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

$ComposeContent = @"
# Dynamically added $CpId
# Created: $Timestamp
# Can be stopped with: docker compose -f $OverrideFile down

services:
  ev-cp-e-${CpNumber}:
    build:
      context: .
      dockerfile: docker/Dockerfile.cp_e
    container_name: ev-cp-e-${CpNumber}
    environment:
      CP_ENGINE_KAFKA_BOOTSTRAP: $KafkaBootstrap
      CP_ENGINE_CP_ID: $CpId
      CP_ENGINE_HEALTH_PORT: $HealthPort
      CP_ENGINE_LOG_LEVEL: INFO
      CP_ENGINE_KW_RATE: $KwRate
      CP_ENGINE_EURO_RATE: $EuroRate
      CP_ENGINE_TELEMETRY_INTERVAL: 1.0
    networks:
      - evcharging-network
    restart: unless-stopped

  ev-cp-m-${CpNumber}:
    build:
      context: .
      dockerfile: docker/Dockerfile.cp_m
    container_name: ev-cp-m-${CpNumber}
    environment:
      CP_MONITOR_CP_ID: $CpId
      CP_MONITOR_CP_E_HOST: ev-cp-e-${CpNumber}
      CP_MONITOR_CP_E_PORT: $HealthPort
      CP_MONITOR_CENTRAL_HOST: $CentralHost
      CP_MONITOR_CENTRAL_PORT: $CentralPort
      CP_MONITOR_HEALTH_INTERVAL: 2.0
      CP_MONITOR_LOG_LEVEL: INFO
      CP_MONITOR_KAFKA_BOOTSTRAP: $KafkaBootstrap
    depends_on:
      - ev-cp-e-${CpNumber}
    networks:
      - evcharging-network
    restart: unless-stopped

networks:
  evcharging-network:
    external: true
    name: ev-charging-simulation_evcharging-network
"@


# Write compose file
$ComposeContent | Out-File -FilePath $OverrideFile -Encoding UTF8
Write-Host "[OK] Created override file: $OverrideFile" -ForegroundColor Green
Write-Host ""

# Start the services
Write-Host "[STARTING] Starting CP services..." -ForegroundColor Yellow
docker compose -f $OverrideFile up -d

if ($LASTEXITCODE -ne 0) {
    Write-Host "[FAIL] Failed to start CP services" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[WAITING] Waiting for services to start (5 seconds)..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

# Verify
Write-Host ""
Write-Host "[VERYFING] Verification:" -ForegroundColor Cyan

$engineRunning = docker ps --filter "name=ev-cp-e-$CpNumber" --format "{{.Names}}"
if ($engineRunning) {
    Write-Host "   [OK] CP Engine (ev-cp-e-$CpNumber) is running" -ForegroundColor Green
} else {
    Write-Host "   [FAIL] CP Engine failed to start" -ForegroundColor Red
}

$monitorRunning = docker ps --filter "name=ev-cp-m-$CpNumber" --format "{{.Names}}"
if ($monitorRunning) {
    Write-Host "   [OK] CP Monitor (ev-cp-m-$CpNumber) is running" -ForegroundColor Green
} else {
    Write-Host "   [FAIL] CP Monitor failed to start" -ForegroundColor Red
}

Write-Host ""
Write-Host " Check CP status in Central:" -ForegroundColor Cyan
Write-Host "   curl http://localhost:8000/cp | jq '.charging_points[] | select(.cp_id==`"$CpId`")'"
Write-Host ""
Write-Host " View logs:" -ForegroundColor Cyan
Write-Host "   docker logs ev-cp-e-$CpNumber"
Write-Host "   docker logs ev-cp-m-$CpNumber"
Write-Host ""
Write-Host " To remove this CP:" -ForegroundColor Yellow
Write-Host "   docker compose -f $OverrideFile down"
Write-Host "   Remove-Item $OverrideFile"
Write-Host ""
Write-Host "[OK] $CpId deployment complete!" -ForegroundColor Green
