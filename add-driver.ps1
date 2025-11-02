# PowerShell script to dynamically add a new Driver at runtime
# Usage: .\add-driver.ps1 <driver_name> [dashboard_port]
#
# Example: .\add-driver.ps1 frank 8105

param(
    [Parameter(Mandatory=$true)]
    [string]$DriverName,
    
    [Parameter(Mandatory=$false)]
    [int]$DashboardPort = 8105,
    
    [Parameter(Mandatory=$false)]
    [double]$RequestInterval = 5.0
)

$ErrorActionPreference = "Stop"

# Configuration
$DriverId = "driver-$DriverName"

# Get environment variables or use defaults
$KafkaBootstrap = if ($env:KAFKA_BOOTSTRAP) { $env:KAFKA_BOOTSTRAP } else { "kafka:9092" }
$CentralHttpUrl = if ($env:CENTRAL_HTTP_URL) { $env:CENTRAL_HTTP_URL } else { "http://ev-central:8000" }

Write-Host ""
Write-Host "🚗 Adding New Driver" -ForegroundColor Cyan
Write-Host "====================" -ForegroundColor Cyan
Write-Host "Driver Name:      $DriverName"
Write-Host "Driver ID:        $DriverId"
Write-Host "Dashboard Port:   $DashboardPort"
Write-Host "Request Interval: $RequestInterval seconds"
Write-Host "Kafka:            $KafkaBootstrap"
Write-Host ""

# Create docker-compose override file
$OverrideFile = "docker-compose.driver-$DriverName.yml"
$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

$ComposeContent = @"
# Dynamically added driver-$DriverName
# Created: $Timestamp
# Can be stopped with: docker compose -f $OverrideFile down

services:
  ev-driver-$DriverName`:
    build:
      context: .
      dockerfile: docker/Dockerfile.driver
    container_name: ev-driver-$DriverName
    environment:
      DRIVER_DRIVER_ID: $DriverId
      DRIVER_KAFKA_BOOTSTRAP: $KafkaBootstrap
      DRIVER_REQUEST_INTERVAL: $RequestInterval
      DRIVER_LOG_LEVEL: INFO
      DRIVER_DASHBOARD_PORT: $DashboardPort
      DRIVER_CENTRAL_HTTP_URL: $CentralHttpUrl
    volumes:
      - ./requests.txt:/app/requests.txt:ro
    ports:
      - "$DashboardPort`:$DashboardPort"
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
Write-Host "Created override file: $OverrideFile" -ForegroundColor Green
Write-Host ""

# Start the service
Write-Host "Starting Driver service..." -ForegroundColor Yellow
docker compose -f $OverrideFile up -d

if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to start Driver service" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Waiting for service to start (5 seconds)..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

# Verify
Write-Host ""
Write-Host "Verification:" -ForegroundColor Cyan

$driverRunning = docker ps --filter "name=ev-driver-$DriverName" --format "{{.Names}}"
if ($driverRunning) {
    Write-Host "   Driver (ev-driver-$DriverName) is running" -ForegroundColor Green
} else {
    Write-Host "   Driver failed to start" -ForegroundColor Red
}

Write-Host ""
Write-Host "Access Driver Dashboard:" -ForegroundColor Cyan
Write-Host "   http://localhost:$DashboardPort"
Write-Host ""
Write-Host "Check available CPs:" -ForegroundColor Cyan
Write-Host "   curl http://localhost:$DashboardPort/charging-points | jq '.[0:3]'"
Write-Host ""
Write-Host "View logs:" -ForegroundColor Cyan
Write-Host "   docker logs ev-driver-$DriverName"
Write-Host ""
Write-Host "To remove this driver:" -ForegroundColor Yellow
Write-Host "   docker compose -f $OverrideFile down"
Write-Host "   Remove-Item $OverrideFile"
Write-Host ""
Write-Host "Driver $DriverId deployment complete!" -ForegroundColor Green
