# EV Charging Simulation - Deployment Guide

## Overview

This guide provides comprehensive instructions for deploying the EV Charging Simulation system in various environments, including lab machines and remote configurations.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Deployment Scenarios](#deployment-scenarios)
3. [Quick Start](#quick-start)
4. [Detailed Deployment Options](#detailed-deployment-options)
5. [Lab Machine Deployment](#lab-machine-deployment)
6. [Configuration](#configuration)
7. [Troubleshooting](#troubleshooting)
8. [Verification](#verification)

---

## Prerequisites

### Required Tools

- **Docker**: Version 20.10 or higher
- **Docker Compose**: Version 2.0 or higher (or `docker-compose` v1.29+)
- **Python 3.11+**: For local development (optional)
- **Network Access**: To Kafka broker (local or remote)

### Verification

Run the deployment script to check prerequisites:

```bash
./deploy.sh
```

Or manually check:

```bash
docker --version
docker compose version
python3 --version
```

---

## Deployment Scenarios

### 1. Full Local Deployment (Recommended for Development)

**Use Case**: Testing entire system on a single machine

**Components**: All services including Kafka

```bash
docker compose up -d
```

**Access**:
- Dashboard: http://localhost:8000
- Kafka: localhost:9092
- Central TCP: localhost:9999

---

### 2. Remote Kafka Deployment

**Use Case**: Kafka is running on a separate server/cluster

**Components**: All services except Kafka

**Configuration**:

```bash
# Set Kafka address
export KAFKA_BOOTSTRAP=kafka.example.com:9092

# Deploy
docker compose -f docker/docker-compose.remote-kafka.yml up -d
```

Or use the interactive script:

```bash
./deploy.sh
# Select option 2
```

---

### 3. Lab Machine Deployment (Distributed)

**Use Case**: Deploy different components on different lab machines

#### Scenario A: Machine 1 runs Kafka + Central, Machine 2 runs Charging Points

**Machine 1 (Kafka + Central)**:

```bash
# Start Kafka and Central
docker compose up -d kafka ev-central

# Note the machine's IP address
hostname -I
```

**Machine 2 (Charging Points)**:

```bash
# Set remote Kafka and Central addresses
export KAFKA_BOOTSTRAP=<machine1-ip>:9092
export CENTRAL_HOST=<machine1-ip>

# Deploy only charging points
docker compose up -d ev-cp-e-1 ev-cp-e-2 ev-cp-e-3 ev-cp-m-1 ev-cp-m-2 ev-cp-m-3
```

#### Scenario B: All services use shared remote Kafka

**Shared Kafka Server** (already running): `kafka.lab.local:9092`

**Machine 1 (Central)**:

```bash
export KAFKA_BOOTSTRAP=kafka.lab.local:9092
docker compose -f docker/docker-compose.remote-kafka.yml up -d ev-central
```

**Machine 2 (Charging Points)**:

```bash
export KAFKA_BOOTSTRAP=kafka.lab.local:9092
export CENTRAL_HOST=<machine1-ip>
docker compose -f docker/docker-compose.remote-kafka.yml up -d ev-cp-e-1 ev-cp-e-2 ev-cp-e-3 ev-cp-m-1 ev-cp-m-2 ev-cp-m-3
```

**Machine 3 (Driver)**:

```bash
export KAFKA_BOOTSTRAP=kafka.lab.local:9092
docker compose -f docker/docker-compose.remote-kafka.yml up -d ev-driver ev-driver-2
```

---

### 4. Local Python Deployment (No Docker)

**Use Case**: Development without Docker, direct Python execution

**Prerequisites**: Kafka must be running (locally or remotely)

**Setup**:

```bash
# Install dependencies
pip install -r requirements.txt

# Configure environment
export CENTRAL_KAFKA_BOOTSTRAP=localhost:9092
export CP_ENGINE_KAFKA_BOOTSTRAP=localhost:9092
export DRIVER_KAFKA_BOOTSTRAP=localhost:9092
```

**Start Services**:

```bash
# Terminal 1: Central
python -m evcharging.apps.ev_central.main

# Terminal 2: CP Engine 1
export CP_ENGINE_CP_ID=CP-001
export CP_ENGINE_HEALTH_PORT=8001
python -m evcharging.apps.ev_cp_e.main

# Terminal 3: CP Engine 2
export CP_ENGINE_CP_ID=CP-002
export CP_ENGINE_HEALTH_PORT=8002
python -m evcharging.apps.ev_cp_e.main

# Terminal 4: CP Monitor 1
export CP_MONITOR_CP_ID=CP-001
export CP_MONITOR_CP_E_PORT=8001
python -m evcharging.apps.ev_cp_m.main

# Terminal 5: CP Monitor 2
export CP_MONITOR_CP_ID=CP-002
export CP_MONITOR_CP_E_PORT=8002
python -m evcharging.apps.ev_cp_m.main

# Terminal 6: Driver (when ready)
export DRIVER_DRIVER_ID=driver-alice
python -m evcharging.apps.ev_driver.main
```

Or use Make:

```bash
make local-run
```

---

## Quick Start

### Option 1: Interactive Script (Easiest)

```bash
./deploy.sh
```

Follow the menu to select your deployment scenario.

### Option 2: Docker Compose Commands

**Full deployment**:

```bash
docker compose up -d
docker compose logs -f
```

**Remote Kafka**:

```bash
export KAFKA_BOOTSTRAP=your-kafka:9092
docker compose -f docker/docker-compose.remote-kafka.yml up -d
```

### Option 3: Makefile Commands

```bash
make up          # Start all services
make logs        # View logs
make down        # Stop services
make clean       # Clean everything
```

---

## Configuration

### Environment Variables

All services are configured via environment variables with the prefix:

- `CENTRAL_*`: Central controller settings
- `CP_ENGINE_*`: Charging point engine settings
- `CP_MONITOR_*`: Charging point monitor settings
- `DRIVER_*`: Driver client settings

### Key Configuration Variables

#### Central

```bash
CENTRAL_KAFKA_BOOTSTRAP=kafka:9092    # Kafka address
CENTRAL_HTTP_PORT=8000                 # Dashboard port
CENTRAL_LISTEN_PORT=9999               # TCP control port
CENTRAL_LOG_LEVEL=INFO                 # Logging level
```

#### CP Engine

```bash
CP_ENGINE_KAFKA_BOOTSTRAP=kafka:9092   # Kafka address
CP_ENGINE_CP_ID=CP-001                 # Unique CP identifier
CP_ENGINE_HEALTH_PORT=8001             # Health check port
CP_ENGINE_KW_RATE=22.0                 # Power rating (kW)
CP_ENGINE_EURO_RATE=0.30               # Cost per kWh (€)
CP_ENGINE_LOG_LEVEL=INFO               # Logging level
```

#### CP Monitor

```bash
CP_MONITOR_CP_ID=CP-001                # Must match CP Engine ID
CP_MONITOR_CP_E_HOST=ev-cp-e-1         # CP Engine hostname
CP_MONITOR_CP_E_PORT=8001              # CP Engine port
CP_MONITOR_CENTRAL_HOST=ev-central     # Central hostname
CP_MONITOR_CENTRAL_PORT=8000           # Central HTTP port
CP_MONITOR_HEALTH_INTERVAL=1.0         # Check interval (seconds)
CP_MONITOR_LOG_LEVEL=INFO              # Logging level
```

#### Driver

```bash
DRIVER_DRIVER_ID=driver-alice          # Driver identifier
DRIVER_KAFKA_BOOTSTRAP=kafka:9092      # Kafka address
DRIVER_REQUESTS_FILE=requests.txt      # File with CP requests
DRIVER_REQUEST_INTERVAL=4.0            # Time between requests (s)
DRIVER_LOG_LEVEL=INFO                  # Logging level
```

### Creating Custom Configuration

Create a `.env` file in the project root:

```bash
# .env file example
KAFKA_BOOTSTRAP=kafka.example.com:9092
CENTRAL_LOG_LEVEL=DEBUG
CP_ENGINE_KW_RATE=50.0
```

Docker Compose will automatically load this file.

---

## Lab Machine Deployment

### Example: 3-Machine Setup

#### Prerequisites

1. All machines must be on the same network
2. Firewall rules allow traffic on required ports
3. Docker installed on all machines

#### Setup

**Machine 1 (Kafka + Central)** - IP: 192.168.1.10

```bash
# Clone repository
git clone <repo-url>
cd ev-charging-simulation

# Start Kafka and Central
docker compose up -d kafka ev-central

# Verify
docker compose ps
curl http://localhost:8000/health
```

**Machine 2 (Charging Points)** - IP: 192.168.1.11

```bash
# Clone repository
git clone <repo-url>
cd ev-charging-simulation

# Create .env file
cat > .env << EOF
KAFKA_BOOTSTRAP=192.168.1.10:9092
CENTRAL_HOST=192.168.1.10
EOF

# Start charging points
docker compose up -d ev-cp-e-1 ev-cp-e-2 ev-cp-e-3 ev-cp-m-1 ev-cp-m-2 ev-cp-m-3

# Verify
docker compose ps
```

**Machine 3 (Driver)** - IP: 192.168.1.12

```bash
# Clone repository
git clone <repo-url>
cd ev-charging-simulation

# Create .env file
cat > .env << EOF
KAFKA_BOOTSTRAP=192.168.1.10:9092
EOF

# Start driver
docker compose up -d ev-driver ev-driver-2

# Verify
docker compose logs ev-driver
```

### Port Requirements

| Service | Port | Protocol | Purpose |
|---------|------|----------|---------|
| Kafka | 9092 | TCP | Message broker |
| Central HTTP | 8000 | HTTP | Dashboard & API |
| Central TCP | 9999 | TCP | Control plane |
| CP Engine | 8001-8002 | TCP | Health checks |

Ensure these ports are accessible between machines.

---

## Troubleshooting

### Issue: Services can't connect to Kafka

**Symptoms**:
- Services crash on startup
- Logs show "Connection refused" or "Broker not available"

**Solutions**:

1. Verify Kafka is running:
   ```bash
   docker compose ps kafka
   # or
   nc -zv localhost 9092
   ```

2. Check Kafka address in environment variables:
   ```bash
   docker compose exec ev-central env | grep KAFKA
   ```

3. Ensure network connectivity:
   ```bash
   docker compose exec ev-central ping kafka
   ```

4. For remote Kafka, verify firewall rules allow port 9092

### Issue: Central not accessible from Charging Points

**Symptoms**:
- CP Monitors can't reach Central
- Dashboard shows no charging points

**Solutions**:

1. Verify Central is running:
   ```bash
   curl http://localhost:8000/health
   ```

2. Check network connectivity:
   ```bash
   docker compose exec ev-cp-m-1 ping ev-central
   ```

3. Verify environment variables:
   ```bash
   docker compose exec ev-cp-m-1 env | grep CENTRAL
   ```

### Issue: Docker build fails

**Symptoms**:
- Build errors during `docker compose up`
- Missing dependencies

**Solutions**:

1. Check Docker version:
   ```bash
   docker --version  # Should be 20.10+
   ```

2. Clean Docker cache:
   ```bash
   docker compose down
   docker system prune -a
   docker compose build --no-cache
   ```

3. Ensure requirements.txt is present:
   ```bash
   ls -la requirements.txt
   ```

### Issue: Services start but don't communicate

**Symptoms**:
- All containers running
- No charging sessions happening
- Dashboard shows disconnected status

**Solutions**:

1. Check Kafka topics:
   ```bash
   docker compose exec kafka kafka-topics.sh \
     --bootstrap-server localhost:9092 --list
   ```

2. Verify service logs:
   ```bash
   docker compose logs ev-central
   docker compose logs ev-cp-e-1
   ```

3. Restart services in order:
   ```bash
   docker compose restart kafka
   sleep 10
   docker compose restart ev-central
   sleep 5
   docker compose restart ev-cp-e-1 ev-cp-e-2
   docker compose restart ev-cp-m-1 ev-cp-m-2
   ```

---

## Verification

### 1. Check All Services Running

```bash
docker compose ps
```

Expected output: All services should be "Up"

### 2. Verify Kafka Topics

```bash
docker compose exec kafka kafka-topics.sh \
  --bootstrap-server localhost:9092 --list
```

Expected topics:
- central.commands
- cp.status
- cp.telemetry
- driver.requests
- driver.updates

### 3. Test Central Dashboard

```bash
curl http://localhost:8000/health
```

Expected: `{"status": "healthy"}`

Open browser: http://localhost:8000

### 4. Test Charging Session

```bash
# Watch logs
docker compose logs -f ev-driver ev-central

# In another terminal, trigger driver
docker compose restart ev-driver
```

Expected: Driver requests charging, session starts, telemetry flows

### 5. Automated Verification Script

```bash
./verify.sh
```

This script checks:
- Docker services status
- Network connectivity
- Kafka topics
- HTTP endpoints
- Log output for errors

---

## Maintenance

### Viewing Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f ev-central

# Last 100 lines
docker compose logs --tail=100

# Since timestamp
docker compose logs --since 2024-01-01T10:00:00
```

### Updating Services

```bash
# Pull latest changes
git pull

# Rebuild and restart
docker compose down
docker compose build
docker compose up -d
```

### Backup and Restore

**Backup Kafka data**:

```bash
docker run --rm -v ev-charging-simulation_kafka-data:/data \
  -v $(pwd):/backup alpine tar czf /backup/kafka-backup.tar.gz /data
```

**Restore Kafka data**:

```bash
docker run --rm -v ev-charging-simulation_kafka-data:/data \
  -v $(pwd):/backup alpine tar xzf /backup/kafka-backup.tar.gz -C /
```

---

## Production Considerations

### Security

1. **Use TLS for Kafka**: Configure SSL/SASL authentication
2. **Secure HTTP endpoints**: Add authentication to dashboard
3. **Network segmentation**: Use Docker networks properly
4. **Environment secrets**: Use Docker secrets or vault

### Scaling

1. **Multiple CP instances**: Add more CP Engine/Monitor pairs
2. **Kafka partitions**: Increase partitions for higher throughput
3. **Load balancing**: Use nginx/haproxy for Central HTTP
4. **Monitoring**: Add Prometheus/Grafana for metrics

### High Availability

1. **Kafka cluster**: Deploy multi-node Kafka cluster
2. **Replicated services**: Run multiple Central instances
3. **Health checks**: Configure proper liveness/readiness probes
4. **Automatic restart**: Use `restart: always` in production

---

## Support

For issues or questions:

1. Check logs: `docker compose logs`
2. Run verification: `./verify.sh`
3. Review this guide's troubleshooting section
4. Check project README.md

---

## Quick Reference

### Common Commands

```bash
# Start everything
docker compose up -d

# Start with logs
docker compose up

# Stop everything
docker compose down

# Restart a service
docker compose restart ev-central

# View logs
docker compose logs -f

# Check status
docker compose ps

# Clean everything
docker compose down -v
make clean
```

### File Locations

- Main config: `docker-compose.yml`
- Remote Kafka config: `docker/docker-compose.remote-kafka.yml`
- Dockerfiles: `docker/Dockerfile.*`
- App code: `evcharging/apps/`
- Configuration: `evcharging/common/config.py`

---

**Last Updated**: October 2025
