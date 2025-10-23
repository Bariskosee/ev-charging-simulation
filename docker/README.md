# Docker Deployment Files

This directory contains Docker and Docker Compose configurations for deploying the EV Charging Simulation system.

## Files

### Docker Compose Files

- **`docker-compose.yml`** - Full local deployment with Kafka
- **`docker-compose.remote-kafka.yml`** - Deployment using external Kafka

### Dockerfiles

- **`Dockerfile.central`** - Central controller image
- **`Dockerfile.cp_e`** - Charging Point Engine image
- **`Dockerfile.cp_m`** - Charging Point Monitor image
- **`Dockerfile.driver`** - Driver client image

---

## Quick Start

### Full Local Deployment

From the **project root** (not this directory):

```bash
docker compose up -d
```

Or from this directory:

```bash
cd ..
docker compose up -d
```

### Remote Kafka Deployment

```bash
cd ..
export KAFKA_BOOTSTRAP=kafka.example.com:9092
docker compose -f docker/docker-compose.remote-kafka.yml up -d
```

---

## Docker Compose Configurations

### docker-compose.yml (Full Deployment)

Deploys all components including Kafka:

- Kafka (KRaft mode, no Zookeeper)
- Central controller
- 2x CP Engine instances
- 2x CP Monitor instances
- Driver client

**Use when**: Testing full system on single machine

### docker-compose.remote-kafka.yml (Remote Kafka)

Deploys application services only, connects to external Kafka:

- Central controller
- 2x CP Engine instances
- 2x CP Monitor instances
- Driver client

**Use when**: Kafka already running elsewhere

**Configuration**: Set `KAFKA_BOOTSTRAP` environment variable

---

## Dockerfiles

### Dockerfile.central

Builds the Central controller service.

**Base**: Python 3.11-slim  
**Exposed Ports**: 8000 (HTTP), 9999 (TCP)  
**Entry Point**: `python -m evcharging.apps.ev_central.main`

### Dockerfile.cp_e

Builds the Charging Point Engine service.

**Base**: Python 3.11-slim  
**Exposed Ports**: 8001 (health check)  
**Entry Point**: `python -m evcharging.apps.ev_cp_e.main`

### Dockerfile.cp_m

Builds the Charging Point Monitor service.

**Base**: Python 3.11-slim  
**Exposed Ports**: None  
**Entry Point**: `python -m evcharging.apps.ev_cp_m.main`

### Dockerfile.driver

Builds the Driver client service.

**Base**: Python 3.11-slim  
**Exposed Ports**: None  
**Entry Point**: `python -m evcharging.apps.ev_driver.main`

---

## Building Images

### Build All Images

```bash
cd ..
docker compose build
```

### Build Specific Service

```bash
cd ..
docker compose build ev-central
```

### Build Without Cache

```bash
cd ..
docker compose build --no-cache
```

---

## Environment Variables

### Central Controller

```bash
CENTRAL_KAFKA_BOOTSTRAP=kafka:9092
CENTRAL_HTTP_PORT=8000
CENTRAL_LISTEN_PORT=9999
CENTRAL_LOG_LEVEL=INFO
```

### CP Engine

```bash
CP_ENGINE_KAFKA_BOOTSTRAP=kafka:9092
CP_ENGINE_CP_ID=CP-001                 # Unique per instance
CP_ENGINE_HEALTH_PORT=8001             # Unique per instance
CP_ENGINE_LOG_LEVEL=INFO
CP_ENGINE_KW_RATE=22.0
CP_ENGINE_EURO_RATE=0.30
```

### CP Monitor

```bash
CP_MONITOR_CP_ID=CP-001                # Must match Engine
CP_MONITOR_CP_E_HOST=ev-cp-e-1
CP_MONITOR_CP_E_PORT=8001
CP_MONITOR_CENTRAL_HOST=ev-central
CP_MONITOR_CENTRAL_PORT=8000
CP_MONITOR_HEALTH_INTERVAL=1.0
CP_MONITOR_LOG_LEVEL=INFO
```

### Driver

```bash
DRIVER_DRIVER_ID=driver-alice
DRIVER_KAFKA_BOOTSTRAP=kafka:9092
DRIVER_REQUEST_INTERVAL=4.0
DRIVER_LOG_LEVEL=INFO
```

---

## Network Configuration

### Docker Network

All services use the `evcharging-network` bridge network.

**Service Names (DNS)**:
- `kafka` - Kafka broker
- `ev-central` - Central controller
- `ev-cp-e-1`, `ev-cp-e-2` - CP Engines
- `ev-cp-m-1`, `ev-cp-m-2` - CP Monitors
- `ev-driver` - Driver client

**Internal Communication**:
Services communicate using service names as hostnames.

**External Access**:
Exposed ports map to localhost:
- 8000 → Central HTTP
- 9092 → Kafka
- 9999 → Central TCP

---

## Volume Management

### Kafka Data Volume

```bash
kafka-data
```

Persists Kafka data between restarts.

**Backup**:
```bash
docker run --rm \
  -v ev-charging-simulation_kafka-data:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/kafka-backup.tar.gz /data
```

**Restore**:
```bash
docker run --rm \
  -v ev-charging-simulation_kafka-data:/data \
  -v $(pwd):/backup \
  alpine tar xzf /backup/kafka-backup.tar.gz -C /
```

---

## Lab Deployment Examples

### Scenario 1: All on One Machine

```bash
cd ..
docker compose up -d
```

### Scenario 2: Distributed (2 Machines)

**Machine 1** (Kafka + Central):
```bash
cd ..
docker compose up -d kafka ev-central
hostname -I  # Note this IP
```

**Machine 2** (Charging Points):
```bash
cd ..
export KAFKA_BOOTSTRAP=<machine1-ip>:9092
docker compose up -d ev-cp-e-1 ev-cp-e-2 ev-cp-e-3 ev-cp-m-1 ev-cp-m-2 ev-cp-m-3
```

### Scenario 3: Remote Kafka

**Prerequisite**: Kafka running at `kafka.lab.edu:9092`

```bash
cd ..
export KAFKA_BOOTSTRAP=kafka.lab.edu:9092
docker compose -f docker/docker-compose.remote-kafka.yml up -d
```

---

## Troubleshooting

### Services Not Starting

```bash
# Check logs
docker compose logs

# Check specific service
docker compose logs ev-central

# Rebuild images
docker compose down
docker compose build --no-cache
docker compose up -d
```

### Network Issues

```bash
# Test Kafka connectivity from Central
docker compose exec ev-central ping kafka

# Test Central connectivity from CP Monitor
docker compose exec ev-cp-m-1 ping ev-central

# Check network
docker network inspect ev-charging-simulation_evcharging-network
```

### Port Conflicts

```bash
# Check what's using a port
lsof -i :8000
lsof -i :9092

# Kill process or change port in docker-compose.yml
```

### Clean Start

```bash
# Stop and remove everything
docker compose down -v

# Remove images
docker compose down --rmi all

# Rebuild from scratch
docker compose build --no-cache
docker compose up -d
```

---

## Customization

### Add More Charging Points

Edit `docker-compose.yml`:

```yaml
ev-cp-e-3:
  build:
    context: ..
    dockerfile: docker/Dockerfile.cp_e
  container_name: ev-cp-e-3
  environment:
    CP_ENGINE_KAFKA_BOOTSTRAP: kafka:9092
    CP_ENGINE_CP_ID: CP-003
    CP_ENGINE_HEALTH_PORT: 8003
    # ... other config
  depends_on:
    kafka:
      condition: service_healthy
  networks:
    - evcharging-network

ev-cp-m-3:
  build:
    context: ..
    dockerfile: docker/Dockerfile.cp_m
  container_name: ev-cp-m-3
  environment:
    CP_MONITOR_CP_ID: CP-003
    CP_MONITOR_CP_E_HOST: ev-cp-e-3
    CP_MONITOR_CP_E_PORT: 8003
    # ... other config
  depends_on:
    - ev-central
    - ev-cp-e-3
  networks:
    - evcharging-network
```

### Change Service Configuration

1. Edit environment variables in `docker-compose.yml`
2. Restart service: `docker compose restart <service>`

### Use Different Base Image

Edit Dockerfiles to change `FROM python:3.11-slim` to desired image.

---

## Production Considerations

### Security

1. **Don't expose all ports** - Only expose what's needed
2. **Use secrets** - For credentials and keys
3. **Enable TLS** - For Kafka and HTTP
4. **Non-root users** - Run containers as non-root
5. **Scan images** - Use security scanning tools

### Performance

1. **Resource limits** - Add CPU/memory limits
2. **Health checks** - Configure proper intervals
3. **Restart policies** - Use `restart: always` in production
4. **Logging** - Configure log rotation

### Monitoring

1. **Add Prometheus** - For metrics collection
2. **Add Grafana** - For visualization
3. **Log aggregation** - Use ELK or similar
4. **Alerting** - Set up alerts for issues

### Example Production Additions

```yaml
services:
  ev-central:
    # ... existing config
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 256M
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    restart: always
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

---

## Reference

### Common Commands

```bash
# From project root
docker compose up -d              # Start services
docker compose down               # Stop services
docker compose ps                 # Show status
docker compose logs -f            # Follow logs
docker compose restart <service>  # Restart service
docker compose build              # Build images
docker compose pull               # Pull images
```

### Service Management

```bash
# Start specific services
docker compose up -d ev-central ev-cp-e-1

# Stop specific services
docker compose stop ev-driver

# Remove specific services
docker compose rm -f ev-driver

# Scale services (not applicable to our setup)
docker compose up -d --scale ev-cp-e=3
```

---

## Getting Help

- **Main Documentation**: See `../DEPLOYMENT_GUIDE.md`
- **Quick Start**: See `../QUICKSTART.md`
- **Verification**: Run `../verify.sh`
- **Logs**: `docker compose logs -f`

---

**Note**: Always run `docker compose` commands from the project root, not from this directory, unless you adjust paths accordingly.
