# System Deployment Readiness - Lab Environment

## ✅ Deployment Status: PRODUCTION READY

The EV Charging Simulation system is now fully configured for deployment **without requiring compilation environments**. All builds are containerized and can be deployed on lab machines or with remote infrastructure.

---

## Deployment Capabilities

### ✅ Fully Automated Deployment

- **One-command deployment**: `docker compose up -d`
- **Interactive script**: `./deploy.sh` with menu-driven options
- **Make targets**: `make up`, `make remote-kafka`, `make lab-deploy`
- **No manual compilation required**
- **Service roster**: 10 services (Kafka, Central, 3×CP Engines, 3×CP Monitors, 2×Drivers) ready for grading stress tests

### ✅ Multiple Deployment Scenarios

1. **Full Local** - Everything on one machine (development/testing)
2. **Remote Kafka** - Use existing Kafka infrastructure
3. **Distributed Lab** - Components across multiple machines
4. **Hybrid** - Mix of local and remote components

### ✅ Pre-Built Configurations

- `docker-compose.yml` - Full deployment with Kafka
- `docker/docker-compose.remote-kafka.yml` - Connect to external Kafka
- `.env.example` - Configuration templates
- All Dockerfiles ready to build

### ✅ Verification & Monitoring

- `verify.sh` - Automated health checks
- `make verify` - Quick status check
- `make status` - Service overview
- Built-in health endpoints

---

## Lab Machine Deployment Examples

### Scenario 1: Single Lab Machine (Simplest)

```bash
# Clone repository
git clone <repo-url>
cd ev-charging-simulation

# Deploy everything
docker compose up -d

# Access dashboard
open http://localhost:8000
```

**No configuration needed!** Everything works out of the box.

---

### Scenario 2: Two Lab Machines (Distributed)

**Machine A** (Kafka + Central) - `192.168.1.10`

```bash
# Clone and start infrastructure
git clone <repo-url>
cd ev-charging-simulation
docker compose up -d kafka ev-central

# Verify
docker compose ps
curl http://localhost:8000/health
```

**Machine B** (Charging Points) - `192.168.1.11`

```bash
# Clone repository
git clone <repo-url>
cd ev-charging-simulation

# Configure connection to Machine A
export KAFKA_BOOTSTRAP=192.168.1.10:9092

# Start only charging point services
docker compose up -d ev-cp-e-1 ev-cp-e-2 ev-cp-e-3 ev-cp-m-1 ev-cp-m-2 ev-cp-m-3

# Verify
docker compose ps
```

**Access**: Open `http://192.168.1.10:8000` from any machine

---

### Scenario 3: Using Remote Kafka (Lab Infrastructure)

**Prerequisite**: Kafka already running at `kafka.lab.edu:9092`

**Any Lab Machine**:

```bash
# Clone repository
git clone <repo-url>
cd ev-charging-simulation

# Configure to use remote Kafka
export KAFKA_BOOTSTRAP=kafka.lab.edu:9092

# Deploy all application services
docker compose -f docker/docker-compose.remote-kafka.yml up -d

# Or use interactive script
./deploy.sh
# Select option 2: Remote Kafka deployment
```

---

### Scenario 4: Three Machines (Fully Distributed)

**Setup**: Shared Kafka at `kafka.lab.edu:9092`

**Machine 1** (Central Controller):
```bash
export KAFKA_BOOTSTRAP=kafka.lab.edu:9092
docker compose -f docker/docker-compose.remote-kafka.yml up -d ev-central
```

**Machine 2** (Charging Points):
```bash
export KAFKA_BOOTSTRAP=kafka.lab.edu:9092
export CENTRAL_HOST=<machine1-ip>
docker compose -f docker/docker-compose.remote-kafka.yml up -d \
  ev-cp-e-1 ev-cp-e-2 ev-cp-e-3 \
  ev-cp-m-1 ev-cp-m-2 ev-cp-m-3
```

**Machine 3** (Driver Client):
```bash
export KAFKA_BOOTSTRAP=kafka.lab.edu:9092
docker compose -f docker/docker-compose.remote-kafka.yml up -d ev-driver ev-driver-2
```

---

## Hands-Off Classroom Demonstration

To satisfy the grading requirement of launching the entire solution without additional interaction:

1. **Start everything at once** (on a single node or orchestrating nodes with shared compose file):
   ```bash
   docker compose up -d
   ```

2. **Observe the system** without touching it further:
   ```bash
   docker compose logs -f ev-central ev-driver ev-driver-2
   ```
   - Central logs show CP registrations and session orchestration.
   - Both drivers emit charging requests against multiple CPs.

3. **Optional projector view**: open the Central dashboard at `http://<central-host>:8000` to watch CP state changes and driver sessions unfold.

4. **Health confirmation** (non-interactive once running):
   ```bash
   make verify
   ```
   The script checks all 10 services, Kafka topics, and HTTP/TCP endpoints without needing code changes or rebuilds.

---

## Key Features for Lab Deployment

### ✅ No Compilation Required

- All builds happen in Docker containers
- Consistent build environment
- No need to install Python, pip, or dependencies
- Same results on any machine

### ✅ Environment-Based Configuration

```bash
# Single variable to change Kafka location
export KAFKA_BOOTSTRAP=kafka.example.com:9092

# Single variable to change Central location
export CENTRAL_HOST=central.example.com

# Docker Compose reads these automatically
docker compose up -d
```

### ✅ Service Independence

Each service can be deployed separately:

```bash
# Just Central
docker compose up -d ev-central

# Just Charging Points
docker compose up -d ev-cp-e-1 ev-cp-e-2 ev-cp-e-3 ev-cp-m-1 ev-cp-m-2 ev-cp-m-3

# Just Driver
docker compose up -d ev-driver ev-driver-2

# Just Kafka
docker compose up -d kafka
```

### ✅ Network Flexibility

- Services auto-discover via Docker DNS
- Or use IP addresses for cross-machine
- Configurable via environment variables
- Works with firewalls (only needs specific ports)

---

## Deployment Tools

### 1. Interactive Deployment Script

```bash
./deploy.sh
```

**Menu Options**:
1. Full deployment (All components)
2. Remote Kafka deployment
3. Lab machine deployment (guided)
4. Local Python (no Docker)
5. Check system status
6. Stop services
7. Clean everything

**Features**:
- Prerequisite checking
- Step-by-step guidance
- Error detection
- Status monitoring

### 2. Makefile Commands

```bash
make help          # Show all commands
make up            # Full deployment
make remote-kafka  # With remote Kafka
make lab-deploy    # Interactive lab menu
make verify        # Health checks
make status        # Quick status
make logs          # View logs
make down          # Stop services
make clean         # Clean up
```

### 3. Verification Script

```bash
./verify.sh
```

**Checks**:
- ✓ Docker services running
- ✓ Network connectivity
- ✓ Kafka topics created
- ✓ Service health endpoints
- ✓ Log errors
- ✓ Optional session test

---

## Documentation

### Comprehensive Guides

1. **QUICKSTART.md** - Get running in 5 minutes
2. **DEPLOYMENT_GUIDE.md** - 50+ pages of detailed instructions
3. **DEPLOYMENT_SUMMARY.md** - Architecture and scenarios
4. **docker/README.md** - Docker-specific documentation
5. **.env.example** - Configuration examples

### What's Documented

- ✓ All deployment scenarios
- ✓ Lab machine setup steps
- ✓ Network configuration
- ✓ Environment variables
- ✓ Troubleshooting guide
- ✓ Port requirements
- ✓ Resource requirements
- ✓ Security considerations
- ✓ Scaling options
- ✓ Maintenance procedures

---

## Requirements

### Lab Machine Requirements

**Minimum**:
- Docker 20.10+
- Docker Compose 2.0+
- 2 CPU cores
- 4GB RAM
- 2GB disk space
- Network connectivity

**Operating Systems**:
- Linux (any distribution)
- macOS
- Windows (with Docker Desktop)

**Network**:
- Access to Kafka (port 9092)
- Access to Central (port 8000) if distributed
- No special firewall rules needed for single machine

### What's NOT Required

- ❌ Python installation
- ❌ pip or virtualenv
- ❌ Build tools (gcc, make)
- ❌ Node.js or npm
- ❌ Java or JDK
- ❌ Any compilation environment
- ❌ Manual dependency management

---

## Port Configuration

### Default Ports

| Port | Service | Required By |
|------|---------|-------------|
| 9092 | Kafka | All services |
| 8000 | Central HTTP | Dashboard, API, CP Monitors |
| 9999 | Central TCP | Control plane (optional) |
| 8001 | CP Engine 1 | Health monitoring |
| 8002 | CP Engine 2 | Health monitoring |

### Firewall Rules (Distributed Deployment)

**Machine with Kafka**:
- Allow inbound TCP 9092 from application machines

**Machine with Central**:
- Allow inbound TCP 8000 from CP Monitor machines
- Allow inbound TCP 8000 for dashboard access

**Machine with CP Engines**:
- Allow inbound TCP 8001, 8002 from CP Monitor machines (if separate)

---

## Quick Reference

### Deploy Full System (One Machine)

```bash
docker compose up -d
./verify.sh
```

### Deploy with Remote Kafka

```bash
export KAFKA_BOOTSTRAP=kafka.example.com:9092
docker compose -f docker/docker-compose.remote-kafka.yml up -d
./verify.sh
```

### Deploy Specific Components

```bash
# Central only
docker compose up -d ev-central

# Charging Points only
docker compose up -d ev-cp-e-1 ev-cp-e-2 ev-cp-e-3 ev-cp-m-1 ev-cp-m-2 ev-cp-m-3
```

### Check Status

```bash
docker compose ps
curl http://localhost:8000/health
./verify.sh
```

### View Logs

```bash
docker compose logs -f
docker compose logs -f ev-central
```

### Stop Everything

```bash
docker compose down
```

### Clean Everything

```bash
docker compose down -v
make clean
```

---

## Verification Checklist

After deployment, verify:

- [ ] All services show "Up" status: `docker compose ps`
- [ ] Dashboard accessible: http://localhost:8000
- [ ] Health endpoint responds: `curl http://localhost:8000/health`
- [ ] Kafka topics exist: `docker compose exec kafka kafka-topics.sh --bootstrap-server localhost:9092 --list`
- [ ] Charging points visible in dashboard
- [ ] Driver can request charging sessions
- [ ] Telemetry data flows correctly
- [ ] No errors in logs: `docker compose logs | grep -i error`

**Automated Check**: `./verify.sh` runs all these checks

---

## Troubleshooting

### Services Won't Start

```bash
# Check Docker is running
docker info

# Check logs
docker compose logs

# Rebuild
docker compose build --no-cache
docker compose up -d
```

### Can't Connect to Remote Kafka

```bash
# Test connectivity
nc -zv kafka.example.com 9092

# Check firewall
telnet kafka.example.com 9092

# Verify environment variable
echo $KAFKA_BOOTSTRAP
```

### Dashboard Not Accessible

```bash
# Check service
docker compose ps ev-central

# Test locally
curl http://localhost:8000/health

# Check port not in use
lsof -i :8000
```

### Run Full Verification

```bash
./verify.sh
```

---

## Success Criteria ✅

The system meets all requirements for lab deployment:

✅ **No Compilation Required** - All builds containerized  
✅ **Multiple Scenarios** - Lab, remote, local, distributed  
✅ **Automated Deployment** - One command deployment  
✅ **Configuration Flexible** - Environment variables  
✅ **Fully Documented** - Comprehensive guides  
✅ **Verified Working** - Automated verification  
✅ **Service Independence** - Deploy components separately  
✅ **Network Flexibility** - Works across machines  
✅ **Resource Efficient** - Runs on modest hardware  
✅ **Production Ready** - Proper error handling  

---

## Getting Started

1. **Clone the repository**:
   ```bash
   git clone <repo-url>
   cd ev-charging-simulation
   ```

2. **Choose deployment method**:
   - Simple: `docker compose up -d`
   - Interactive: `./deploy.sh`
   - Makefile: `make up`

3. **Verify deployment**:
   ```bash
   ./verify.sh
   ```

4. **Access dashboard**:
   ```
   http://localhost:8000
   ```

5. **Read documentation**:
   - Quick start: `QUICKSTART.md`
   - Full guide: `DEPLOYMENT_GUIDE.md`

---

## Support

For issues or questions:

1. Check logs: `docker compose logs`
2. Run verification: `./verify.sh`
3. Consult `DEPLOYMENT_GUIDE.md` troubleshooting section
4. Review this document

---

**Status**: ✅ **PRODUCTION READY FOR LAB DEPLOYMENT**

**Version**: 1.0  
**Last Updated**: October 2025  
**Tested**: Docker 24.0+, Docker Compose 2.20+
