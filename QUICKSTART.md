# Quick Start Guide - EV Charging Simulation

Get the system running in under 5 minutes!

## Prerequisites

- **Docker** and **Docker Compose** installed
- 4GB+ free RAM
- Ports available: 8000, 9092, 9999

## Option 1: One-Command Deployment (Easiest)

```bash
# Full deployment with Kafka included
docker compose up -d

# Wait 30 seconds for services to start
sleep 30

# Access the dashboard
open http://localhost:8000
```

**That's it!** The system is running with:
- 2 charging points (CP-001, CP-002)
- 1 driver (driver-alice)
- Kafka message broker
- Central controller with dashboard

## Option 2: Using Make (Recommended)

```bash
# View all available commands
make help

# Deploy everything
make up

# Check status
make verify

# View logs
make logs

# Stop when done
make down
```

## Option 3: Interactive Deployment

```bash
./deploy.sh
```

Follow the menu to select your deployment scenario.

---

## Quick Verification

### 1. Check Services are Running

```bash
docker compose ps
```

All services should show "Up" status.

### 2. Access the Dashboard

Open browser: **http://localhost:8000**

You should see:
- Charging points list
- Active sessions
- Real-time status

### 3. Watch It Work

```bash
# See charging sessions in action
docker compose logs -f ev-driver ev-central

# Restart driver to see a new session
docker compose restart ev-driver
```

### 4. Run Automated Verification

```bash
./verify.sh
```

This checks all services and connectivity.

---

## Understanding the System

### Components Running

1. **Kafka** (port 9092): Message broker for async communication
2. **Central** (ports 8000, 9999): Main controller + dashboard
3. **CP Engines** (ev-cp-e-1, ev-cp-e-2): Charging point hardware simulation
4. **CP Monitors** (ev-cp-m-1, ev-cp-m-2): Health monitoring
5. **Driver** (ev-driver): Simulated EV driver requesting charging

### Data Flow

```
Driver → Kafka → Central → Kafka → CP Engine
                    ↓
                Dashboard (you can see it!)
                    ↑
            CP Monitor ← CP Engine
```

---

## Common Commands

```bash
# Start services
docker compose up -d

# Stop services
docker compose down

# View all logs
docker compose logs -f

# View specific service logs
docker compose logs -f ev-central

# Restart a service
docker compose restart ev-driver

# Check status
docker compose ps

# Run verification
./verify.sh

# Clean everything
make clean
```

---

## Customization

### Change Number of Charging Points

Edit `docker-compose.yml` to add more CP pairs (Engine + Monitor).

### Modify Charging Parameters

Edit environment variables in `docker-compose.yml`:

```yaml
CP_ENGINE_KW_RATE: 50.0      # Power rating (kW)
CP_ENGINE_EURO_RATE: 0.40    # Cost per kWh (€)
```

### Custom Driver Requests

Edit `requests.txt` to specify which charging points to request:

```
CP-001
CP-002
CP-001
```

Then restart driver:

```bash
docker compose restart ev-driver
```

---

## Lab Deployment (Multiple Machines)

### Machine 1: Run Kafka + Central

```bash
docker compose up -d kafka ev-central

# Get your IP
hostname -I
```

### Machine 2: Run Charging Points

```bash
# Set Machine 1's IP
export KAFKA_BOOTSTRAP=<machine1-ip>:9092

# Run charging points
docker compose up -d ev-cp-e-1 ev-cp-e-2 ev-cp-e-3 ev-cp-m-1 ev-cp-m-2 ev-cp-m-3
```

See [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) for detailed lab instructions.

---

## Remote Kafka (Kafka Already Running)

If you have Kafka running elsewhere:

```bash
# Set Kafka address
export KAFKA_BOOTSTRAP=your-kafka-server:9092

# Deploy without Kafka
docker compose -f docker/docker-compose.remote-kafka.yml up -d
```

---

## Troubleshooting

### Services won't start

```bash
# Check Docker is running
docker info

# Check for port conflicts
lsof -i :8000
lsof -i :9092

# View startup logs
docker compose logs
```

### Can't access dashboard

```bash
# Check Central is running
curl http://localhost:8000/health

# Should return: {"status":"healthy"}

# If not, check logs
docker compose logs ev-central
```

### Charging sessions not working

```bash
# Verify Kafka topics exist
docker compose exec kafka kafka-topics.sh \
  --bootstrap-server localhost:9092 --list

# Restart services in order
docker compose restart kafka
sleep 10
docker compose restart ev-central ev-cp-e-1 ev-cp-e-2
```

### Still having issues?

Run the verification script:

```bash
./verify.sh
```

It will identify and report problems.

---

## Next Steps

1. **Explore the Dashboard**: http://localhost:8000
   - See charging points
   - Monitor active sessions
   - View telemetry data

2. **Experiment**: 
   - Restart the driver to trigger new sessions
   - Modify charging parameters
   - Add more charging points

3. **Learn More**:
   - Read [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) for advanced deployment
   - Check [README.md](README.md) for architecture details
   - Review [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md) for features

4. **Develop**:
   - Modify code in `evcharging/apps/`
   - Rebuild: `docker compose build`
   - Test locally: `make local-run`

---

## Clean Up

When you're done:

```bash
# Stop services (keeps data)
docker compose down

# Stop and remove all data
docker compose down -v

# Complete cleanup (including images)
make clean-all
```

---

## Getting Help

- **Logs**: `docker compose logs -f`
- **Status**: `docker compose ps`
- **Verification**: `./verify.sh`
- **Deployment Issues**: See [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)

---

**Enjoy exploring the EV Charging Simulation!** 🚗⚡
