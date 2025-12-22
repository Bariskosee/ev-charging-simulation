# ⚡ EV Charging Simulation System

A distributed, event-driven electric vehicle charging management system demonstrating modern software architecture patterns including microservices, state machines, event streaming, and fault tolerance. Built with Python, Docker, Apache Kafka, and TCP sockets.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-required-blue.svg)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🆕 Release 2: EV_Registry Service

**NEW in Release 2**: Secure REST API for Charging Point registration, deregistration, and authentication.

- 🔒 **Secure CP registration** with bcrypt credentials and JWT tokens
- 🌐 **REST API** with OpenAPI/Swagger documentation
- 🔑 **Authentication system** for CPs before connecting to EV_Central
- 🛡️ **TLS/HTTPS support** for production deployments
- 📜 **Certificate-based authentication** (optional)

**Quick Start**:
```bash
# Start EV_Registry service
make registry

# Access API documentation
open http://localhost:8080/docs

# Run tests
make registry-test
```

**Documentation**:
- **[EV_REGISTRY_QUICKSTART.md](EV_REGISTRY_QUICKSTART.md)** - 5-minute getting started guide
- **[EV_REGISTRY_README.md](EV_REGISTRY_README.md)** - Complete API documentation
- **[EV_REGISTRY_IMPLEMENTATION.md](EV_REGISTRY_IMPLEMENTATION.md)** - Implementation details

---

## 🎬 Autonomous Operation

**This system is designed for fully autonomous operation with ZERO user interaction required.**

### ⚡ Quick Start

**Option 1: Local Testing (Single Computer)** - Recommended for development/testing
```bash
docker compose up -d
```

**Option 2: Lab Deployment (3 Windows Computers)** - For classroom demonstrations
```powershell
# See LAB_DEPLOYMENT_SUMMARY.md for detailed instructions
```

That's it! The entire system will:
- ✅ Start **19 services** automatically (1 Kafka, 1 Central, 1 Registry, 1 Front, 5 CPs, 5 Monitors, 5 Drivers)
- ✅ Initialize and connect without intervention
- ✅ Begin autonomous charging operations
- ✅ Demonstrate all functionality through observable terminal outputs
- ✅ Run continuously and handle all scenarios (success, failures, recovery)

### 📚 Documentation

**Release 2 (NEW)**:
- **[EV_REGISTRY_QUICKSTART.md](EV_REGISTRY_QUICKSTART.md)** - 🆕 Quick start for CP registration API
- **[EV_REGISTRY_README.md](EV_REGISTRY_README.md)** - 🆕 Complete Registry documentation
- **[EV_REGISTRY_IMPLEMENTATION.md](EV_REGISTRY_IMPLEMENTATION.md)** - 🆕 Implementation summary
- **[EV_FRONT_README.md](EV_FRONT_README.md)** - 🆕 Global Status Dashboard - Multi-screen monitoring

**Release 1**:
- **[QUICK_REFERENCE.md](QUICK_REFERENCE.md)** - 📄 Quick reference card for lab deployments (print this!)
- **[QUICKSTART.md](QUICKSTART.md)** - Fast local setup for single computer (Windows/macOS/Linux)
- **[LAB_DEPLOYMENT_SUMMARY.md](LAB_DEPLOYMENT_SUMMARY.md)** - Complete guide for 3 Windows lab computers
- **[WINDOWS_DEPLOYMENT.md](WINDOWS_DEPLOYMENT.md)** - 🪟 Windows PowerShell scripts and 3-window lab guide
- **[TROUBLESHOOTING_GUIDE.md](TROUBLESHOOTING_GUIDE.md)** - 🔧 Complete troubleshooting guide for multi-machine deployments
- **[DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)** - Comprehensive deployment options
- **[CRASH_RESILIENCE.md](CRASH_RESILIENCE.md)** - Crash simulation and fault tolerance testing
- **[DYNAMIC_DEPLOYMENT.md](DYNAMIC_DEPLOYMENT.md)** - Dynamic CP/Driver addition at runtime

### 📊 Observe the System

**Web Dashboards**:
```
EV Global Dashboard:   http://localhost:8500  (NEW - Multi-screen capable!)
EV Central Dashboard:  http://localhost:8000
EV Registry API Docs:  http://localhost:8080/docs
```

**Terminal Logs** (detailed event streams):
```bash
./view-logs.sh all         # All services
./view-logs.sh central     # Central controller only
./view-logs.sh cp          # All charging points
./view-logs.sh driver      # All drivers
```

### 🎯 What You'll See

The system autonomously demonstrates:
- 🔄 **Concurrent charging** across 10 charging points
- 🚗 **5 drivers** continuously requesting charging sessions
- 💚 **Health monitoring** with fault detection and recovery
- ⚡ **Real-time telemetry** streaming (kW, cost, duration)
- 🔌 **State machine** transitions for all CP lifecycle events
- 🛡️ **Fault tolerance** with circuit breakers and automatic failover

**No interaction needed** - just start it and observe! Perfect for validation, testing, and demonstrations.

📖 **See [AUTONOMOUS_OPERATION.md](AUTONOMOUS_OPERATION.md) for complete details on what to observe and expect.**

---

## 📖 Project Overview

This project implements a realistic simulation of an EV charging network infrastructure, demonstrating how distributed systems coordinate to manage multiple charging points, handle driver requests, monitor system health, and ensure reliable power delivery.

### 🎯 Project Goals

1. **Distributed System Design** - Showcase microservices architecture with event-driven communication
2. **State Machine Implementation** - Demonstrate robust state management for charging point lifecycle
3. **Fault Tolerance** - Implement circuit breakers, health monitoring, and automatic failover
4. **Real-time Monitoring** - Provide live dashboard for system observability
5. **Scalability** - Design for horizontal scaling with multiple charging points
6. **Protocol Implementation** - Demonstrate TCP framing, message validation, and reliable messaging

### 🔬 What We're Building

This system simulates a **commercial EV charging network** where:

- **Multiple charging points** operate independently with their own state machines
- **Drivers** submit charging requests through a client application
- **Central controller** orchestrates request routing and charging point assignment
- **Health monitors** continuously check charging point status and detect faults
- **Event streaming** via Kafka enables loose coupling and scalability
- **Real-time telemetry** tracks power delivery, cost, and session metrics
- **Fault recovery** automatically handles failures with circuit breaker patterns
- **Database persistence** maintains historical records for analytics

## 🏗️ System Architecture

This project simulates a distributed EV charging infrastructure with the following components:

```
┌─────────────────┐         ┌──────────────┐         ┌─────────────────┐
│   EV Driver     │────────▶│  EV Central  │◀────────│  EV CP Monitor  │
│   (Client)      │         │ (Controller) │         │  (Health Check) │
└─────────────────┘         └──────────────┘         └─────────────────┘
        │                           │                          │
        │                           │                          │
        │         Kafka Topics      │                          │
        └───────────────────────────┴──────────────────────────┘
                                    │
                                    ▼
                          ┌──────────────────┐
                          │  EV CP Engine    │
                          │  (Power Control) │
                          └──────────────────┘
```

### 🧩 System Components

#### 1. **EV Central (Controller)**
The brain of the system - coordinates all charging operations.

**Responsibilities:**
- Accept and validate driver charging requests
- Assign drivers to available charging points
- Route commands to charging point engines
- Maintain charging point registry and availability
- Provide web dashboard for real-time monitoring
- Track fault history and health metrics
- Manage database persistence

**Technologies:**
- FastAPI for HTTP dashboard (port 8000)
- TCP server for control plane (port 9999)
- Kafka consumer/producer for event streaming
- SQLite for persistent storage
- Circuit breaker pattern for fault tolerance

**Key Features:**
- Automatic failover when CPs become faulty
- Real-time session tracking
- Health snapshot recording
- Fault event logging

---

#### 2. **EV CP Engine (CP_E)**
The charging point control system - manages power delivery state machine.

**Responsibilities:**
- Execute state machine for charging lifecycle
- Control power delivery to vehicles
- Emit real-time telemetry (kW, cost, session data)
- Handle commands from Central (START_SUPPLY, STOP_SUPPLY, SHUTDOWN)
- Validate payloads and handle errors gracefully
- Provide health check endpoint for monitoring

**State Machine:**
```
DISCONNECTED: Initial state, no connection
    ↓ [CONNECT event]
ACTIVATED: Ready to charge, awaiting command
    ↓ [START_SUPPLY command]
SUPPLYING: Actively charging, emitting telemetry
    ↓ [STOP_SUPPLY command or completion]
ACTIVATED: Session complete, ready for next
    ↓ [DISCONNECT event]
DISCONNECTED

STOPPED: Administrative pause (can resume to ACTIVATED)
FAULT: Error state (requires recovery)
```

**Technologies:**
- Async Python with asyncio for concurrent operations
- Kafka consumer/producer
- HTTP health endpoint
- Pydantic for message validation

**Key Features:**
- Graceful shutdown handling
- Payload validation prevents crashes
- UTC-aware datetime handling
- Configurable power/cost rates

---

#### 3. **EV CP Monitor (CP_M)**
The health watchdog - continuously monitors charging point status.

**Responsibilities:**
- Perform periodic health checks via HTTP
- Detect consecutive failures (3+ threshold)
- Notify Central of fault/recovery events
- Register charging point with Central on startup
- Track health metrics over time

**Health Check Logic:**
```python
Every 5 seconds:
  1. HTTP GET to CP_E health endpoint
  2. If success: Reset failure counter, notify recovery if was faulty
  3. If failure: Increment counter
     - If counter >= 3: Notify Central of fault
  4. Record health snapshot to database
```

**Technologies:**
- httpx for async HTTP requests
- Configurable check intervals and thresholds
- RESTful communication with Central

**Key Features:**
- Automatic fault detection
- Recovery notification
- Consecutive failure tracking
- Integration with Central's fault management

---

#### 4. **EV Driver (Client)**
The end-user simulation - requests charging sessions.

**Responsibilities:**
- Read charging point IDs from configuration file
- Submit charging requests to Central via Kafka
- Receive status updates (ACCEPTED, IN_PROGRESS, COMPLETED, DENIED, FAILED)
- Log charging session progress
- Simulate multiple drivers in sequence

**Request Flow:**
```
1. Read CP ID from requests.txt
2. Send DriverRequest to Kafka (driver.requests topic)
3. Wait for ACCEPTED response
4. Receive periodic IN_PROGRESS updates with kW/€
5. Receive final COMPLETED or FAILED status
6. Wait interval and request next CP
```

**Technologies:**
- Kafka producer for requests
- Kafka consumer for updates
- Configurable request intervals

**Key Features:**
- Handles all response statuses gracefully
- Colored console output for visibility
- Configurable driver ID and intervals

---

#### 5. **Apache Kafka (Event Backbone)**
The message bus - enables distributed, decoupled communication.

**Topics:**
- `central.commands` - Commands from Central to CP_E
- `cp.status` - State updates from CP_E to Central
- `cp.telemetry` - Real-time charging data from CP_E
- `driver.requests` - Charging requests from drivers
- `driver.updates` - Status updates to drivers

**Benefits:**
- Loose coupling between services
- Fault tolerance through message persistence
- Horizontal scalability
- Event replay capability
- Asynchronous communication

---

### 🔄 Charging Point State Machine

The core of the system's reliability - each charging point follows a strict state machine:

```
DISCONNECTED → ACTIVATED → SUPPLYING → ACTIVATED
      ↓            ↓             ↓
    FAULT ← ← ← ← FAULT ← ← ← FAULT
      ↓
  ACTIVATED

ACTIVATED ↔ STOPPED (administrative control)
```

## 🚀 Quick Start

### Prerequisites

- **Docker & Docker Compose** (recommended) - [Install Docker](https://docs.docker.com/get-docker/)
- **Python 3.11+** (for local development) - [Download Python](https://www.python.org/downloads/)
- **Make** (optional, for convenience commands)

### Running with Docker Compose (Recommended)

1. **Clone the repository:**
   ```bash
   git clone <your-repo-url>
   cd ev-charging-simulation
   ```

2. **Start all services:**
   ```bash
   make up
   # or
   cd docker && docker-compose up
   ```

3. **Access the dashboard:**
   
   Open http://localhost:8000 in your browser

4. **View logs:**
   ```bash
   make logs
   # or
   cd docker && docker-compose logs -f
   ```

5. **Stop services:**
   ```bash
   make down
   ```

### Running Locally (Without Docker)

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Start Kafka** (using Docker):
   ```bash
   docker run -d --name kafka \
     -p 9092:9092 \
     -e KAFKA_NODE_ID=1 \
     -e KAFKA_PROCESS_ROLES=broker,controller \
     -e KAFKA_LISTENERS=PLAINTEXT://0.0.0.0:9092,CONTROLLER://0.0.0.0:9093 \
     -e KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://localhost:9092 \
     -e KAFKA_CONTROLLER_LISTENER_NAMES=CONTROLLER \
     -e KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT \
     -e KAFKA_CONTROLLER_QUORUM_VOTERS=1@localhost:9093 \
     -e KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1 \
     -e CLUSTER_ID=MkU3OEVBNTcwNTJENDM2Qk \
     apache/kafka:3.7.0
   ```

3. **Start services in separate terminals:**

   **Terminal 1 - EV Central:**
   ```bash
   export PYTHONPATH=.
   python -m evcharging.apps.ev_central.main \
     --kafka-bootstrap localhost:9092 \
     --http-port 8000 \
     --listen-port 9999
   ```

   **Terminal 2 - CP Engine 1:**
   ```bash
   export PYTHONPATH=.
   python -m evcharging.apps.ev_cp_e.main \
     --kafka-bootstrap localhost:9092 \
     --cp-id CP-001 \
     --health-port 8001
   ```

   **Terminal 3 - CP Engine 2:**
   ```bash
   export PYTHONPATH=.
   python -m evcharging.apps.ev_cp_e.main \
     --kafka-bootstrap localhost:9092 \
     --cp-id CP-002 \
     --health-port 8002
   ```

   **Terminal 4 - CP Monitor 1:**
   ```bash
   export PYTHONPATH=.
   python -m evcharging.apps.ev_cp_m.main \
     --cp-id CP-001 \
     --cp-e-host localhost \
     --cp-e-port 8001 \
     --central-host localhost \
     --central-port 8000
   ```

   **Terminal 5 - CP Monitor 2:**
   ```bash
   export PYTHONPATH=.
   python -m evcharging.apps.ev_cp_m.main \
     --cp-id CP-002 \
     --cp-e-host localhost \
     --cp-e-port 8002 \
     --central-host localhost \
     --central-port 8000
   ```

   **Terminal 6 - EV Driver:**
   ```bash
   export PYTHONPATH=.
   python -m evcharging.apps.ev_driver.main \
     --driver-id driver-alice \
     --kafka-bootstrap localhost:9092 \
     --requests-file requests.txt
   ```

## 📊 Dashboard

The web dashboard at http://localhost:8000 displays:

- **Real-time charging point states** with color-coded badges
- **Active charging sessions** with driver information
- **Live telemetry:** Power delivery (kW) and cost (€)
- **Auto-refresh** every 2 seconds for real-time updates

### Dashboard Preview

![Dashboard](docs/dashboard-preview.png)

*The dashboard shows all charging points with their current states, active sessions, and real-time power/cost metrics.*

## 🏢 Deployment Options

The system supports **multiple deployment scenarios** without requiring compilation environments. All builds are containerized for consistent, reproducible deployments.

### 📦 Deployment Scenarios

#### 1. Full Local Deployment (Single Machine)

Perfect for development and testing:

```bash
docker compose up -d
```

**What's included**: Kafka, Central, 2x CP Engines, 2x CP Monitors, Driver

#### 2. Remote Kafka Deployment

Use existing Kafka infrastructure:

```bash
export KAFKA_BOOTSTRAP=kafka.example.com:9092
docker compose -f docker/docker-compose.remote-kafka.yml up -d
```

#### 3. Lab Machine Deployment (Distributed - 3 Machines)

Deploy components across 3 machines for realistic testing:

**Machine 1** (Kafka + Central):
```bash
export KAFKA_ADVERTISED_HOST=192.168.1.105  # Your IP
docker compose up -d kafka ev-central
```

**Machine 2** (5 Charging Points + Monitors):
```bash
export KAFKA_BOOTSTRAP=192.168.1.105:9092
export CENTRAL_HOST=192.168.1.105
./deploy-lab-cp.sh  # Starts 10 services
```

**Machine 3** (5 Drivers):
```bash
export KAFKA_BOOTSTRAP=192.168.1.105:9092
export CENTRAL_HTTP_URL=http://192.168.1.105:8000
./deploy-lab-driver.sh  # Starts 5 driver clients
```

**Total: 17 services across 3 machines** - See [LAB_DEPLOYMENT_SUMMARY.md](LAB_DEPLOYMENT_SUMMARY.md) for complete guide.

#### 4. Interactive Deployment

Use the deployment script for guided setup:

```bash
./deploy.sh
```

### ✅ Verification

After deployment, verify the system:

```bash
./verify.sh
```

This checks:
- ✓ All services running
- ✓ Network connectivity
- ✓ Kafka topics created
- ✓ Service health
- ✓ Log errors

### 📚 Deployment Documentation

- **[QUICKSTART.md](QUICKSTART.md)** - Get running in 5 minutes
- **[DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)** - Comprehensive 50+ page guide
- **[LAB_DEPLOYMENT_SUMMARY.md](LAB_DEPLOYMENT_SUMMARY.md)** - 🎓 **3-Machine Lab Deployment (Windows/Linux/macOS)** - Cross-platform setup with 17 services

### 📚 Fault Tolerance Documentation

- **[RECOVERY_SCALABILITY_GUIDE.md](RECOVERY_SCALABILITY_GUIDE.md)** - 🔄 Recovery and horizontal scaling guide
- **[CP_STATUS_LOGIC.md](CP_STATUS_LOGIC.md)** - 🔌 Charging Point status determination (Monitor/Engine logic)
- **[FAULT_TOLERANCE.md](FAULT_TOLERANCE.md)** - Complete fault tolerance implementation
- **[FAULT_TOLERANCE_QUICKREF.md](FAULT_TOLERANCE_QUICKREF.md)** - Quick reference guide
- **[AUTONOMOUS_OPERATION_VALIDATION.md](AUTONOMOUS_OPERATION_VALIDATION.md)** - Autonomous operation tests

### 📚 Protocol Documentation

- **[TCP_FRAMING_PROTOCOL.md](TCP_FRAMING_PROTOCOL.md)** - 📡 TCP message framing protocol (`<STX><DATA><ETX><LRC>`)

**Key Features**:
- ✅ No compilation environment required
- ✅ Docker-based containerization
- ✅ Environment variable configuration
- ✅ Multiple deployment scenarios
- ✅ Automated verification
- ✅ Comprehensive documentation

## 🧪 Testing

Run unit tests:

```bash
make test
# or
pytest evcharging/tests/ -v
```

**Test coverage includes:**
- Message validation and JSON schemas
- State machine transitions
- Guard conditions
- Error handling

Expected output:
```
evcharging/tests/test_messages.py ........ [50%]
evcharging/tests/test_states.py .......... [100%]

======================== 25 passed in 0.5s ========================
```

## 📁 Project Structure

```
ev-charging-simulation/
├── evcharging/
│   ├── apps/
│   │   ├── ev_central/         # Central controller & dashboard
│   │   │   ├── main.py         # Controller logic
│   │   │   ├── dashboard.py    # FastAPI web interface
│   │   │   └── tcp_server.py   # TCP control plane
│   │   ├── ev_cp_e/            # Charging Point Engine
│   │   │   └── main.py         # State machine & telemetry
│   │   ├── ev_cp_m/            # Charging Point Monitor
│   │   │   └── main.py         # Health checks & registration
│   │   └── ev_driver/          # Driver client
│   │       └── main.py         # Request handler
│   ├── common/
│   │   ├── config.py           # Pydantic settings
│   │   ├── kafka.py            # Kafka helpers
│   │   ├── messages.py         # Message schemas
│   │   ├── states.py           # State machine
│   │   └── utils.py            # Utility functions
│   └── tests/
│       ├── test_messages.py    # Message validation tests
│       └── test_states.py      # State machine tests
├── docker/
│   ├── docker-compose.yml      # Service orchestration
│   └── Dockerfile.*            # Service images
├── .env.example                # Environment template
├── requirements.txt            # Python dependencies
├── requests.txt                # Sample CP IDs for driver
├── Makefile                    # Convenience commands
└── README.md                   # This file
```

## 🔧 Configuration

Copy `.env.example` to `.env` and adjust settings:

```bash
cp .env.example .env
```

### Key Configuration Options

| Variable | Description | Default |
|----------|-------------|---------|
| `CENTRAL_KAFKA_BOOTSTRAP` | Kafka broker address | `localhost:9092` |
| `CENTRAL_HTTP_PORT` | Dashboard HTTP port | `8000` |
| `CP_ENGINE_KW_RATE` | Power delivery rate (kW) | `22.0` |
| `CP_ENGINE_EURO_RATE` | Cost per kWh (€) | `0.30` |
| `DRIVER_REQUEST_INTERVAL` | Time between requests (s) | `4.0` |

See `.env.example` for all available options.

## 📡 Kafka Topics

The system uses the following Kafka topics:

| Topic | Direction | Purpose |
|-------|-----------|---------|
| `central.commands` | Central → CP_E | Commands (start/stop charging) |
| `cp.status` | CP_E → Central | State updates |
| `cp.telemetry` | CP_E → Central | Real-time charging data |
| `driver.requests` | Driver → Central | Charging requests |
| `driver.updates` | Central → Driver | Status updates |

### Message Formats

All messages use JSON format with Pydantic validation. Example:

```json
// Driver Request
{
  "request_id": "req-abc123",
  "driver_id": "driver-alice",
  "cp_id": "CP-001",
  "ts": "2025-10-13T12:00:00Z"
}

// CP Telemetry
{
  "cp_id": "CP-001",
  "kw": 22.5,
  "euros": 3.75,
  "driver_id": "driver-alice",
  "session_id": "session-xyz",
  "ts": "2025-10-13T12:00:05Z"
}
```

## 🎯 Usage Example

### Happy Path Flow

1. **Driver sends request** for CP-001
2. **Central validates** CP availability → Sends ACCEPTED
3. **Central commands** CP_E to start supply
4. **CP_E transitions** ACTIVATED → SUPPLYING
5. **Telemetry flows** every 1 second (kW, €)
6. **Driver receives** IN_PROGRESS updates
7. **Session completes** after 10 seconds
8. **CP_E transitions** SUPPLYING → ACTIVATED
9. **Driver receives** COMPLETED status

### Sample Log Output

```
2025-10-13 12:00:05 | INFO | Driver:driver-alice | 📤 Requested charging at CP-001
2025-10-13 12:00:06 | INFO | Driver:driver-alice | ✅ CP-001 | ACCEPTED
2025-10-13 12:00:07 | INFO | CP_E:CP-001 | Charging session started for driver-alice
2025-10-13 12:00:08 | INFO | Driver:driver-alice | 🔋 CP-001 | IN_PROGRESS | 22.0 kW, €0.01
2025-10-13 12:00:09 | INFO | Driver:driver-alice | 🔋 CP-001 | IN_PROGRESS | 22.0 kW, €0.02
...
2025-10-13 12:00:16 | INFO | CP_E:CP-001 | Session completed. Total: 0.06 kWh, €0.02
2025-10-13 12:00:16 | INFO | Driver:driver-alice | ✔️ CP-001 | COMPLETED
```

## 🛠️ Development

### Adding More Charging Points

Edit `docker/docker-compose.yml` and add new services:

```yaml
ev-cp-e-3:
  build:
    context: ..
    dockerfile: docker/Dockerfile.cp_e
  environment:
    CP_ENGINE_CP_ID: CP-003
    CP_ENGINE_HEALTH_PORT: 8001
    # ... other config

ev-cp-m-3:
  build:
    context: ..
    dockerfile: docker/Dockerfile.cp_m
  environment:
    CP_MONITOR_CP_ID: CP-003
    CP_MONITOR_CP_E_HOST: ev-cp-e-3
    # ... other config
```

### Running Tests

```bash
# All tests
make test

# Specific test file
pytest evcharging/tests/test_states.py -v

# With coverage
pytest --cov=evcharging evcharging/tests/
```

### Code Quality

```bash
# Type checking (optional)
mypy evcharging/

# Linting (optional)
ruff check evcharging/
```

## 🐛 Troubleshooting

### Services won't start

```bash
# Check Docker status
docker ps

# Check Kafka logs
docker logs ev-kafka

# Restart everything
make clean && make up
```

### Port conflicts

```bash
# Check what's using the port
lsof -i :8000
lsof -i :9092

# Kill the process or change port in .env
```

### Connection errors

```bash
# Verify network
docker network ls
docker network inspect docker_evcharging-network

# Check Kafka topics
docker exec -it ev-kafka kafka-topics.sh --list --bootstrap-server localhost:9092
```

## � Technical Implementation Details

### Event-Driven Architecture

The system uses **Apache Kafka** as the central message bus, enabling:

1. **Loose Coupling** - Services communicate through events, not direct calls
2. **Scalability** - Add more consumers/producers without code changes
3. **Resilience** - Message persistence survives service restarts
4. **Replay** - Event history enables debugging and analytics
5. **Async Processing** - Non-blocking message handling

### State Management

Each charging point maintains its state independently:

```python
class ChargingPoint:
    state: CPState                    # Current state
    current_driver: str | None        # Active driver ID
    current_session: str | None       # Session identifier
    last_telemetry: CPTelemetry       # Latest power/cost data
    is_faulty: bool                   # Fault flag from monitor
    circuit_breaker: CircuitBreaker   # Failure protection
```

### Message Flow Example

**Scenario:** Driver requests charging at CP-001

```
1. Driver → Kafka(driver.requests)
   {
     "request_id": "req-123",
     "driver_id": "alice",
     "cp_id": "CP-001"
   }

2. Central consumes request
   - Check: CP-001 exists? ✓
   - Check: CP-001 available? ✓
   - Check: CP-001 not faulty? ✓
   - Mark CP-001 as assigned to alice

3. Central → Kafka(central.commands)
   {
     "cp_id": "CP-001",
     "cmd": "START_SUPPLY",
     "payload": {
       "driver_id": "alice",
       "session_id": "session-xyz"
     }
   }

4. CP_E consumes command
   - Validate payload ✓
   - State machine: ACTIVATED → SUPPLYING
   - Start telemetry task

5. CP_E → Kafka(cp.status)
   {
     "cp_id": "CP-001",
     "state": "SUPPLYING"
   }

6. CP_E → Kafka(cp.telemetry) [every 1s]
   {
     "cp_id": "CP-001",
     "kw": 22.0,
     "euros": 0.006,
     "driver_id": "alice"
   }

7. Central → Kafka(driver.updates)
   {
     "request_id": "req-123",
     "status": "IN_PROGRESS",
     "reason": "Charging: 22.0 kW, €0.006"
   }

8. [10 seconds later] CP_E completes session
   - State machine: SUPPLYING → ACTIVATED
   - Record session end in database

9. Central notifies driver
   {
     "request_id": "req-123",
     "status": "COMPLETED",
     "reason": "Charging completed successfully"
   }
```

### Fault Handling Flow

**Scenario:** CP-001 becomes unresponsive

```
1. CP_M performs health check every 5s
   GET http://cp-e-001:8001/health

2. Request fails 3 consecutive times
   - CP_M.consecutive_failures = 3
   - Threshold exceeded!

3. CP_M → Central (HTTP POST)
   POST http://central:8000/cp/fault
   {
     "cp_id": "CP-001",
     "is_faulty": true,
     "reason": "Health check failed after 3 attempts"
   }

4. Central marks CP-001 as faulty
   - Set is_faulty = True
   - Record fault event in database
   - Circuit breaker transitions to OPEN
   - Future requests won't be assigned to CP-001

5. CP_M detects recovery
   - Health check succeeds
   - consecutive_failures = 0

6. CP_M → Central (HTTP POST)
   POST http://central:8000/cp/fault
   {
     "cp_id": "CP-001",
     "is_faulty": false,
     "reason": "Health check recovered"
   }

7. Central clears fault
   - Set is_faulty = False
   - Record recovery event
   - Circuit breaker transitions to HALF_OPEN
   - CP-001 available for new requests
```

### Database Schema

```sql
-- Track all fault and recovery events
CREATE TABLE fault_events (
    id INTEGER PRIMARY KEY,
    cp_id TEXT NOT NULL,
    event_type TEXT NOT NULL,  -- 'FAULT' or 'RECOVERY'
    reason TEXT,
    timestamp TEXT NOT NULL,
    INDEX(cp_id, timestamp)
);

-- Periodic health snapshots for trending
CREATE TABLE cp_health_history (
    id INTEGER PRIMARY KEY,
    cp_id TEXT NOT NULL,
    state TEXT NOT NULL,
    is_faulty BOOLEAN,
    fault_reason TEXT,
    circuit_breaker_state TEXT,
    timestamp TEXT NOT NULL,
    INDEX(cp_id, timestamp)
);

-- Complete charging session records
CREATE TABLE charging_sessions (
    id INTEGER PRIMARY KEY,
    session_id TEXT UNIQUE NOT NULL,
    cp_id TEXT NOT NULL,
    driver_id TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT,
    total_kwh REAL,
    total_cost REAL,
    status TEXT,  -- 'ACTIVE', 'COMPLETED', 'FAILED'
    INDEX(cp_id, driver_id, session_id)
);
```

### Performance Characteristics

| Metric | Value | Notes |
|--------|-------|-------|
| **Request Latency** | < 100ms | Driver request → ACCEPTED response |
| **Telemetry Rate** | 1 Hz | Real-time power/cost updates |
| **Health Check Interval** | 5s | CP_M → CP_E monitoring frequency |
| **Session Duration** | ~10s | Simulated charging time |
| **Concurrent Sessions** | Unlimited | Limited only by CP count |
| **Fault Detection** | < 15s | 3 failures × 5s interval |
| **Database Writes** | ~2/s per CP | Status + telemetry updates |
| **Kafka Throughput** | 100+ msg/s | Event streaming capacity |

---

## 🎓 Learning Objectives

This project demonstrates proficiency in:

### Software Engineering
- ✅ Microservices architecture design
- ✅ Event-driven system patterns
- ✅ State machine implementation
- ✅ Async/await concurrency
- ✅ Error handling and validation
- ✅ Configuration management
- ✅ Logging and observability

### Distributed Systems
- ✅ Message-oriented middleware (Kafka)
- ✅ Service discovery and registration
- ✅ Fault tolerance and recovery
- ✅ Circuit breaker pattern
- ✅ Health monitoring
- ✅ Data consistency

### DevOps & Infrastructure
- ✅ Docker containerization
- ✅ Docker Compose orchestration
- ✅ Environment configuration
- ✅ Multi-service deployment
- ✅ Log aggregation

### Testing & Quality
- ✅ Unit testing with pytest
- ✅ Message validation
- ✅ State machine testing
- ✅ Mocking and fixtures
- ✅ Test coverage

### Web Development
- ✅ FastAPI REST endpoints
- ✅ Real-time dashboard
- ✅ HTTP API design
- ✅ WebSocket preparation

### Database & Persistence
- ✅ SQL schema design
- ✅ Transaction management
- ✅ Query optimization
- ✅ Data modeling

---

## �📚 API Reference

### Central HTTP Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard HTML |
| `/health` | GET | Health check |
| `/cp` | GET | List all charging points |
| `/cp/{cp_id}` | GET | Get specific CP details |
| `/cp/register` | POST | Register/update CP |
| `/telemetry` | GET | Get all telemetry |

### Example API Calls

```bash
# Health check
curl http://localhost:8000/health

# List all charging points
curl http://localhost:8000/cp | jq

# Get specific CP
curl http://localhost:8000/cp/CP-001 | jq

# Get telemetry
curl http://localhost:8000/telemetry | jq
```

## 🎨 Design Patterns & Best Practices

### Implemented Patterns

#### 1. **State Machine Pattern** ✅
- Explicit state definitions with CPState enum
- Event-driven transitions with guard conditions
- Prevents invalid state transitions
- Clear separation of states and events

#### 2. **Circuit Breaker Pattern** ✅
- Three states: CLOSED, OPEN, HALF_OPEN
- Automatic failure detection and recovery
- Prevents cascade failures
- Configurable thresholds and timeouts

#### 3. **Microservices Architecture** ✅
- Independent, loosely-coupled services
- Event-driven communication via Kafka
- Single responsibility per service
- Horizontal scalability

#### 4. **Producer-Consumer Pattern** ✅
- Kafka topics for asynchronous messaging
- Decoupled request/response flows
- Message persistence and replay

#### 5. **Health Check Pattern** ✅
- Dedicated monitoring service (CP_M)
- HTTP-based health endpoints
- Automatic fault detection
- Recovery notification

#### 6. **Repository Pattern** ✅
- Database abstraction layer
- Centralized data access
- Transaction management
- Query optimization

#### 7. **Framing Protocol** ✅
- TCP message boundaries with STX/ETX
- Error detection with LRC checksum
- Escape sequences for binary safety
- Stateful buffer management

### Code Quality Features

- ✅ **Pydantic v2** - Type-safe message validation with ConfigDict
- ✅ **UTC-aware datetimes** - Consistent timezone handling with `utc_now()`
- ✅ **Async/await** - Non-blocking I/O with asyncio
- ✅ **Graceful shutdown** - Proper cleanup of resources and connections
- ✅ **Error handling** - Payload validation prevents crashes
- ✅ **Structured logging** - Loguru with context binding
- ✅ **Type hints** - Full type annotations for IDE support
- ✅ **Configuration management** - Environment-based with Pydantic BaseSettings
- ✅ **Unit testing** - 22+ tests with pytest
- ✅ **Docker containerization** - Reproducible deployments

### Reliability Features

#### Fault Tolerance
- **Automatic failover** - Faulty CPs excluded from assignment
- **Circuit breaker** - Prevents repeated calls to failing services
- **Health monitoring** - Continuous status checks with CP_M
- **Graceful degradation** - System continues with reduced capacity

#### Data Persistence
- **Fault history** - SQLite database tracks all fault/recovery events
- **Health snapshots** - Periodic state recording for trending
- **Session tracking** - Complete charging session lifecycle
- **Query APIs** - Historical data retrieval and analytics

#### Observability
- **Real-time dashboard** - Live system state visualization
- **Structured logs** - JSON-compatible logging format
- **Health metrics** - Per-service health endpoints
- **Telemetry streams** - Real-time power/cost data

---

## 🔮 Future Enhancements

### Phase 1: Enhanced Monitoring ⚡
- [ ] **Dashboard visual alerts** - Red badges and fault event feeds
- [ ] **Prometheus metrics** - /metrics endpoints for monitoring
- [ ] **Grafana dashboards** - Visual analytics and alerting
- [ ] **Advanced charts** - Power trends with Chart.js/Plotly
- [ ] **WebSocket support** - Real-time dashboard updates without polling

### Phase 2: Advanced Features 🚀
- [ ] **Authentication & Authorization** - JWT-based auth for drivers
- [ ] **Reservation system** - Book charging slots in advance
- [ ] **Payment processing** - Simulate payment flows with Stripe
- [ ] **Dynamic pricing** - Time-based and demand-based rates
- [ ] **Load balancing** - Intelligent CP assignment algorithms
- [ ] **Multi-region support** - Geo-distributed deployments

### Phase 3: Scale & Performance 📈
- [ ] **PostgreSQL migration** - Scale beyond SQLite
- [ ] **Redis caching** - Fast session state lookup
- [ ] **Rate limiting** - Prevent abuse and ensure fairness
- [ ] **Connection pooling** - Optimize database connections
- [ ] **Horizontal scaling** - Multiple Central instances with leader election
- [ ] **CDN integration** - Fast dashboard delivery

### Phase 4: Client Applications 📱
- [ ] **Mobile app** - React Native client for drivers
- [ ] **Admin portal** - React web app for operators
- [ ] **Public API** - RESTful API with OpenAPI docs
- [ ] **SDK libraries** - Python/JavaScript client SDKs
- [ ] **Notification system** - Push notifications for session updates

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Authors

- Your Name - Initial work

## 🙏 Acknowledgments

- Apache Kafka for event streaming
- FastAPI for the web framework
- Pydantic for data validation
- Docker for containerization

## 📞 Support

For issues or questions:
- Open an issue on GitHub
- Check the [QUICK_REFERENCE.md](QUICK_REFERENCE.md) for common operations
- Review test files for usage examples

---

**Happy Charging! ⚡🚗**
