.PHONY: help install test up down logs clean deploy verify build status remote-kafka lab-deploy registry-test

help:
	@echo "EV Charging Simulation - Makefile Commands"
	@echo ""
	@echo "Deployment:"
	@echo "  make deploy         - Interactive deployment menu"
	@echo "  make up             - Start all services (full deployment)"
	@echo "  make remote-kafka   - Start services with remote Kafka"
	@echo "  make lab-deploy     - Deploy for lab environment"
	@echo "  make build          - Build Docker images"
	@echo ""
	@echo "EV_Registry (Release 2):"
	@echo "  make registry       - Start only EV_Registry service"
	@echo "  make registry-test  - Run EV_Registry API tests"
	@echo "  make registry-logs  - Show EV_Registry logs"
	@echo ""
	@echo "Management:"
	@echo "  make down           - Stop all services"
	@echo "  make restart        - Restart all services"
	@echo "  make logs           - Show logs from all services"
	@echo "  make status         - Show service status"
	@echo "  make verify         - Run verification checks"
	@echo ""
	@echo "Development:"
	@echo "  make install        - Install Python dependencies"
	@echo "  make test           - Run unit tests"
	@echo "  make local-run      - Run services locally (requires Kafka)"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean          - Clean up containers and volumes"
	@echo "  make clean-all      - Deep clean (including images)"
	@echo ""

install:
	pip install -r requirements.txt

test:
	pytest evcharging/tests/ -v

# EV_Registry commands
registry:
	@echo "Starting EV_Registry service..."
	docker compose up -d ev-registry
	@echo ""
	@echo "EV_Registry started! Access API docs at http://localhost:8080/docs"
	@echo "Run 'make registry-test' to test the API"

registry-test:
	@echo "Running EV_Registry API tests..."
	@./test_registry.sh

registry-logs:
	docker compose logs -f ev-registry

# Deployment commands
deploy:
	@echo "Running interactive deployment..."
	./deploy.sh

build:
	@echo "Building Docker images..."
	docker compose build

up:
	@echo "Starting all services (full deployment)..."
	docker compose up -d
	@echo ""
	@echo "Services started! Access dashboard at http://localhost:8000"
	@echo "EV_Registry API: http://localhost:8080/docs"
	@echo "Run 'make logs' to view logs or 'make verify' to check status"

remote-kafka:
	@echo "Starting services with remote Kafka..."
	@if [ -z "$$KAFKA_BOOTSTRAP" ]; then \
		echo "Error: KAFKA_BOOTSTRAP environment variable not set"; \
		echo "Usage: KAFKA_BOOTSTRAP=kafka.example.com:9092 make remote-kafka"; \
		exit 1; \
	fi
	docker compose -f docker/docker-compose.remote-kafka.yml up -d
	@echo "Services started with Kafka at $$KAFKA_BOOTSTRAP"

lab-deploy:
	@echo "Lab deployment mode"
	@echo "Select components to deploy:"
	@echo "  1) Central only"
	@echo "  2) Charging Points only"  
	@echo "  3) Driver only"
	@echo "  4) Central + Charging Points"
	@read -p "Enter choice [1-4]: " choice; \
	case $$choice in \
		1) docker compose up -d ev-central ;; \
		2) docker compose up -d ev-cp-e-1 ev-cp-e-2 ev-cp-m-1 ev-cp-m-2 ;; \
		3) docker compose up -d ev-driver ;; \
		4) docker compose up -d ev-central ev-cp-e-1 ev-cp-e-2 ev-cp-m-1 ev-cp-m-2 ;; \
		*) echo "Invalid choice" ;; \
	esac

down:
	@echo "Stopping all services..."
	docker compose down

restart:
	@echo "Restarting all services..."
	docker compose restart

logs:
	docker compose logs -f

status:
	@echo "=== Docker Services Status ==="
	docker compose ps
	@echo ""
	@echo "=== Quick Health Check ==="
	@curl -s http://localhost:8000/health 2>/dev/null | grep -q healthy && \
		echo "✓ Central is healthy" || echo "✗ Central is not responding"

verify:
	@echo "Running verification checks..."
	./verify.sh

clean:
	@echo "Cleaning up containers and volumes..."
	docker compose down -v
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

clean-all: clean
	@echo "Deep clean: removing images..."
	docker compose down --rmi all 2>/dev/null || true
	@echo "Cleanup complete!"

# Local development (assumes Kafka running on localhost:9092)
local-run:
	@echo "Starting services locally..."
	@echo "Make sure Kafka is running on localhost:9092"
	@echo ""
	python -m evcharging.apps.ev_central.main &
	sleep 2
	python -m evcharging.apps.ev_cp_e.main --cp-id CP-001 --health-port 8001 &
	python -m evcharging.apps.ev_cp_e.main --cp-id CP-002 --health-port 8002 &
	sleep 2
	python -m evcharging.apps.ev_cp_m.main --cp-id CP-001 --cp-e-port 8001 &
	python -m evcharging.apps.ev_cp_m.main --cp-id CP-002 --cp-e-port 8002 &
	sleep 2
	python -m evcharging.apps.ev_driver.main --driver-id driver-alice --requests-file requests.txt
