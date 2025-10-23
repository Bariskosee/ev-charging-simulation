#!/bin/bash
# Comprehensive Deployment Script for EV Charging Simulation
# Supports multiple deployment scenarios

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}$1${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
}

# Check prerequisites
check_prerequisites() {
    print_header "Checking Prerequisites"
    
    local missing_tools=0
    
    # Check Docker
    if command -v docker &> /dev/null; then
        print_success "Docker is installed: $(docker --version)"
    else
        print_error "Docker is not installed"
        missing_tools=1
    fi
    
    # Check Docker Compose
    if docker compose version &> /dev/null; then
        print_success "Docker Compose is installed: $(docker compose version)"
    elif command -v docker-compose &> /dev/null; then
        print_success "Docker Compose is installed: $(docker-compose --version)"
    else
        print_error "Docker Compose is not installed"
        missing_tools=1
    fi
    
    # Check Python (for local deployment)
    if command -v python3 &> /dev/null; then
        print_success "Python is installed: $(python3 --version)"
    else
        print_warning "Python 3 is not installed (needed for local deployment)"
    fi
    
    if [ $missing_tools -eq 1 ]; then
        print_error "Missing required tools. Please install them first."
        exit 1
    fi
    
    print_success "All prerequisites met!"
}

# Display deployment options
show_menu() {
    print_header "EV Charging Simulation - Deployment Options"
    echo "1) Full deployment (All components including Kafka)"
    echo "2) Deploy with remote Kafka (Kafka running elsewhere)"
    echo "3) Deploy on lab machines (partial deployment)"
    echo "4) Local Python deployment (no Docker)"
    echo "5) Check system status"
    echo "6) Stop all services"
    echo "7) Clean everything"
    echo "0) Exit"
    echo ""
}

# Full deployment with local Kafka
deploy_full() {
    print_header "Full Deployment - All Components"
    
    print_info "Building Docker images..."
    docker compose build
    
    print_info "Starting all services..."
    docker compose up -d
    
    print_info "Waiting for services to be healthy..."
    sleep 10
    
    print_success "Deployment complete!"
    print_info "Access the dashboard at: http://localhost:8000"
    print_info "View logs with: docker compose logs -f"
}

# Deploy with remote Kafka
deploy_remote_kafka() {
    print_header "Deployment with Remote Kafka"
    
    # Ask for Kafka address
    read -p "Enter Kafka bootstrap server (e.g., kafka.example.com:9092): " kafka_addr
    
    if [ -z "$kafka_addr" ]; then
        print_error "Kafka address is required"
        return 1
    fi
    
    print_info "Using Kafka at: $kafka_addr"
    
    # Create .env file for configuration
    cat > .env << EOF
KAFKA_BOOTSTRAP=$kafka_addr
EOF
    
    print_info "Building Docker images..."
    docker compose -f docker/docker-compose.remote-kafka.yml build
    
    print_info "Starting services (without Kafka)..."
    KAFKA_BOOTSTRAP=$kafka_addr docker compose -f docker/docker-compose.remote-kafka.yml up -d
    
    print_success "Deployment complete!"
    print_info "Access the dashboard at: http://localhost:8000"
    print_warning "Make sure Kafka at $kafka_addr is accessible"
}

# Deploy on lab machines (partial)
deploy_lab() {
    print_header "Lab Machine Deployment"
    
    echo "Select components to deploy on this machine:"
    echo "1) Only Central (requires remote Kafka)"
    echo "2) Only Charging Points (requires remote Kafka and Central)"
    echo "3) Only Driver (requires remote Kafka and Central)"
    echo "4) Central + Charging Points"
    read -p "Enter choice [1-4]: " lab_choice
    
    read -p "Enter Kafka bootstrap server: " kafka_addr
    read -p "Enter Central host (if deploying CPs): " central_host
    
    case $lab_choice in
        1)
            print_info "Deploying Central only..."
            docker compose up -d ev-central
            ;;
        2)
            print_info "Deploying Charging Points only..."
            KAFKA_BOOTSTRAP=$kafka_addr docker compose up -d \
                ev-cp-e-1 ev-cp-e-2 ev-cp-e-3 \
                ev-cp-m-1 ev-cp-m-2 ev-cp-m-3
            ;;
        3)
            print_info "Deploying Driver only..."
            KAFKA_BOOTSTRAP=$kafka_addr docker compose up -d ev-driver ev-driver-2
            ;;
        4)
            print_info "Deploying Central and Charging Points..."
            KAFKA_BOOTSTRAP=$kafka_addr docker compose up -d \
                ev-central \
                ev-cp-e-1 ev-cp-e-2 ev-cp-e-3 \
                ev-cp-m-1 ev-cp-m-2 ev-cp-m-3
            ;;
        *)
            print_error "Invalid choice"
            return 1
            ;;
    esac
    
    print_success "Lab deployment complete!"
}

# Local Python deployment
deploy_local() {
    print_header "Local Python Deployment"
    
    print_warning "This requires Kafka running on localhost:9092"
    read -p "Is Kafka running locally? (y/n): " kafka_ready
    
    if [ "$kafka_ready" != "y" ]; then
        print_info "Starting local Kafka with Docker..."
        docker compose up -d kafka
        print_info "Waiting for Kafka to be ready..."
        sleep 15
    fi
    
    print_info "Installing Python dependencies..."
    pip install -r requirements.txt
    
    print_info "Starting services locally..."
    print_warning "Services will run in background. Check logs in terminal."
    
    # Start Central
    python -m evcharging.apps.ev_central.main &
    CENTRAL_PID=$!
    print_info "Central started (PID: $CENTRAL_PID)"
    sleep 3
    
    # Start CP Engines
    CP_ENGINE_CP_ID=CP-001 CP_ENGINE_HEALTH_PORT=8001 python -m evcharging.apps.ev_cp_e.main &
    print_info "CP Engine 1 started"
    CP_ENGINE_CP_ID=CP-002 CP_ENGINE_HEALTH_PORT=8002 python -m evcharging.apps.ev_cp_e.main &
    print_info "CP Engine 2 started"
    sleep 3
    
    # Start CP Monitors
    CP_MONITOR_CP_ID=CP-001 CP_MONITOR_CP_E_PORT=8001 python -m evcharging.apps.ev_cp_m.main &
    print_info "CP Monitor 1 started"
    CP_MONITOR_CP_ID=CP-002 CP_MONITOR_CP_E_PORT=8002 python -m evcharging.apps.ev_cp_m.main &
    print_info "CP Monitor 2 started"
    sleep 3
    
    print_success "Local deployment complete!"
    print_info "Dashboard: http://localhost:8000"
    print_warning "To stop services, use 'pkill -f evcharging'"
}

# Check system status
check_status() {
    print_header "System Status Check"
    
    print_info "Docker containers:"
    docker compose ps
    
    echo ""
    print_info "Service health:"
    
    # Check Central
    if curl -s http://localhost:8000/health > /dev/null 2>&1; then
        print_success "Central is healthy"
    else
        print_warning "Central is not responding"
    fi
    
    # Check if Kafka is running
    if docker compose ps | grep -q "ev-kafka.*Up"; then
        print_success "Kafka is running"
    elif nc -z localhost 9092 2>/dev/null; then
        print_success "Kafka is accessible on localhost:9092"
    else
        print_warning "Kafka not detected"
    fi
    
    echo ""
    print_info "Recent logs (last 20 lines):"
    docker compose logs --tail=20
}

# Stop all services
stop_services() {
    print_header "Stopping All Services"
    
    # Stop Docker services
    if [ -f "docker-compose.yml" ]; then
        print_info "Stopping Docker services..."
        docker compose down
    fi
    
    # Stop local Python processes
    print_info "Stopping local Python processes..."
    pkill -f "evcharging.apps" 2>/dev/null || true
    
    print_success "All services stopped"
}

# Clean everything
clean_all() {
    print_header "Cleaning Everything"
    
    read -p "This will remove all containers, volumes, and images. Continue? (y/n): " confirm
    
    if [ "$confirm" != "y" ]; then
        print_info "Cancelled"
        return
    fi
    
    print_info "Stopping and removing containers..."
    docker compose down -v
    
    print_info "Removing images..."
    docker compose down --rmi all 2>/dev/null || true
    
    print_info "Cleaning Python cache..."
    find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
    find . -type f -name "*.pyc" -delete 2>/dev/null || true
    
    print_info "Removing .env files..."
    rm -f .env
    
    print_success "Cleanup complete!"
}

# Main script
main() {
    check_prerequisites
    
    while true; do
        show_menu
        read -p "Enter choice [0-7]: " choice
        
        case $choice in
            1) deploy_full ;;
            2) deploy_remote_kafka ;;
            3) deploy_lab ;;
            4) deploy_local ;;
            5) check_status ;;
            6) stop_services ;;
            7) clean_all ;;
            0) 
                print_info "Goodbye!"
                exit 0
                ;;
            *)
                print_error "Invalid choice"
                ;;
        esac
        
        echo ""
        read -p "Press Enter to continue..."
    done
}

# Run main function
main
