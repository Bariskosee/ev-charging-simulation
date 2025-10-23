#!/bin/bash
# Verification script for EV Charging Simulation deployment

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}$1${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

ERRORS=0
WARNINGS=0

# Check Docker services
check_docker_services() {
    print_header "Checking Docker Services"
    
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed"
        ((ERRORS++))
        return
    fi
    
    # Get list of expected services
    local services=(
        "kafka"
        "ev-central"
        "ev-cp-e-1"
        "ev-cp-e-2"
        "ev-cp-e-3"
        "ev-cp-m-1"
        "ev-cp-m-2"
        "ev-cp-m-3"
        "ev-driver"
        "ev-driver-2"
    )
    
    for service in "${services[@]}"; do
        if docker compose ps | grep -q "$service.*Up"; then
            print_success "$service is running"
        else
            print_warning "$service is not running"
            ((WARNINGS++))
        fi
    done
}

# Check network connectivity
check_network() {
    print_header "Checking Network Connectivity"
    
    # Check Kafka
    if nc -z localhost 9092 2>/dev/null; then
        print_success "Kafka is accessible on localhost:9092"
    else
        print_error "Kafka is not accessible on localhost:9092"
        ((ERRORS++))
    fi
    
    # Check Central HTTP
    if curl -s http://localhost:8000/health > /dev/null 2>&1; then
        print_success "Central HTTP is accessible on localhost:8000"
    else
        print_error "Central HTTP is not accessible on localhost:8000"
        ((ERRORS++))
    fi
    
    # Check Central TCP
    if nc -z localhost 9999 2>/dev/null; then
        print_success "Central TCP is accessible on localhost:9999"
    else
        print_warning "Central TCP port 9999 may not be exposed"
        ((WARNINGS++))
    fi
}

# Check Kafka topics
check_kafka_topics() {
    print_header "Checking Kafka Topics"
    
    if ! docker compose ps | grep -q "kafka.*Up"; then
        print_warning "Kafka container not running, skipping topic check"
        ((WARNINGS++))
        return
    fi
    
    local expected_topics=("central.commands" "cp.status" "cp.telemetry" "driver.requests" "driver.updates")
    
    # Get topics list
    local topics=$(docker compose exec -T kafka kafka-topics.sh --bootstrap-server localhost:9092 --list 2>/dev/null || echo "")
    
    if [ -z "$topics" ]; then
        print_warning "Could not retrieve Kafka topics"
        ((WARNINGS++))
        return
    fi
    
    for topic in "${expected_topics[@]}"; do
        if echo "$topics" | grep -q "^${topic}$"; then
            print_success "Topic '$topic' exists"
        else
            print_warning "Topic '$topic' does not exist (will be created automatically)"
            ((WARNINGS++))
        fi
    done
}

# Check service health
check_service_health() {
    print_header "Checking Service Health"
    
    # Check Central health endpoint
    local central_health=$(curl -s http://localhost:8000/health 2>/dev/null || echo "")
    if echo "$central_health" | grep -q "healthy"; then
        print_success "Central service is healthy"
    else
        print_error "Central service is not healthy"
        ((ERRORS++))
    fi
    
    # Check if charging points are registered
    local cp_status=$(curl -s http://localhost:8000/api/charging-points 2>/dev/null || echo "")
    if [ -n "$cp_status" ]; then
        local cp_count=$(echo "$cp_status" | grep -o '"cp_id"' | wc -l)
        if [ "$cp_count" -gt 0 ]; then
            print_success "Found $cp_count charging point(s) registered"
        else
            print_warning "No charging points registered yet"
            ((WARNINGS++))
        fi
    fi
}

# Check logs for errors
check_logs() {
    print_header "Checking Logs for Errors"
    
    local services=("ev-central" "ev-cp-e-1" "ev-cp-e-2" "ev-cp-e-3")
    
    for service in "${services[@]}"; do
        if docker compose ps | grep -q "$service.*Up"; then
            local error_count=$(docker compose logs --tail=50 "$service" 2>/dev/null | grep -i "error\|exception\|failed" | wc -l)
            if [ "$error_count" -eq 0 ]; then
                print_success "$service: No errors in recent logs"
            else
                print_warning "$service: Found $error_count error/exception lines in recent logs"
                ((WARNINGS++))
            fi
        fi
    done
}

# Check Python environment (for local deployment)
check_python_env() {
    print_header "Checking Python Environment (Optional)"
    
    if ! command -v python3 &> /dev/null; then
        print_info "Python 3 not installed (not required for Docker deployment)"
        return
    fi
    
    print_success "Python: $(python3 --version)"
    
    if [ -f "requirements.txt" ]; then
        print_success "requirements.txt found"
        
        # Check if key packages are installed
        local packages=("aiokafka" "fastapi" "pydantic")
        for pkg in "${packages[@]}"; do
            if python3 -c "import $pkg" 2>/dev/null; then
                print_success "Package '$pkg' is installed"
            else
                print_info "Package '$pkg' not installed (only needed for local deployment)"
            fi
        done
    fi
}

# Test charging session (optional)
test_charging_session() {
    print_header "Testing Charging Session (Optional)"
    
    print_info "This test will restart the driver to trigger a charging session"
    read -p "Do you want to run this test? (y/n): " run_test
    
    if [ "$run_test" != "y" ]; then
        print_info "Skipping charging session test"
        return
    fi
    
    print_info "Restarting driver..."
    docker compose restart ev-driver > /dev/null 2>&1
    
    print_info "Waiting for session to start (10 seconds)..."
    sleep 10
    
    # Check driver logs
    local driver_logs=$(docker compose logs --tail=20 ev-driver 2>/dev/null)
    if echo "$driver_logs" | grep -q "CHARGING\|session"; then
        print_success "Charging session appears to be working"
    else
        print_warning "Could not confirm charging session (check logs manually)"
        ((WARNINGS++))
    fi
}

# Summary
print_summary() {
    print_header "Verification Summary"
    
    if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
        echo -e "${GREEN}✓ All checks passed! System is healthy.${NC}"
        echo ""
        echo -e "Access the dashboard at: ${BLUE}http://localhost:8000${NC}"
        echo ""
        return 0
    elif [ $ERRORS -eq 0 ]; then
        echo -e "${YELLOW}⚠ System is running but there are $WARNINGS warning(s).${NC}"
        echo ""
        echo "This is usually normal during startup. Wait a few minutes and run again."
        echo ""
        return 0
    else
        echo -e "${RED}✗ Found $ERRORS error(s) and $WARNINGS warning(s).${NC}"
        echo ""
        echo "Common solutions:"
        echo "1. Ensure Docker is running: docker info"
        echo "2. Start services: docker compose up -d"
        echo "3. Check logs: docker compose logs -f"
        echo "4. Restart services: docker compose restart"
        echo ""
        return 1
    fi
}

# Main execution
main() {
    echo ""
    echo -e "${BLUE}╔═══════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║   EV Charging Simulation - Verification   ║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════╝${NC}"
    
    check_docker_services
    check_network
    check_kafka_topics
    check_service_health
    check_logs
    check_python_env
    
    # Optional test
    if [ $ERRORS -eq 0 ]; then
        test_charging_session
    fi
    
    print_summary
    exit $?
}

main
