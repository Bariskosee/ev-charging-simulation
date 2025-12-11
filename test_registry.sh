#!/bin/bash

# EV_Registry API Test Script
# Tests all endpoints with comprehensive scenarios

set -e

REGISTRY_URL="${REGISTRY_URL:-http://localhost:8080}"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=================================================="
echo "EV_Registry API Test Suite"
echo "=================================================="
echo "Testing against: $REGISTRY_URL"
echo ""

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

# Helper function to run test
run_test() {
    local test_name="$1"
    local command="$2"
    local expected_status="$3"
    
    echo -n "Testing: $test_name... "
    
    response=$(eval "$command" 2>&1)
    status=$?
    
    if echo "$response" | grep -q "\"$expected_status\"" || [ "$expected_status" == "ANY" ]; then
        echo -e "${GREEN}✓ PASSED${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}✗ FAILED${NC}"
        echo "Response: $response"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# Test 1: Health check
echo -e "${YELLOW}=== Health Check ===${NC}"
run_test "GET / (health)" \
    "curl -s $REGISTRY_URL/" \
    "operational"

# Test 2: Register first CP
echo -e "\n${YELLOW}=== CP Registration ===${NC}"
REGISTER_RESPONSE=$(curl -s -X POST "$REGISTRY_URL/cp/register" \
    -H "Content-Type: application/json" \
    -d '{
        "cp_id": "CP-TEST-001",
        "location": "Berlin",
        "metadata": {"power_rating": "22kW", "type": "AC"}
    }')

echo "$REGISTER_RESPONSE" | jq .
CP_CREDENTIALS=$(echo "$REGISTER_RESPONSE" | jq -r '.credentials // empty')

if [ -n "$CP_CREDENTIALS" ]; then
    echo -e "${GREEN}✓ CP-TEST-001 registered successfully${NC}"
    echo "Credentials: $CP_CREDENTIALS"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}✗ Failed to register CP-TEST-001${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Test 3: Register second CP
REGISTER_RESPONSE_2=$(curl -s -X POST "$REGISTRY_URL/cp/register" \
    -H "Content-Type: application/json" \
    -d '{
        "cp_id": "CP-TEST-002",
        "location": "Munich"
    }')

CP_CREDENTIALS_2=$(echo "$REGISTER_RESPONSE_2" | jq -r '.credentials // empty')

if [ -n "$CP_CREDENTIALS_2" ]; then
    echo -e "${GREEN}✓ CP-TEST-002 registered successfully${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}✗ Failed to register CP-TEST-002${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Test 4: Re-register same CP (should update)
echo -e "\n${YELLOW}=== Re-registration Test ===${NC}"
run_test "Re-register CP-TEST-001" \
    "curl -s -X POST $REGISTRY_URL/cp/register -H 'Content-Type: application/json' -d '{\"cp_id\": \"CP-TEST-001\", \"location\": \"Berlin Updated\"}'" \
    "REGISTERED"

# Test 5: Authenticate with valid credentials
echo -e "\n${YELLOW}=== Authentication Tests ===${NC}"
if [ -n "$CP_CREDENTIALS" ]; then
    AUTH_RESPONSE=$(curl -s -X POST "$REGISTRY_URL/cp/authenticate" \
        -H "Content-Type: application/json" \
        -d "{
            \"cp_id\": \"CP-TEST-001\",
            \"credentials\": \"$CP_CREDENTIALS\"
        }")
    
    if echo "$AUTH_RESPONSE" | grep -q "Authentication successful"; then
        echo -e "${GREEN}✓ Authentication successful for CP-TEST-001${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        JWT_TOKEN=$(echo "$AUTH_RESPONSE" | jq -r '.token')
        echo "JWT Token: ${JWT_TOKEN:0:50}..."
    else
        echo -e "${RED}✗ Authentication failed${NC}"
        echo "$AUTH_RESPONSE" | jq .
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
fi

# Test 6: Authenticate with invalid credentials
run_test "Auth with invalid credentials" \
    "curl -s -X POST $REGISTRY_URL/cp/authenticate -H 'Content-Type: application/json' -d '{\"cp_id\": \"CP-TEST-001\", \"credentials\": \"invalid\"}'" \
    "Invalid credentials"

# Test 7: Get CP information
echo -e "\n${YELLOW}=== Query Tests ===${NC}"
run_test "GET /cp/CP-TEST-001" \
    "curl -s $REGISTRY_URL/cp/CP-TEST-001" \
    "CP-TEST-001"

# Test 8: Get non-existent CP
run_test "GET /cp/CP-NONEXISTENT" \
    "curl -s $REGISTRY_URL/cp/CP-NONEXISTENT" \
    "not found"

# Test 9: List all CPs
echo -e "\n${YELLOW}=== List Tests ===${NC}"
LIST_RESPONSE=$(curl -s "$REGISTRY_URL/cp")
CP_COUNT=$(echo "$LIST_RESPONSE" | jq '.total')

if [ "$CP_COUNT" -ge 2 ]; then
    echo -e "${GREEN}✓ List CPs returned $CP_COUNT CPs${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}✗ Expected at least 2 CPs, got $CP_COUNT${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Test 10: List with filters
run_test "List with status filter" \
    "curl -s '$REGISTRY_URL/cp?status_filter=REGISTERED'" \
    "REGISTERED"

# Test 11: List with pagination
run_test "List with limit=1" \
    "curl -s '$REGISTRY_URL/cp?limit=1'" \
    "\"limit\":1"

# Test 12: Deregister CP
echo -e "\n${YELLOW}=== Deregistration Tests ===${NC}"
run_test "DELETE /cp/CP-TEST-002" \
    "curl -s -X DELETE $REGISTRY_URL/cp/CP-TEST-002" \
    "DEREGISTERED"

# Test 13: Try to authenticate deregistered CP
if [ -n "$CP_CREDENTIALS_2" ]; then
    run_test "Auth deregistered CP" \
        "curl -s -X POST $REGISTRY_URL/cp/authenticate -H 'Content-Type: application/json' -d '{\"cp_id\": \"CP-TEST-002\", \"credentials\": \"$CP_CREDENTIALS_2\"}'" \
        "deregistered"
fi

# Test 14: Verify deregistered status
run_test "GET deregistered CP" \
    "curl -s $REGISTRY_URL/cp/CP-TEST-002" \
    "DEREGISTERED"

# Test 15: Input validation tests
echo -e "\n${YELLOW}=== Validation Tests ===${NC}"
run_test "Invalid CP ID (too short)" \
    "curl -s -X POST $REGISTRY_URL/cp/register -H 'Content-Type: application/json' -d '{\"cp_id\": \"CP\", \"location\": \"Test\"}'" \
    "Invalid"

run_test "Invalid location (too short)" \
    "curl -s -X POST $REGISTRY_URL/cp/register -H 'Content-Type: application/json' -d '{\"cp_id\": \"CP-TEST-999\", \"location\": \"X\"}'" \
    "Invalid"

# Test 16: Cleanup - deregister test CP
echo -e "\n${YELLOW}=== Cleanup ===${NC}"
curl -s -X DELETE "$REGISTRY_URL/cp/CP-TEST-001" > /dev/null
echo "Cleaned up test data"

# Summary
echo ""
echo "=================================================="
echo "Test Summary"
echo "=================================================="
echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
echo "Total Tests: $((TESTS_PASSED + TESTS_FAILED))"
echo "=================================================="

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed! ✓${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed ✗${NC}"
    exit 1
fi
