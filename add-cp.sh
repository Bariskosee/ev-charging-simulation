#!/bin/bash
# Script to dynamically add a new Charging Point at runtime
# Usage: ./add-cp.sh <cp_number> [kw_rate] [euro_rate]
#
# Example: ./add-cp.sh 11 150.0 0.40

set -e

if [ -z "$1" ]; then
    echo "❌ Usage: $0 <cp_number> [kw_rate] [euro_rate]"
    echo "   Example: $0 11 150.0 0.40"
    exit 1
fi

CP_NUM=$1
CP_ID=$(printf "CP-%03d" $CP_NUM)
KW_RATE=${2:-22.0}
EURO_RATE=${3:-0.30}
HEALTH_PORT=$((8000 + CP_NUM))

KAFKA_BOOTSTRAP=${KAFKA_BOOTSTRAP:-kafka:9092}
CENTRAL_HOST=${CENTRAL_HOST:-ev-central}
CENTRAL_PORT=${CENTRAL_PORT:-8000}

echo "🔌 Adding New Charging Point"
echo "=============================="
echo "CP ID:        $CP_ID"
echo "CP Number:    $CP_NUM"
echo "Power Rate:   $KW_RATE kW"
echo "Price:        €$EURO_RATE/kWh"
echo "Health Port:  $HEALTH_PORT"
echo "Kafka:        $KAFKA_BOOTSTRAP"
echo ""

# Create docker-compose override file
OVERRIDE_FILE="docker-compose.cp-${CP_NUM}.yml"

cat > "$OVERRIDE_FILE" <<EOF
# Dynamically added CP-${CP_ID}
# Created: $(date)
# Can be stopped with: docker compose -f $OVERRIDE_FILE down

services:
  ev-cp-e-${CP_NUM}:
    build:
      context: .
      dockerfile: docker/Dockerfile.cp_e
    container_name: ev-cp-e-${CP_NUM}
    environment:
      CP_ENGINE_KAFKA_BOOTSTRAP: ${KAFKA_BOOTSTRAP}
      CP_ENGINE_CP_ID: ${CP_ID}
      CP_ENGINE_HEALTH_PORT: ${HEALTH_PORT}
      CP_ENGINE_LOG_LEVEL: INFO
      CP_ENGINE_KW_RATE: ${KW_RATE}
      CP_ENGINE_EURO_RATE: ${EURO_RATE}
      CP_ENGINE_TELEMETRY_INTERVAL: 1.0
    networks:
      - evcharging-network
    restart: unless-stopped

  ev-cp-m-${CP_NUM}:
    build:
      context: .
      dockerfile: docker/Dockerfile.cp_m
    container_name: ev-cp-m-${CP_NUM}
    environment:
      CP_MONITOR_CP_ID: ${CP_ID}
      CP_MONITOR_CP_E_HOST: ev-cp-e-${CP_NUM}
      CP_MONITOR_CP_E_PORT: ${HEALTH_PORT}
      CP_MONITOR_CENTRAL_HOST: ${CENTRAL_HOST}
      CP_MONITOR_CENTRAL_PORT: ${CENTRAL_PORT}
      CP_MONITOR_HEALTH_INTERVAL: 2.0
      CP_MONITOR_LOG_LEVEL: INFO
    depends_on:
      - ev-cp-e-${CP_NUM}
    networks:
      - evcharging-network
    restart: unless-stopped

networks:
  evcharging-network:
    external: true
    name: ev-charging-simulation-3_evcharging-network
EOF

echo "✅ Created override file: $OVERRIDE_FILE"
echo ""

# Start the services
echo "🚀 Starting CP services..."
docker compose -f "$OVERRIDE_FILE" up -d

echo ""
echo "⏳ Waiting for services to start (5 seconds)..."
sleep 5

# Verify
echo ""
echo "📊 Verification:"
if docker ps | grep -q "ev-cp-e-${CP_NUM}"; then
    echo "   ✅ CP Engine (ev-cp-e-${CP_NUM}) is running"
else
    echo "   ❌ CP Engine failed to start"
fi

if docker ps | grep -q "ev-cp-m-${CP_NUM}"; then
    echo "   ✅ CP Monitor (ev-cp-m-${CP_NUM}) is running"
else
    echo "   ❌ CP Monitor failed to start"
fi

echo ""
echo "🔍 Check CP status in Central:"
echo "   curl http://localhost:8000/cp | jq '.charging_points[] | select(.cp_id==\"$CP_ID\")'"
echo ""
echo "📝 View logs:"
echo "   docker logs ev-cp-e-${CP_NUM}"
echo "   docker logs ev-cp-m-${CP_NUM}"
echo ""
echo "🛑 To remove this CP:"
echo "   docker compose -f $OVERRIDE_FILE down"
echo "   rm $OVERRIDE_FILE"
echo ""
echo "✅ CP-${CP_ID} deployment complete!"
