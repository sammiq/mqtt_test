#!/usr/bin/env bash
set -euo pipefail

CONTAINER_NAME="mqtt-test-hivemq"
PORT=1884
WS_PORT=8084
CONFIG_DIR=$(mktemp -d)
chmod 755 "$CONFIG_DIR"

cleanup() {
    echo "Stopping HiveMQ CE container..."
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    rm -rf "$CONFIG_DIR"
}
trap cleanup EXIT

# Remove any leftover container from a previous run
docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

# Create HiveMQ config with WebSocket listener
cat > "$CONFIG_DIR/config.xml" <<'XMLEOF'
<?xml version="1.0"?>
<hivemq>
    <listeners>
        <tcp-listener>
            <port>1883</port>
            <bind-address>0.0.0.0</bind-address>
        </tcp-listener>
        <websocket-listener>
            <port>8083</port>
            <bind-address>0.0.0.0</bind-address>
            <path>/mqtt</path>
            <subprotocols>
                <subprotocol>mqtt</subprotocol>
            </subprotocols>
            <allow-extensions>true</allow-extensions>
        </websocket-listener>
    </listeners>
</hivemq>
XMLEOF

echo "Starting HiveMQ CE container on ports $PORT (TCP), $WS_PORT (WebSocket)..."
docker run -d --name "$CONTAINER_NAME" \
    -p "$PORT:1883" -p "$WS_PORT:8083" \
    -v "$CONFIG_DIR/config.xml:/opt/hivemq/conf/config.xml:ro" \
    hivemq/hivemq-ce:latest

# Wait for HiveMQ to be fully ready (not just the port being open —
# HiveMQ binds early during JVM startup before it can handle MQTT packets)
echo "Waiting for HiveMQ CE to accept connections..."
for i in $(seq 1 60); do
    if docker logs "$CONTAINER_NAME" 2>&1 | grep -q "Started HiveMQ"; then
        break
    fi
    sleep 1
done

# Verify the container is actually running
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "ERROR: HiveMQ CE container failed to start"
    docker logs "$CONTAINER_NAME" 2>&1 || true
    exit 1
fi

echo "Running MQTT compliance tests (TCP + WebSocket) against HiveMQ CE..."
echo
cargo run -- 127.0.0.1 \
    --tcp-port "$PORT" --no-tls --ws-port "$WS_PORT" "$@"
