#!/usr/bin/env bash
set -euo pipefail

CONTAINER_NAME="mqtt-test-hivemq"
PORT=1884
TLS_PORT=8884
WS_PORT=8084
CERT_DIR=$(mktemp -d)
chmod 755 "$CERT_DIR"

cleanup() {
    echo "Stopping HiveMQ CE container..."
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    rm -rf "$CERT_DIR"
}
trap cleanup EXIT

# Remove any leftover container from a previous run
docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

# Generate CA and server certificates for TLS testing
echo "Generating TLS certificates..."
openssl req -x509 -newkey rsa:2048 -keyout "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.crt" \
    -days 1 -nodes -subj "/CN=MQTT Test CA" 2>/dev/null
openssl req -newkey rsa:2048 -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.csr" \
    -nodes -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
openssl x509 -req -in "$CERT_DIR/server.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial -out "$CERT_DIR/server.crt" -days 1 \
    -copy_extensions copyall 2>/dev/null

# Convert to PKCS12 keystore for HiveMQ (Java-based broker)
openssl pkcs12 -export -in "$CERT_DIR/server.crt" -inkey "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.p12" -name mqtt-server -password pass:changeit 2>/dev/null
chmod 644 "$CERT_DIR"/*

# Create HiveMQ config with TCP, TLS, and WebSocket listeners
cat > "$CERT_DIR/config.xml" <<'XMLEOF'
<?xml version="1.0"?>
<hivemq>
    <listeners>
        <tcp-listener>
            <port>1883</port>
            <bind-address>0.0.0.0</bind-address>
        </tcp-listener>
        <tls-tcp-listener>
            <port>8883</port>
            <bind-address>0.0.0.0</bind-address>
            <tls>
                <keystore>
                    <path>/certs/server.p12</path>
                    <password>changeit</password>
                    <private-key-password>changeit</private-key-password>
                </keystore>
            </tls>
        </tls-tcp-listener>
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

echo "Starting HiveMQ CE container on ports $PORT (TCP), $TLS_PORT (TLS), $WS_PORT (WebSocket)..."
docker run -d --name "$CONTAINER_NAME" \
    -p "$PORT:1883" -p "$TLS_PORT:8883" -p "$WS_PORT:8083" \
    --security-opt label=disable \
    -v "$CERT_DIR:/certs:ro" \
    -v "$CERT_DIR/config.xml:/opt/hivemq/conf/config.xml:ro" \
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

echo "Running MQTT compliance tests (TCP + TLS + WebSocket) against HiveMQ CE..."
echo
cargo run -- 127.0.0.1 \
    --tcp-port "$PORT" --tls-port "$TLS_PORT" --ws-port "$WS_PORT" \
    --ca-cert "$CERT_DIR/ca.crt" "$@"
