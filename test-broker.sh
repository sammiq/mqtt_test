#!/usr/bin/env bash
set -euo pipefail

CONTAINER_NAME="mqtt-test-mosquitto"
PORT=1883
TLS_PORT=8883
CERT_DIR=$(mktemp -d)
chmod 755 "$CERT_DIR"

cleanup() {
    echo "Stopping mosquitto container..."
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
chmod 644 "$CERT_DIR"/*

echo "Starting mosquitto container on ports $PORT (TCP) and $TLS_PORT (TLS)..."
docker run -d --name "$CONTAINER_NAME" \
    -p "$PORT:1883" -p "$TLS_PORT:8883" \
    --security-opt label=disable \
    -v "$CERT_DIR:/certs" \
    eclipse-mosquitto:latest \
    sh -c 'printf "listener 1883\nallow_anonymous true\n\nlistener 8883\nallow_anonymous true\ncafile /certs/ca.crt\ncertfile /certs/server.crt\nkeyfile /certs/server.key\n" > /tmp/mosquitto.conf && mosquitto -c /tmp/mosquitto.conf -v'

# Wait for mosquitto to be ready — use docker exec to verify from inside the container
echo "Waiting for mosquitto to accept connections..."
for i in $(seq 1 30); do
    if docker exec "$CONTAINER_NAME" sh -c 'test -e /proc/1/status' 2>/dev/null; then
        # Container is running, now check if the port is listening
        if nc -z 127.0.0.1 "$PORT" 2>/dev/null; then
            break
        fi
    fi
    sleep 0.5
done

# Verify the container is actually running
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "ERROR: mosquitto container failed to start"
    docker logs "$CONTAINER_NAME" 2>&1 || true
    exit 1
fi

echo "Running MQTT compliance tests (TCP + TLS)..."
echo
cargo run -- \
    --broker "127.0.0.1:$PORT" \
    --tls-broker "127.0.0.1:$TLS_PORT" \
    --ca-cert "$CERT_DIR/ca.crt" \
    "$@"
