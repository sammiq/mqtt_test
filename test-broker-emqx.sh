#!/usr/bin/env bash
set -euo pipefail

CONTAINER_NAME="mqtt-test-emqx"
PORT=1885
TLS_PORT=8885
WS_PORT=8085
CERT_DIR=$(mktemp -d)
chmod 755 "$CERT_DIR"

cleanup() {
    echo "Stopping EMQX Enterprise container..."
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

echo "Starting EMQX Enterprise container on ports $PORT (TCP), $TLS_PORT (TLS), $WS_PORT (WebSocket)..."
docker run -d --name "$CONTAINER_NAME" \
    -p "$PORT:1883" -p "$TLS_PORT:8883" -p "$WS_PORT:8083" \
    --security-opt label=disable \
    -v "$CERT_DIR:/certs:ro" \
    -e EMQX_LISTENERS__SSL__DEFAULT__BIND=8883 \
    -e EMQX_LISTENERS__SSL__DEFAULT__SSL_OPTIONS__CERTFILE=/certs/server.crt \
    -e EMQX_LISTENERS__SSL__DEFAULT__SSL_OPTIONS__KEYFILE=/certs/server.key \
    -e EMQX_LISTENERS__SSL__DEFAULT__SSL_OPTIONS__CACERTFILE=/certs/ca.crt \
    -e EMQX_LISTENERS__WS__DEFAULT__BIND=8083 \
    -e EMQX_AUTHORIZATION__NO_MATCH=allow \
    emqx/emqx-enterprise:latest

# Wait for EMQX to be fully ready
echo "Waiting for EMQX Enterprise to accept connections..."
for i in $(seq 1 60); do
    if docker logs "$CONTAINER_NAME" 2>&1 | grep -q "EMQX .* is running now"; then
        break
    fi
    sleep 1
done

# Verify the container is actually running
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "ERROR: EMQX Enterprise container failed to start"
    docker logs "$CONTAINER_NAME" 2>&1 || true
    exit 1
fi

echo "Running MQTT compliance tests (TCP + TLS + WebSocket) against EMQX Enterprise..."
echo
cargo run -- 127.0.0.1 \
    --tcp-port "$PORT" --tls-port "$TLS_PORT" --ws-port "$WS_PORT" \
    --ca-cert "$CERT_DIR/ca.crt" "$@"
