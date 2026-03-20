#!/usr/bin/env bash
set -euo pipefail

CONTAINER_NAME="mqtt-test-mosquitto"
PORT=1883

cleanup() {
    echo "Stopping mosquitto container..."
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Remove any leftover container from a previous run
docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

echo "Starting mosquitto container on port $PORT..."
docker run -d --name "$CONTAINER_NAME" -p "$PORT:1883" \
    eclipse-mosquitto:latest \
    sh -c 'printf "listener 1883\nallow_anonymous true\n" > /tmp/mosquitto.conf && mosquitto -c /tmp/mosquitto.conf -v'

# Wait for mosquitto to be ready
echo "Waiting for mosquitto to accept connections..."
for i in $(seq 1 10); do
    if nc -z 127.0.0.1 "$PORT" 2>/dev/null; then
        break
    fi
    sleep 0.5
done

echo "Running MQTT compliance tests..."
echo
cargo run -- --broker "127.0.0.1:$PORT" "$@"
