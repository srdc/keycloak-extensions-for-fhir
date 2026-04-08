#!/usr/bin/env bash

# start.sh - Start a Keycloak container from the alvearie/smart-keycloak image
set -euo pipefail

KC_IMAGE="${KC_IMAGE:-alvearie/smart-keycloak:25.0.5}"
KC_CONTAINER="smart-kc-test"
NETWORK="smart-kc-net"

KC_ADMIN_USER="${KC_ADMIN_USER:-admin}"
KC_ADMIN_PASS="${KC_ADMIN_PASS:-admin}"
KC_PORT="${KC_PORT:-8080}"

# Clean
echo "==> Removing previous container and network if exists..."
docker rm -f "$KC_CONTAINER" 2>/dev/null || true
docker network rm "$NETWORK" 2>/dev/null || true

# Network
echo "==> Creating Docker network: $NETWORK"
docker network create "$NETWORK"

# Keycloak
echo "==> Starting Keycloak container: $KC_CONTAINER"
docker run -d \
  --name "$KC_CONTAINER" \
  --network "$NETWORK" \
  -p "${KC_PORT}:8080" \
  -e KC_HEALTH_ENABLED=true \
  -e KEYCLOAK_ADMIN="$KC_ADMIN_USER" \
  -e KEYCLOAK_ADMIN_PASSWORD="$KC_ADMIN_PASS" \
  "$KC_IMAGE"

echo ""
echo "Keycloak is booting up on http://localhost:${KC_PORT}"
echo "Wait until it is ready, then run ./configure.sh to provision the realm."
