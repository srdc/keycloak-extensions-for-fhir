#!/usr/bin/env bash

# build-config.sh - Build the realm configuration tool image
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
KC_CONFIG_IMAGE="alvearie/smart-keycloak-config:25.0.5"

echo "==> Building config tool image: $KC_CONFIG_IMAGE"
docker build -t "$KC_CONFIG_IMAGE" -f "$PROJECT_DIR/keycloak-config/Dockerfile" "$PROJECT_DIR"

echo ""
echo "Done. Image ready: $KC_CONFIG_IMAGE"
