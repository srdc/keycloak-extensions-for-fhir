#!/usr/bin/env bash

# build-keycloak.sh - Build the Keycloak server image
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
KC_IMAGE="alvearie/smart-keycloak:25.0.5"

echo "==> Building Keycloak image: $KC_IMAGE"
docker build -t "$KC_IMAGE" -f "$PROJECT_DIR/Dockerfile" "$PROJECT_DIR"

echo ""
echo "Done. Image ready: $KC_IMAGE"
