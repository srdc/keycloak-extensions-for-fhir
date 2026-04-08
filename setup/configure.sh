#!/usr/bin/env bash

# configure.sh - Provision a SMART on FHIR realm on a running Keycloak
set -euo pipefail

KC_CONFIG_IMAGE="${KC_CONFIG_IMAGE:-alvearie/smart-keycloak-config:25.0.5}"
KC_CONFIG_CONTAINER="smart-kc-config-test"
KC_CONTAINER="smart-kc-test"
NETWORK="smart-kc-net"

KC_ADMIN_USER="${KC_ADMIN_USER:-admin}"
KC_ADMIN_PASS="${KC_ADMIN_PASS:-admin}"
KC_PORT="${KC_PORT:-8080}"
KC_REALM="${KC_REALM:-test}"
FHIR_BASE_URL="${FHIR_BASE_URL:-https://localhost:9443/fhir-server/api/v4}"

echo "==> Provisioning realm '${KC_REALM}' ..."

docker run --rm \
  --name "$KC_CONFIG_CONTAINER" \
  --network "$NETWORK" \
  -e KEYCLOAK_BASE_URL="http://${KC_CONTAINER}:8080" \
  -e KEYCLOAK_REALM="$KC_REALM" \
  -e KEYCLOAK_USER="$KC_ADMIN_USER" \
  -e KEYCLOAK_PASSWORD="$KC_ADMIN_PASS" \
  -e FHIR_BASE_URL="$FHIR_BASE_URL" \
  "$KC_CONFIG_IMAGE" \
  -configFile config/keycloak-config.json

echo ""
echo " Realm '${KC_REALM}' is ready."
echo ""
echo " Admin console : http://localhost:${KC_PORT}/admin"
echo "                  user: ${KC_ADMIN_USER} / pass: ${KC_ADMIN_PASS}"
echo ""
echo " OIDC discovery: http://localhost:${KC_PORT}/realms/${KC_REALM}/.well-known/openid-configuration"
echo ""
echo " Test login (paste in browser):"
echo "   http://localhost:${KC_PORT}/realms/${KC_REALM}/protocol/openid-connect/auth?client_id=inferno&response_type=code&scope=openid%20fhirUser%20launch/patient%20patient/*.read&redirect_uri=http://localhost:4567/inferno/callback&aud=${FHIR_BASE_URL}"
echo ""
echo " Login with: fhiruser / change-password (if not changed through keycloak-config configurations)"
