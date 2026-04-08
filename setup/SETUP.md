# Local Setup and Testing Guide

## Prerequisites

- Docker installed and running

## Quick Start

The workflow uses multiple scripts, which can be run individually in an order as specified below.

### 1. Build the images

There are two separate build scripts per each section of the project.

**Build the Keycloak server image** (only needed when the source code changes):

```bash
./setup/build-keycloak.sh
```

Produces **alvearie/smart-keycloak:25.0.5** — Keycloak 25 with the custom SMART authenticators and protocol mappers installed as a provider JAR.

**Build the config tool image** (needed when configuration files or the source code changes):

```bash
./setup/build-config.sh
```

Produces **alvearie/smart-keycloak-config:25.0.5** — a standalone CLI that provisions a Keycloak realm with all SMART on FHIR scopes, mappers, flows, and test users.

The if a configuration change is made only, the original building task for Smart Keycloak can be skipped as this script takes less time than re-building the entire pipeline.

### 2. Start Keycloak

```bash
./setup/start.sh
```

This creates a Docker network (`smart-kc-net`), then starts a Keycloak container in development mode on `http://localhost:8080`. The script is safe to re-run as it removes any leftover containers and networks from a previous session first.

Before moving on with the final script, wait until Keycloak can respond to:

```bash
curl -sf http://localhost:8080/realms/master
```

### 3. Configure the realm

```bash
./setup/configure.sh
```

This runs the config tool on the Smart Keycloak instance and sets up a realm with respect to the Keycloak Config configurations.
On default, the created realm is called `test`, containing:

- All SMART on FHIR client scopes (`launch/patient`, `fhirUser`, `patient/*.read`, individual resource scopes etc.) with the appropriate audience and claim mappers
- The **inferno** public test client
- A **SMART App Launch** browser authentication flow with audience validation and patient selection steps
- A test user: **fhiruser** / **change-password**, with the `relatedPatients` attribute set to `Patient1`
- The User Profile `unmanagedAttributePolicy` set to `ENABLED`, so that custom attributes like `relatedPatients` are visible and editable in the admin console without extra configuration

## Verification

Once `configure.sh` completes, final verification can be conducted through:

### Admin console

Open `http://localhost:8080/admin` and log in with `admin` / `admin`. Navigate to the `test` realm, then check Users > fhiruser > Attributes to confirm the `relatedPatients` attribute is present.

### OIDC discovery endpoint

```bash
curl -s http://localhost:8080/realms/test/.well-known/openid-configuration | python -m json.tool
```

This should return a complete OIDC discovery document for the `test` realm. If it contains the SMART scopes as needed, the setup is most likely successful. However, further verifications are still helpful.

### SMART App Launch flow (browser)

Paste this URL into a browser to start an authorization request as the `inferno` client:

```
http://localhost:8080/realms/test/protocol/openid-connect/auth?client_id=inferno&response_type=code&scope=openid%20fhirUser%20launch/patient%20patient/*.read&redirect_uri=http://localhost:4567/inferno/callback&aud=https://localhost:9443/fhir-server/api/v4
```

Log in with `fhiruser` / `change-password`. If the authentication flow completes (consent screen or redirect), the extensions and configuration are working together correctly.

Note: The redirect will fail if Inferno client isn't set, however, it is not needed as long as the response returns a "code=..." field to provide the auth code that can be used in a request as given below to retrieve the final Access Token:

```bash
curl -s -X POST http://localhost:8080/realms/test/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=<auth_code>" \
  -d "redirect_uri=http://localhost:4567/inferno/callback" \
  -d "client_id=inferno"
```

Replace `<auth_code>` with the value of the `code` parameter from the redirect URL. A successful response will include an `access_token`, `token_type`, and a `patient` field in the token response body confirming the patient context was resolved correctly.

## Customisation

All four scripts accept environment variables to override defaults. Certain deployment values from before are only set as examples.

## Cleanup

To stop the Keycloak container and remove the Docker network:

```bash
docker rm -f smart-kc-test && docker network rm smart-kc-net
```

## Post-Config

After the initial configuration of Keycloak, the base SMART Keycloak image and the test realm can be edited and reused by exporting and re-importing the said components.
Alternatively, Keycloak-Config can be edited by itself to initialize a realm of desired specs from scratch.