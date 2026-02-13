# Verification Steps: OpenFGA OIDC Authentication Integration for SIOPV

**Date:** 2026-02-11
**Author:** verifier (OpenFGA Execution Plan Team)
**Project:** SIOPV (`~/siopv/`)
**Purpose:** Copy-paste-ready test commands, expected outputs, rollback procedures, and failure scenarios for each implementation phase.

---

## Table of Contents

1. [Pre-Implementation Baseline](#1-pre-implementation-baseline)
2. [Phase 1 Verification: Configuration Foundation](#2-phase-1-verification-configuration-foundation)
3. [Phase 2 Verification: Adapter Authentication Support](#3-phase-2-verification-adapter-authentication-support)
4. [Phase 3 Verification: Infrastructure Setup](#4-phase-3-verification-infrastructure-setup)
5. [Phase 4 Verification: OIDC Migration](#5-phase-4-verification-oidc-migration)
6. [Phase 5 Verification: Production Hardening](#6-phase-5-verification-production-hardening)
7. [Cross-Phase Regression Checks](#7-cross-phase-regression-checks)
8. [Rollback Procedures](#8-rollback-procedures)
9. [Failure Scenarios and Troubleshooting](#9-failure-scenarios-and-troubleshooting)

---

## 1. Pre-Implementation Baseline

**Purpose:** Capture current state before ANY changes. Run these ONCE before starting Phase 1.

### 1.1 Snapshot Current Test Suite

```bash
cd ~/siopv

# Run full test suite and save baseline
pytest tests/ -v --tb=short 2>&1 | tee /tmp/siopv-baseline-tests.txt

# Count passing tests
pytest tests/ -q 2>&1 | tail -1
```

**Expected output:** All existing 87+ tests pass. Save the exact count as your baseline.

```
# Expected pattern:
87 passed in X.XXs
```

### 1.2 Verify Current Settings Fields

```bash
cd ~/siopv

# Confirm only 2 OpenFGA fields exist currently
python3 -c "
from siopv.infrastructure.config.settings import Settings
import os
os.environ['SIOPV_ANTHROPIC_API_KEY'] = 'test'
s = Settings()
openfga_fields = [f for f in s.model_fields if 'openfga' in f]
print(f'OpenFGA fields: {len(openfga_fields)}')
for f in openfga_fields:
    print(f'  - {f}: {getattr(s, f)}')
"
```

**Expected output:**
```
OpenFGA fields: 2
  - openfga_api_url: None
  - openfga_store_id: None
```

### 1.3 Verify Current Adapter Init Signature

```bash
cd ~/siopv

# Check adapter only reads 2 settings
grep -n "self\._api_url\|self\._store_id\|self\._auth_method\|self\._api_token\|self\._client_id" \
  src/siopv/adapters/authorization/openfga_adapter.py | head -20
```

**Expected output:** Only `self._api_url` and `self._store_id` should appear in `__init__`.

### 1.4 Verify .env.example Current State

```bash
cd ~/siopv

# Count OpenFGA-related lines
grep -c "OPENFGA" .env.example
```

**Expected output:** Should show lines already present (currently has auth method, api_token, OIDC vars — the .env.example was already partially updated). Current count: approximately 11 lines.

### 1.5 Git Clean State

```bash
cd ~/siopv

git status --short
git stash list
```

**Expected output:** Clean working directory or known stashed changes. Record this state.

---

## 2. Phase 1 Verification: Configuration Foundation

**Goal verified:** Application can be configured for authenticated OpenFGA connections via environment variables.

### 2.1 Verify New Settings Fields Exist

```bash
cd ~/siopv

python3 -c "
from siopv.infrastructure.config.settings import Settings
import os
os.environ['SIOPV_ANTHROPIC_API_KEY'] = 'test'
s = Settings()
openfga_fields = [f for f in s.model_fields if 'openfga' in f]
print(f'OpenFGA fields: {len(openfga_fields)}')
for f in sorted(openfga_fields):
    val = getattr(s, f)
    print(f'  - {f}: {repr(val)}')
"
```

**Expected output (9 fields):**
```
OpenFGA fields: 9
  - openfga_api_audience: None
  - openfga_api_token: None
  - openfga_api_token_issuer: None
  - openfga_api_url: None
  - openfga_auth_method: 'none'
  - openfga_authorization_model_id: None
  - openfga_client_id: None
  - openfga_client_secret: None
  - openfga_store_id: None
```

**Failure indicators:**
- `KeyError` or `AttributeError` → Field not added to Settings class
- Fewer than 9 fields → Some fields missing
- `openfga_auth_method` not defaulting to `'none'` → Default value wrong

### 2.2 Verify SecretStr Types

```bash
cd ~/siopv

python3 -c "
from siopv.infrastructure.config.settings import Settings
import os
os.environ['SIOPV_ANTHROPIC_API_KEY'] = 'test'
os.environ['SIOPV_OPENFGA_API_TOKEN'] = 'secret-token-123'
os.environ['SIOPV_OPENFGA_CLIENT_SECRET'] = 'secret-client-456'
s = Settings()
# Verify SecretStr behavior - should NOT print secrets
print(f'api_token type: {type(s.openfga_api_token).__name__}')
print(f'api_token repr: {repr(s.openfga_api_token)}')
print(f'api_token secret: {s.openfga_api_token.get_secret_value()}')
print(f'client_secret type: {type(s.openfga_client_secret).__name__}')
print(f'client_secret repr: {repr(s.openfga_client_secret)}')
print(f'client_secret secret: {s.openfga_client_secret.get_secret_value()}')
"
```

**Expected output:**
```
api_token type: SecretStr
api_token repr: SecretStr('**********')
api_token secret: secret-token-123
client_secret type: SecretStr
client_secret repr: SecretStr('**********')
client_secret secret: secret-client-456
```

**Failure indicators:**
- Type is `str` instead of `SecretStr` → Field type wrong
- `repr()` shows actual secret → SecretStr not used properly

### 2.3 Verify Literal Type for auth_method

```bash
cd ~/siopv

python3 -c "
from siopv.infrastructure.config.settings import Settings
import os
os.environ['SIOPV_ANTHROPIC_API_KEY'] = 'test'
# Test valid values
for method in ['none', 'api_token', 'client_credentials']:
    os.environ['SIOPV_OPENFGA_AUTH_METHOD'] = method
    s = Settings()
    print(f'{method}: OK ({s.openfga_auth_method})')

# Test invalid value
os.environ['SIOPV_OPENFGA_AUTH_METHOD'] = 'invalid_method'
try:
    s = Settings()
    print(f'FAIL: accepted invalid value: {s.openfga_auth_method}')
except Exception as e:
    print(f'Correctly rejected invalid value: {type(e).__name__}')
"
```

**Expected output:**
```
none: OK (none)
api_token: OK (api_token)
client_credentials: OK (client_credentials)
Correctly rejected invalid value: ValidationError
```

**Failure indicators:**
- `invalid_method` accepted → Not using `Literal` type
- Valid values rejected → Literal enum wrong

### 2.4 Verify Backward Compatibility

```bash
cd ~/siopv

# All new fields must have defaults — Settings should work with only ANTHROPIC_API_KEY
python3 -c "
from siopv.infrastructure.config.settings import Settings
import os
# Clear all OpenFGA env vars
for key in list(os.environ.keys()):
    if 'OPENFGA' in key:
        del os.environ[key]
os.environ['SIOPV_ANTHROPIC_API_KEY'] = 'test'
s = Settings()
print(f'auth_method: {s.openfga_auth_method}')
print(f'api_url: {s.openfga_api_url}')
print(f'store_id: {s.openfga_store_id}')
print(f'api_token: {s.openfga_api_token}')
print('Backward compatibility: OK')
"
```

**Expected output:**
```
auth_method: none
api_url: None
store_id: None
api_token: None
Backward compatibility: OK
```

### 2.5 Verify .env.example Contains All Variables

```bash
cd ~/siopv

# Check all required env vars exist in .env.example
for var in SIOPV_OPENFGA_API_URL SIOPV_OPENFGA_STORE_ID SIOPV_OPENFGA_AUTH_METHOD \
           SIOPV_OPENFGA_API_TOKEN SIOPV_OPENFGA_AUTHORIZATION_MODEL_ID \
           SIOPV_OPENFGA_CLIENT_ID SIOPV_OPENFGA_CLIENT_SECRET \
           SIOPV_OPENFGA_API_AUDIENCE SIOPV_OPENFGA_API_TOKEN_ISSUER; do
    if grep -q "$var" .env.example; then
        echo "OK: $var found"
    else
        echo "MISSING: $var not in .env.example"
    fi
done
```

**Expected output:** All 9 variables show `OK`.

### 2.6 Run Settings Unit Tests

```bash
cd ~/siopv

# Run settings tests specifically
pytest tests/unit/infrastructure/test_settings.py -v --tb=short 2>&1

# If test file doesn't exist yet, run the general test suite
# to check nothing breaks:
pytest tests/ -v --tb=short -x 2>&1 | tail -20
```

**Expected output:** All tests pass, including new tests for:
- `test_settings_openfga_auth_defaults`
- `test_settings_openfga_api_token_from_env`
- `test_settings_openfga_oidc_from_env`

### 2.7 Phase 1 Lint Check

```bash
cd ~/siopv

# Type check the settings file
mypy src/siopv/infrastructure/config/settings.py --ignore-missing-imports

# Lint check
ruff check src/siopv/infrastructure/config/settings.py
```

**Expected output:** No errors from mypy or ruff.

---

## 3. Phase 2 Verification: Adapter Authentication Support

**Goal verified:** Adapter creates `ClientConfiguration` with credentials when configured.

### 3.1 Verify Adapter Reads New Settings

```bash
cd ~/siopv

python3 -c "
from unittest.mock import MagicMock
from siopv.adapters.authorization import OpenFGAAdapter

settings = MagicMock()
settings.openfga_api_url = 'http://localhost:8080'
settings.openfga_store_id = 'test-store'
settings.openfga_api_token = None
settings.openfga_authorization_model_id = None
settings.openfga_auth_method = 'none'
settings.openfga_client_id = None
settings.openfga_client_secret = None
settings.openfga_api_audience = None
settings.openfga_api_token_issuer = None
settings.circuit_breaker_failure_threshold = 5
settings.circuit_breaker_recovery_timeout = 60

adapter = OpenFGAAdapter(settings)
print(f'auth_method: {adapter._auth_method}')
print(f'api_token: {adapter._api_token}')
print(f'client_id: {adapter._client_id}')
print(f'authorization_model_id: {adapter._authorization_model_id}')
print('Adapter init: OK')
"
```

**Expected output:**
```
auth_method: none
api_token: None
client_id: None
authorization_model_id: None
Adapter init: OK
```

**Failure indicators:**
- `AttributeError: 'OpenFGAAdapter' object has no attribute '_auth_method'` → `__init__` not updated
- `AttributeError` on mock settings → Adapter trying to read a field not set in mock

### 3.2 Verify API Token Credential Path

```bash
cd ~/siopv

python3 -c "
from unittest.mock import MagicMock, patch, AsyncMock
from siopv.adapters.authorization import OpenFGAAdapter

settings = MagicMock()
settings.openfga_api_url = 'http://localhost:8080'
settings.openfga_store_id = 'test-store'
settings.openfga_auth_method = 'api_token'
settings.openfga_api_token = MagicMock()
settings.openfga_api_token.get_secret_value.return_value = 'my-secret-token'
settings.openfga_authorization_model_id = None
settings.openfga_client_id = None
settings.openfga_client_secret = None
settings.openfga_api_audience = None
settings.openfga_api_token_issuer = None
settings.circuit_breaker_failure_threshold = 5
settings.circuit_breaker_recovery_timeout = 60

adapter = OpenFGAAdapter(settings)
print(f'auth_method: {adapter._auth_method}')
assert adapter._auth_method == 'api_token'
assert adapter._api_token.get_secret_value() == 'my-secret-token'
print('API token credential path: OK')
"
```

**Expected output:**
```
auth_method: api_token
API token credential path: OK
```

### 3.3 Verify Client Credentials Path

```bash
cd ~/siopv

python3 -c "
from unittest.mock import MagicMock
from siopv.adapters.authorization import OpenFGAAdapter

settings = MagicMock()
settings.openfga_api_url = 'http://localhost:8080'
settings.openfga_store_id = 'test-store'
settings.openfga_auth_method = 'client_credentials'
settings.openfga_api_token = None
settings.openfga_authorization_model_id = None
settings.openfga_client_id = 'siopv-client'
settings.openfga_client_secret = MagicMock()
settings.openfga_client_secret.get_secret_value.return_value = 'client-secret-123'
settings.openfga_api_audience = 'openfga-api'
settings.openfga_api_token_issuer = 'https://keycloak.example.com/realms/siopv'
settings.circuit_breaker_failure_threshold = 5
settings.circuit_breaker_recovery_timeout = 60

adapter = OpenFGAAdapter(settings)
assert adapter._auth_method == 'client_credentials'
assert adapter._client_id == 'siopv-client'
assert adapter._client_secret.get_secret_value() == 'client-secret-123'
assert adapter._api_audience == 'openfga-api'
assert adapter._api_token_issuer == 'https://keycloak.example.com/realms/siopv'
print('Client credentials path: OK')
"
```

**Expected output:**
```
Client credentials path: OK
```

### 3.4 Verify Credentials Import

```bash
cd ~/siopv

# Verify the import exists in the adapter
grep -n "from openfga_sdk.credentials import" src/siopv/adapters/authorization/openfga_adapter.py
```

**Expected output:**
```
XX:from openfga_sdk.credentials import Credentials, CredentialConfiguration
```

**Failure indicator:** No output → Import missing.

### 3.5 Verify Credentials Import is Valid

```bash
cd ~/siopv

python3 -c "
from openfga_sdk.credentials import Credentials, CredentialConfiguration
print(f'Credentials: {Credentials}')
print(f'CredentialConfiguration: {CredentialConfiguration}')
print('Import: OK')
"
```

**Expected output:**
```
Credentials: <class 'openfga_sdk.credentials.Credentials'>
CredentialConfiguration: <class 'openfga_sdk.credentials.CredentialConfiguration'>
Import: OK
```

**Failure indicator:** `ImportError` → openfga-sdk version too old or import path changed. Check `pip show openfga-sdk`.

### 3.6 Verify DI Container Logging

```bash
cd ~/siopv

grep -A5 "creating_authorization_adapter" src/siopv/infrastructure/di/authorization.py
```

**Expected output should include:**
```python
logger.debug(
    "creating_authorization_adapter",
    api_url=settings.openfga_api_url,
    store_id=settings.openfga_store_id,
    auth_method=settings.openfga_auth_method,
    model_id=settings.openfga_authorization_model_id,
)
```

### 3.7 Run Adapter Unit Tests

```bash
cd ~/siopv

pytest tests/unit/adapters/authorization/test_openfga_adapter.py -v --tb=short 2>&1
```

**Expected output:** All existing tests pass + new auth tests pass:
- `test_initialize_with_api_token`
- `test_initialize_with_client_credentials`
- `test_initialize_with_model_id`
- `test_initialize_no_auth_backward_compatible`

### 3.8 Verify Mock Fixtures Updated

```bash
cd ~/siopv

# The mock_settings fixture must include ALL new fields
grep -A20 "def mock_settings" tests/unit/adapters/authorization/test_openfga_adapter.py
```

**Expected output must include:**
```python
settings.openfga_api_token = None
settings.openfga_authorization_model_id = None
settings.openfga_auth_method = "none"
settings.openfga_client_id = None
settings.openfga_client_secret = None
settings.openfga_api_audience = None
settings.openfga_api_token_issuer = None
```

**Failure indicator:** If missing, existing tests will fail with `AttributeError` on strict mocks.

### 3.9 Phase 2 Lint and Type Check

```bash
cd ~/siopv

mypy src/siopv/adapters/authorization/openfga_adapter.py --ignore-missing-imports
ruff check src/siopv/adapters/authorization/openfga_adapter.py
mypy src/siopv/infrastructure/di/authorization.py --ignore-missing-imports
ruff check src/siopv/infrastructure/di/authorization.py
```

**Expected output:** No errors.

### 3.10 Full Regression After Phase 1+2

```bash
cd ~/siopv

# Run ENTIRE test suite to confirm no regressions
pytest tests/ -v --tb=short 2>&1 | tail -20

# Compare with baseline
echo "--- Baseline was: ---"
tail -1 /tmp/siopv-baseline-tests.txt
```

**Expected output:** Same or more tests passing than baseline. Zero failures.

---

## 4. Phase 3 Verification: Infrastructure Setup

**Goal verified:** Developers can `docker compose up` and run integration tests against a real server.

### 4.1 Verify Docker Compose File Syntax

```bash
cd ~/siopv

# Validate compose file
docker compose config --quiet 2>&1
echo "Exit code: $?"
```

**Expected output:**
```
Exit code: 0
```

**Failure indicator:** Non-zero exit → YAML syntax error or invalid compose schema.

### 4.2 Verify Docker Compose Services

```bash
cd ~/siopv

docker compose config --services 2>&1 | sort
```

**Expected output (minimum):**
```
openfga
openfga-migrate
openfga-postgres
```

### 4.3 Start Infrastructure

```bash
cd ~/siopv

# Start all services
docker compose up -d 2>&1

# Wait for healthy state
echo "Waiting for services..."
sleep 30

# Check service health
docker compose ps 2>&1
```

**Expected output:** All services showing `Up` or `healthy`:
```
NAME              STATUS
openfga-postgres  Up (healthy)
openfga-migrate   Exited (0)
openfga           Up (healthy)
```

**Failure indicators:**
- `openfga-postgres` not healthy → PostgreSQL didn't start
- `openfga-migrate` exit code != 0 → Migration failed
- `openfga` not healthy → Server didn't start or can't reach database

### 4.4 Verify OpenFGA Health Endpoint

```bash
# Health check
curl -sf http://localhost:8080/healthz && echo " OK" || echo " FAILED"
```

**Expected output:**
```
{"status":"SERVING"} OK
```

### 4.5 Verify OpenFGA Authentication

```bash
# Without token (should fail with 401 if auth enabled)
curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/stores
echo ""

# With correct token
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer dev-key-siopv-local-1" \
  http://localhost:8080/stores
echo ""
```

**Expected output:**
```
401
200
```

**Failure indicators:**
- First request returns `200` → Authentication not enabled on server
- Second request returns `401` → Token doesn't match `OPENFGA_AUTHN_PRESHARED_KEYS`

### 4.6 Verify Authorization Model File Exists

```bash
cd ~/siopv

# Check model file exists and has correct types
ls -la openfga/model.fga

# Verify all 5 types are defined
for type in user organization project vulnerability report; do
    if grep -q "type $type" openfga/model.fga; then
        echo "OK: type $type found"
    else
        echo "MISSING: type $type"
    fi
done
```

**Expected output:**
```
OK: type user found
OK: type organization found
OK: type project found
OK: type vulnerability found
OK: type report found
```

### 4.7 Run Bootstrap Script

```bash
cd ~/siopv

chmod +x scripts/setup-openfga.sh
./scripts/setup-openfga.sh 2>&1
```

**Expected output (pattern):**
```
=== SIOPV OpenFGA Setup ===
API URL: http://localhost:8080
Waiting for OpenFGA...
OpenFGA is ready.
Creating store...
Store ID: <26-char-alphanumeric-id>
Writing authorization model...
Model ID: <26-char-alphanumeric-id>

=== Add to your .env file ===
SIOPV_OPENFGA_API_URL=http://localhost:8080
SIOPV_OPENFGA_STORE_ID=<store-id>
SIOPV_OPENFGA_API_TOKEN=dev-key-siopv-local-1
SIOPV_OPENFGA_AUTHORIZATION_MODEL_ID=<model-id>
SIOPV_OPENFGA_AUTH_METHOD=api_token

=== Setup complete ===
```

**Failure indicators:**
- `ERROR: OpenFGA not ready after 30s` → Server not running
- `curl` errors → Authentication or URL issues
- Empty Store ID / Model ID → API call failed silently

### 4.8 Verify Store and Model via API

```bash
# Replace <STORE_ID> with output from setup script
STORE_ID="<PASTE_STORE_ID_HERE>"
TOKEN="dev-key-siopv-local-1"

# List stores
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/stores | python3 -m json.tool

# Get authorization models
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/stores/$STORE_ID/authorization-models" | python3 -m json.tool
```

**Expected output:** JSON with store data and at least one authorization model containing the 5 types.

### 4.9 End-to-End Tuple Write/Check Test

```bash
STORE_ID="<PASTE_STORE_ID_HERE>"
MODEL_ID="<PASTE_MODEL_ID_HERE>"
TOKEN="dev-key-siopv-local-1"
BASE="http://localhost:8080"

# 1. Write a tuple: user:alice is viewer of project:test-project
curl -s -X POST "$BASE/stores/$STORE_ID/write" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"writes\": {
      \"tuple_keys\": [{
        \"user\": \"user:alice\",
        \"relation\": \"viewer\",
        \"object\": \"project:test-project\"
      }]
    },
    \"authorization_model_id\": \"$MODEL_ID\"
  }" | python3 -m json.tool

# 2. Check: user:alice viewer project:test-project (should be allowed)
curl -s -X POST "$BASE/stores/$STORE_ID/check" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"tuple_key\": {
      \"user\": \"user:alice\",
      \"relation\": \"viewer\",
      \"object\": \"project:test-project\"
    },
    \"authorization_model_id\": \"$MODEL_ID\"
  }" | python3 -m json.tool

# 3. Check: user:bob viewer project:test-project (should be denied)
curl -s -X POST "$BASE/stores/$STORE_ID/check" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"tuple_key\": {
      \"user\": \"user:bob\",
      \"relation\": \"viewer\",
      \"object\": \"project:test-project\"
    },
    \"authorization_model_id\": \"$MODEL_ID\"
  }" | python3 -m json.tool
```

**Expected output:**
```json
// Write: empty response = success
{}

// Check alice (should be allowed):
{"allowed": true, "resolution": "..."}

// Check bob (should be denied):
{"allowed": false}
```

### 4.10 Run Integration Tests (Real Server)

```bash
cd ~/siopv

# Set env vars from bootstrap output
export SIOPV_OPENFGA_API_URL=http://localhost:8080
export SIOPV_OPENFGA_STORE_ID=<PASTE_STORE_ID>
export SIOPV_OPENFGA_API_TOKEN=dev-key-siopv-local-1
export SIOPV_OPENFGA_AUTH_METHOD=api_token
export SIOPV_OPENFGA_AUTHORIZATION_MODEL_ID=<PASTE_MODEL_ID>

# Run integration tests
pytest tests/integration/test_openfga_real_server.py -v --tb=short 2>&1
```

**Expected output:**
```
tests/integration/test_openfga_real_server.py::TestRealOpenFGAConnection::test_health_check PASSED
tests/integration/test_openfga_real_server.py::TestRealOpenFGAConnection::test_get_model_id PASSED
```

### 4.11 Verify Playground Access

```bash
# Playground should be accessible at port 3000
curl -s -o /dev/null -w "%{http_code}" http://localhost:3000
echo ""
```

**Expected output:** `200`

### 4.12 Clean Up Infrastructure

```bash
cd ~/siopv

# Stop and remove containers + volumes
docker compose down -v 2>&1
```

**Expected output:** All containers and volumes removed.

---

## 5. Phase 4 Verification: OIDC Migration

**Goal verified:** SIOPV can authenticate to OpenFGA via an OIDC provider.

### 5.1 Verify Keycloak Starts

```bash
cd ~/siopv

# Start full stack including Keycloak
docker compose up -d 2>&1

# Wait for Keycloak (takes longer)
echo "Waiting for Keycloak..."
for i in $(seq 1 60); do
    if curl -sf http://localhost:8180/realms/master > /dev/null 2>&1; then
        echo "Keycloak ready after ${i}s"
        break
    fi
    if [ "$i" -eq 60 ]; then
        echo "ERROR: Keycloak not ready after 60s"
    fi
    sleep 1
done
```

**Expected output:** `Keycloak ready after XXs`

### 5.2 Run Keycloak Bootstrap Script

```bash
cd ~/siopv

chmod +x scripts/setup-keycloak.sh
./scripts/setup-keycloak.sh 2>&1
```

**Expected output (pattern):**
```
=== Keycloak Configuration Complete ===
Client ID:     siopv-openfga-client
Client Secret: <generated-uuid>
Issuer URL:    http://localhost:8180/realms/siopv
Audience:      openfga-api
```

### 5.3 Verify OIDC Token Exchange

```bash
# Use values from Keycloak bootstrap output
CLIENT_ID="siopv-openfga-client"
CLIENT_SECRET="<PASTE_SECRET>"
ISSUER="http://localhost:8180/realms/siopv"

# Request token via client_credentials flow
TOKEN_RESPONSE=$(curl -s -X POST "$ISSUER/protocol/openid-connect/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET")

echo "$TOKEN_RESPONSE" | python3 -m json.tool

# Extract access_token
ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])")
echo "Token length: ${#ACCESS_TOKEN}"
```

**Expected output:** JSON with `access_token`, `token_type: "Bearer"`, `expires_in`. Token length > 100 characters.

**Failure indicators:**
- `invalid_client` → Client secret wrong or client not created
- `invalid_grant` → Client not configured for client_credentials

### 5.4 Verify JWT Contains Correct Audience

```bash
# Decode JWT payload (base64, no verification)
ACCESS_TOKEN="<PASTE_TOKEN>"
echo "$ACCESS_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

**Expected output includes:**
```json
{
  "iss": "http://localhost:8180/realms/siopv",
  "aud": ["openfga-api"],
  ...
}
```

**Failure indicator:** `aud` doesn't contain `openfga-api` → Audience mapper not configured in Keycloak.

### 5.5 Verify OpenFGA Accepts OIDC Token

```bash
# OpenFGA must be configured with OIDC auth
# Use the JWT from step 5.3

curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  http://localhost:8080/stores
echo ""
```

**Expected output:** `200`

**Failure indicators:**
- `401` → OpenFGA can't validate JWT (check issuer URL, audience match)
- `403` → Token valid but insufficient permissions

### 5.6 Verify SIOPV Adapter with OIDC

```bash
cd ~/siopv

# Set OIDC env vars
export SIOPV_OPENFGA_API_URL=http://localhost:8080
export SIOPV_OPENFGA_STORE_ID=<PASTE_STORE_ID>
export SIOPV_OPENFGA_AUTH_METHOD=client_credentials
export SIOPV_OPENFGA_CLIENT_ID=siopv-openfga-client
export SIOPV_OPENFGA_CLIENT_SECRET=<PASTE_SECRET>
export SIOPV_OPENFGA_API_AUDIENCE=openfga-api
export SIOPV_OPENFGA_API_TOKEN_ISSUER=http://localhost:8180/realms/siopv

# Run integration tests with OIDC
pytest tests/integration/test_openfga_real_server.py -v --tb=long 2>&1
```

**Expected output:** All integration tests pass using OIDC authentication.

### 5.7 Verify Token Refresh Behavior

```bash
cd ~/siopv

python3 -c "
import asyncio
from unittest.mock import MagicMock
from pydantic import SecretStr
from siopv.adapters.authorization import OpenFGAAdapter

settings = MagicMock()
settings.openfga_api_url = 'http://localhost:8080'
settings.openfga_store_id = '<PASTE_STORE_ID>'
settings.openfga_auth_method = 'client_credentials'
settings.openfga_api_token = None
settings.openfga_authorization_model_id = '<PASTE_MODEL_ID>'
settings.openfga_client_id = 'siopv-openfga-client'
settings.openfga_client_secret = SecretStr('<PASTE_SECRET>')
settings.openfga_api_audience = 'openfga-api'
settings.openfga_api_token_issuer = 'http://localhost:8180/realms/siopv'
settings.circuit_breaker_failure_threshold = 5
settings.circuit_breaker_recovery_timeout = 60

async def test():
    adapter = OpenFGAAdapter(settings)
    await adapter.initialize()
    # Make two calls - SDK should handle token automatically
    result1 = await adapter.health_check()
    print(f'Health check 1: {result1}')
    result2 = await adapter.health_check()
    print(f'Health check 2: {result2}')
    await adapter.close()
    print('Token refresh: SDK handled automatically')

asyncio.run(test())
"
```

**Expected output:**
```
Health check 1: True
Health check 2: True
Token refresh: SDK handled automatically
```

---

## 6. Phase 5 Verification: Production Hardening

**Goal verified:** Production-ready OpenFGA deployment configuration.

### 6.1 Verify Environment Validator

```bash
cd ~/siopv

# Test: api_token method without token (should warn)
python3 -c "
import warnings
import os
os.environ['SIOPV_ANTHROPIC_API_KEY'] = 'test'
os.environ['SIOPV_OPENFGA_AUTH_METHOD'] = 'api_token'
# Intentionally NOT setting SIOPV_OPENFGA_API_TOKEN
for key in ['SIOPV_OPENFGA_API_TOKEN']:
    os.environ.pop(key, None)
with warnings.catch_warnings(record=True) as w:
    warnings.simplefilter('always')
    from siopv.infrastructure.config.settings import Settings
    s = Settings()
    if w:
        print(f'Warning raised: {w[0].message}')
    else:
        print('No warning raised (might need to check validator)')
"
```

**Expected output:**
```
Warning raised: SIOPV_OPENFGA_AUTH_METHOD=api_token but SIOPV_OPENFGA_API_TOKEN is not set
```

### 6.2 Verify Client Credentials Validator

```bash
cd ~/siopv

python3 -c "
import warnings
import os
os.environ['SIOPV_ANTHROPIC_API_KEY'] = 'test'
os.environ['SIOPV_OPENFGA_AUTH_METHOD'] = 'client_credentials'
# Intentionally missing client_id, client_secret, issuer
for key in ['SIOPV_OPENFGA_CLIENT_ID', 'SIOPV_OPENFGA_CLIENT_SECRET', 'SIOPV_OPENFGA_API_TOKEN_ISSUER']:
    os.environ.pop(key, None)
with warnings.catch_warnings(record=True) as w:
    warnings.simplefilter('always')
    from importlib import reload
    import siopv.infrastructure.config.settings as mod
    reload(mod)
    s = mod.Settings()
    if w:
        for warning in w:
            print(f'Warning: {warning.message}')
    else:
        print('No warning raised')
"
```

**Expected output should include:**
```
Warning: SIOPV_OPENFGA_AUTH_METHOD=client_credentials but missing: SIOPV_OPENFGA_CLIENT_ID, SIOPV_OPENFGA_CLIENT_SECRET, SIOPV_OPENFGA_API_TOKEN_ISSUER
```

### 6.3 Verify No Secrets in Logs

```bash
cd ~/siopv

# Grep for potential secret leaks in logging calls
grep -rn "get_secret_value" src/siopv/ --include="*.py" | grep -v "test" | grep -v "__pycache__"
```

**Expected output:** Only in `openfga_adapter.py` within the `initialize` method (where it's passed to SDK config). Should NOT appear in any `logger.*` call.

```bash
# Verify structlog calls don't include secrets
grep -rn "logger\.\(info\|debug\|warning\|error\)" src/siopv/adapters/authorization/openfga_adapter.py | grep -i "token\|secret\|password\|key"
```

**Expected output:** No lines should show actual secret values being logged.

---

## 7. Cross-Phase Regression Checks

Run these after EACH phase to ensure no regressions.

### 7.1 Full Unit Test Suite

```bash
cd ~/siopv

pytest tests/ -v --tb=short -x 2>&1
```

**Expected output:** All tests pass. Test count >= baseline count.

### 7.2 Type Checking

```bash
cd ~/siopv

mypy src/siopv/infrastructure/config/settings.py \
     src/siopv/adapters/authorization/openfga_adapter.py \
     src/siopv/infrastructure/di/authorization.py \
     --ignore-missing-imports
```

**Expected output:** No errors.

### 7.3 Linting

```bash
cd ~/siopv

ruff check src/siopv/infrastructure/config/settings.py \
           src/siopv/adapters/authorization/openfga_adapter.py \
           src/siopv/infrastructure/di/authorization.py
```

**Expected output:** No errors.

### 7.4 Import Verification

```bash
cd ~/siopv

python3 -c "
from siopv.infrastructure.config.settings import Settings
from siopv.adapters.authorization import OpenFGAAdapter
from siopv.infrastructure.di.authorization import create_authorization_adapter
print('All imports: OK')
"
```

**Expected output:** `All imports: OK`

---

## 8. Rollback Procedures

### 8.1 Phase 1+2 Rollback (Git Revert)

```bash
cd ~/siopv

# If Phase 1+2 was committed as a single commit:
git log --oneline -5  # Find the commit hash
git revert <commit-hash>

# If multiple commits:
git log --oneline -10  # Find the range
git revert <oldest-hash>..<newest-hash>

# Verify rollback
python3 -c "
from siopv.infrastructure.config.settings import Settings
import os
os.environ['SIOPV_ANTHROPIC_API_KEY'] = 'test'
s = Settings()
openfga_fields = [f for f in s.model_fields if 'openfga' in f]
print(f'OpenFGA fields: {len(openfga_fields)}')
# Should be back to 2
"

# Run tests to confirm
pytest tests/ -v --tb=short -x
```

### 8.2 Phase 3 Rollback (Infrastructure)

```bash
cd ~/siopv

# Stop all containers
docker compose down -v

# Remove infrastructure files
rm -f docker-compose.yml
rm -rf openfga/
rm -f scripts/setup-openfga.sh
rm -f tests/integration/test_openfga_real_server.py

# Verify app still works without infrastructure
pytest tests/ -v --tb=short -x
```

### 8.3 Phase 4 Rollback (OIDC → Pre-Shared Key)

```bash
cd ~/siopv

# 1. Change app configuration
# In .env:
# SIOPV_OPENFGA_AUTH_METHOD=api_token
# SIOPV_OPENFGA_API_TOKEN=dev-key-siopv-local-1

# 2. Change OpenFGA server (in docker-compose.yml):
# OPENFGA_AUTHN_METHOD=preshared
# OPENFGA_AUTHN_PRESHARED_KEYS=dev-key-siopv-local-1
# (remove OPENFGA_AUTHN_OIDC_* vars)

# 3. Restart services
docker compose down
docker compose up -d

# 4. Verify pre-shared key works
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer dev-key-siopv-local-1" \
  http://localhost:8080/stores
echo ""
# Expected: 200
```

### 8.4 Emergency: Disable All Authentication

```bash
cd ~/siopv

# 1. App: set auth method to none
# In .env:
# SIOPV_OPENFGA_AUTH_METHOD=none

# 2. Server: disable authentication
# In docker-compose.yml, remove or change:
# OPENFGA_AUTHN_METHOD=none
# (remove all OPENFGA_AUTHN_* vars)

# 3. Restart
docker compose down
docker compose up -d

# 4. Verify unauthenticated access works
curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/stores
echo ""
# Expected: 200 (no auth needed)
```

---

## 9. Failure Scenarios and Troubleshooting

### 9.1 Settings Import Error

**Symptom:** `ImportError` or `ValidationError` when importing Settings

**Diagnosis:**
```bash
cd ~/siopv
python3 -c "
try:
    from siopv.infrastructure.config.settings import Settings
    print('Import OK')
except Exception as e:
    print(f'Error: {type(e).__name__}: {e}')
"
```

**Common causes:**
| Error | Cause | Fix |
|-------|-------|-----|
| `ImportError: cannot import name 'Literal'` | Wrong Python version | Requires Python >= 3.8 (already in project) |
| `ValidationError` on `openfga_auth_method` | Env var has invalid value | Check `.env` for typos in `SIOPV_OPENFGA_AUTH_METHOD` |
| `ImportError: SecretStr` | Pydantic not installed | `pip install pydantic` |

### 9.2 Adapter AttributeError

**Symptom:** `AttributeError: 'OpenFGAAdapter' object has no attribute '_auth_method'`

**Diagnosis:**
```bash
cd ~/siopv
grep "_auth_method\|_api_token\|_client_id" src/siopv/adapters/authorization/openfga_adapter.py
```

**Fix:** Ensure `__init__` assigns all new fields from settings.

### 9.3 Mock Settings Incomplete

**Symptom:** `AttributeError: Mock object has no attribute 'openfga_auth_method'` in tests

**Diagnosis:**
```bash
cd ~/siopv
grep -B2 -A15 "def mock_settings" tests/unit/adapters/authorization/test_openfga_adapter.py
```

**Fix:** Add ALL new settings fields to mock_settings fixture.

### 9.4 OpenFGA SDK Import Error

**Symptom:** `ImportError: cannot import name 'Credentials' from 'openfga_sdk.credentials'`

**Diagnosis:**
```bash
pip show openfga-sdk
python3 -c "import openfga_sdk; print(openfga_sdk.__version__)"
python3 -c "from openfga_sdk import credentials; print(dir(credentials))"
```

**Fix:** Ensure `openfga-sdk >= 0.6.0`. If import path changed, check [SDK changelog](https://github.com/openfga/python-sdk/releases).

### 9.5 Docker Compose Won't Start

**Symptom:** Services crash or fail to start

**Diagnosis:**
```bash
docker compose ps -a
docker compose logs openfga 2>&1 | tail -30
docker compose logs openfga-postgres 2>&1 | tail -20
docker compose logs openfga-migrate 2>&1 | tail -20
```

**Common causes:**
| Symptom | Cause | Fix |
|---------|-------|-----|
| postgres unhealthy | Port 5432 in use | `lsof -i :5432` then stop conflicting service |
| migrate fails | DB not ready | Check `depends_on` has `condition: service_healthy` |
| openfga crashes | Bad env vars | Check `OPENFGA_DATASTORE_URI` format |
| Port conflict | 8080 in use | `lsof -i :8080` or change compose port mapping |

### 9.6 Bootstrap Script Fails

**Symptom:** setup-openfga.sh returns empty Store ID or Model ID

**Diagnosis:**
```bash
# Check if OpenFGA is reachable
curl -v http://localhost:8080/healthz

# Try manual store creation with verbose output
curl -v -X POST http://localhost:8080/stores \
  -H "Authorization: Bearer dev-key-siopv-local-1" \
  -H "Content-Type: application/json" \
  -d '{"name": "test"}'
```

**Common causes:**
| Symptom | Cause | Fix |
|---------|-------|-----|
| Connection refused | Server not running | `docker compose up -d` |
| 401 Unauthorized | Wrong token | Check `OPENFGA_AUTHN_PRESHARED_KEYS` in compose |
| Empty response | JSON parsing error | Check `python3` and `jq` availability |

### 9.7 OIDC Token Exchange Fails

**Symptom:** Keycloak returns `invalid_client` or empty token

**Diagnosis:**
```bash
# Check Keycloak is running
curl -s http://localhost:8180/realms/master

# Check realm exists
curl -s http://localhost:8180/realms/siopv

# Check client exists (admin login first)
TOKEN=$(curl -s -X POST "http://localhost:8180/realms/master/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=admin-cli&username=admin&password=admin" | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

curl -s "http://localhost:8180/admin/realms/siopv/clients?clientId=siopv-openfga-client" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

### 9.8 OpenFGA Rejects OIDC Token

**Symptom:** OpenFGA returns 401 when using JWT from Keycloak

**Diagnosis:**
```bash
# Check OpenFGA OIDC config
docker compose logs openfga 2>&1 | grep -i "oidc\|issuer\|audience"

# Decode token and check claims
echo "$ACCESS_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool

# Check issuer matches
# Token's "iss" MUST match OPENFGA_AUTHN_OIDC_ISSUER exactly
# Token's "aud" MUST contain OPENFGA_AUTHN_OIDC_AUDIENCE
```

**Common causes:**
| Symptom | Cause | Fix |
|---------|-------|-----|
| `iss` mismatch | Internal vs external URL | Use same URL format in both configs |
| `aud` missing | Audience mapper not added | Add audience mapper to Keycloak client |
| JWKS fetch fail | Network issue | Ensure OpenFGA can reach Keycloak (Docker network) |

---

## Quick Reference: Phase-by-Phase Checklist

### Phase 1 Checklist
- [ ] 9 OpenFGA fields in Settings class
- [ ] `SecretStr` for `openfga_api_token` and `openfga_client_secret`
- [ ] `Literal["none", "api_token", "client_credentials"]` for `openfga_auth_method`
- [ ] All new fields default to `None` or `"none"`
- [ ] `.env.example` has all 9 variables
- [ ] Settings tests pass
- [ ] mypy + ruff clean
- [ ] Full test suite passes (no regressions)

### Phase 2 Checklist
- [ ] Adapter `__init__` reads 7 new settings fields
- [ ] `from openfga_sdk.credentials import Credentials, CredentialConfiguration` added
- [ ] `initialize()` creates `Credentials` for `api_token` method
- [ ] `initialize()` creates `Credentials` for `client_credentials` method
- [ ] `initialize()` uses `authorization_model_id` when set
- [ ] DI logging includes `auth_method` and `model_id`
- [ ] Mock fixtures updated with all new fields
- [ ] New auth test cases pass
- [ ] All 87+ existing tests still pass
- [ ] mypy + ruff clean

### Phase 3 Checklist
- [ ] `docker-compose.yml` validates (`docker compose config`)
- [ ] 3+ services defined (openfga, postgres, migrate)
- [ ] `docker compose up -d` brings all services healthy
- [ ] `/healthz` returns `SERVING`
- [ ] Pre-shared key auth works (401 without, 200 with token)
- [ ] `openfga/model.fga` has 5 types
- [ ] `scripts/setup-openfga.sh` outputs store_id and model_id
- [ ] Tuple write + check works via curl
- [ ] Integration tests pass with real server
- [ ] Playground accessible at `:3000`

### Phase 4 Checklist
- [ ] Keycloak starts and responds
- [ ] Realm `siopv` created
- [ ] Client `siopv-openfga-client` created with service account
- [ ] Audience mapper adds `openfga-api` to JWT
- [ ] Token exchange succeeds (client_credentials flow)
- [ ] JWT contains correct `iss` and `aud` claims
- [ ] OpenFGA accepts OIDC token (200 response)
- [ ] SIOPV adapter connects via OIDC
- [ ] Integration tests pass with OIDC auth
- [ ] SDK handles token refresh automatically

### Phase 5 Checklist
- [ ] Environment validator warns on misconfigured api_token
- [ ] Environment validator warns on misconfigured client_credentials
- [ ] No secrets logged (grep audit passes)
- [ ] All tests pass
- [ ] mypy + ruff clean across all changed files
