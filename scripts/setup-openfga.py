#!/usr/bin/env python3
"""
OpenFGA Bootstrap Script for SIOPV

Initializes OpenFGA with store creation and authorization model upload.
Outputs configuration variables for .env file.
"""

import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

# Configuration
OPENFGA_BASE_URL = "http://localhost:8080"
OPENFGA_API_TOKEN = "dev-key-siopv-local-1"
HEALTH_CHECK_TIMEOUT = 30
HEALTH_CHECK_INTERVAL = 2
MODEL_FILE_PATH = Path(__file__).parent.parent / "openfga" / "model.json"
HTTP_OK = 200


def make_request(
    url: str,
    method: str = "GET",
    data: dict[str, Any] | None = None,
    token: str | None = None,
) -> dict[str, Any]:
    """Make HTTP request to OpenFGA API.

    Sends an HTTP request using urllib with JSON encoding/decoding
    and optional bearer token authentication.

    Args:
        url: The full URL to send the request to.
        method: HTTP method to use. Defaults to "GET".
        data: Optional JSON-serializable data to send in request body. Defaults to None.
        token: Optional bearer token for authentication. Defaults to None.

    Returns:
        Dictionary containing the JSON response from the server,
        or empty dict if response body is empty.

    Raises:
        urllib.error.HTTPError: If server returns an HTTP error status.
        urllib.error.URLError: If network connection fails.
    """
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request_data = json.dumps(data).encode("utf-8") if data else None
    request = urllib.request.Request(url, data=request_data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            response_data = response.read().decode("utf-8")
            return json.loads(response_data) if response_data else {}
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8")
        print(f"❌ HTTP {e.code} error: {error_body}", file=sys.stderr)
        raise
    except urllib.error.URLError as e:
        print(f"❌ Network error: {e.reason}", file=sys.stderr)
        raise


def wait_for_openfga(timeout: int = HEALTH_CHECK_TIMEOUT) -> bool:
    """Wait for OpenFGA server to become available.

    Polls the OpenFGA health endpoint until it responds with 200 OK
    or the timeout is reached. Checks every HEALTH_CHECK_INTERVAL seconds.

    Args:
        timeout: Maximum seconds to wait before giving up. Defaults to HEALTH_CHECK_TIMEOUT.

    Returns:
        True if OpenFGA becomes available within timeout, False otherwise.
    """
    print(f"⏳ Waiting for OpenFGA at {OPENFGA_BASE_URL} (timeout: {timeout}s)...")
    start_time = time.time()

    while time.time() - start_time < timeout:
        try:
            response = urllib.request.urlopen(f"{OPENFGA_BASE_URL}/healthz", timeout=5)
            if response.status == HTTP_OK:
                print("✅ OpenFGA is ready")
                return True
        except (urllib.error.URLError, urllib.error.HTTPError):
            pass

        time.sleep(HEALTH_CHECK_INTERVAL)

    print(
        f"❌ OpenFGA not available after {timeout}s. Is the service running?",
        file=sys.stderr,
    )
    return False


def _require_value(value: str | None, label: str) -> str:
    """Validate that a response value is present.

    Args:
        value: The value to check.
        label: Human-readable label for error messages.

    Returns:
        The validated non-None value.

    Raises:
        ValueError: If value is None or empty.
    """
    if not value:
        msg = f"{label} not returned in response"
        raise ValueError(msg)
    return value


def create_store(store_name: str = "siopv") -> str:
    """Create a new OpenFGA store.

    Sends a POST request to create a store with the specified name
    and returns the generated store ID.

    Args:
        store_name: Name for the new store. Defaults to "siopv".

    Returns:
        The unique store ID string assigned by OpenFGA.

    Raises:
        ValueError: If store ID is not returned in the response.
        urllib.error.HTTPError: If the API request fails.
        urllib.error.URLError: If network connection fails.
    """
    print(f"📦 Creating OpenFGA store '{store_name}'...")

    try:
        response = make_request(
            f"{OPENFGA_BASE_URL}/stores",
            method="POST",
            data={"name": store_name},
            token=OPENFGA_API_TOKEN,
        )

        store_id = _require_value(response.get("id"), "Store ID")

        print(f"✅ Store created: {store_id}")

    except (ValueError, urllib.error.HTTPError, urllib.error.URLError) as e:
        print(f"❌ Failed to create store: {e}", file=sys.stderr)
        raise
    else:
        return store_id


def upload_authorization_model(store_id: str, model_path: Path) -> str:
    """Upload authorization model from JSON file to OpenFGA store.

    Reads the authorization model from the specified file path,
    validates it exists, and uploads it to the given store.

    Args:
        store_id: The target store ID to upload the model to.
        model_path: Path to JSON file containing the authorization model.

    Returns:
        The unique authorization model ID string assigned by OpenFGA.

    Raises:
        FileNotFoundError: If model file does not exist at model_path.
        ValueError: If authorization model ID is not returned in the response.
        urllib.error.HTTPError: If the API request fails.
        urllib.error.URLError: If network connection fails.
        json.JSONDecodeError: If model file contains invalid JSON.
    """
    print(f"📤 Reading authorization model from {model_path}...")

    if not model_path.exists():
        msg = f"Model file not found: {model_path}"
        raise FileNotFoundError(msg)

    model_data = json.loads(model_path.read_text())
    print(f"✅ Model loaded: {len(model_data.get('type_definitions', []))} type definitions")

    print(f"📤 Uploading authorization model to store {store_id}...")

    try:
        response = make_request(
            f"{OPENFGA_BASE_URL}/stores/{store_id}/authorization-models",
            method="POST",
            data=model_data,
            token=OPENFGA_API_TOKEN,
        )

        model_id = _require_value(response.get("authorization_model_id"), "Authorization model ID")

        print(f"✅ Authorization model uploaded: {model_id}")

    except (
        ValueError,
        urllib.error.HTTPError,
        urllib.error.URLError,
        FileNotFoundError,
        json.JSONDecodeError,
    ) as e:
        print(f"❌ Failed to upload authorization model: {e}", file=sys.stderr)
        raise
    else:
        return model_id


def print_configuration(store_id: str, model_id: str) -> None:
    """Print OpenFGA configuration for adding to .env file.

    Displays formatted output with store ID, model ID, and API token,
    along with ready-to-copy environment variable assignments.

    Args:
        store_id: The OpenFGA store ID to display.
        model_id: The authorization model ID to display.
    """
    print("\n" + "=" * 70)
    print("✅ OpenFGA Bootstrap Complete!")
    print("=" * 70)
    print(f"\nStore ID:        {store_id}")
    print(f"Model ID:        {model_id}")
    print(f"API Token:       {OPENFGA_API_TOKEN}")
    print("\n📝 Add these lines to your .env file:\n")
    print(f"SIOPV_OPENFGA_STORE_ID={store_id}")
    print(f"SIOPV_OPENFGA_AUTHORIZATION_MODEL_ID={model_id}")
    print(f"SIOPV_OPENFGA_API_TOKEN={OPENFGA_API_TOKEN}")
    print("SIOPV_OPENFGA_AUTH_METHOD=api_token")
    print("\n" + "=" * 70)


def main() -> int:
    """Execute OpenFGA bootstrap workflow.

    Orchestrates the complete setup process:
    1. Wait for OpenFGA server availability
    2. Create a new store
    3. Upload authorization model
    4. Print configuration for .env file

    Returns:
        Exit code: 0 for success, 1 for failure, 130 for keyboard interrupt.
    """
    try:
        # Step 1: Wait for OpenFGA availability
        if not wait_for_openfga():
            return 1

        # Step 2: Create store
        store_id = create_store()

        # Step 3: Upload authorization model
        model_id = upload_authorization_model(store_id, MODEL_FILE_PATH)

        # Step 4: Print configuration
        print_configuration(store_id, model_id)

    except KeyboardInterrupt:
        print("\n⚠️  Interrupted by user", file=sys.stderr)
        return 130
    except (
        ValueError,
        FileNotFoundError,
        urllib.error.HTTPError,
        urllib.error.URLError,
        json.JSONDecodeError,
    ) as e:
        msg = f"Bootstrap failed: {e}"
        print(f"\n❌ {msg}", file=sys.stderr)
        return 1
    else:
        return 0


if __name__ == "__main__":
    sys.exit(main())
