"""FastAPI webhook adapter for receiving Trivy scan results from CI/CD.

Implements WebhookReceiverPort. Validates HMAC-SHA256 signatures and
triggers pipeline runs asynchronously via background tasks.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog
from fastapi import APIRouter, BackgroundTasks, Request, Response, status

from siopv.application.ports.webhook_receiver import WebhookReceiverPort
from siopv.domain.exceptions import (
    WebhookAuthenticationError,
    WebhookPayloadError,
)
from siopv.infrastructure.resilience.rate_limiter import TokenBucket

if TYPE_CHECKING:
    from pydantic import SecretStr

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/v1/webhook", tags=["webhook"])

# Module-level state set by DI at startup
_webhook_receiver: WebhookReceiverPort | None = None

# Fallback body cap used only when a custom (non-TrivyWebhookReceiver) port is wired
_DEFAULT_MAX_BODY_BYTES = 10_485_760  # 10 MB
_SECONDS_PER_MINUTE = 60.0
# Bound the per-IP bucket map so a spray of distinct source IPs cannot exhaust memory
_MAX_TRACKED_IPS = 10_000

# Error messages
_ERR_MISSING_SIGNATURE = "Missing webhook signature header"
_ERR_INVALID_SIGNATURE = "Invalid webhook signature"
_ERR_MALFORMED_JSON = "Malformed JSON payload"
_ERR_NOT_OBJECT = "Payload must be a JSON object"


def set_webhook_receiver(receiver: WebhookReceiverPort) -> None:
    """Set the module-level webhook receiver (called by DI at app startup)."""
    global _webhook_receiver  # noqa: PLW0603
    _webhook_receiver = receiver


class _PerIpRateLimiter:
    """In-process per-IP token-bucket rate limiter for the webhook endpoint.

    Single-instance only (matches the single-instance deployment model). Each
    source IP gets its own bucket of ``rpm`` tokens refilling at ``rpm/60`` per
    second. The bucket map is bounded; when it fills it is cleared wholesale,
    which at worst grants one extra request to in-flight callers.
    """

    def __init__(self, rpm: int, *, max_tracked_ips: int = _MAX_TRACKED_IPS) -> None:
        self._capacity = float(rpm)
        self._refill_rate = rpm / _SECONDS_PER_MINUTE
        self._max_tracked_ips = max_tracked_ips
        self._buckets: dict[str, TokenBucket] = {}

    def allow(self, ip: str) -> bool:
        """Return True if a request from ``ip`` is within its rate budget."""
        bucket = self._buckets.get(ip)
        if bucket is None:
            if len(self._buckets) >= self._max_tracked_ips:
                self._buckets.clear()
            bucket = TokenBucket(capacity=self._capacity, refill_rate=self._refill_rate)
            self._buckets[ip] = bucket
        return bucket.consume()


class TrivyWebhookReceiver(WebhookReceiverPort):
    """Receives Trivy scan payloads via webhook with HMAC-SHA256 verification."""

    def __init__(
        self,
        secret: SecretStr | None,
        output_dir: Path,
        *,
        max_body_bytes: int,
        rate_limit_rpm: int,
    ) -> None:
        self._secret = secret
        self._output_dir = output_dir
        self._max_body_bytes = max_body_bytes
        self._rate_limiter = _PerIpRateLimiter(rate_limit_rpm)

    async def receive_payload(
        self,
        payload: bytes,
        signature: str | None,
    ) -> dict[str, Any]:
        """Validate HMAC signature and parse payload."""
        self._verify_signature(payload, signature)
        return self._parse_payload(payload)

    def _verify_signature(self, payload: bytes, signature: str | None) -> None:
        if self._secret is None:
            return

        if signature is None:
            raise WebhookAuthenticationError(_ERR_MISSING_SIGNATURE)

        # Strip optional "sha256=" prefix
        sig_value = signature.removeprefix("sha256=")

        expected = hmac.new(
            self._secret.get_secret_value().encode(),
            payload,
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(sig_value, expected):
            raise WebhookAuthenticationError(_ERR_INVALID_SIGNATURE)

    def _parse_payload(self, payload: bytes) -> dict[str, Any]:
        try:
            data = json.loads(payload)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise WebhookPayloadError(_ERR_MALFORMED_JSON) from exc

        if not isinstance(data, dict):
            raise WebhookPayloadError(_ERR_NOT_OBJECT)

        return data


async def _run_pipeline_background(payload: dict[str, Any], output_dir: Path) -> None:
    """Run the SIOPV pipeline in a background task with full DI wiring."""
    from siopv.application.orchestration.graph import run_pipeline  # noqa: PLC0415
    from siopv.infrastructure.config.settings import get_settings  # noqa: PLC0415
    from siopv.infrastructure.di.pipeline import build_pipeline_ports  # noqa: PLC0415

    # Write payload to a temp file for the pipeline (expects a file path)
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".json",
        dir=str(output_dir),
        delete=False,
        prefix="webhook-trivy-",
    ) as tmp:
        json.dump(payload, tmp)
        tmp_path = Path(tmp.name)

    try:
        settings = get_settings()
        ports = build_pipeline_ports(settings, output_dir=output_dir)

        logger.info("webhook_pipeline_started", report_path=str(tmp_path))
        await run_pipeline(
            report_path=tmp_path,
            ports=ports,
            user_id=settings.default_user_id,
            project_id=settings.default_project_id,
            system_execution=True,
        )
        logger.info("webhook_pipeline_completed", report_path=str(tmp_path))
    except Exception:
        logger.exception("webhook_pipeline_failed", report_path=str(tmp_path))
    finally:
        tmp_path.unlink(missing_ok=True)


def _declared_content_length(request: Request) -> int | None:
    """Return the declared Content-Length, or None if absent/unparseable."""
    raw = request.headers.get("content-length")
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _payload_too_large_response() -> Response:
    return Response(
        content='{"detail":"Payload too large"}',
        status_code=status.HTTP_413_CONTENT_TOO_LARGE,
        media_type="application/json",
    )


async def _read_request_body(
    request: Request,
    *,
    max_body_bytes: int,
    rate_limiter: _PerIpRateLimiter | None,
    remote: str,
) -> bytes | Response:
    """Rate-limit, size-check, and stream the request body.

    Returns the body bytes on success, or an error ``Response`` (429/413) that
    the caller should return directly.
    """
    # Per-IP rate limit (before any body read to bound resource use)
    if rate_limiter is not None and not rate_limiter.allow(remote):
        logger.warning("webhook_rate_limited", remote=remote)
        return Response(
            content='{"detail":"Too many requests"}',
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            media_type="application/json",
        )

    # Reject oversized payloads up front via the declared Content-Length
    declared_length = _declared_content_length(request)
    if declared_length is not None and declared_length > max_body_bytes:
        logger.warning("webhook_body_too_large", remote=remote, declared=declared_length)
        return _payload_too_large_response()

    # Stream the body with a hard running cap (handles missing/lying Content-Length)
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > max_body_bytes:
            logger.warning("webhook_body_too_large_stream", remote=remote, read=len(body))
            return _payload_too_large_response()
    return bytes(body)


@router.post(
    "/trivy",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=None,
)
async def receive_trivy_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
) -> Response:
    """Receive a Trivy scan report via webhook.

    Validates HMAC-SHA256 signature and enqueues pipeline processing.
    Returns 202 Accepted immediately.
    """
    receiver = _webhook_receiver
    if receiver is None:
        return Response(
            content='{"detail":"Webhook not configured"}',
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            media_type="application/json",
        )

    remote = request.client.host if request.client else "unknown"

    # Resolve hardening config from the concrete receiver; fall back conservatively
    # for any custom WebhookReceiverPort implementation.
    if isinstance(receiver, TrivyWebhookReceiver):
        max_body_bytes = receiver._max_body_bytes
        rate_limiter: _PerIpRateLimiter | None = receiver._rate_limiter
        output_dir = receiver._output_dir
    else:
        max_body_bytes = _DEFAULT_MAX_BODY_BYTES
        rate_limiter = None
        output_dir = Path("./output")

    body_or_error = await _read_request_body(
        request,
        max_body_bytes=max_body_bytes,
        rate_limiter=rate_limiter,
        remote=remote,
    )
    if isinstance(body_or_error, Response):
        return body_or_error
    body = body_or_error

    signature = request.headers.get("X-Webhook-Signature-256")

    try:
        payload = await receiver.receive_payload(body, signature)
    except WebhookAuthenticationError:
        logger.warning("webhook_auth_failed", remote=remote)
        return Response(
            content='{"detail":"Unauthorized"}',
            status_code=status.HTTP_401_UNAUTHORIZED,
            media_type="application/json",
        )
    except WebhookPayloadError as exc:
        logger.warning("webhook_payload_error", error=str(exc))
        return Response(
            content='{"detail":"Bad request"}',
            status_code=status.HTTP_400_BAD_REQUEST,
            media_type="application/json",
        )

    background_tasks.add_task(_run_pipeline_background, payload, output_dir)

    return Response(
        content='{"status":"accepted","message":"Pipeline processing enqueued"}',
        status_code=status.HTTP_202_ACCEPTED,
        media_type="application/json",
    )


__all__ = [
    "TrivyWebhookReceiver",
    "router",
    "set_webhook_receiver",
]
