"""Shared stdlib HTTPS POST helper for native provider adapters.

One exact allowlisted URL per call, TLS with redirect refusal, no
retries, bounded response bytes. The socket timeout bounds each read;
the absolute wall-clock bound stays with the caller's worker/control
deadline. No key material enters logs, exceptions or usage records.
"""

import json
import ssl
import threading
import urllib.error
import urllib.request
from collections.abc import Callable

from app.ai.providers.base import ProviderError, ProviderTimeout


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects: any 3xx surfaces instead of being followed."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _default_opener(context: ssl.SSLContext):
    """Native opener with TLS context and redirect refusal."""
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), _NoRedirect)


def post_json(
    *,
    url: str,
    headers: dict,
    body: bytes,
    timeout_s: float,
    max_response_bytes: int,
    max_wire_bytes: int,
    opener_factory: Callable | None = None,
) -> dict:
    """POST exactly one allowlisted URL and parse one JSON object body."""
    if len(body) > max_wire_bytes:
        raise ProviderError("The provider dispatch exceeds its bound.")
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    factory = opener_factory or _default_opener
    opener = factory(ssl.create_default_context())
    try:
        with opener.open(request, timeout=timeout_s) as response:
            raw = response.read(max_response_bytes + 1)
    except urllib.error.HTTPError as exc:
        raise ProviderError(f"The provider refused the request ({exc.code}).") from exc
    except (urllib.error.URLError, ssl.SSLError, TimeoutError) as exc:
        raise ProviderTimeout("The provider did not answer in time.") from exc
    except ProviderError:
        raise
    except Exception as exc:
        raise ProviderError("The provider request failed.") from exc
    if len(raw) > max_response_bytes:
        raise ProviderError("The provider response exceeds its bound.")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except ValueError as exc:
        raise ProviderError("The provider answer is malformed.") from exc
    if not isinstance(payload, dict):
        raise ProviderError("The provider answer is malformed.")
    return payload


def check_cancel(cancel: threading.Event) -> None:
    """Fail fast when the investigation was cancelled before dispatch."""
    from app.ai.providers.base import ProviderCancelled

    if cancel.is_set():
        raise ProviderCancelled("The investigation was cancelled.")
