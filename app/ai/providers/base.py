"""Provider adapter contract (T7).

Adapters translate one bounded investigation step into provider text
plus scripted tool requests. The fake adapter serves routine tests;
the real Meta transport is a separate T8 slice and does not exist
here, so production use resolves to an explicit unavailable error
rather than to a silent fake answer.
"""

import abc
import threading
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ToolCall:
    name: str
    arguments: dict
    # Responses ``function_call`` correlation ID; empty for legacy
    # scripted (fake) calls, required for real stateless dispatches.
    call_id: str = ""


@dataclass(frozen=True)
class ProviderRequest:
    prompt_text: str
    max_output_tokens: int
    # Exact immutable serialized Responses dispatch built, decoded-
    # validated and byte-capped by the service; empty for fake
    # providers. The adapter sends these bytes verbatim and never
    # invents fields.
    body: bytes = b""


@dataclass(frozen=True)
class ProviderResponse:
    text: str
    input_tokens: int
    output_tokens: int
    tool_calls: tuple = ()
    # Validated real usage
    # (input/output/cached/reasoning counts); empty for legacy
    # scripted responses, which keep planning-estimate accounting.
    usage: dict = field(default_factory=dict)
    # Server response ID (correlation/debugging only, no content).
    response_id: str = ""


@dataclass(frozen=True)
class ProviderInfo:
    provider: str
    model: str


class ProviderError(RuntimeError):
    """The provider transport or backend failed for this attempt."""


class ProviderTimeout(ProviderError):
    """The provider did not answer within the bounded wait."""


class ProviderCancelled(ProviderError):
    """The investigation was cancelled while waiting for the provider."""


class BackendUnavailable(ProviderError):
    """No provider transport is implemented for this configuration."""


class ProviderAdapter(abc.ABC):
    """One bounded completion; implementations must honor cancel promptly."""

    name: str = "base"

    @abc.abstractmethod
    def complete(self, request: ProviderRequest, *, cancel: threading.Event) -> ProviderResponse:
        """Return the next assistant text and any tool requests."""
        raise NotImplementedError


@dataclass
class CapturedRequest:
    prompt_text: str
    max_output_tokens: int
