"""Fake provider for routine tests (T7).

Serves scripted responses without any network, key or account. Every
outgoing prompt is captured verbatim so tests can assert the egress
boundary over prompts, history, retries and replayed context. Optional
delays and scripted failures exercise timeout, cancellation and
provider-failure paths. Never used as a production answer source: the
service selects it only when tests inject it explicitly.
"""

import threading
import time
from dataclasses import dataclass, field

from app.ai.providers.base import (
    CapturedRequest,
    ProviderAdapter,
    ProviderCancelled,
    ProviderError,
    ProviderRequest,
    ProviderResponse,
)


@dataclass
class FakeProvider(ProviderAdapter):
    """Scripted, network-free provider with full outgoing capture."""

    name: str = "fake"
    script: list = field(default_factory=list)
    delay_s: float = 0.0
    fail_with: object = None
    outgoing: list = field(default_factory=list)

    def complete(self, request: ProviderRequest, *, cancel: threading.Event) -> ProviderResponse:
        self.outgoing.append(
            CapturedRequest(
                prompt_text=request.prompt_text,
                max_output_tokens=request.max_output_tokens,
            )
        )
        if self.delay_s > 0 and cancel.wait(self.delay_s):
            raise ProviderCancelled("The investigation was cancelled.")
        if cancel.is_set():
            raise ProviderCancelled("The investigation was cancelled.")
        if self.fail_with is not None:
            if isinstance(self.fail_with, type):
                raise self.fail_with("Scripted provider failure.")
            raise ProviderError(str(self.fail_with))
        if self.script:
            return self.script.pop(0)
        return ProviderResponse(text="", input_tokens=0, output_tokens=0)

    def captured_prompts(self) -> list[str]:
        """Every prompt text sent to this fake, in order."""
        return [item.prompt_text for item in self.outgoing]

    @staticmethod
    def paced_delay(total_s: float, cancel: threading.Event, step_s: float = 0.01) -> bool:
        """Wait total_s in small steps; True when cancelled during the wait."""
        deadline = time.monotonic() + total_s
        while True:
            if cancel.is_set():
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(step_s, remaining))
