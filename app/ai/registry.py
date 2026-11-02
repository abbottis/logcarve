"""Provider registry: one native entry per supported provider (ADR 0004).

The service resolves every real dispatch through this registry instead
of provider-specific imports, so adding a provider cannot silently
reuse another provider's body builder, immutable-wire checks or
pricing. Unknown providers fail closed before any key or endpoint is
touched.
"""

from app.ai import catalog


def _meta_entry():
    from app.ai.providers import meta_responses

    return {
        "adapter_name": meta_responses.MetaResponsesAdapter.name,
        "adapter_cls": meta_responses.MetaResponsesAdapter,
        "build_dispatch_body": meta_responses.build_dispatch_body,
        "serialize_body": meta_responses.serialize_body,
        "validate_body": meta_responses.validate_body,
        "cost_micro_usd": meta_responses.cost_micro_usd,
        "framing_tokens": meta_responses.WIRE_FRAMING_TOKENS,
        "pricing_version": meta_responses.PRICING_VERSION,
    }


def _openai_entry():
    from app.ai.providers import openai_responses

    return {
        "adapter_name": openai_responses.OpenAIResponsesAdapter.name,
        "adapter_cls": openai_responses.OpenAIResponsesAdapter,
        "build_dispatch_body": openai_responses.build_dispatch_body,
        "serialize_body": openai_responses.serialize_body,
        "validate_body": openai_responses.validate_body,
        "cost_micro_usd": openai_responses.cost_micro_usd,
        "framing_tokens": openai_responses.WIRE_FRAMING_TOKENS,
        "pricing_version": openai_responses.PRICING_VERSION,
    }


def _gemini_entry():
    from app.ai.providers import gemini_generate

    return {
        "adapter_name": gemini_generate.GeminiGenerateContentAdapter.name,
        "adapter_cls": gemini_generate.GeminiGenerateContentAdapter,
        "build_dispatch_body": gemini_generate.build_dispatch_body,
        "serialize_body": gemini_generate.serialize_body,
        "validate_body": gemini_generate.validate_body,
        "cost_micro_usd": gemini_generate.cost_micro_usd,
        "framing_tokens": gemini_generate.WIRE_FRAMING_TOKENS,
        "pricing_version": gemini_generate.PRICING_VERSION,
    }


def _anthropic_entry():
    from app.ai.providers import anthropic_messages

    return {
        "adapter_name": anthropic_messages.AnthropicMessagesAdapter.name,
        "adapter_cls": anthropic_messages.AnthropicMessagesAdapter,
        "build_dispatch_body": anthropic_messages.build_dispatch_body,
        "serialize_body": anthropic_messages.serialize_body,
        "validate_body": anthropic_messages.validate_body,
        "cost_micro_usd": None,  # Four-arg tiered cost; see anthropic_cost().
        "framing_tokens": anthropic_messages.WIRE_FRAMING_TOKENS,
        "pricing_version": anthropic_messages.PRICING_VERSION,
    }


_BUILDERS = {
    "meta": _meta_entry,
    "openai": _openai_entry,
    "gemini": _gemini_entry,
    "anthropic": _anthropic_entry,
}


def entry_for(provider: str) -> dict:
    """Registry entry for one supported provider; unknown fails closed."""
    builder = _BUILDERS.get(provider)
    if builder is None:
        raise ValueError(f"unknown provider: {provider!r}")
    return builder()


def real_adapter_names() -> frozenset:
    """Adapter names treated as real dispatches (keys/endpoints required)."""
    return catalog.REAL_ADAPTER_NAMES


def endpoint_for(provider: str, model: str) -> str:
    """Exact trusted native endpoint URL for one allowlisted pair."""
    catalog.validate_pair(provider, model)
    if provider == "meta":
        from app.ai.providers import meta_responses

        return (
            f"https://{meta_responses.ENDPOINT_HOST}"
            f":{meta_responses.ENDPOINT_PORT}{meta_responses.ENDPOINT_PATH}"
        )
    if provider == "openai":
        from app.ai.providers import openai_responses

        return (
            f"https://{openai_responses.ENDPOINT_HOST}"
            f":{openai_responses.ENDPOINT_PORT}{openai_responses.ENDPOINT_PATH}"
        )
    if provider == "gemini":
        from app.ai.providers import gemini_generate

        return (
            f"https://{gemini_generate.ENDPOINT_HOST}"
            f":{gemini_generate.ENDPOINT_PORT}{gemini_generate.ENDPOINT_PATH_PREFIX}"
            f"{model}{gemini_generate.ENDPOINT_PATH_SUFFIX}"
        )
    if provider == "anthropic":
        from app.ai.providers import anthropic_messages

        return (
            f"https://{anthropic_messages.ENDPOINT_HOST}"
            f":{anthropic_messages.ENDPOINT_PORT}{anthropic_messages.ENDPOINT_PATH}"
        )
    raise ValueError(f"unknown provider: {provider!r}")


def cost_for(provider: str, usage: dict) -> int:
    """Model-specific integer micro-USD charge for validated usage counts."""
    entry = entry_for(provider)
    if provider == "anthropic":
        from app.ai.providers import anthropic_messages

        unknown = usage.get("cache_creation_tokens", 0)
        five = usage.get("cache_creation_5m_tokens", 0)
        one_h = usage.get("cache_creation_1h_tokens", 0)
        read = usage.get("cached_tokens", 0)
        # Adapter convention: usage["input_tokens"] is the disjoint
        # total (base + all creation buckets + read); decompose
        # defensively so nothing is double-counted or dropped.
        base = usage["input_tokens"] - unknown - five - one_h - read
        if base < 0:
            from app.ai.providers.base import ProviderError

            raise ProviderError("The provider usage is malformed.")
        return anthropic_messages.cost_micro_usd(
            input_tokens=base,
            cache_creation_tokens=unknown,
            cache_read_tokens=read,
            output_tokens=usage["output_tokens"],
            cache_creation_5m_tokens=five,
            cache_creation_1h_tokens=one_h,
        )
    cost = entry["cost_micro_usd"]
    return cost(
        input_tokens=usage["input_tokens"],
        cached_tokens=usage.get("cached_tokens", 0),
        output_tokens=usage["output_tokens"],
    )


def step_cap_for(provider: str, *, input_upper: int, max_output_tokens: int) -> int:
    """Conservative per-step reservation for the exact immutable body size.

    The Anthropic reservation prices the whole input upper bound as
    worst-case 1-hour cache creation (unknown TTL): creation can bill
    at 2x the input rate, so reserving only 1x input would let the
    actual charge exceed its reservation. The validated usage bound
    (``input_upper``) stays far below the large-tier threshold, so the
    small-tier 1-hour rate applies; the large tier remains enforced
    inside the cost function as defense in depth.
    """
    entry = entry_for(provider)
    framing = entry["framing_tokens"]
    total_upper = input_upper + framing
    if provider == "anthropic":
        from app.ai.providers import anthropic_messages

        return anthropic_messages.cost_micro_usd(
            input_tokens=0,
            cache_creation_tokens=total_upper,
            cache_read_tokens=0,
            output_tokens=max_output_tokens,
        )
    cost = entry["cost_micro_usd"]
    return cost(input_tokens=total_upper, cached_tokens=0, output_tokens=max_output_tokens)
