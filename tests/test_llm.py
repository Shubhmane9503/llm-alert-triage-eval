from __future__ import annotations

from triage_eval.llm import normalize_azure_base_url


def test_azure_endpoint_is_normalized() -> None:
    assert normalize_azure_base_url(
        "https://example.openai.azure.com"
    ) == "https://example.openai.azure.com/openai/v1/"

    assert normalize_azure_base_url(
        "https://example.openai.azure.com/openai/v1/"
    ) == "https://example.openai.azure.com/openai/v1/"
