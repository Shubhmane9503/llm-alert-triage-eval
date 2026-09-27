from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import TriageResponse


class LLMError(RuntimeError):
    """A live model call did not produce usable structured output."""


@dataclass(frozen=True)
class ModelCall:
    output: Any
    model: str
    input_tokens: int
    output_tokens: int
    latency_ms: float


def normalize_azure_base_url(endpoint: str) -> str:
    root = endpoint.rstrip("/")
    if root.endswith("/openai/v1"):
        return root + "/"
    return root + "/openai/v1/"


class AzureOpenAITriageClient:
    def __init__(
        self,
        *,
        endpoint: str,
        api_key: str,
        deployment: str,
        system_prompt: str,
        timeout: float = 60.0,
    ) -> None:
        from openai import OpenAI

        self.deployment = deployment
        self.system_prompt = system_prompt
        self.client = OpenAI(
            base_url=normalize_azure_base_url(
                endpoint
            ),
            api_key=api_key,
            timeout=timeout,
        )

    @classmethod
    def from_env(
        cls,
        prompt_path: Path,
    ) -> AzureOpenAITriageClient:
        required = (
            "AZURE_OPENAI_ENDPOINT",
            "AZURE_OPENAI_API_KEY",
            "AZURE_OPENAI_DEPLOYMENT",
        )
        missing = [
            name
            for name in required
            if not os.getenv(name)
        ]
        if missing:
            raise LLMError(
                "missing required environment variables: "
                + ", ".join(missing)
            )

        return cls(
            endpoint=os.environ[
                "AZURE_OPENAI_ENDPOINT"
            ],
            api_key=os.environ[
                "AZURE_OPENAI_API_KEY"
            ],
            deployment=os.environ[
                "AZURE_OPENAI_DEPLOYMENT"
            ],
            system_prompt=prompt_path.read_text(
                encoding="utf-8"
            ),
        )

    def call(
        self,
        user_content: str,
    ) -> ModelCall:
        started = time.perf_counter()
        response = self.client.responses.parse(
            model=self.deployment,
            input=[
                {
                    "role": "system",
                    "content": self.system_prompt,
                },
                {
                    "role": "user",
                    "content": user_content,
                },
            ],
            text_format=TriageResponse,
        )
        latency_ms = (
            time.perf_counter() - started
        ) * 1000
        parsed = response.output_parsed
        if parsed is None:
            raise LLMError(
                "model returned no parsed "
                "structured output"
            )

        usage = response.usage
        return ModelCall(
            output=parsed,
            model=str(
                response.model or self.deployment
            ),
            input_tokens=int(
                getattr(
                    usage,
                    "input_tokens",
                    0,
                )
                or 0
            ),
            output_tokens=int(
                getattr(
                    usage,
                    "output_tokens",
                    0,
                )
                or 0
            ),
            latency_ms=latency_ms,
        )
