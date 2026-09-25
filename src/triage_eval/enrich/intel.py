from __future__ import annotations

import ipaddress
import json
import os
from collections.abc import Iterable
from pathlib import Path
from typing import Protocol

import httpx
from pydantic import BaseModel, ConfigDict, Field

from ..models import AlertGroup


class ThreatIntelFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str
    indicator: str
    status: str
    score: float | None = None
    details: dict[str, object] = Field(default_factory=dict)


class ThreatIntelProvider(Protocol):
    name: str

    def lookup(
        self,
        indicator: str,
    ) -> ThreatIntelFinding: ...


class ThreatIntelCache:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._values: dict[str, dict[str, object]] = {}
        if path.exists():
            value = json.loads(
                path.read_text(encoding="utf-8")
            )
            if isinstance(value, dict):
                self._values = value

    @staticmethod
    def _key(provider: str, indicator: str) -> str:
        return f"{provider}:{indicator}"

    def get(
        self,
        provider: str,
        indicator: str,
    ) -> ThreatIntelFinding | None:
        raw = self._values.get(
            self._key(provider, indicator)
        )
        if raw is None:
            return None
        return ThreatIntelFinding.model_validate(raw)

    def put(self, finding: ThreatIntelFinding) -> None:
        self._values[
            self._key(finding.provider, finding.indicator)
        ] = finding.model_dump(mode="json")
        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        self.path.write_text(
            json.dumps(
                self._values,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


class AbuseIPDBProvider:
    name = "abuseipdb"
    endpoint = "https://api.abuseipdb.com/api/v2/check"

    def __init__(
        self,
        api_key: str,
        *,
        max_age_days: int = 30,
        timeout: float = 10.0,
    ) -> None:
        self.api_key = api_key
        self.max_age_days = max_age_days
        self.timeout = timeout

    @classmethod
    def from_env(cls) -> AbuseIPDBProvider | None:
        key = os.getenv("ABUSEIPDB_API_KEY")
        return cls(key) if key else None

    def lookup(
        self,
        indicator: str,
    ) -> ThreatIntelFinding:
        response = httpx.get(
            self.endpoint,
            params={
                "ipAddress": indicator,
                "maxAgeInDays": self.max_age_days,
            },
            headers={
                "Accept": "application/json",
                "Key": self.api_key,
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        data = response.json().get("data", {})
        score = float(
            data.get("abuseConfidenceScore", 0)
        )
        reports = int(data.get("totalReports", 0))
        return ThreatIntelFinding(
            provider=self.name,
            indicator=indicator,
            status=(
                "hit"
                if score > 0 or reports > 0
                else "no_hit"
            ),
            score=score,
            details={
                "total_reports": reports,
                "country_code": data.get("countryCode"),
                "usage_type": data.get("usageType"),
                "domain": data.get("domain"),
            },
        )


class ThreatFoxProvider:
    name = "threatfox"
    endpoint = "https://threatfox-api.abuse.ch/api/v1/"

    def __init__(
        self,
        auth_key: str,
        *,
        timeout: float = 10.0,
    ) -> None:
        self.auth_key = auth_key
        self.timeout = timeout

    @classmethod
    def from_env(cls) -> ThreatFoxProvider | None:
        key = os.getenv("THREATFOX_AUTH_KEY")
        return cls(key) if key else None

    def lookup(
        self,
        indicator: str,
    ) -> ThreatIntelFinding:
        response = httpx.post(
            self.endpoint,
            headers={"Auth-Key": self.auth_key},
            json={
                "query": "search_ioc",
                "search_term": indicator,
                "exact_match": True,
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        payload = response.json()
        status = str(
            payload.get("query_status", "unknown")
        )
        rows = payload.get("data")
        hits = rows if isinstance(rows, list) else []
        return ThreatIntelFinding(
            provider=self.name,
            indicator=indicator,
            status=(
                "hit"
                if status == "ok" and hits
                else "no_hit"
            ),
            details={
                "query_status": status,
                "matches": [
                    {
                        "ioc": item.get("ioc"),
                        "threat_type": item.get(
                            "threat_type"
                        ),
                        "malware": (
                            item.get("malware_printable")
                            or item.get("malware")
                        ),
                    }
                    for item in hits[:5]
                    if isinstance(item, dict)
                ],
            },
        )


def enrich_group_ips(
    group: AlertGroup,
    providers: Iterable[ThreatIntelProvider],
    cache: ThreatIntelCache,
) -> list[ThreatIntelFinding]:
    indicators = sorted(
        {
            value
            for value in (
                group.source_ip,
                group.destination_ip,
            )
            if value
        }
    )
    findings: list[ThreatIntelFinding] = []
    for indicator in indicators:
        if not _is_public_ip(indicator):
            findings.append(
                ThreatIntelFinding(
                    provider="local",
                    indicator=indicator,
                    status=(
                        "skipped_private_or_nonpublic"
                    ),
                )
            )
            continue

        for provider in providers:
            cached = cache.get(
                provider.name,
                indicator,
            )
            if cached is not None:
                findings.append(cached)
                continue
            try:
                finding = provider.lookup(indicator)
            except (
                httpx.HTTPError,
                ValueError,
                KeyError,
            ) as exc:
                finding = ThreatIntelFinding(
                    provider=provider.name,
                    indicator=indicator,
                    status="error",
                    details={
                        "error": type(exc).__name__
                    },
                )
            cache.put(finding)
            findings.append(finding)
    return findings
