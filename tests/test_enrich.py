from __future__ import annotations

from pathlib import Path

from triage_eval.enrich.assets import (
    AssetInventory,
    AssetRecord,
    match_assets,
)
from triage_eval.enrich.intel import (
    ThreatIntelCache,
    enrich_group_ips,
)
from triage_eval.group import group_alerts


def test_asset_context_matches_host(alert_factory) -> None:
    group = group_alerts(
        [alert_factory(host="intranet_server")]
    )[0]
    inventory = AssetInventory(
        assets=[
            AssetRecord(
                name="intranet_server",
                role="web",
                criticality="high",
            )
        ]
    )
    matches = match_assets(group, inventory)
    assert [item.name for item in matches] == [
        "intranet_server"
    ]


def test_private_ips_skip_network_providers(
    alert_factory,
    tmp_path: Path,
) -> None:
    group = group_alerts(
        [
            alert_factory(
                source_ip="10.0.0.2",
                destination_ip="192.168.1.4",
            )
        ]
    )[0]
    cache = ThreatIntelCache(tmp_path / "cache.json")
    findings = enrich_group_ips(group, [], cache)
    assert len(findings) == 2
    assert all(
        item.status == "skipped_private_or_nonpublic"
        for item in findings
    )
