from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

from ..models import AlertGroup


class AssetRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    aliases: list[str] = Field(default_factory=list)
    addresses: list[str] = Field(default_factory=list)
    role: str
    criticality: str = "medium"
    tags: list[str] = Field(default_factory=list)


class AssetInventory(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assets: list[AssetRecord] = Field(default_factory=list)


def load_asset_inventory(path: Path) -> AssetInventory:
    raw = yaml.safe_load(
        path.read_text(encoding="utf-8")
    ) or {"assets": []}
    return AssetInventory.model_validate(raw)


def match_assets(
    group: AlertGroup,
    inventory: AssetInventory,
) -> list[AssetRecord]:
    rep = group.representative
    observed = {
        value
        for value in (
            rep.source_ip,
            rep.destination_ip,
            rep.host,
        )
        if value
    }
    matches: list[AssetRecord] = []
    for asset in inventory.assets:
        identifiers = {
            asset.name,
            *asset.aliases,
            *asset.addresses,
        }
        if observed & identifiers:
            matches.append(asset)
    return matches
