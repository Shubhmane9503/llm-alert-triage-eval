from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_script():
    path = Path(__file__).parents[1] / "scripts" / "label_agreement.py"
    spec = importlib.util.spec_from_file_location("label_agreement", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_wilson_interval_contains_observed_rate() -> None:
    module = _load_script()
    low, high = module.wilson_interval(8, 10)
    assert low < 0.8 < high


def test_compute_agreement(tmp_path) -> None:
    module = _load_script()
    sheet = tmp_path / "manual.csv"
    sheet.write_text(
        "derived_label,manual_label\n"
        "malicious,malicious\n"
        "benign,malicious\n"
        "uncertain,uncertain\n"
        "benign,\n",
        encoding="utf-8",
    )
    result = module.compute_agreement(sheet)
    assert result["reviewed"] == 3
    assert result["matches"] == 2
    assert result["errors"] == 1
