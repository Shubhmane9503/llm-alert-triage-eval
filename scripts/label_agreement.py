from __future__ import annotations

from pathlib import Path
import argparse
import csv
import json
import math


VALID_LABELS = {"malicious", "benign", "uncertain"}


def wilson_interval(
    successes: int,
    total: int,
    *,
    z: float = 1.959963984540054,
) -> tuple[float, float]:
    if total <= 0:
        raise ValueError("total must be positive")
    p = successes / total
    z2 = z * z
    denominator = 1 + z2 / total
    center = (p + z2 / (2 * total)) / denominator
    margin = (
        z
        * math.sqrt(
            (p * (1 - p) / total)
            + (z2 / (4 * total * total))
        )
        / denominator
    )
    return max(0.0, center - margin), min(1.0, center + margin)


def compute_agreement(path: Path) -> dict[str, object]:
    reviewed: list[tuple[str, str]] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"derived_label", "manual_label"}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError(
                f"{path} must contain derived_label and manual_label columns"
            )
        for row_number, row in enumerate(reader, start=2):
            manual = str(row.get("manual_label", "")).strip().lower()
            if not manual:
                continue
            derived = str(row.get("derived_label", "")).strip().lower()
            if manual not in VALID_LABELS:
                raise ValueError(
                    f"{path}:{row_number}: invalid manual_label {manual!r}"
                )
            if derived not in VALID_LABELS:
                raise ValueError(
                    f"{path}:{row_number}: invalid derived_label {derived!r}"
                )
            reviewed.append((derived, manual))

    if not reviewed:
        raise ValueError("no completed manual labels found")

    matches = sum(derived == manual for derived, manual in reviewed)
    total = len(reviewed)
    agreement = matches / total
    agreement_low, agreement_high = wilson_interval(matches, total)
    errors = total - matches

    by_derived: dict[str, dict[str, int]] = {}
    for derived, manual in reviewed:
        counts = by_derived.setdefault(
            derived,
            {"reviewed": 0, "matches": 0, "errors": 0},
        )
        counts["reviewed"] += 1
        if derived == manual:
            counts["matches"] += 1
        else:
            counts["errors"] += 1

    return {
        "reviewed": total,
        "matches": matches,
        "errors": errors,
        "agreement": agreement,
        "agreement_wilson_95": [agreement_low, agreement_high],
        "error_rate": errors / total,
        "error_rate_wilson_95": [
            1 - agreement_high,
            1 - agreement_low,
        ],
        "by_derived_label": by_derived,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compute manual-vs-derived label agreement with Wilson CI."
    )
    parser.add_argument(
        "sheet",
        nargs="?",
        type=Path,
        default=Path("labels/manual_check.csv"),
    )
    args = parser.parse_args()
    print(json.dumps(compute_agreement(args.sheet), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
