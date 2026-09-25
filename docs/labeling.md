# Labeling methodology

AIT-ADS publishes attack-phase time windows in `labels.csv`, not authoritative
per-alert binary labels. For this MVP, an alert is derived as malicious only if
both conditions hold:

1. its normalized ISO timestamp is inside an attack-phase window for its
   scenario; and
2. one of the normalized source, destination, or host fields matches an
   explicitly configured attacker address/host for that scenario.

The loader deliberately prefers the ISO `timestamp` field in Wazuh alerts. The
public dataset documentation notes that Wazuh's numeric generation timestamp
was produced later and does not line up with the original scenario ground
truth.

`configs/attacker_hosts.yaml` is fail-closed: a scenario with no configured
attacker hosts cannot be labeled. This prevents a missing mapping from silently
turning the benchmark into all-benign data.

A group is malicious if any member is malicious. Mixed-label groups are counted
and reported. `triage-eval label` also writes a stratified manual-check sheet to
`labels/manual_check.csv`; at least 100 rows must be manually reviewed before a
held-out run is accepted.
