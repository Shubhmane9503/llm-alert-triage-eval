# Labeling methodology

AIT-ADS publishes attack-phase time windows in labels.csv, not authoritative
per-alert binary labels. For this MVP, an alert is derived as malicious only if
both conditions hold:

1. its normalized ISO timestamp is inside an attack-phase window for its
   scenario; and
2. one of the normalized source, destination, or host fields matches an
   explicitly configured attacker address/host for that scenario.

The loader deliberately prefers the ISO timestamp field in Wazuh alerts. The
public dataset documentation notes that Wazuh's numeric generation timestamp
was produced later and does not line up with the original scenario ground
truth.

## Attacker-address source

The default attacker IPv4 address for every scenario is taken from the AIT
authors' public alert-data-set repository, specifically the
server_configs/<scenario>.yaml file and its attacker_0.default_ipv4_address
field. No address is inferred from alert prevalence or from held-out labels.

Configured values:

- fox: 192.168.130.77
- harrison: 172.28.192.242
- russellmitchell: 192.168.230.122
- santos: 10.229.2.216
- shaw: 10.70.33.202
- wardbeck: 192.168.96.3
- wheeler: 172.27.181.218
- wilson: 192.168.226.71

Source repository:
https://github.com/ait-aecid/alert-data-set/tree/main/server_configs

The attacker-host configuration remains fail-closed: a scenario with no
configured attacker hosts cannot be labeled. This prevents a missing mapping
from silently turning the benchmark into all-benign data.

A group is malicious if any member is malicious. Mixed-label groups are counted
and reported. triage-eval label also writes a stratified manual-check sheet to
labels/manual_check.csv; at least 100 rows must be manually reviewed before a
held-out run is accepted.

## Limitations

Window-plus-attacker-address labels are derived labels, not the original
dataset's more precise event-level labels. Some malicious activity after initial
access may be represented by internal victim traffic and therefore not contain
the attacker's default IP. The manual check and reported label-error rate are
required specifically to quantify this limitation instead of hiding it.


## Rule-family refinement from dev validation

A real dev-data diagnostic identified victim-side Wazuh rule families that do
not carry the upstream event-label strings in their rendered alert text. Inside
the published phase window and on a victim host, the following are treated as
phase evidence:

- privilege escalation: Wazuh 5304 (changed UID), 5402 (sudo to ROOT), 5501
  (PAM session opened), and 5502 (PAM session closed);
- service scans: Wazuh 5706 (sshd insecure connection attempt / scan).

Generic TLS, mail, ClamAV and unrelated authentication alerts that happen to
fall inside an attack window are not promoted to malicious solely by timing;
they remain `uncertain` unless attacker/VPN IP or phase-family evidence exists.
