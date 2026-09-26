# Threat model

This project treats all alert fields as untrusted input. The principal LLM risk
is indirect prompt injection through attacker-controlled fields such as URLs,
user agents, and raw log messages. The model receives no tools and no network
access. Outputs are schema constrained, then revalidated and evidence checked.
Any persistent validation failure falls back to the deterministic baseline.

No disposition value can close or suppress an alert. Human review remains the
only path to closure.
