# llm-alert-triage-eval

LLM-assisted SIEM alert triage with an evaluation harness on public labeled alert data.

**Status: planning. This README is the build spec; implementation is in progress.**

Nothing described below exists yet unless a milestone checkbox is ticked. No results have been produced. The README describes the finished project so that it can be built against, and reviewed against, one milestone at a time.

Maintained by Shubham Mane ([shubhammane.com](https://www.shubhammane.com)).

---

## Table of contents

1. [Why this project exists](#why-this-project-exists)
2. [What the finished project looks like](#what-the-finished-project-looks-like)
3. [Scope](#scope)
4. [Architecture and tech stack](#architecture-and-tech-stack)
5. [Planned repository layout](#planned-repository-layout)
6. [Data sources, labels and attribution](#data-sources-labels-and-attribution)
7. [Evaluation methodology](#evaluation-methodology)
8. [Testing strategy](#testing-strategy)
9. [Guardrails and security design](#guardrails-and-security-design)
10. [Milestones](#milestones)
11. [Definition of done](#definition-of-done)
12. [Known risks and gaps](#known-risks-and-gaps)
13. [Building this with an AI assistant](#building-this-with-an-ai-assistant)
14. [License](#license)

---

## Why this project exists

Every SOC vendor claims AI triage, and few publish numbers. This project answers the questions a SOC lead would ask before trusting an LLM with alert triage:

1. **Does an LLM triage alerts better than well-tuned rules?** Measured on held-out, labeled, public alert data, against a rules-only baseline tuned on separate dev data.
2. **What does each alert cost?** Tokens multiplied by the published price on the run date, plus p50/p95 latency.
3. **What happens when an attacker writes into the log fields the model reads?** Measured with an injection suite that plants payloads in alert fields and reports how often the disposition flips.

The design principle is that **the model suggests, deterministic checks decide what gets shown, and only a human closes an alert.** The false-negative rate is the headline number, because a missed attack costs more than a noisy one. If the LLM loses to tuned rules, that is still a publishable and useful result.

---

## What the finished project looks like

### Features

- **Loader** for [AIT-ADS](https://zenodo.org/records/8263181) Wazuh and Suricata alerts into one normalized Pydantic model (own code; the dataset's scripts are GPL-3.0 and are not used).
- **Grouping** of duplicate alerts by rule ID, source, destination and a 5-minute window, so thousands of near-identical scanner alerts become a manageable number of alert groups.
- **Labeling** of alerts and groups from the dataset's attack-phase time windows plus the attacker host, with a hand-checked sample and a stated error rate.
- **Enrichment** with asset context from a hand-written testbed inventory, plus threat intel behind a provider interface ([AbuseIPDB](https://www.abuseipdb.com/pricing), [ThreatFox](https://threatfox.abuse.ch/api/)) with a local cache.
- **LLM triage** that returns schema-constrained JSON: summary, disposition (`escalate` / `likely_benign` / `needs_more_data`), confidence, and citations to alert fields.
- **Guards** that validate every model output and fail closed to the rules verdict.
- **Rules-only baseline**: a Wazuh `rule.level` threshold plus an allowlist of known-noise rule IDs, tuned on dev data only.
- **Evaluation CLI** that runs both approaches on the same held-out sample and writes a report and chart.
- **Injection suite** of 50+ alerts with payloads planted in log fields, reporting the disposition-flip rate.
- **Audit log**: every LLM call recorded to JSONL (model, tokens, latency, verdict, validation result).

### User-facing commands

| Command | What it does |
|---|---|
| `make setup` | Creates a virtual environment and installs pinned dependencies. |
| `make data` | Downloads the AIT-ADS archive from Zenodo into a git-ignored `data/` folder and verifies its checksum. |
| `make labels` | Builds alert and group labels from `labels.csv` time windows plus attacker host, and exports a sample for manual checking. |
| `make baseline` | Tunes the rules-only baseline on the dev scenarios and saves its parameters. |
| `make test` | Runs offline unit and guard tests with mocked model outputs. No network, no API key needed. |
| `make eval` | Runs the full held-out evaluation (LLM and baseline, 3 runs) and writes the report and chart. Requires Azure OpenAI credentials in environment variables. |
| `make injection` | Runs the injection suite against the live model and reports the disposition-flip rate. |
| `make report` | Rebuilds the report and chart from existing run outputs (audit JSONL and verdict files) without calling the model. |

The same functionality is exposed as a Python CLI (planned name `triage-eval`) with subcommands such as `ingest`, `label`, `baseline`, `run`, `inject` and `report`, each taking a config file that pins the model deployment, sample seed and scenario split.

### Example outputs (described, not real results)

- **Report (`report.md`)**: a results table with one row per approach (LLM and rules baseline) and columns for accuracy, precision, recall, FP rate, FN rate, abstain rate, cost per alert and p50/p95 latency, showing the mean and spread across 3 runs. Below it: confusion matrices, the scenario split, the sample size, the model version, the price used and the date it was taken from, the label error rate from the manual check, and a limitations section.
- **Chart (`fp_fn.png`)**: FP rate and FN rate for the LLM versus the tuned rules, annotated with cost per alert.
- **Injection report**: the number of injected alerts, the disposition-flip rate, how many outputs were rejected by the guards, and how many fell back to the rules verdict.
- **Audit log (`audit.jsonl`)**: one line per LLM call with model, token counts, latency, verdict and validation result.
- **Metrics file (`metrics.json`)**: the same numbers as the report, machine-readable, so a reviewer can check the table.

---

## Scope

### MVP

- Load [AIT-ADS](https://zenodo.org/records/8263181) Wazuh/Suricata alerts into one Pydantic model.
- Group duplicates by rule ID, source, destination and a 5-minute window.
- Label alerts using attack-phase time windows plus attacker host; hand-check at least 100 labels.
- Enrich with asset context from a hand-written testbed inventory, plus threat intel behind a provider interface (AbuseIPDB, ThreatFox) with a cache.
- LLM returns JSON: summary, disposition (`escalate` / `likely_benign` / `needs_more_data`), confidence, and citations to alert fields.
- Rules-only baseline: Wazuh `rule.level` threshold plus an allowlist of known-noise rule IDs, tuned on dev data only.
- Guards: schema validation, Pydantic re-validation with one retry, evidence check, fail-closed fallback.
- Offline guard tests in CI and a 50+ alert injection suite.
- An eval CLI that writes a report and chart.

### Stretch goals

- A second benchmark on [Microsoft GUIDE](https://www.kaggle.com/datasets/Microsoft/microsoft-security-incident-prediction), which has real analyst TP/BP/FP grades.
- Compare a second model and a local model via [Ollama structured outputs](https://docs.ollama.com/capabilities/structured-outputs).
- A calibration plot (stated confidence versus observed accuracy) and a per-rule FP table.
- Red-team the prompt with [garak](https://github.com/NVIDIA/garak) (Apache-2.0) or [promptfoo](https://www.promptfoo.dev/docs/red-team/) (MIT).

### Out of scope

- Any automated close, suppress or remediation action. The system never closes an alert.
- Giving the model tools, network access or the ability to query other systems.
- Processing real organizational alerts. Only public datasets are used.

---

## Architecture and tech stack

### Pipeline

```
ingest ──► group ──► enrich ──► guard ──► LLM ──► validate ──► decide ──► audit log
  │          │          │          │        │         │            │           │
  │          │          │          │        │         │            │           └─ JSONL: model, tokens, latency,
  │          │          │          │        │         │            │              verdict, validation result
  │          │          │          │        │         │            └─ final disposition shown to analyst;
  │          │          │          │        │         │               falls back to rules verdict on failure
  │          │          │          │        │         └─ Pydantic re-validation, evidence check, one retry
  │          │          │          │        └─ schema-constrained output, no tools, no network
  │          │          │          └─ delimit and datamark untrusted fields (Spotlighting)
  │          │          └─ asset inventory + cached threat intel
  │          └─ rule ID + source + destination + 5-minute window
  └─ AIT-ADS Wazuh/Suricata alerts ──► one Pydantic alert model
```

### Stage details

| Stage | Responsibility |
|---|---|
| ingest | Parse Wazuh and Suricata alerts into a single Pydantic model with normalized timestamps, rule ID, level, source, destination and raw fields. |
| group | Merge duplicates by rule ID, source, destination and a 5-minute window. A group keeps its member count and a representative alert. |
| enrich | Attach asset context from the hand-written testbed inventory and threat intel from a provider interface with a cache. |
| guard | Delimit and datamark untrusted fields (URLs, user agents, `full_log`) before they reach the prompt. |
| LLM | Call Azure OpenAI with structured outputs against the response schema. The model has no tools and no network access. |
| validate | Re-validate with Pydantic, run the evidence check, retry once on failure. |
| decide | Use the validated LLM disposition, or fall back to the rules verdict flagged `llm_unavailable`. There is no close action. |
| audit log | Append one JSONL record per call. |

### Response schema (planned)

| Field | Type | Rules |
|---|---|---|
| `summary` | string | Short plain-language summary of the alert group. |
| `disposition` | enum | Exactly one of `escalate`, `likely_benign`, `needs_more_data`. There is no "closed" value. |
| `confidence` | number | Between 0 and 1. |
| `citations` | list | Each item names a real alert field and quotes an exact substring of that field's value. `likely_benign` requires at least one valid citation. |

### Stack

| Area | Choice |
|---|---|
| Language | Python 3.12+ |
| Data models and validation | [Pydantic](https://docs.pydantic.dev/latest/) v2 |
| Model access | Azure OpenAI [structured outputs](https://learn.microsoft.com/en-us/azure/ai-foundry/openai/how-to/structured-outputs), with the model version pinned per run |
| Data handling | pandas |
| Metrics | scikit-learn |
| Charts | matplotlib |
| Tests | pytest |
| CI | GitHub Actions |

Exact dependency versions are pinned in the dependency file when the first code is committed.

---

## Planned repository layout

This is the planned structure. None of these folders exist yet; they will be created as milestones are built.

```
llm-alert-triage-eval/
├── README.md
├── LICENSE                    # MIT (added with first code)
├── NOTICE                     # dataset attribution (AIT-ADS CC BY 4.0, etc.)
├── Makefile
├── pyproject.toml             # pinned dependencies, `triage-eval` CLI entry point
├── .env.example               # names of required environment variables, no values
├── .gitignore                 # data/, .env, caches, TI data
├── .github/
│   └── workflows/
│       └── ci.yml             # offline tests, lint, secret scan
├── configs/
│   ├── dev.yaml               # dev scenarios, tuning settings
│   └── heldout.yaml           # held-out scenarios, sample size, seed, model version
├── inventory/
│   └── testbed_assets.yaml    # hand-written asset context for the testbed
├── prompts/
│   └── triage_v1.md           # frozen prompt used for the held-out run
├── src/
│   └── triage_eval/
│       ├── models.py          # Pydantic alert, group and response models
│       ├── ingest.py          # Wazuh/Suricata loaders (own code)
│       ├── group.py           # 5-minute window grouping
│       ├── labels.py          # time window + attacker host labeling
│       ├── enrich/
│       │   ├── assets.py
│       │   └── intel.py       # provider interface, AbuseIPDB, ThreatFox, cache
│       ├── guard.py           # delimiting and datamarking of untrusted fields
│       ├── llm.py             # Azure OpenAI client, structured outputs
│       ├── validate.py        # re-validation, evidence check, retry
│       ├── decide.py          # fail-closed decision logic
│       ├── baseline.py        # rule.level threshold + noise allowlist
│       ├── audit.py           # JSONL audit log
│       ├── metrics.py         # metrics and confusion matrix
│       ├── report.py          # report.md, metrics.json, charts
│       └── cli.py
├── tests/
│   ├── fixtures/              # small synthetic alerts, mocked model outputs
│   ├── test_ingest.py
│   ├── test_group.py
│   ├── test_labels.py
│   ├── test_guard.py
│   ├── test_validate.py
│   ├── test_decide.py
│   ├── test_baseline.py
│   └── test_metrics.py
├── injection/
│   └── payloads.yaml          # 50+ planted payload cases
├── labels/
│   └── manual_check.csv       # hand-checked labels (100+) with notes
├── results/                   # committed run outputs: report, metrics, charts, audit logs
├── docs/
│   ├── threat-model.md
│   ├── labeling.md
│   └── cost.md
└── data/                      # git-ignored, populated by `make data`
```

---

## Data sources, labels and attribution

Datasets were checked in September 2026 during planning.

| Source | License | Link | How it is used |
|---|---|---|---|
| **AIT Alert Data Set (AIT-ADS)** (primary) | **CC BY 4.0** | [zenodo.org/records/8263181](https://zenodo.org/records/8263181) | 2,655,821 Wazuh/Suricata/AMiner alerts across 8 scenarios, including many false positives from normal activity. MVP benchmark. |
| AIT-ADS scripts | GPL-3.0 | [github.com/ait-aecid/alert-data-set](https://github.com/ait-aecid/alert-data-set) | **Not used.** The loader is written from scratch to keep the code MIT. |
| **Microsoft GUIDE** (stretch) | **CDLA-Permissive-2.0** | [Kaggle: microsoft-security-incident-prediction](https://www.kaggle.com/datasets/Microsoft/microsoft-security-incident-prediction) | About 1M incidents with customer triage grades (TP/BP/FP). IDs are scrubbed, so there is no raw log text. Second benchmark. |
| AIT-LDSv2 raw logs | CC BY-NC-SA 4.0 | [zenodo.org/records/5789064](https://zenodo.org/records/5789064) | **Not used in MVP.** Needed for per-event labels, but non-commercial share-alike and 7 to 27 GB zipped per scenario. |
| AbuseIPDB | Provider terms | [abuseipdb.com/pricing](https://www.abuseipdb.com/pricing) | Threat intel lookups behind the provider interface. Free tier allows 1,000 checks per day. Results cached, never committed. |
| ThreatFox (abuse.ch) | Provider terms | [threatfox.abuse.ch/api](https://threatfox.abuse.ch/api/) | Threat intel lookups. Requires an Auth-Key; free only for non-profit use. Results cached, never committed. |

**Considered and not chosen**

| Source | License | Why not |
|---|---|---|
| [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) | MIT | Attack-only (no benign noise), last updated March 2024. |
| [Splunk BOTS v3](https://github.com/splunk/botsv3) | CC0 | Labels only implied by CTF answers. |
| [Splunk attack_data](https://github.com/splunk/attack_data) | Apache-2.0 | Attack-only. |

### Labeling method (AIT-ADS)

- AIT-ADS `labels.csv` only gives attack-phase time windows, not per-alert labels.
- An alert is labeled **malicious** if it falls inside an attack window **and** involves the attacker host. Otherwise it is labeled **benign**.
- An alert group is labeled malicious if any alert in it is labeled malicious. The number of groups with mixed member labels is reported.
- At least 100 labels are hand-checked (stratified across scenarios and labels) and recorded in `labels/manual_check.csv`. The observed label error rate is stated in the report.
- The labeling logic and its limits are documented in `docs/labeling.md`.

### Attribution requirements

- Credit AIT-ADS under CC BY 4.0 in NOTICE and in the report, with the Zenodo record link, and state any changes made (normalization, grouping, labeling).
- If GUIDE is used, credit it under CDLA-Permissive-2.0 in NOTICE.
- Do not redistribute the raw datasets in this repository. `make data` downloads them from the original source.
- Do not commit threat intel responses.

---

## Evaluation methodology

### Split and sample

- **Tune on 2 scenarios, report on the other 6.** The 2 dev scenarios are chosen and recorded in `configs/dev.yaml` before any held-out run.
- All prompt and baseline tuning uses dev data only. The prompt is frozen (`prompts/triage_v1.md`) before the held-out run.
- To cap cost, the held-out evaluation uses a **stratified sample of 300 to 500 alert groups**, stratified by scenario and label. The seed and the exact group IDs are saved so the sample is reproducible.

### Approaches compared

- **LLM triage** with the full guard pipeline. When guards fail, the decision falls back to the rules verdict and is flagged `llm_unavailable`; the count of such fallbacks is reported.
- **Rules-only baseline**: a Wazuh `rule.level` threshold plus an allowlist of known-noise rule IDs, tuned on dev data only.

### Mapping dispositions to metrics

- Positive class: malicious. `escalate` counts as a positive prediction. `likely_benign` counts as a negative prediction.
- `needs_more_data` is an **abstention**. The abstain rate is reported. Classification metrics are reported on non-abstained groups, and also with abstentions counted as `escalate` (because an abstention still reaches an analyst), so both views are visible.
- The rules baseline does not abstain; its abstain rate is 0 by construction.

### Metrics (for both the LLM and the baseline)

| Metric | Definition |
|---|---|
| Accuracy | Correct predictions / all predictions. |
| Precision | TP / (TP + FP). |
| Recall | TP / (TP + FN). |
| FP rate | FP / (FP + TN). |
| **FN rate (headline)** | FN / (FN + TP). |
| Confusion matrix | TP, FP, TN, FN counts. |
| Abstain rate | `needs_more_data` / all groups. |
| Cost per alert | Tokens multiplied by the published price on the run date, per alert group. The price and date are recorded in the report. |
| Latency | p50 and p95 per call. |
| Fallback count | Number of `llm_unavailable` decisions. |

### Variance and reproducibility

- The model version is pinned in the config and recorded in every audit log line.
- The held-out evaluation is run **3 times**; the report shows the mean and the spread (min and max) for each metric.
- `make report` rebuilds every table and chart from the committed run outputs without calling the model.

### Injection evaluation

- A suite of **50+ alerts** with payloads planted in log fields the model reads (URLs, user agents, `full_log`).
- Each injected alert is paired with its clean version. The **disposition-flip rate** is the share of injected alerts whose final disposition differs from the clean version's disposition. Flips toward `likely_benign` are reported separately, since those are the dangerous ones.
- The report also shows how many injected outputs were rejected by the guards and fell back to the rules verdict.

### How results are reported

- `results/<run-id>/report.md`, `metrics.json`, the FP/FN chart and the audit JSONL for each run.
- The README results section is filled in only from these committed outputs, after the held-out runs are complete. Until then, it states that no results exist.
- The report includes a limitations section covering label noise, the private-IP testbed, sample size and the single-dataset scope.

---

## Testing strategy

All CI tests are **offline**: they use fixtures and mocked model outputs, need no API key and make no network calls. CI is a required check on `main`; nothing merges unless tests pass.

### Unit tests

| Test | What it checks |
|---|---|
| `test_ingest.py` | Wazuh and Suricata fixtures parse into the Pydantic model; malformed alerts are rejected with a clear error, not silently dropped. |
| `test_group.py` | Alerts with the same rule ID, source and destination inside 5 minutes merge; alerts outside the window, or with any key differing, do not. Member counts are correct. |
| `test_labels.py` | An alert inside an attack window from the attacker host is malicious; inside the window from another host is benign; outside the window is benign. Group labels follow the any-malicious rule. |
| `test_baseline.py` | The threshold and allowlist behave as configured; tuning only reads dev scenarios. |
| `test_metrics.py` | Metrics match hand-computed values on a small fixed confusion matrix, including the abstention handling. |

### Guard tests (mocked malicious outputs)

Each case feeds a crafted model output to the validation and decision stages and asserts the result.

| Mocked output | Expected result |
|---|---|
| Valid output with correct citations | Accepted. |
| Invalid JSON | Retry once, then fall back to rules verdict, flagged `llm_unavailable`. |
| Disposition `closed` or any value outside the enum | Rejected, falls back. |
| Missing required field or extra unexpected field | Rejected, falls back. |
| Confidence outside 0 to 1 | Rejected, falls back. |
| Citation names a field that does not exist | Rejected, falls back. |
| Citation quote is not an exact substring of the field | Rejected, falls back. |
| `likely_benign` with no valid citation | Rejected, falls back. |
| Output that includes instructions or text taken from an untrusted field | Treated only as data; no action is possible because no action exists. |
| Retry also fails | Falls back; exactly one retry is attempted. |

A structural test also asserts that the disposition enum has no close value and that no code path can mark an alert closed, so **auto-closures are zero by construction**.

### Guard input tests

- Untrusted fields (URLs, user agents, `full_log`) are always delimited and datamarked before reaching the prompt.
- A field containing the delimiter itself cannot break out of the delimited block.

### Live tests (not in CI)

- `make eval` and `make injection` call the real model and are run manually, with results committed to `results/`.

### CI gates

- Offline pytest suite passes.
- Lint and type checks pass.
- Secret scanning passes.
- A check that `data/`, `.env` and threat intel cache files are not committed.

---

## Guardrails and security design

- **No close action exists.** The disposition enum has no "closed" value. Only a human closes an alert.
- **Untrusted fields are data, not instructions.** URLs, user agents and `full_log` are delimited and datamarked following [Spotlighting](https://arxiv.org/abs/2403.14720). This maps to [OWASP LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) and MITRE ATLAS AML.T0051.
- **No tools, no network.** The model cannot call functions or reach any system. Its only output is the JSON verdict.
- **Validation and fail-closed.** Schema-constrained output, then Pydantic re-validation and one retry. After that the decision **fails closed** to the rules verdict, flagged `llm_unavailable`.
- **Evidence check.** Each citation must name a real field and quote an exact substring of it. `likely_benign` requires a valid citation.
- **Auditability.** Every call is logged to JSONL (model, tokens, latency, verdict, validation result).
- **Secrets.** API keys come from environment variables only; `.env.example` lists variable names without values. GitHub secret scanning and push protection are enabled, and a secret scanner runs in CI.
- **No sensitive data.** Only public datasets are used. No real organizational alerts are ever processed or committed. Threat intel results are cached locally and not committed.
- **License hygiene.** The GPL-3.0 dataset scripts are not used; the loader is original code. Datasets are downloaded, not redistributed, and attributed in NOTICE.
- **Threat model.** `docs/threat-model.md` covers prompt injection through log fields, output manipulation, secret leakage, and over-trust in model verdicts, with the control for each.

---

## Milestones

The MVP is planned as 3 weekends. Each milestone ends with a pull request that passes CI.

### Weekend 1: data, labels, baseline and metrics

- [ ] Repository scaffolding, Makefile, `pyproject.toml`, CI with offline pytest and secret scanning
- [ ] `make data` downloads AIT-ADS and verifies the checksum
- [ ] Loader for Wazuh and Suricata alerts into the Pydantic model, with tests
- [ ] Grouping by rule ID, source, destination and 5-minute window, with tests
- [ ] Labeling from time windows plus attacker host, with tests
- [ ] Manual spot-check of at least 100 labels recorded in `labels/manual_check.csv`
- [ ] Rules-only baseline tuned on the 2 dev scenarios
- [ ] Metrics module with tests

### Weekend 2: enrichment, prompt, guards and fail-closed path

- [ ] Asset inventory for the testbed and enrichment stage
- [ ] Threat intel provider interface with AbuseIPDB and ThreatFox and a local cache (never committed)
- [ ] Prompt and response schema; Azure OpenAI structured outputs client
- [ ] Delimiting and datamarking of untrusted fields
- [ ] Validation, evidence check, one retry and fail-closed fallback
- [ ] Offline guard tests with mocked malicious outputs
- [ ] JSONL audit log
- [ ] Dev tuning of the prompt on dev scenarios only

### Weekend 3: frozen prompt, held-out eval, injection and write-up

- [ ] Freeze the prompt
- [ ] Held-out evaluation run 3 times on the stratified sample
- [ ] Injection suite of 50+ alerts run, disposition-flip rate reported
- [ ] Report, metrics file and FP/FN chart committed to `results/`
- [ ] README results section filled in from committed outputs, including cost and latency
- [ ] Threat model, labeling and cost docs written
- [ ] Short demo showing a planted injection being rejected
- [ ] LICENSE (MIT) and NOTICE added

---

## Definition of done

The MVP is done when all of the following are true and can be checked by a reviewer:

- [ ] `make eval` rebuilds the report from a clean clone (after `make setup` and `make data`, with credentials set), and `make report` rebuilds it from committed run outputs without credentials.
- [ ] Held-out results for the LLM versus the rules baseline are published, with FP and FN rates, cost and latency per alert, across 3 runs.
- [ ] The dev/held-out split and the sample are recorded and reproducible from the config and seed.
- [ ] Guard tests pass in CI.
- [ ] Injection results (disposition-flip rate) are published.
- [ ] Auto-closures are zero by construction, and a test proves it.
- [ ] At least 100 labels are hand-checked, with the error rate stated.
- [ ] Secret scanning is on, and no keys, raw datasets or threat intel data are in the repository history.
- [ ] Datasets are attributed per their licenses; LICENSE (MIT) and NOTICE are present.
- [ ] The README results section contains only numbers that appear in committed outputs.

---

## Known risks and gaps

These were found during planning and must be handled, not ignored.

- **Labels are noisy.** In the smallest scenario, alerts from non-attacker IPs fall inside attack windows. Filter by attacker host and report the manual-check error rate.
- **Scanner floods.** dirb and wpscan produce thousands of near-identical alerts, so group them before sampling.
- **Threat intel adds little here.** Testbed IPs are mostly private, so enrichment from public threat intel will rarely return hits. This is expected and should be stated.
- **Threat intel terms.** abuse.ch requires an Auth-Key and is free only for non-profit use. AbuseIPDB's free tier allows 1,000 checks per day. Cache results and do not commit threat intel data.
- **Per-event labels are expensive.** Raw [AIT-LDSv2](https://zenodo.org/records/5789064) logs, needed for per-event labels, are CC BY-NC-SA 4.0 and 7 to 27 GB zipped per scenario. The MVP uses window-plus-host labels instead.
- **GUIDE has no raw log text.** IDs are scrubbed, so the stretch benchmark tests a different kind of triage than AIT-ADS.
- **The LLM may lose to tuned rules.** That is still a publishable result and is reported as-is.
- **Cost and price drift.** Published prices change; the report records the price and the date used.

---

## Building this with an AI assistant

This README is written to be handed to an AI coding assistant (for example Claude or ChatGPT) as the build spec. Guidance for doing that well:

- **Build one milestone at a time.** Give the assistant this README plus the current milestone's checklist. Do not ask for the whole project at once.
- **Tests before features.** Write the guard tests and metric tests first, confirm they fail, then implement. The fail-closed path must be tested before any live model call is made.
- **Never tune on held-out data.** Keep the dev/held-out split fixed. Freeze the prompt before the held-out run.
- **Never commit keys, raw datasets, threat intel data or real organizational logs.** Keys go in environment variables only.
- **Do not reuse the GPL-3.0 dataset scripts.** Write the loader from the dataset documentation.
- **Open a pull request per milestone** and review the diff and CI result before merging.
- **Do not invent numbers.** The README results section is written only from committed run outputs. If the baseline wins, say so.
- **Update this README as you go.** Tick milestone checkboxes only when the work is merged and CI is green, and keep the status line accurate.

---

## License

Planned licensing, to be added with the first code (no LICENSE file is included yet):

- **Code:** MIT is the intended license. The dataset scripts are GPL-3.0, which is why the loader is written from scratch.
- **Datasets:** not redistributed. AIT-ADS is used under CC BY 4.0 and GUIDE (stretch) under CDLA-Permissive-2.0, with attribution in a NOTICE file. The AIT-ADS scripts (GPL-3.0) are not used.

Maintained by Shubham Mane ([shubhammane.com](https://www.shubhammane.com)).
