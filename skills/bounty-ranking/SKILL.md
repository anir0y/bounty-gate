---
title: Bounty-rank post-processing — dedup → canonical, rank by estimated reward, demote unverified
target_personas: ['bug-bounty hunter', 'triage']
attack_surface: 'the findings UNION from audit_suite / detectors / agents'
last_updated: 2026-07-22
related:
  - tools/bounty_rank.py
  - tools/audit_suite.py
  - skills/triage-validation/SKILL.md
---

# Bounty-rank post-processing

The detectors + agents produce a *union* of findings; `audit_suite` only gives a severity **count**.
`bounty_rank` adds the triage layer that answers **what to look at first**: it **dedups** the union
into canonical clusters, then **ranks by estimated bounty impact** ($ range + reasoning), and
**demotes theoretical / test-only / unverified findings last** — the verify-before-rating discipline,
mechanized.

Clean-room reimplementation of the post-processing PATTERN from `Kritt-ai/open-kritt` (AGPL-3.0 —
patterns only, **no code copied**): its `dedupe_schema` (cluster→canonical) + `ranker_schema`
(`impact_level`/`minimum_reward`/`maximum_reward`/`rank_reasoning`/`missing_from_prompt`) + swappable
severity-ranker **prompts**.

## Run it
```bash
python3 tools/audit_suite.py --dir repo --json | python3 tools/bounty_rank.py --stdin
python3 tools/bounty_rank.py --from-audit repo [--min-severity HIGH]     # runs audit_suite for you
python3 tools/bounty_rank.py --findings union.json --ranker web2-impact --json
python3 tools/bounty_rank.py --list-rankers
```

## What it does
1. **Dedup → canonical.** Clusters findings by `(file, line-bucket, detector, rule)`; the
   highest-severity / lowest-line member is `dedupe_is_canonical`, the rest carry the same
   `dedupe_cluster_id` and are marked `(dup)`. Deterministic (no LLM).
2. **Rank by estimated reward.** Each finding gets `impact_level` (critical…informational),
   a `minimum_reward`/`maximum_reward` band (a rough **estimate to prioritize**, not a promise),
   `rank_reasoning`, and `missing_from_prompt` (what to verify before submitting). Sorted worst-first.
3. **Demote (verify-before-rating).** −2 levels for a **test/example/fixture path** (not production);
   −1 level for a **static LEAD / verify-at-sink-pending** finding (unverified). Likely FPs sort last.
   This operationalizes the ranker prompt deterministically.

## Ranker prompts (`--ranker`, swappable)
A ranker is a named **prompt**, not code — swap the triage lens without touching the tool:
- **`bounty-triage`** (default) — conservative production-impact; demote theoretical/test-only/
  privileged-local/unverified; rank likely FPs last. (Encodes SeethaAi's core discipline.)
- **`web2-impact`** — rewards exploited chains: SSRF→cloud-metadata, IDOR→write/privesc, auth bypass;
  demotes reflected-only / self-only / config-hardening.

Add your own in `RANKERS`. Prompts are used by `--llm` (below) and their demotion rules inform the
deterministic heuristic.

## `--llm` refinement (optional)
Deterministic ranking runs always. `--llm` refines `impact_level`/reward/`rank_reasoning`/order via a
pluggable `MODEL_FN` (wire to `brain.py`/`opencode`); it **falls back to the heuristic** if no model
is wired or the call fails. The heuristic is the tested, offline default.

## Reserved keys → dashboard tabs (open-kritt convention)
A finding may carry two reserved Markdown keys, **preserved through ranking**:
- **`_reserved_report`** — a Markdown report → render as a **Report** tab on the finding.
- **`_reserved_poc`** — a Markdown PoC → render as a **PoC** tab.
`bounty_rank` surfaces `[report]`/`[poc]` indicators in its output and keeps the keys in `--json`.
Populate them from `report_generator.py` / `sink_verifier.py`. The SeethaAi dashboard renders the
tabs in **`dashboard/src/components/FindingTabs.jsx`** (used by `FindingsTable` — reads
`f._reserved_report ?? f.report` and `f._reserved_poc ?? f.poc`; nothing renders when neither is
present). Keep the reserved key *names* exact so producer → render stays wired.

## Hard rules
- **Reward bands are ESTIMATES** for ordering only — never quote them to a program; actual payout is
  the program's call. The tool prints this caveat.
- **Ranking is not verification.** A high `bounty_rank` still requires verify-at-sink + a dup-check +
  a fileable channel before submission (`sink_verifier` → `validate.py --preflight` → `ghsa_submit`).
  `missing_from_prompt` names what's outstanding.
- Demotion is deliberately conservative (demote-when-uncertain) — over-ranking is the worse error.

## Cross-references
- `tools/bounty_rank.py` — the pass. `tools/audit_suite.py` — the findings union it consumes.
- `skills/triage-validation/SKILL.md` — the 7-Question Gate / never-submit list (bounty_rank feeds it).
- Provenance: clean-room from `Kritt-ai/open-kritt` (AGPL) — patterns only. See `reference_open_kritt_eval_2026-07-22` (memory).
