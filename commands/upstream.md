# /upstream — harvest ideas from watched repos, license-gated

Automates the _Daily check protocol_ in `improvement_watchlist.md`.

```bash
python3 tools/upstream_watch.py --check                    # poll all watched repos
python3 tools/upstream_watch.py --digest --gaps-only       # only signals we don't name-match
python3 tools/upstream_watch.py --check --only usestrix/strix PurpleAILAB/Decepticon
python3 tools/upstream_watch.py --selftest                 # parser + license-gate controls
```

Runs daily 08:30 via `com.seethaai.upstreamwatch` → `tools/upstream_watch.sh`
(silent unless something shipped or a repo went unreachable).

## Adding a repo to the watch

Add a row to the `## Watch table` in `improvement_watchlist.md`. That file is the
single source of truth — the watcher parses repo slugs straight out of it, so
there is no second config to drift. License is fetched **live** from the GitHub
API on every run, never hand-maintained.

## The license gate — read this before porting anything

Policy is derived from the SPDX id and **fails closed**:

| Policy | Licenses | What you may do |
|---|---|---|
| `PORT_WITH_ATTRIBUTION` | MIT, Apache-2.0, BSD, ISC, 0BSD, CC0 | Copy code **only** with an `ATTRIBUTIONS.md` row (upstream path + commit) and the upstream NOTICE preserved |
| `IDEA_ONLY` | AGPL, GPL, LGPL, MPL-2.0 | **Never copy code.** Read for technique, reimplement from a blank file. Copying makes our derived work copyleft |
| `BLOCK` | no LICENSE, `NOASSERTION`, SSPL, BUSL, Elastic | Nothing may be copied; the idea itself needs a manual legal look |

A repo can change license between runs — `LICENSE-CHANGE` is emitted as a
high-relevance signal for exactly that reason.

## What the verdicts mean

- `NO-MATCH` — no component of ours matches by name. **Read these first.**
- `NAME-MATCH` — our component *names* overlap. This is **not** a coverage
  claim: `sandbox_audit.py` name-matches "sandbox isolation" while we own no
  sandbox at all. Verify the named components yourself.

The tool is deterministic and never sends upstream text to an LLM — commit
messages and release notes are third-party attacker-controllable text, treated
as data, sanitised (control chars, bidi overrides, instruction phrases defanged)
and length-capped.

## What it never does

It does not clone, copy, patch, or write into `skills/` `tools/` `commands/`.
Per `improvement_watchlist.md`: *"we borrow patterns/functions, we do not adopt
pre-1.0 external projects as core infra. Steal the idea, implement it natively."*
And per `daily_learn.sh`: code changes are only ever **proposed**.

Promotion is the operator's, one lead at a time:

```bash
python3 tools/upstream_watch.py --promote <lead_id> \
  --component tools/agent_graph.py \
  --verdict "adopt pheromone decay for lead staleness; AGPL so reimplement"
```

That appends one line to the _Harvested ideas_ log — prose into the doctrine
file, never code into the framework.

## Failure discipline

- A zero is always printed with a parse count. 0 repos parsed = exit 3 + iMessage
  alarm, never "all quiet" (a silently-empty watch list is a fail-open).
- An unreachable repo is `ERROR`, explicitly *not* "no change".
- Unknown license → `BLOCK`.
