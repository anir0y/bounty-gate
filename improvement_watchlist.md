# Improvement Watchlist

Repos this install tracks for ideas. `tools/upstream_watch.py` parses the
**Watch table** below — this file is the single source of truth, so adding a row
enrolls the repo. Nothing else needs editing.

The license of each repo is fetched **live** from the GitHub API on every run and
decides what you may legally do with what you find:

| Policy | Licenses | What you may do |
|---|---|---|
| `PORT_WITH_ATTRIBUTION` | MIT, Apache-2.0, BSD, ISC, 0BSD, CC0 | Copy code **only** with attribution + upstream NOTICE preserved |
| `IDEA_ONLY` | AGPL, GPL, LGPL, MPL-2.0 | **Never copy code** — read for technique, reimplement from a blank file |
| `BLOCK` | no LICENSE, `NOASSERTION`, SSPL, BUSL, Elastic | Nothing may be copied; the idea needs a legal look |

## Watch table

| Repo | ★ | What it is | What to look for |
|---|---|---|---|
| [usestrix/strix](https://github.com/usestrix/strix) | 59.8k | OSS AI pentester + commercial platform. Apache-2.0, Python. Own Docker sandbox, Caido proxy, browser, Python exploit runtime. Ships skills for coding agents | Execution-plane design; spec-driven API testing (OpenAPI/Postman as a target type); PR-diff scope mode + SARIF for CI; local run viewer with a per-run token |
| [PurpleAILAB/Decepticon](https://github.com/PurpleAILAB/Decepticon) | 5.4k | LangGraph red-team agent, Apache-2.0. Agents organised by kill-chain phase, Kali sandbox on an isolated network, Neo4j knowledge graph | Two-network isolation (management plane vs operational sandbox); tmux interactive-shell driver with prompt detection; agent-driven container lifecycle; pre-engagement RoE/OPPLAN generation; per-agent model tiering with fallback |
| [Armur-Ai/Pentest-Swarm-AI](https://github.com/Armur-Ai/Pentest-Swarm-AI) | 2.4k | Go single binary, **AGPL-3.0**, self-labelled alpha. Stigmergic blackboard swarm with pheromone decay | **AGPL — patterns only, never copy code.** Per-finding-type pheromone half-lives (stale leads dying on a clock); scope enforced at BOTH the tool layer and the executor; cleanup registry registered before execution; honest stable/beta/alpha status labels |

Add your own rows in the same shape. Anything with a GitHub link in the first
cell gets watched; a row without one is reported as unparsed rather than
silently dropped.

## Daily check protocol

```bash
python3 tools/upstream_watch.py --check              # poll everything
python3 tools/upstream_watch.py --digest --gaps-only # only what you don't already have
```

Signals are `NO-MATCH` (nothing of yours matches by name — read first) or
`NAME-MATCH` (names overlap; **not** a coverage claim — verify it yourself).

## Harvested ideas (log)

Append one line per adopted idea, with the date, the source ref, and the
component it maps to:

```bash
python3 tools/upstream_watch.py --promote <lead_id> \
  --component tools/your_file.py --verdict "adopt / build-our-own / skip + why"
```
