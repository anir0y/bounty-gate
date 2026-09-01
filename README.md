# bounty-gate

**The decision layer for AI-assisted vulnerability disclosure.**

Most AI security tooling optimises finding bugs. This optimises *deciding whether
a finding is worth filing* — the half that determines whether you get paid, and
the half that determines whether you add to the AI-slop pile maintainers are
drowning in.

It is not a scanner. It has no exploitation capability and does not want any.
Point your scanner of choice at the target; point this at the output.

## What's in it

| Component | Does |
|---|---|
| `tools/validate.py --preflight` | Non-interactive mechanical HARD gate. Exit 0 = pass, 2 = BLOCKED. |
| `tools/bounty_rank.py` | Dedup + rank findings by expected reward, not by severity label. |
| `tools/upstream_watch.py` | License-gated competitive intake: watch peer repos, classify what you may legally copy. |
| `skills/triage-validation` | The 7-Question Gate and the never-submit list. |
| `skills/pre-bounty` | Program economics: payout ceiling vs crowd vs setup-moat vs freshness. |
| `skills/report-writing` | Platform-shaped reports (H1 / Bugcrowd / Intigriti / GHSA), CVSS 3.1. |
| `skills/bounty-ranking` | Target prioritisation — "ceiling is not opportunity". |

## The gate

`--preflight` refuses a submission on any of:

- payload schema violations (severity XOR CVSS vector, ecosystem enum, empty `patched_versions`)
- `GATE.json` declaring `confidence: low`, `contestable: true`, or `is_published_cve_itself: true`
- accepted-risk / by-design language in the draft, unless an `OVERRIDE.accepted-risk` rebuttal is present
- evidence floor: a live finding with an empty `poc/`, or a structural claim with no `file:line`
- **the anti-AI-slop gate** — `ai_assisted: true` requires `human_verified_code_path`, high confidence,
  and `references_verified` on every cited advisory ID

That last one exists because a hallucinated GHSA reference once made it into a
draft here — a cited advisory ID that did not exist. Maintainers of large OSS
projects have publicly described being swamped by LLM-generated reports that
look well-formed and describe nothing real. If you point an agent at open
source, this gate is what keeps you out of that pile.

## The license gate

`upstream_watch.py` watches peer projects for ideas and classifies each by the
license the GitHub API reports, failing closed:

- permissive (MIT/Apache-2.0/BSD/ISC) → `PORT_WITH_ATTRIBUTION`
- copyleft (AGPL/GPL/LGPL/MPL) → `IDEA_ONLY` — reimplement, never copy
- no LICENSE, `NOASSERTION`, SSPL/BUSL/Elastic → `BLOCK`

It emits `LICENSE-CHANGE` when a watched repo relicenses under you. Upstream
commit text is treated as untrusted data — sanitised, never sent to an LLM.

## Install

```
/plugin marketplace add anir0y/bounty-gate
/plugin install bounty-gate
```

## Design stance

- **Deterministic where it can be.** Gates are mechanical; judgement is the operator's.
- **Fail closed.** Unknown license, missing evidence, unparseable input → refuse.
- **A zero needs a count.** Every "nothing found" ships with how many things were examined.
- **Degrade loudly.** An unreachable check is an error, never a pass.

## License

MIT. Portions of the parent framework are omitted from this distribution because
their upstream grants no redistribution right.
