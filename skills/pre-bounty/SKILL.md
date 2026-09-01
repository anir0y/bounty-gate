---
name: pre-bounty
description: >-
  Pre-engagement recon + target prioritization for a bug-bounty/VDP scope. Given a program
  URL (HackerOne, Bugcrowd, Intigriti, YesWeHack, self-hosted VDP) or a pasted scope list,
  it maps the scope, pulls bug history (disclosed reports + CVEs/writeups), extracts the
  in/out boundary gotchas, then scores and RANKS every asset best→worst by opportunity
  (payout ceiling, crowdedness, replication-setup difficulty as a MOAT, freshness) and
  renders a ranked list + asset→setup→ROI view. Use WHENEVER sizing up a program, asked
  "where should I hunt / which target is worth my time / what's least crowded", or handed a
  program link or scope table. Recon-only: it never tests/exploits live targets, and it does
  NOT write/file reports (hand off to report-writing).
---

# Pre-bounty: scope recon & target prioritization

**Provenance:** adapted from the Forefy `pre-bounty` skill (github.com/forefy/.context,
commit 6145d834). This local version keeps the thesis, workflow, sourcing cheatsheet, and
scoring rubric, but **grounds the payout/crowd axes in this repo's tested data tools** instead
of LLM synthesis. See `references/sourcing.md` and `references/scoring.md`.

## Core thesis
Most hunters converge on whatever is cheapest to start testing, so **the crowd is an artifact
of the setup barrier, not of where the bugs are**. Rank the scope by
> **opportunity ≈ (payout ceiling × freshness) ÷ crowd**, with **setup difficulty as a MOAT** —
> a hard-to-reproduce rig keeps competitors out, so it is a *positive* when the ceiling is high.

A high-ceiling asset that is trivial to set up and already swept (many resolved reports) is a
*worse* target than a modest one nobody has tooled up for. Surfacing that inversion is the point.

## Inputs
A program URL, a pasted scope table/asset list, or a description of API/repo access. If the
platform page is JS-rendered (HackerOne/Bugcrowd/Intigriti/YWH all are), **use the browser
tools** (`claude-in-chrome`: navigate → `get_page_text`/`read_page`); `WebFetch` returns an
empty SPA shell. Read BOTH the policy/overview tab and the scope tab. (Confirmed live: one large H1 program
H1 + Akamai pages 403 raw fetchers; the browser is the reliable path.)

## Workflow (5 stages; 1–3 parallelize)
1. **Gather scope** — per asset: name, type, in/out, payout tier + **max reward (ceiling)**,
   **resolved-report share (crowd proxy)**, **last-updated (freshness)**, testing constraints;
   plus program-wide reward table + severity mix. Exact per-platform field locations →
   `references/sourcing.md`.
2. **Mine bug history** — disclosed reports/hacktivity (many programs disclose nothing — say so),
   web-search CVEs/writeups for the recurring bug *class*, note dedup/remediation-project risk.
3. **Boundary gotchas** — adjacent in✅/out❌ pairs, excluded classes, systemic-dedup / payout
   nerfs, testing constraints. Render as a compact in/out table. **Enforce wildcards precisely**
   (e.g. a program can list `foo.example.com` in-scope while `*.example.com` is ineligible → no
   enumeration; that case).
4. **Score & rank** — apply `references/scoring.md` (4 axes → 0–100 + verdict bucket
   Prime·Good·Recon·Skip·Dead). **Ground the hard axes with this repo's tools, don't guess:**
   - **Payout ceiling / channel** → `tools/paid_targets.py <owner/repo>`, `tools/bbp_scope.py`,
     `tools/ibb_scope.py`, `target_profile.vrp_channel_for()` — real, fetched payout-channel data
     (GHSA-only = $0). A finding with no paying channel is deprioritized regardless of ceiling.
   - **Crowd / hardenedness** → `tools/target_profile.py <owner/repo> --class <c>`
     (GO/CAUTION/KILL: OSS-Fuzz density, prior-advisory count, class-already-mined, stars,
     huntr bounty count) + resolved-report share for hosted programs.
   - **Ranking / dedup clustering** → `tools/bounty_rank.py` over the union of findings.
   - **Setup moat + freshness** → your synthesis (label as estimate; these are the axes the
     tools don't compute).
   Keep the hard data (channel, crowd counts, dates) visibly separate from your estimates.
5. **Deliver** — lead with the ranking; see output spec.

## Output spec
Tables + widgets are load-bearing; prose only connects them. Never restate a cell in a sentence.
Deliver in order: (1) program header — one line; (2) boundary gotchas in/out **table** + ≤3-4
one-line nerf bullets; (3) severity economics **table** (severity·share·avg·range) + one italic
"where crits actually land"; (4) **ranked list** best→worst (rank, verdict chip, ceiling+channel,
setup time, crowd %, freshness, one-line why) — see `references/sankey.md`; (5) **ranked
asset→setup→ROI Sankey** (`references/sankey.md` template; needs a dataviz/`show_widget` tool —
if unavailable, emit the ranked table only and say so); (6) **verdict** ≤120 words: top 1–3
picks (why now), the ceiling≠opportunity inversion in one sentence, any technique-development
target.

### Prose discipline
Header = 1 line; each table ≤1 lead-in + ≤1 follow-up; verdict ≤120 words. No row-by-row
narration of the ranked list (that's the widget's job). One sources line (CVE/writeup links) at
the end. When in doubt, move the sentence into a cell or delete it.

## Judgment / guardrails
- **Estimate, but flag estimates.** Ceiling/crowd/dates are hard data from the program or the
  tools; setup-time and opportunity scores are synthesis — keep them visibly separate. Never
  invent numbers; a labeled estimate beats a fake data point.
- **Scale to the ask** — "quick take" → ranked list is enough; "full workup" → all artifacts.
- **Authorized-recon lane only** — reads public program data + public vuln history to prioritize.
  It does NOT test, exploit, or probe live targets; reproduction happens later under program
  rules. Respect scope exclusions/wildcards absolutely.
- Pairs with `report-writing` for the next phase; do not file reports here.
