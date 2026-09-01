---
description: Triage findings before writing a report. Single-finding = quick 7-Question Gate. Batch = bounty_rank (dedup + estimated-reward ranking) then gate top-down. Kills N/A submissions before they happen. Usage: /triage [repo|findings.json]
---

# /triage

Decide: submit or kill? Two modes.

- **Single finding** — you describe one finding → run the **7-Question Gate** below.
- **Batch / queue** — you have a *union* of findings (a repo you just swept, an `audit_suite --json`
  dump, or a findings file) → run **`bounty_rank`** to dedup + rank by estimated reward + demote
  unverified, then apply the 7-Question Gate **top-down** until the queue drops below your bar.

## When to Use

Before spending time writing a report. If triage passes, run `/validate` for the full 4-gate check, then `/report`.

## Batch mode — rank the queue first (bounty_rank)

When triaging more than one finding, don't eyeball them — **rank first, gate top-down**:

```bash
# from a repo (runs audit_suite for you), or pipe an existing union, or a saved file:
python3 tools/bounty_rank.py --from-audit <repo> [--min-severity HIGH]
python3 tools/audit_suite.py --dir <repo> --json | python3 tools/bounty_rank.py --stdin
python3 tools/bounty_rank.py --findings union.json [--ranker bounty-triage|web2-impact]
```

`bounty_rank` outputs a worst-first queue: each finding gets an `impact_level`, an **estimated
reward band** (`$min-$max`), `rank_reasoning`, and `missing_from_prompt` (what to verify). It
**dedups** to canonical (skip the `(dup)` rows) and **demotes** test-path / unverified-lead findings.

Then, top-down:
1. Take the top **canonical, non-demoted** finding.
2. Run the **7-Question Gate** on it (below). First NO = kill; Q6 fail = downgrade.
3. `missing_from_prompt` tells you what to verify at the sink before it counts.
4. Survivors → `/validate` → `/report`. Stop when `impact_level` drops below your bar (usually medium).

**Guardrails:** the reward band is an **ESTIMATE to prioritize** — never quote it to a program.
**Ranking ≠ verification** — a high rank still needs verify-at-sink + dup-check + a fileable channel
(`sink_verifier` → `validate.py --preflight` → `ghsa_submit`). Static-analysis leads are demoted
precisely because they're unverified; the gate + verify-at-sink is where they earn a submission.

## Usage

```
/triage                 # single finding — describe it, run the 7 questions
/triage <repo>          # batch — bounty_rank the sweep, then gate top-down
/triage union.json      # batch — rank a saved findings union
```

Describe the finding in one sentence. Example:
- "I can read other users' orders by changing user_id in /api/orders/{id}"
- "The /api/export endpoint returns 200 with data even with no auth header"
- "I found X-Forwarded-Host is reflected in the password reset email"

## The 7 Questions (Fast Version)

Answer YES or NO to each. First NO = kill it immediately.

```
Q1: Can I demonstrate this with a real HTTP request RIGHT NOW?
    YES: I have the request/response already
    NO: I need to look at more code first → KILL

Q2: Is this impact type accepted by the program?
    YES: Bug class is on their accepted list
    NO: They explicitly exclude this type → KILL

Q3: Is the vulnerable asset owned by and in scope for the program?
    YES: Domain confirmed in-scope, not third-party
    NO: Third-party service or excluded domain → KILL

Q4: Does this work without admin/privileged access?
    YES: Regular user account is enough
    NO: Requires admin → KILL (99% of programs)

Q5: Is this NOT already known/disclosed/documented behavior?
    YES: Not in changelogs, not in disclosed reports
    NO: It's documented as intended → KILL

Q6: Can I prove impact beyond "technically possible"?
    YES: I have actual data in the response / action completed
    NO: I only have a 200 status or error message → DOWNGRADE

Q7: Is this NOT on the never-submit list?
    YES: It's a real bug class
    NO: Missing headers, self-XSS, open redirect alone, etc. → KILL or CHAIN
```

## Fast Kill Checklist

Kill immediately if ANY of these are true:
```
[ ] "Admin can do X" = not a bug
[ ] "Could theoretically lead to..." = no PoC = not a bug
[ ] Bug requires 3+ preconditions simultaneously
[ ] Finding is a missing header, missing flag, missing DMARC
[ ] SSRF with DNS callback only, no data returned
[ ] Open redirect with no OAuth chain or ATO path
[ ] Self-XSS (only affects your own account)
[ ] Introspection only (no IDOR, no auth bypass shown)
[ ] Rate limit on login/contact/search (Cloudflare covers it)
```

## Conditional Kill (chain required)

If it's on the never-submit list BUT you can chain it:
```
Open redirect → OAuth code theft → ATO        = report the chain
SSRF DNS → internal service access = data     = report the chain
CORS → credentialed data exfil PoC            = report the chain
Prompt injection → IDOR via chatbot           = report the chain
```

If you can't build the chain today → KILL IT.

## Output

**GO:** "All 7 pass. Run /validate for full check, then /report."

**KILL [reason]:**
- "Q1 fails — no HTTP request yet"
- "Q4 fails — requires admin access"
- "Q7 fails — open redirect alone is not submittable. Chain it with OAuth theft first."

**DOWNGRADE:**
- "Q6 — you have 200 status but not actual other-user data. Reproduce with two accounts and show victim's PII in the response before reporting."
