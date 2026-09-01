#!/usr/bin/env python3
"""
validate.py — Interactive bug validation assistant.
Walks through the 4 validation gates, checks for duplicates, calculates CVSS,
and generates a skeleton HackerOne report.

Usage:
  python3 tools/validate.py
  python3 tools/validate.py --output findings/myreport.md
"""

import argparse
import json
import os
import re
import ssl
import sys
import urllib.request
import urllib.error
from datetime import datetime

# macOS: Python may not have system SSL certs. Use unverified context for API queries.
_SSL_CTX = ssl.create_default_context()
try:
    import certifi
    _SSL_CTX = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    _SSL_CTX.check_hostname = False
    _SSL_CTX.verify_mode = ssl.CERT_NONE

# ─── Color codes ──────────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

# ─── CVSS 3.1 scoring ─────────────────────────────────────────────────────────

CVSS_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {
        "N":  {"U": 0.85, "C": 0.85},
        "L":  {"U": 0.62, "C": 0.68},
        "H":  {"U": 0.27, "C": 0.50},
    },
    "UI": {"N": 0.85, "R": 0.62},
    "C":  {"H": 0.56, "L": 0.22, "N": 0.00},
    "I":  {"H": 0.56, "L": 0.22, "N": 0.00},
    "A":  {"H": 0.56, "L": 0.22, "N": 0.00},
}


def calculate_cvss(av, ac, pr, ui, s, c, i, a) -> tuple[float, str]:
    """Calculate CVSS 3.1 base score and return (score, vector_string)."""
    scope_changed = (s == "C")

    av_w = CVSS_WEIGHTS["AV"][av]
    ac_w = CVSS_WEIGHTS["AC"][ac]
    pr_w = CVSS_WEIGHTS["PR"][pr][s]
    ui_w = CVSS_WEIGHTS["UI"][ui]
    c_w  = CVSS_WEIGHTS["C"][c]
    i_w  = CVSS_WEIGHTS["I"][i]
    a_w  = CVSS_WEIGHTS["A"][a]

    isc_base = 1 - (1 - c_w) * (1 - i_w) * (1 - a_w)

    if scope_changed:
        isc = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)
    else:
        isc = 6.42 * isc_base

    if isc <= 0:
        return 0.0, f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"

    exploitability = 8.22 * av_w * ac_w * pr_w * ui_w

    if scope_changed:
        base_score = min(1.08 * (isc + exploitability), 10)
    else:
        base_score = min(isc + exploitability, 10)

    # Round up to 1 decimal
    base_score = round(base_score * 10) / 10

    vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
    return base_score, vector


def severity_from_score(score: float) -> str:
    if score == 0.0:  return "NONE"
    if score < 4.0:   return "LOW"
    if score < 7.0:   return "MEDIUM"
    if score < 9.0:   return "HIGH"
    return "CRITICAL"


# ─── HackerOne dup check ──────────────────────────────────────────────────────

def check_h1_dups(program_handle: str, vuln_keyword: str) -> list[dict]:
    """Search HackerOne for potential duplicates."""
    if not program_handle:
        return []

    query = {
        "query": f"""{{
          hacktivity_items(
            first: 10,
            order_by: {{ field: popular, direction: DESC }},
            where: {{
              team: {{ handle: {{ _eq: "{program_handle}" }} }},
              report: {{ title: {{ _icontains: "{vuln_keyword}" }} }}
            }}
          ) {{
            nodes {{
              ... on HacktivityDocument {{
                report {{
                  title
                  severity_rating
                  disclosed_at
                  url
                  state
                }}
              }}
            }}
          }}
        }}"""
    }
    try:
        req = urllib.request.Request(
            "https://hackerone.com/graphql",
            data=json.dumps(query).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10, context=_SSL_CTX) as resp:
            data = json.loads(resp.read().decode())
        nodes = (data.get("data") or {}).get("hacktivity_items", {}).get("nodes", [])
        results = []
        for node in nodes:
            r = node.get("report")
            if r:
                results.append(r)
        return results
    except Exception:
        return []


# ─── Interactive prompt helpers ───────────────────────────────────────────────

def ask(prompt: str, default: str = "") -> str:
    if default:
        val = input(f"  {prompt} [{default}]: ").strip()
        return val if val else default
    return input(f"  {prompt}: ").strip()


def ask_yn(prompt: str, default: bool = True) -> bool:
    yn = "Y/n" if default else "y/N"
    val = input(f"  {prompt} [{yn}]: ").strip().lower()
    if not val:
        return default
    return val in ("y", "yes")


def ask_choice(prompt: str, choices: list[tuple[str, str]]) -> str:
    """Ask user to pick from labeled choices. Returns the choice key."""
    print(f"\n  {prompt}")
    for key, label in choices:
        print(f"    {CYAN}{key}{RESET}) {label}")
    while True:
        val = input(f"  Choice: ").strip().upper()
        if val in [k for k, _ in choices]:
            return val
        print(f"  {YELLOW}Invalid — enter one of: {', '.join(k for k,_ in choices)}{RESET}")


def section(title: str):
    print(f"\n{BOLD}{BLUE}{'─' * 60}{RESET}")
    print(f"{BOLD}{BLUE}  {title}{RESET}")
    print(f"{BOLD}{BLUE}{'─' * 60}{RESET}\n")


def gate_header(n: int, name: str, status: str | None = None):
    status_str = ""
    if status == "PASS":
        status_str = f" {GREEN}✓ PASS{RESET}"
    elif status == "FAIL":
        status_str = f" {RED}✗ FAIL{RESET}"
    print(f"\n{BOLD}Gate {n}: {name}{RESET}{status_str}")
    print(f"{'─' * 40}")


# ─── Gate implementations ─────────────────────────────────────────────────────

def gate1_is_real() -> tuple[bool, dict]:
    gate_header(1, "Is It Real?")
    print("  Can you reproduce the bug from scratch — clean browser, no Burp artifacts?")
    print()
    repro3   = ask_yn("Reproduced 3/3 times deterministically?")
    no_burp  = ask_yn("Works with plain curl or fresh browser (not just in Burp)?")
    no_state = ask_yn("No unusual preconditions (doesn't require specific timing or race)?")
    rtfm     = ask_yn("Checked documentation — this isn't expected/documented behavior?")

    passed = repro3 and no_burp and no_state and rtfm
    notes = {
        "repro_3_3": repro3,
        "works_without_proxy": no_burp,
        "no_special_state": no_state,
        "not_documented_behavior": rtfm,
    }

    if not passed:
        print(f"\n  {RED}GATE 1 FAIL: Not reliably reproducible.{RESET}")
        print(f"  {DIM}Do not submit yet. Verify the bug is deterministic first.{RESET}")
    else:
        print(f"\n  {GREEN}GATE 1 PASS{RESET}")

    return passed, notes


def gate2_in_scope(program_handle: str) -> tuple[bool, dict]:
    gate_header(2, "Is It In Scope?")
    print("  Check the program scope page explicitly — don't assume.")
    print()

    asset_in_scope  = ask_yn("The affected domain/asset is listed on the program's scope page?")
    not_excluded    = ask_yn("Not in the out-of-scope list (check staging, third-party exclusions)?")
    version_ok      = ask_yn("Affected software version is in scope (not an excluded old version)?")

    if program_handle:
        print(f"\n  {DIM}Checking HackerOne scope for '{program_handle}'...{RESET}")
        try:
            query = {
                "query": f'{{ team(handle: "{program_handle}") {{ policy_scopes(archived: false) {{ edges {{ node {{ asset_type asset_identifier eligible_for_bounty }} }} }} }} }}'
            }
            req = urllib.request.Request(
                "https://hackerone.com/graphql",
                data=json.dumps(query).encode(),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=8, context=_SSL_CTX) as resp:
                data = json.loads(resp.read().decode())
            scopes = (data.get("data") or {}).get("team", {}).get("policy_scopes", {}).get("edges", [])
            if scopes:
                print(f"\n  {CYAN}In-scope assets for {program_handle}:{RESET}")
                for edge in scopes[:10]:
                    node = edge.get("node", {})
                    bounty = " (eligible)" if node.get("eligible_for_bounty") else ""
                    print(f"    • [{node.get('asset_type','?')}] {node.get('asset_identifier','?')}{bounty}")
        except Exception:
            print(f"  {YELLOW}Could not fetch scope (network error){RESET}")

    passed = asset_in_scope and not_excluded and version_ok
    notes = {
        "asset_in_scope": asset_in_scope,
        "not_excluded": not_excluded,
        "version_ok": version_ok,
    }

    if not passed:
        print(f"\n  {RED}GATE 2 FAIL: May be out of scope.{RESET}")
        print(f"  {DIM}Confirm scope before submitting.{RESET}")
    else:
        print(f"\n  {GREEN}GATE 2 PASS{RESET}")

    return passed, notes


def gate3_exploitable() -> tuple[bool, dict]:
    gate_header(3, "Is It Exploitable?")
    print("  Can you demonstrate concrete impact without unrealistic preconditions?")
    print()

    concrete_impact  = ask_yn("Can you show concrete impact (not just 'theoretically an attacker could')?")
    no_unrealistic   = ask_yn("No unrealistic preconditions (not 'must be admin already', not 'victim must run JS')?")
    can_demonstrate  = ask_yn("Have proof you can show a triager (screenshot, curl, PoC)?")

    print()
    print("  What is the concrete impact? (be specific)")
    impact_desc = ask("Describe the impact")

    passed = concrete_impact and no_unrealistic and can_demonstrate
    notes = {
        "concrete_impact": concrete_impact,
        "no_unrealistic_preconditions": no_unrealistic,
        "has_proof": can_demonstrate,
        "impact_description": impact_desc,
    }

    if not passed:
        print(f"\n  {RED}GATE 3 FAIL: Exploitability not demonstrated.{RESET}")
        print(f"  {DIM}Build a working PoC before submitting.{RESET}")
    else:
        print(f"\n  {GREEN}GATE 3 PASS{RESET}")

    return passed, notes


def gate4_not_dup(vuln_type: str, endpoint: str, program_handle: str) -> tuple[bool, dict]:
    gate_header(4, "Is It a Dup?")
    print("  Check HackerOne disclosed reports, GitHub issues, and recent changelog.")
    print()

    # Auto-check HackerOne
    h1_results = []
    if program_handle and vuln_type:
        print(f"  {DIM}Searching HackerOne for '{vuln_type}' in '{program_handle}'...{RESET}")
        h1_results = check_h1_dups(program_handle, vuln_type)
        if h1_results:
            print(f"\n  {YELLOW}Found {len(h1_results)} potentially similar disclosed reports:{RESET}")
            for r in h1_results:
                disclosed = (r.get("disclosed_at") or "")[:10]
                print(f"    • [{r.get('severity_rating','?').upper()}] {r.get('title','')} ({disclosed})")
                if r.get("url"):
                    print(f"      {DIM}{r['url']}{RESET}")
        else:
            print(f"  {GREEN}No similar disclosed reports found on HackerOne.{RESET}")

    print()
    not_disclosed   = ask_yn("Not found in HackerOne disclosed reports for this program?")
    not_in_issues   = ask_yn("Not already fixed/reported in GitHub issues or CHANGELOG?")
    checked_history = ask_yn("Checked git log for recent security fixes with this pattern?")

    passed = not_disclosed and not_in_issues and checked_history
    notes = {
        "not_in_h1_disclosed": not_disclosed,
        "not_in_github_issues": not_in_issues,
        "checked_git_history": checked_history,
        "h1_similar_reports": [r.get("title") for r in h1_results],
    }

    if not passed:
        print(f"\n  {RED}GATE 4 FAIL: Possible duplicate.{RESET}")
        print(f"  {DIM}Verify it's not already known before submitting.{RESET}")
    else:
        print(f"\n  {GREEN}GATE 4 PASS{RESET}")

    return passed, notes


# ─── CVSS interactive scorer ──────────────────────────────────────────────────

def score_cvss() -> tuple[float, str, dict]:
    section("CVSS 3.1 Scoring")

    av = ask_choice("Attack Vector (AV)", [
        ("N", "Network — exploitable remotely over internet"),
        ("A", "Adjacent — requires same network segment"),
        ("L", "Local — requires local access to system"),
        ("P", "Physical — requires physical device access"),
    ])
    ac = ask_choice("Attack Complexity (AC)", [
        ("L", "Low — reliable, no special conditions"),
        ("H", "High — requires specific conditions or timing"),
    ])
    pr = ask_choice("Privileges Required (PR)", [
        ("N", "None — no account needed"),
        ("L", "Low — regular user account"),
        ("H", "High — admin / elevated privileges"),
    ])
    ui = ask_choice("User Interaction (UI)", [
        ("N", "None — no victim interaction required"),
        ("R", "Required — victim must click link, load page, etc."),
    ])
    s  = ask_choice("Scope (S)", [
        ("U", "Unchanged — stays in same security context"),
        ("C", "Changed — impacts resources beyond attacker's authorization scope"),
    ])
    c  = ask_choice("Confidentiality Impact (C)", [
        ("H", "High — complete loss (all data readable)"),
        ("L", "Low — partial disclosure"),
        ("N", "None"),
    ])
    i  = ask_choice("Integrity Impact (I)", [
        ("H", "High — complete loss (attacker can write/modify anything)"),
        ("L", "Low — some modification possible"),
        ("N", "None"),
    ])
    a  = ask_choice("Availability Impact (A)", [
        ("H", "High — complete shutdown/denial"),
        ("L", "Low — reduced performance"),
        ("N", "None"),
    ])

    score, vector = calculate_cvss(av, ac, pr, ui, s, c, i, a)
    sev = severity_from_score(score)

    sev_color = RED if sev in ("CRITICAL", "HIGH") else (YELLOW if sev == "MEDIUM" else GREEN)
    print(f"\n  {BOLD}CVSS Score: {sev_color}{score} {sev}{RESET}")
    print(f"  {BOLD}Vector:{RESET} {vector}")

    params = {"AV": av, "AC": ac, "PR": pr, "UI": ui, "S": s, "C": c, "I": i, "A": a}
    return score, vector, params


# ─── Report skeleton generator ────────────────────────────────────────────────

def generate_report_skeleton(info: dict) -> str:
    """Generate a HackerOne-style report skeleton."""
    vuln_type  = info.get("vuln_type", "VULN_TYPE")
    target     = info.get("target", "TARGET")
    endpoint   = info.get("endpoint", "ENDPOINT")
    impact     = info.get("impact", "IMPACT_DESCRIPTION")
    score      = info.get("cvss_score", 0.0)
    vector     = info.get("cvss_vector", "CVSS:3.1/...")
    sev        = severity_from_score(score)
    date       = datetime.now().strftime("%Y-%m-%d")

    return f"""# {vuln_type} on {endpoint} — [fill in specific impact]

**Program:** {target}
**Severity:** {sev} ({score}) — {vector}
**Date Found:** {date}

---

## Summary

[2-3 sentences. What is the vulnerability? Where is it? What can an attacker do?]

The `{endpoint}` endpoint [describe the vulnerability in one sentence]. By [describe
the attack], an attacker can [describe the concrete impact].

---

## Steps to Reproduce

> **Setup:** Create two accounts — Attacker (email: attacker@test.com) and Victim (email: victim@test.com).

1. Log in as **Attacker**
2. [Step 2 — specific action]
3. [Step 3 — specific request with actual parameter names]
   ```
   [INSERT ACTUAL HTTP REQUEST HERE — e.g., curl command or Burp request]
   ```
4. [Step 4 — what to observe in the response]
5. Confirm: [what proves the vulnerability — e.g., victim's data appears in response]

---

## Proof of Concept

**Request:**
```http
[PASTE ACTUAL REQUEST — METHOD, URL, HEADERS, BODY]
```

**Response:**
```json
[PASTE ACTUAL RESPONSE SHOWING THE VULNERABILITY]
```

**Screenshots:** [attach: TARGET-{vuln_type.lower().replace(' ','-')}-step1.png, etc.]

---

## Impact

{impact}

[Quantify: number of users affected, type of data exposed, what actions an attacker can take]

---

## CVSS

**Vector:** `{vector}`
**Score:** {score} ({sev})

| Metric | Value | Rationale |
|---|---|---|
| Attack Vector | {info.get('cvss_params', {}).get('AV', '?')} | [explain] |
| Attack Complexity | {info.get('cvss_params', {}).get('AC', '?')} | [explain] |
| Privileges Required | {info.get('cvss_params', {}).get('PR', '?')} | [explain] |
| User Interaction | {info.get('cvss_params', {}).get('UI', '?')} | [explain] |
| Scope | {info.get('cvss_params', {}).get('S', '?')} | [explain] |
| Confidentiality | {info.get('cvss_params', {}).get('C', '?')} | [explain] |
| Integrity | {info.get('cvss_params', {}).get('I', '?')} | [explain] |
| Availability | {info.get('cvss_params', {}).get('A', '?')} | [explain] |

---

## Fix Recommendation

[Specific code-level fix — name the file, function, and what to change]

Example: In `path/to/file.ts`, the `functionName` function should verify
`resource.user_id === req.user.id` before returning data.

---

## Validation Notes

| Gate | Result |
|---|---|
| Is it real? | {'PASS' if info.get('gate1_pass') else 'FAIL'} |
| Is it in scope? | {'PASS' if info.get('gate2_pass') else 'FAIL'} |
| Is it exploitable? | {'PASS' if info.get('gate3_pass') else 'FAIL'} |
| Is it a dup? | {'PASS' if info.get('gate4_pass') else 'FAIL'} |
"""


# ─── Mechanical pre-submit gate (GHSA disclosure flow) ────────────────────────
#
# Non-interactive HARD gate for the autonomous incomplete-fix disclosure flow.
# Run BEFORE any `gh api ... security-advisories/reports` POST. Exit 0 = submit
# allowed; exit 2 = BLOCKED (do not submit). It exists because, under sustained
# /goal count-pressure, borderline HELD findings (e.g. documented accepted-risk)
# got routed to submission via an operator menu. This makes "when in doubt, HOLD"
# mechanical instead of advisory.
#
# A report dir (reports/<slug>/) must contain:
#   payload.json   — the GHSA report body (summary, description, vulnerabilities,
#                    cvss_vector_string XOR severity, cwe_ids)
#   GATE.json      — {confidence: high|medium|low, contestable: bool,
#                    dup_checked: bool, is_published_cve_itself: bool,
#                    poc_type: live|structural-absence, atlas_ids?: [AML.Txxxx, ...]}
#   evidence       — poc/ dir (non-empty) for poc_type=live, OR EVIDENCE.md with
#                    a file:line citation for poc_type=structural-absence
#   one of *.md    — the human-readable draft (GHSA_DRAFT.md / GHSA_SUBMISSION.md)
#
# Override (conscious, documented): a hit on the accepted-risk scan blocks unless
# reports/<slug>/OVERRIDE.accepted-risk exists with a written rebuttal.

# Signals that the gap is the project's documented/intended behavior — the exact
# class that produces triage pushback. Tuned to catch the skillctl miss.
_ACCEPTED_RISK_SIGNALS = [
    "by design", "by-design", "accepted risk", "accepted-risk", "acceptable for",
    "won't fix", "wont fix", "wontfix", "working as intended", "intended behavior",
    "intended behaviour", "out of scope", "out-of-scope", "known limitation",
    "documented as", "is trusted", "are trusted", "layout is trusted",
    "not a vulnerability", "not considered a vulnerability", "deliberately",
]

# The ONLY ecosystem values GitHub's security-advisories API accepts (it 422s otherwise).
_GH_ECOSYSTEMS = {
    "rubygems", "npm", "pip", "maven", "nuget", "composer", "go", "rust",
    "erlang", "actions", "pub", "other", "swift",
}
# Common spellings from OSV/other sources → the GitHub name (lmdeploy 422'd on "PyPI").
_OSV_TO_GH_ECO = {
    "pypi": "pip", "crates.io": "rust", "crates": "rust", "packagist": "composer",
    "hex": "erlang", "go": "go", "golang": "go", "rubygems.org": "rubygems",
    "nuget.org": "nuget", "maven central": "maven", "swifturl": "swift", "githubactions": "actions",
}


def _pf_fail(msg: str) -> None:
    print(f"  {RED}✗ BLOCK{RESET} {msg}")


def _pf_ok(msg: str) -> None:
    print(f"  {GREEN}✓{RESET} {msg}")


def _pf_warn(msg: str) -> None:
    print(f"  {YELLOW}⚠ WARN{RESET} {msg}")


def preflight_gate(report_dir: str) -> int:
    """Mechanical hard gate. Returns 0 (pass) or 2 (blocked)."""
    print(f"\n{BOLD}{CYAN}{'═' * 60}{RESET}")
    print(f"{BOLD}{CYAN}  GHSA Pre-Submit Gate — {report_dir}{RESET}")
    print(f"{BOLD}{CYAN}{'═' * 60}{RESET}\n")
    blocks: list[str] = []

    if not os.path.isdir(report_dir):
        print(f"  {RED}✗ BLOCK{RESET} report dir not found: {report_dir}")
        return 2

    # ── Gate A: payload.json schema (encodes the 422 lessons) ─────────────────
    payload_path = os.path.join(report_dir, "payload.json")
    payload = None
    if not os.path.isfile(payload_path):
        blocks.append("payload.json missing"); _pf_fail("payload.json missing")
    else:
        try:
            payload = json.load(open(payload_path))
        except Exception as e:
            blocks.append(f"payload.json invalid JSON: {e}"); _pf_fail(f"payload.json invalid: {e}")
    if payload is not None:
        for field in ("summary", "description", "vulnerabilities"):
            if not payload.get(field):
                blocks.append(f"payload.{field} empty"); _pf_fail(f"payload.{field} empty/missing")
        has_cvss = bool(payload.get("cvss_vector_string"))
        has_sev = bool(payload.get("severity"))
        if has_cvss == has_sev:
            blocks.append("must set cvss_vector_string XOR severity (exactly one)")
            _pf_fail("cvss_vector_string XOR severity — set exactly one (GitHub 422 otherwise)")
        else:
            _pf_ok("cvss/severity ok (exactly one set)")
        vulns = payload.get("vulnerabilities") or []
        if vulns:
            pkg = (vulns[0] or {}).get("package") or {}
            if not pkg.get("ecosystem") or not pkg.get("name"):
                blocks.append("vulnerabilities[0].package needs ecosystem+name")
                _pf_fail("vulnerabilities[0].package missing ecosystem/name")
            else:
                # GitHub's GHSA API accepts ONLY this ecosystem enum and 422s on anything
                # else. OSV/other tooling spell several of them differently (PyPI≠pip,
                # crates.io≠rust, Packagist≠composer, Hex≠erlang), so catch the mismatch
                # here instead of after a failed POST. (The lmdeploy submit 422'd on "PyPI".)
                eco = str(pkg.get("ecosystem"))
                if eco not in _GH_ECOSYSTEMS:
                    sugg = _OSV_TO_GH_ECO.get(eco.lower())
                    hint = (f" — use '{sugg}' (GitHub's name), not '{eco}'" if sugg
                            else f" — must be one of: {', '.join(sorted(_GH_ECOSYSTEMS))}")
                    blocks.append(f"package.ecosystem '{eco}' invalid{hint}")
                    _pf_fail(f"package.ecosystem '{eco}' is not a valid GitHub GHSA ecosystem{hint}")
                else:
                    _pf_ok(f"package {eco}:{pkg.get('name')}")
            for v in vulns:
                if isinstance(v, dict) and v.get("patched_versions", None) == "":
                    blocks.append("empty patched_versions:'' — omit it (GitHub 422)")
                    _pf_fail("empty patched_versions \"\" present — omit the key")
        if not payload.get("cwe_ids"):
            blocks.append("cwe_ids missing"); _pf_fail("cwe_ids missing")

    # ── Gate B: GATE.json — confidence / contestable / dup ────────────────────
    gate_path = os.path.join(report_dir, "GATE.json")
    if not os.path.isfile(gate_path):
        blocks.append("GATE.json missing (declare confidence/contestable/dup/poc_type)")
        _pf_fail("GATE.json missing — must declare confidence, contestable, dup_checked, is_published_cve_itself, poc_type")
        meta = {}
    else:
        try:
            meta = json.load(open(gate_path))
        except Exception as e:
            blocks.append(f"GATE.json invalid: {e}"); _pf_fail(f"GATE.json invalid: {e}"); meta = {}
        conf = str(meta.get("confidence", "")).lower()
        if conf not in ("high", "medium", "low"):
            blocks.append("GATE.confidence must be high|medium|low"); _pf_fail("GATE.confidence invalid")
        elif conf == "low":
            blocks.append("confidence=low → HOLD, never auto-submit"); _pf_fail("confidence=low → must be HELD")
        else:
            _pf_ok(f"confidence={conf}")
        # Optional MITRE ATLAS technique IDs for AI/agentic findings — informational,
        # never blocks (the taxonomy travels with the filing; see report_generator.ATLAS_MAP).
        if meta.get("atlas_ids"):
            _pf_ok("ATLAS: " + ", ".join(str(x) for x in meta["atlas_ids"]))
        if meta.get("contestable") is True:
            blocks.append("contestable=true → HOLD, never auto-submit")
            _pf_fail("contestable=true → must be HELD (operator decision off-pressure)")
        elif meta.get("contestable") is False:
            _pf_ok("contestable=false")
        else:
            blocks.append("GATE.contestable must be explicit true/false"); _pf_fail("GATE.contestable missing")
        if meta.get("is_published_cve_itself") is True:
            blocks.append("is_published_cve_itself=true → dup, do not submit"); _pf_fail("is the published CVE itself → dup")
        if meta.get("dup_checked") is not True:
            blocks.append("dup_checked must be true"); _pf_fail("dup_checked not confirmed")

    # ── Gate C: accepted-risk / by-design scan of the draft text ──────────────
    texts = []
    for fn in os.listdir(report_dir):
        if fn.lower().endswith((".md", ".txt")):
            try:
                texts.append((fn, open(os.path.join(report_dir, fn), errors="ignore").read().lower()))
            except Exception:
                pass
    hits = []
    for fn, body in texts:
        for sig in _ACCEPTED_RISK_SIGNALS:
            if sig in body:
                hits.append((fn, sig))
    override = os.path.join(report_dir, "OVERRIDE.accepted-risk")
    if hits:
        uniq = sorted({f"{fn}:'{sig}'" for fn, sig in hits})
        if os.path.isfile(override) and open(override, errors="ignore").read().strip():
            _pf_ok(f"accepted-risk signals present but OVERRIDE.accepted-risk supplied ({len(uniq)} hits)")
        else:
            blocks.append(f"accepted-risk/by-design language in draft ({', '.join(uniq[:6])}) — needs OVERRIDE.accepted-risk rebuttal")
            _pf_fail("accepted-risk/by-design language found — " + ", ".join(uniq[:6]))
            print(f"    {DIM}This is the skillctl class. If you still believe it's a vuln, write a")
            print(f"    rebuttal to {report_dir}/OVERRIDE.accepted-risk and re-run.{RESET}")
    else:
        _pf_ok("no accepted-risk/by-design language in draft")

    # ── Gate D: evidence floor ────────────────────────────────────────────────
    poc_type = str(meta.get("poc_type", "")).lower()
    poc_dir = os.path.join(report_dir, "poc")
    evidence_md = os.path.join(report_dir, "EVIDENCE.md")
    if poc_type == "live":
        if os.path.isdir(poc_dir) and any(not f.startswith(".") for f in os.listdir(poc_dir)):
            _pf_ok("live PoC artifact present (poc/)")
        else:
            blocks.append("poc_type=live but poc/ dir empty/missing"); _pf_fail("poc_type=live requires a non-empty poc/ dir")
    elif poc_type == "structural-absence":
        if os.path.isfile(evidence_md):
            ev = open(evidence_md, errors="ignore").read()
            if re.search(r"[\w./-]+\.\w+:\d+", ev):
                _pf_ok("structural-absence evidence with file:line citation")
            else:
                blocks.append("EVIDENCE.md lacks a file:line citation"); _pf_fail("structural-absence needs a file:line citation in EVIDENCE.md")
        else:
            blocks.append("poc_type=structural-absence but EVIDENCE.md missing"); _pf_fail("structural-absence requires EVIDENCE.md (file:line)")
    else:
        blocks.append("GATE.poc_type must be live|structural-absence"); _pf_fail("poc_type must be live|structural-absence")

    # ── Gate E: anti-AI-slop (human-verification declaration) ─────────────────
    # Motivated by the curl/AI-slop epidemic (2026): ~95% of OSS bug-bounty
    # submissions were LLM hallucinations — non-existent code paths, fabricated
    # advisory IDs (e.g. GHSA-cq7h-538g-9pc5 never existed), unverifiable PoCs.
    # Explicit human-review is the only reliable anti-slop signal we can gate on.
    ai_assisted = meta.get("ai_assisted")
    if ai_assisted is None:
        blocks.append(
            "GATE.ai_assisted missing — declare true|false (required anti-slop gate)"
        )
        _pf_fail(
            "GATE.ai_assisted must be declared: true = AI helped draft/find this; "
            "false = human-originated (no extra friction)"
        )
    elif ai_assisted is True:
        # AI-assisted: require explicit human code-path review before filing
        hv = meta.get("human_verified_code_path")
        # ALTERNATIVE PATH: a machine attestation from tools/autonomous_validate.py may stand
        # in for human code-path review. It is deliberately a DIFFERENT key so the audit trail
        # never conflates the two, and it must carry its own passing criteria (citations all
        # resolve against a real clone, advisory ids all real, a PoC exited 0, an independent
        # tool-capable validator CONFIRMED and reproduced, an independent analysis validator
        # CONFIRMED, zero refutations). Machine attestation is weaker evidence than a human
        # who read the diff, so it is announced loudly rather than passing silently.
        auto = meta.get("autonomous_attestation") or {}
        auto_ok = bool(auto.get("passed")) and bool((auto.get("criteria") or {}).get("tool_capable_confirmed"))
        if auto_ok and hv is not True:
            _pf_warn("human_verified_code_path=false BUT autonomous_attestation passed — "
                     "MACHINE-attested, not human-reviewed")
            for k, v in (auto.get("criteria") or {}).items():
                _pf_ok(f"  auto:{k}={v}")
            hv = True
        if hv is not True:
            blocks.append(
                "ai_assisted=true requires human_verified_code_path=true — "
                "manually confirm the cited code path exists in the target repo"
            )
            _pf_fail(
                "ai_assisted=true: set GATE.human_verified_code_path=true ONLY after "
                "grep/reading the actual source to confirm the path is real"
            )
        else:
            # Say WHICH attestation cleared it. The stored flag is still false when the
            # machine panel substituted for it, and an attestation trail that reads
            # "human_verified_code_path=true" would misrepresent that.
            _pf_ok("ai_assisted=true, code path attested by %s — slop gate clear"
                   % ("MACHINE panel (autonomous_attestation), NOT human review" if auto_ok
                      else "human review (human_verified_code_path=true)"))
        # AI-assisted + medium confidence = too risky
        _conf = str(meta.get("confidence", "")).lower()
        if _conf == "medium":
            blocks.append(
                "ai_assisted=true + confidence=medium → HOLD "
                "(LLM-assisted findings must be high-confidence before filing)"
            )
            _pf_fail("ai_assisted=true requires confidence=high (not medium); verify or HOLD")
        # Scan for GHSA IDs referenced in report text — LLMs hallucinate these
        _all_ghsas: list[str] = []
        for _, _body in texts:
            _all_ghsas += re.findall(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", _body, re.I)
        if payload:
            for _ref in (payload.get("references") or []):
                _url = _ref.get("url", "") if isinstance(_ref, dict) else str(_ref)
                _m = re.search(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", _url, re.I)
                if _m:
                    _all_ghsas.append(_m.group())
        _all_ghsas = sorted({x.upper() for x in _all_ghsas})
        if _all_ghsas and meta.get("references_verified") is not True:
            blocks.append(
                f"ai_assisted=true + unverified GHSA refs "
                f"({', '.join(_all_ghsas[:3])}) — verify each exists at "
                "github.com/advisories then add GATE.references_verified=true"
            )
            _pf_fail(
                f"ai_assisted=true: {len(_all_ghsas)} GHSA ID(s) referenced — "
                "LLMs hallucinate advisory IDs; confirm they are real, then set "
                "GATE.references_verified=true"
            )
        elif _all_ghsas:
            _pf_ok(f"references_verified=true ({len(_all_ghsas)} GHSA ID(s) checked)")
        else:
            pass  # no GHSA refs to verify — nothing to do
    else:
        _pf_ok("ai_assisted=false — human-originated finding, no slop checks needed")

    # ── Verdict ───────────────────────────────────────────────────────────────
    print()
    if blocks:
        print(f"  {BOLD}{RED}GATE: BLOCKED ({len(blocks)} issue(s)) — DO NOT SUBMIT{RESET}")
        for b in blocks:
            print(f"    {RED}•{RESET} {b}")
        print(f"\n  {DIM}A count-goal is never a reason to override this. Unmet count → report unmet.{RESET}")
        return 2
    print(f"  {BOLD}{GREEN}GATE: PASS — submission allowed.{RESET}")
    return 0


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Interactive bug validation assistant")
    parser.add_argument("--output",  default="", help="Output path for generated report skeleton")
    parser.add_argument("--program", default="", help="HackerOne program handle for dup check")
    parser.add_argument("--preflight", default="", metavar="REPORT_DIR",
                        help="Run the mechanical GHSA pre-submit gate on REPORT_DIR and exit (0=pass, 2=blocked)")
    args = parser.parse_args()

    if args.preflight:
        sys.exit(preflight_gate(args.preflight))

    print(f"\n{BOLD}{CYAN}{'═' * 60}{RESET}")
    print(f"{BOLD}{CYAN}  Bug Bounty Validation Assistant{RESET}")
    print(f"{BOLD}{CYAN}{'═' * 60}{RESET}")
    print(f"\nThis will walk you through the 4 validation gates,")
    print(f"calculate your CVSS score, and generate a report skeleton.\n")

    # Collect basic info upfront
    section("Target Information")
    target_program = args.program or ask("HackerOne program handle (e.g., 'target-program')", "unknown")
    vuln_type      = ask("Vulnerability type (e.g., 'IDOR', 'Stored XSS', 'SSRF')")
    endpoint       = ask("Affected endpoint (e.g., '/api/invoices/:id')")

    # Run the 4 gates
    g1_pass, g1_notes = gate1_is_real()
    g2_pass, g2_notes = gate2_in_scope(target_program)
    g3_pass, g3_notes = gate3_exploitable()
    g4_pass, g4_notes = gate4_not_dup(vuln_type, endpoint, target_program)

    # Summary
    section("Validation Summary")
    gates = [
        (1, "Is it real?",       g1_pass),
        (2, "Is it in scope?",   g2_pass),
        (3, "Is it exploitable?",g3_pass),
        (4, "Is it a dup?",      g4_pass),
    ]
    all_pass = all(p for _, _, p in gates)

    for n, name, passed in gates:
        icon = f"{GREEN}✓{RESET}" if passed else f"{RED}✗{RESET}"
        print(f"  Gate {n} — {name}: {icon}")

    print()
    if all_pass:
        print(f"  {BOLD}{GREEN}All gates passed! This looks like a valid finding.{RESET}")
    else:
        failed = [name for _, name, p in gates if not p]
        print(f"  {BOLD}{RED}Failed: {', '.join(failed)}{RESET}")
        print(f"  {DIM}Resolve the failed gates before submitting.{RESET}")

    if not all_pass:
        if not ask_yn("\nContinue to CVSS scoring anyway?", default=False):
            sys.exit(0)

    # CVSS scoring
    cvss_score, cvss_vector, cvss_params = score_cvss()

    # Generate report skeleton
    section("Report Generation")
    impact_desc = g3_notes.get("impact_description", "")

    info = {
        "target":      target_program,
        "vuln_type":   vuln_type,
        "endpoint":    endpoint,
        "impact":      impact_desc,
        "cvss_score":  cvss_score,
        "cvss_vector": cvss_vector,
        "cvss_params": cvss_params,
        "gate1_pass":  g1_pass,
        "gate2_pass":  g2_pass,
        "gate3_pass":  g3_pass,
        "gate4_pass":  g4_pass,
    }

    skeleton = generate_report_skeleton(info)

    # Determine output path
    if args.output:
        output_path = args.output
    else:
        safe_name = vuln_type.lower().replace(" ", "-").replace("/", "-")
        safe_target = target_program.replace(" ", "-")
        base_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "findings", f"{safe_target}-{safe_name}"
        )
        os.makedirs(base_dir, exist_ok=True)
        output_path = os.path.join(base_dir, "hackerone-report.md")

    with open(output_path, "w") as f:
        f.write(skeleton)

    print(f"  {BOLD}{GREEN}Report skeleton generated:{RESET} {output_path}")
    print(f"\n  {BOLD}Next steps:{RESET}")
    print(f"    1. Fill in the actual HTTP request + response in the PoC section")
    print(f"    2. Attach screenshots (naming: TARGET-VULN-TYPE-STEP-N.png)")
    print(f"    3. Replace all [bracketed] placeholders with specific details")
    print(f"    4. Run /bug-bounty-report for the submission checklist")
    print()


if __name__ == "__main__":
    main()
