#!/usr/bin/env python3
"""bounty_rank.py — post-processing pass over a findings UNION: dedup → canonical clusters, then
rank by ESTIMATED BOUNTY IMPACT ($ range + reasoning), demoting unverified/theoretical last.

Clean-room reimplementation of the post-processing PATTERN from Kritt-ai/open-kritt (AGPL — patterns
only, no code copied): its `dedupe_schema` (cluster → canonical) + `ranker_schema` (impact_level,
minimum/maximum_reward, rank_reasoning, missing_from_prompt) + swappable severity-ranker PROMPTS.

SeethaAi already unions detector findings (audit_suite) but only does severity-COUNT rollups. This
adds the triage layer: which findings to look at first, an est. reward band, why, and what to verify.

Deterministic by default (offline, testable). `--llm` optionally refines ranking/reasoning via a
pluggable MODEL_FN (wire to brain.py/opencode); falls back to the heuristic if unavailable.

Reserved output keys (open-kritt convention, for the dashboard): a finding may carry
`_reserved_report` / `_reserved_poc` (Markdown) — preserved through ranking and surfaced so the UI
can render Report / PoC tabs per finding.

Usage:
  python3 tools/audit_suite.py --dir repo --json | python3 tools/bounty_rank.py --stdin
  python3 tools/bounty_rank.py --findings findings.json [--ranker bounty-triage] [--json]
  python3 tools/bounty_rank.py --from-audit repo [--min-severity HIGH]
  python3 tools/bounty_rank.py --list-rankers
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

# ── #2: swappable severity-ranker PROMPTS (clean-room; used by --llm and to derive demotions) ──
RANKERS: dict[str, dict] = {
    "bounty-triage": {
        "description": "Conservative production-impact ranker; verify-before-rating; FPs last.",
        "prompt": (
            "Rank findings for a bug-bounty submission queue. Rank ONLY findings with a concrete, "
            "externally reachable trigger in a default or supplied configuration.\n"
            "- critical: RCE, auth bypass to admin, mass account takeover, or direct fund/data theft.\n"
            "- high: realistic remote input → RCE-adjacent, SSRF→cloud-metadata/creds, stored XSS in "
            "an auth context, IDOR→write/privesc, or significant data exposure.\n"
            "- medium: bounded authz/info/DoS with meaningful prerequisites or limited blast radius.\n"
            "- low: defense-in-depth with a concrete but minor impact.\n"
            "- informational: hardening only, no demonstrated security impact.\n"
            "DEMOTE (rank lower) theoretical, test-only, privileged-local, brute-force, race-dependent, "
            "non-default-config, and UNVERIFIED findings. Treat static-analysis LEADS (verify-at-sink "
            "pending) as unverified until proven. Rank likely false positives LAST. Prefer end-to-end "
            "evidence and reproducible triggers."
        ),
    },
    "web2-impact": {
        "description": "Web2 chain-impact ranker; rewards SSRF→cloud, IDOR→privesc, auth bypass.",
        "prompt": (
            "Rank web2 findings by exploited IMPACT and chainability, not raw class. Elevate SSRF that "
            "reaches cloud metadata/internal services, IDOR that reaches WRITE or privilege escalation, "
            "auth/session bypass, and injection with a proven sink. Demote reflected-only, self-only, "
            "or config-hardening findings. Unverified static leads rank below any verified finding."
        ),
    },
}
DEFAULT_RANKER = "bounty-triage"

# ── bounty impact model (clean-room heuristic $ bands; configurable, clearly an ESTIMATE) ──
_IMPACT_ORDER = ["informational", "low", "medium", "high", "critical"]
_SEV_TO_IMPACT = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
                  "LOW": "low", "INFO": "informational", "INFORMATIONAL": "informational"}
_REWARD_BAND = {          # rough public-program norms; an ESTIMATE to prioritize, not a promise
    "critical": (5000, 25000),
    "high": (1500, 7500),
    "medium": (400, 2000),
    "low": (100, 500),
    "informational": (0, 100),
}
# verify-before-rating demotion signals (operationalizes the ranker prompt, deterministically)
_LEAD_TELL = re.compile(r"\blead\b|verify[- ]?at[- ]?sink|verify the|co-located|confirm (?:the|dynamic|that)"
                        r"|high-recall|not a (?:finding|confirmed)|contestable", re.IGNORECASE)
# `\w*_tests?` covers the integration_tests/ and server_tests/ conventions: the original
# required an EXACT `tests` segment, so securedrop-client's server_tests/server.ts and
# integration_tests/setup.ts (a helper with no `.test.` suffix) ranked high alongside
# production code (2026-08-10).
_TESTPATH = re.compile(
    # A separator before the token is REQUIRED: a bare `\w*` let `contest/` match as
    # `con`+`test`, which the negative control caught.
    r"(?:^|/)(?:__)?(?:\w+[_-])?(?:tests?|specs?)(?:__)?(?:/|$)"
    r"|(?:^|/)(?:examples?|fixtures?|mocks?|testdata|__mocks__)(?:/|$)"
    r"|\.(?:test|spec)\.",
    re.IGNORECASE)
# Non-production paths that are neither tests nor examples, and are therefore missed by
# _TESTPATH. Added 2026-07-30 from two sweeps in one evening where EVERY false positive was a
# PATH problem rather than a pattern problem:
#   kiwitcms/Kiwi  -> docs/source/conf.py, tcms/core/migrations/, tcms/settings/devel.py
#   calibre-web    -> static/js/libs/{plugins,djvu_html5}.js, static/js/compress/libunrar.js
# Findings here are real patterns in code that is vendored, generated, dev-only or never
# request-reachable, so they should rank below anything in the live app.
_NONPROD_PATH = re.compile(
    r"(?:^|/)(?:vendor|vendored|third[_-]?party|node_modules|bower_components|dist|build)(?:/|$)"
    r"|(?:^|/)static/(?:js|css)/(?:libs?|compress|vendor|dist)(?:/|$)"
    r"|(?:^|/)migrations?(?:/|$)"
    # Repo tooling and build config: release scripts (backport.py, print-and-verify-git-tag.py),
    # binary downloaders and *.config.{ts,js,mjs} are developer-run, never attacker-reachable.
    r"|(?:^|/)(?:scripts?|tools?|hack|ci|\.github)(?:/|$)"
    r"|\.config\.(?:[cm]?[jt]s)$|(?:^|/)(?:webpack|rollup|vite|jest|karma|babel)\.[^/]*$"
    r"|(?:^|/)docs?/.*conf\.py$"
    r"|(?:^|/)settings/(?:devel|dev|local)[a-z0-9_]*\.py$"
    r"|(?:^|/)[a-z0-9_]*(?:devel|dev_settings|local_settings)\.py$"
    r"|\.min\.(?:js|css)$|[.-]bundle\.js$|\.devmode\.js$",
    re.IGNORECASE)


def list_rankers() -> str:
    return "\n".join(f"  {n:16} {r['description']}" for n, r in RANKERS.items())


def _norm(f: dict) -> dict:
    """Normalize a finding dict (audit_suite / detector shape) to the fields we rank on."""
    return {
        "detector": f.get("detector") or f.get("tool") or "",
        "rule": str(f.get("rule") or f.get("id") or "?"),
        "severity": str(f.get("severity") or "MEDIUM").upper(),
        "file": str(f.get("file") or ""),
        "line": int(f.get("line") or 0),
        "summary": str(f.get("summary") or f.get("title") or ""),
        "detail": str(f.get("detail") or ""),
        "_reserved_report": f.get("_reserved_report"),
        "_reserved_poc": f.get("_reserved_poc"),
    }


def dedupe(findings: list[dict], line_bucket: int = 5) -> list[dict]:
    """Cluster near-duplicate findings (same file, nearby line, same detector+rule); pick a canonical.
    Mirrors open-kritt's dedupe_schema (cluster_id / is_canonical / canonical) — deterministic here."""
    clusters: dict[tuple, list[int]] = {}
    for i, f in enumerate(findings):
        key = (f["file"], f["line"] // line_bucket if f["line"] else -i,
               f["detector"], f["rule"])
        clusters.setdefault(key, []).append(i)
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "INFORMATIONAL": 4}
    for cid, (key, idxs) in enumerate(clusters.items()):
        canonical = min(idxs, key=lambda i: (sev_rank.get(findings[i]["severity"], 9), findings[i]["line"]))
        for i in idxs:
            findings[i]["dedupe_cluster_id"] = cid
            findings[i]["dedupe_is_canonical"] = (i == canonical)
    return findings


def rank(findings: list[dict], ranker: str = DEFAULT_RANKER) -> list[dict]:
    """Assign impact_level, min/max reward, rank_reasoning, missing_from_prompt; sort worst-first,
    demoting unverified/test/lead findings (verify-before-rating). Deterministic."""
    for f in findings:
        impact = _SEV_TO_IMPACT.get(f["severity"], "medium")
        reasons = [f"{f['severity']} {f['rule']} → base impact '{impact}'"]
        text = f["summary"] + " " + f["detail"]
        # DEMOTE unverified/lead + test-path (the ranker discipline)
        demoted = False
        if _TESTPATH.search(f["file"]):
            impact = _IMPACT_ORDER[max(0, _IMPACT_ORDER.index(impact) - 2)]
            reasons.append("test/example path → demoted 2 (not production)"); demoted = True
        elif _NONPROD_PATH.search(f["file"]):
            impact = _IMPACT_ORDER[max(0, _IMPACT_ORDER.index(impact) - 2)]
            reasons.append("vendored/generated/dev-only path → demoted 2 (not request-reachable)")
            demoted = True
        elif _LEAD_TELL.search(text):
            impact = _IMPACT_ORDER[max(0, _IMPACT_ORDER.index(impact) - 1)]
            reasons.append("static LEAD / verify-at-sink pending → demoted 1 (unverified)"); demoted = True
        if not f.get("dedupe_is_canonical", True):
            reasons.append("duplicate of a canonical finding in its cluster")
        lo, hi = _REWARD_BAND[impact]
        f["impact_level"] = impact
        f["minimum_reward"], f["maximum_reward"] = lo, hi
        f["rank_reasoning"] = "; ".join(reasons)
        f["missing_from_prompt"] = (
            "verify attacker-reachability + at-sink execution and a fileable channel before submission"
            if demoted or impact in ("medium", "low") else
            "confirm the end-to-end trigger and dedupe against public advisories"
        )
        f["_ranker"] = ranker
    findings.sort(key=lambda f: (
        -_IMPACT_ORDER.index(f["impact_level"]),
        0 if f.get("dedupe_is_canonical", True) else 1,
        -f["maximum_reward"], f["file"], f["line"]))
    for i, f in enumerate(findings, 1):
        f["bounty_rank"] = i
    return findings


# Optional LLM refinement hook — set MODEL_FN to a callable(prompt:str)->str to enable --llm.
MODEL_FN = None


def _llm_refine(findings: list[dict], ranker: str) -> list[dict]:
    if MODEL_FN is None:
        print("bounty_rank: --llm requested but no MODEL_FN wired; using heuristic ranking.",
              file=sys.stderr)
        return findings
    prompt = (RANKERS[ranker]["prompt"] + "\n\nFindings (JSON):\n"
              + json.dumps([{k: f[k] for k in ("bounty_rank", "rule", "severity", "file", "line",
                                                "summary", "impact_level")} for f in findings], indent=2)
              + "\n\nReturn JSON: {\"rankings\":[{\"bounty_rank\":int,\"file\":str,\"line\":int,"
                "\"impact_level\":str,\"minimum_reward\":int,\"maximum_reward\":int,"
                "\"rank_reasoning\":str}], \"missing_from_prompt\":str}")
    try:
        out = MODEL_FN(prompt)
        data = json.loads(out)
    except Exception as e:  # noqa: BLE001 — best-effort; heuristic already ran
        print(f"bounty_rank: LLM refine failed ({e}); keeping heuristic.", file=sys.stderr)
        return findings
    by_loc = {(f["file"], f["line"]): f for f in findings}
    for r in data.get("rankings", []):
        f = by_loc.get((r.get("file"), r.get("line")))
        if f:
            for k in ("impact_level", "minimum_reward", "maximum_reward", "rank_reasoning", "bounty_rank"):
                if k in r:
                    f[k] = r[k]
    findings.sort(key=lambda f: f.get("bounty_rank", 9999))
    return findings


def process(findings: list[dict], ranker: str = DEFAULT_RANKER, use_llm: bool = False) -> list[dict]:
    fs = [_norm(f) for f in findings]
    dedupe(fs)
    rank(fs, ranker)
    if use_llm:
        _llm_refine(fs, ranker)
    return fs


def _load(args) -> list[dict]:
    if args.stdin:
        return json.load(sys.stdin)
    if args.findings:
        return json.load(open(args.findings))
    if args.from_audit:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        try:
            import audit_suite  # noqa: E402
        except ImportError:
            # --from-audit is one of three input modes; --findings/--stdin work
            # standalone. In a distribution that ships the ranker without the
            # 85-detector suite, say so instead of dying on an ImportError.
            print("--from-audit needs audit_suite (the detector suite), which is not "
                  "part of this distribution. Run the detectors separately and pipe "
                  "their JSON in:  audit_suite --json DIR | bounty_rank.py --stdin",
                  file=sys.stderr)
            raise SystemExit(2)
        return audit_suite.run_suite(args.from_audit, min_severity=args.min_severity)
    return []


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Bounty-rank + dedup a findings union (post-processing)")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--findings", help="JSON file: list of finding dicts (e.g. audit_suite --json)")
    src.add_argument("--stdin", action="store_true", help="read the findings JSON list from stdin")
    src.add_argument("--from-audit", metavar="DIR", help="run audit_suite over DIR, then rank")
    src.add_argument("--list-rankers", action="store_true")
    ap.add_argument("--ranker", default=DEFAULT_RANKER, choices=list(RANKERS))
    ap.add_argument("--min-severity", default=None, help="(with --from-audit) floor passed to audit_suite")
    ap.add_argument("--llm", action="store_true", help="refine ranking via MODEL_FN if wired")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if args.list_rankers:
        print(list_rankers()); return 0
    findings = _load(args)
    ranked = process(findings, ranker=args.ranker, use_llm=args.llm)

    if args.json:
        print(json.dumps(ranked, indent=2)); return 0
    if not ranked:
        print("No findings."); return 0
    for f in ranked:
        tabs = "".join(t for t, k in (("[report]", "_reserved_report"), ("[poc]", "_reserved_poc")) if f.get(k))
        dup = "" if f.get("dedupe_is_canonical", True) else " (dup)"
        print(f"#{f['bounty_rank']:<3} {f['impact_level']:13} ${f['minimum_reward']}-{f['maximum_reward']:<6} "
              f"{f['rule']:8} {f['file']}:{f['line']}{dup} {tabs}")
        print(f"      {f['summary']}")
        print(f"      rank: {f['rank_reasoning']}")
    canon = [f for f in ranked if f.get("dedupe_is_canonical", True)]
    print(f"\n{len(ranked)} finding(s), {len(canon)} canonical (after dedup). Ranker: {args.ranker}. "
          f"Reward bands are ESTIMATES to prioritize — verify-at-sink before submission.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
