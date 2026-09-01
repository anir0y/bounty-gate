---
name: prioritize
description: Rank findings by exploitability using RAPTOR formula (Impact x Exploitability / Detection_Time)
user_invocable: true
---

# /prioritize — Finding Prioritizer

Rank all findings by exploitability to decide what to work on next.

## Usage
```
/prioritize                    # Rank all findings across all targets
/prioritize target.com         # Rank findings for specific target
/prioritize --time 2.0         # Suggest best finding for 2 hours remaining
```

## Workflow

1. Load findings from `reports/{target}/` directories
2. Score each finding: `Impact x Exploitability / Detection_Time`
3. Display ranked table with scores
4. Suggest the best next finding to work on given time constraints

## Scoring

- **Impact (1-10)**: Based on severity (P1=10, P2=8, P3=5, P4=3, P5=1)
- **Exploitability (1-10)**: Based on vuln class + modifiers (auth required? user interaction?)
- **Detection_Time**: Hours spent finding it (from hunt journal)

## Integration

- Uses `python3 tools/prioritizer.py` for scoring
- Reads from `memory/hunt_journal.py` for timing data
- Reads from `memory/pattern_db.py` for cross-target patterns
- Results inform `/autopilot` target selection
