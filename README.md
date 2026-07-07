# devin-remediator

Event-driven CVE remediation on the [Devin API](https://docs.devin.ai): a
security finding on a repository becomes a **validated, merge-ready pull
request** with no engineer in the loop until code review.

> Status: week-2 build. Full README (architecture diagram, demo instructions,
> simulate mode) lands in week 3.

## The loop

```
scanner (OSV audit, cron) ──files──▶ GitHub issue [devin-remediate]
    ▲                                        │ webhook (issues.labeled)
    │ rescan verifies fix,                   ▼
    │ closes issue                    orchestrator (FastAPI)
    │                                        │ creates Devin session
    │                                        ▼
merged ◀── human review ◀── validation CI ◀── Devin opens PR
```

- **One trigger:** an issue with the `devin-remediate` label appears (the
  scanner files them automatically; a human labeling an issue takes the same
  path).
- **Human gate at PR merge** — the pipeline is autonomous from finding to
  validated PR; judgment stays where engineers already exercise it.
- **Blocked sessions are surfaced, never auto-answered.**
- An issue counts as remediated only when: PR opened → `remediation-validation`
  workflow green → PR merged → next scan confirms the finding is gone.
  Metrics are computed from that evidence chain, never from agent self-reports.

## Quick start

```bash
cp .env.example .env   # fill in credentials
docker compose up --build
```

Run the scanner once by hand:

```bash
python scanner/scan.py --dry-run   # report only
python scanner/scan.py             # file issues / close verified ones
```

Tests:

```bash
pip install -r requirements.txt
pytest tests/
```
