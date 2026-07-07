"""The funnel dashboard — evidence, not self-report.

Detected/session/PR come from our own store; validated/merged/verified are
enriched LIVE from GitHub (check runs, PR merge state, issue state + the
scanner's verification marker). Nothing on this page is the agent's word
for anything: every stage is backed by a green check, a merge, or a rescan.
"""
import re
import time

from .db import Store
from .github_client import GitHubClient

VERIFIED_MARKER = "<!-- devin-remediate:verified -->"
_CACHE: dict[str, tuple[float, dict]] = {}
_TTL = 60.0


def _pr_number(pr_url: str) -> int | None:
    m = re.search(r"/pull/(\d+)$", pr_url or "")
    return int(m.group(1)) if m else None


def enrich(github: GitHubClient, rem: dict) -> dict:
    """validated / merged / verified for one remediation, from GitHub, cached."""
    key = f"{rem['issue_number']}:{rem.get('pr_url')}"
    now = time.time()
    if key in _CACHE and now - _CACHE[key][0] < _TTL:
        return _CACHE[key][1]

    out = {"validated": False, "merged": False, "verified": False}
    pr_n = _pr_number(rem.get("pr_url") or "")
    try:
        if pr_n:
            pr = github._client.get(f"/repos/{github._repo}/pulls/{pr_n}")
            pr.raise_for_status()
            prj = pr.json()
            out["merged"] = bool(prj.get("merged_at"))
            runs = github._client.get(
                f"/repos/{github._repo}/commits/{prj['head']['sha']}/check-runs")
            runs.raise_for_status()
            checks = runs.json().get("check_runs", [])
            out["validated"] = bool(checks) and all(
                c.get("conclusion") == "success" for c in checks)
        comments = github.list_comments(rem["issue_number"])
        out["verified"] = any(VERIFIED_MARKER in (c.get("body") or "") for c in comments)
    except Exception:  # noqa: BLE001 — enrichment is best-effort; stale beats broken
        if key in _CACHE:
            return _CACHE[key][1]
    _CACHE[key] = (now, out)
    return out


def _fmt_duration(rem: dict) -> str:
    if not rem.get("pr_url"):
        return "—"
    secs = int(rem["updated_at"] - rem["created_at"])
    return f"{secs // 60}m {secs % 60:02d}s"


PAGE = """<!doctype html><html><head><title>devin-remediator</title>
<script src="https://unpkg.com/htmx.org@2.0.3"></script>
<style>
 body { font-family: ui-monospace, monospace; margin: 2rem; background: #0d1117; color: #e6edf3; }
 h1 { font-size: 1.3rem; } a { color: #58a6ff; text-decoration: none; }
 .funnel { display: flex; gap: .5rem; margin: 1.5rem 0; flex-wrap: wrap; }
 .stage { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: .8rem 1.2rem; text-align: center; }
 .stage b { display: block; font-size: 1.6rem; }
 table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
 th, td { border-bottom: 1px solid #30363d; padding: .5rem .8rem; text-align: left; font-size: .85rem; }
 .ok { color: #3fb950; } .pend { color: #d29922; } .bad { color: #f85149; }
 .sub { color: #8b949e; font-size: .8rem; }
</style></head><body>
<h1>devin-remediator — evidence funnel</h1>
<p class="sub">Every number backed by a green check, a merged PR, or a re-scan. Never the agent's self-report. Auto-refreshes.</p>
<div hx-get="/dashboard/fragment" hx-trigger="load, every 15s" hx-swap="innerHTML">loading…</div>
</body></html>"""


def render_fragment(store: Store, github: GitHubClient) -> str:
    rems = store.all()
    en = {r["issue_number"]: enrich(github, r) for r in rems}
    counts = {
        "detected": len(rems),
        "session": sum(1 for r in rems if r.get("session_id")),
        "pr": sum(1 for r in rems if r.get("pr_url")),
        "validated": sum(1 for r in rems if en[r["issue_number"]]["validated"]),
        "merged": sum(1 for r in rems if en[r["issue_number"]]["merged"]),
        "verified": sum(1 for r in rems if en[r["issue_number"]]["verified"]),
    }
    stages = "".join(
        f'<div class="stage"><b>{v}</b>{k}</div><div class="stage" style="border:none;background:none">→</div>'
        for k, v in counts.items()
    ).rsplit("<div", 1)[0]

    def yn(v):  # noqa: ANN001
        return '<span class="ok">✓</span>' if v else '<span class="pend">·</span>'

    rows = ""
    for r in sorted(rems, key=lambda x: x["issue_number"]):
        e = en[r["issue_number"]]
        pr = f'<a href="{r["pr_url"]}">#{_pr_number(r["pr_url"])}</a>' if r.get("pr_url") else "—"
        sess = f'<a href="{r["session_url"]}">session</a>' if r.get("session_url") else "—"
        rows += (
            f'<tr><td><a href="https://github.com/{github._repo}/issues/{r["issue_number"]}">'
            f'#{r["issue_number"]}</a></td><td>{r["package"]}</td><td>{r["cve"] or r["vuln_id"]}</td>'
            f"<td>{sess}</td><td>{pr}</td>"
            f"<td>{yn(r.get('pr_url'))} {yn(e['validated'])} {yn(e['merged'])} {yn(e['verified'])}</td>"
            f"<td>{_fmt_duration(r)}</td><td>{r['state']}</td></tr>"
        )
    return (
        f'<div class="funnel">{stages}</div>'
        "<table><tr><th>issue</th><th>package</th><th>cve</th><th>session</th><th>pr</th>"
        "<th>pr · valid · merged · verified</th><th>time to PR</th><th>state</th></tr>"
        f"{rows}</table>"
    )
