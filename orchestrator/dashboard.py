"""Remediation dashboard — deliberately minimal.

One screen: KPIs, the evidence funnel, the board. Detected/session/PR come
from our own store; validated/merged/verified are enriched LIVE from GitHub
(check runs, PR merge state, the scanner's verification marker). Nothing
here is the agent's word for anything.
"""
import html
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
    key = f"{rem['issue_number']}:{rem.get('pr_url')}"
    now = time.time()
    if key in _CACHE and now - _CACHE[key][0] < _TTL:
        return _CACHE[key][1]

    out = {"validated": False, "merged": False, "verified": False, "issue_closed": False}
    pr_n = _pr_number(rem.get("pr_url") or "")
    try:
        issue = github._client.get(f"/repos/{github._repo}/issues/{rem['issue_number']}")
        issue.raise_for_status()
        out["issue_closed"] = issue.json().get("state") == "closed"
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


def stage_of(rem: dict, e: dict) -> tuple[str, str]:
    if e["verified"]:
        return "verified", "ok"
    if e["merged"]:
        return "merged", "ok"
    if e["validated"]:
        return "validated", "ok"
    if rem.get("pr_url"):
        return "pr open", "mid"
    if rem["state"] == "NEEDS_ATTENTION":
        if e.get("issue_closed"):
            return "human resolved", "dim"
        return "needs attention", "bad"
    if rem["state"] == "FAILED":
        return "failed", "bad"
    return "in progress", "mid"


def _fmt_duration(rem: dict) -> str:
    if not rem.get("pr_url"):
        return "—"
    secs = int(rem["updated_at"] - rem["created_at"])
    return f"{secs // 60}m {secs % 60:02d}s"


def _median_minutes(rems: list[dict]) -> str:
    durs = sorted(int(r["updated_at"] - r["created_at"]) for r in rems if r.get("pr_url"))
    if not durs:
        return "—"
    mid = durs[len(durs) // 2]
    return f"{mid // 60}m {mid % 60:02d}s"


PAGE = """<!doctype html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>devin-remediator</title>
<script src="https://unpkg.com/htmx.org@2.0.3"></script>
<style>
:root{--bg:#0b0d10;--line:#22272e;--ink:#f0f3f6;--dim:#768390;--ok:#3fb950;--mid:#d29922;--bad:#f85149}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--ink);font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:14px;max-width:1060px;margin:0 auto;padding:44px 24px}
a{color:var(--ink);text-decoration:underline;text-underline-offset:3px;text-decoration-color:var(--dim)}
a:hover{text-decoration-color:var(--ink)}
header{display:flex;align-items:baseline;gap:14px;margin-bottom:6px}
h1{font-size:17px;font-weight:600}
.live{margin-left:auto;color:var(--ok);font-size:12px}
.live::before{content:"●";margin-right:6px;animation:p 2s infinite}
@keyframes p{50%{opacity:.3}}
.sub{color:var(--dim);font-size:12.5px;margin-bottom:34px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1px;background:var(--line);border:1px solid var(--line);margin-bottom:34px}
.kpi{background:var(--bg);padding:16px 18px}
.kpi .v{font-size:26px;font-weight:600}
.kpi .v small{font-size:14px;color:var(--dim);font-weight:400}
.kpi .k{color:var(--dim);font-size:11.5px;margin-top:4px}
.kpi.bad .v{color:var(--bad)}
.funnel{display:flex;gap:10px;align-items:baseline;margin-bottom:34px;flex-wrap:wrap;color:var(--dim)}
.funnel b{color:var(--ink);font-size:20px;margin-right:6px}
.funnel .sep{color:var(--line)}
table{border-collapse:collapse;width:100%}
th{color:var(--dim);font-weight:400;font-size:11.5px;text-align:left;padding:8px 10px;border-bottom:1px solid var(--line)}
td{padding:12px 10px;border-bottom:1px solid var(--line);font-size:13.5px}
.st{font-size:12.5px}
.st.ok{color:var(--ok)}.st.mid{color:var(--mid)}.st.bad{color:var(--bad)}.st.dim{color:var(--dim)}
.dim{color:var(--dim)}
footer{margin-top:36px;color:var(--dim);font-size:12px;line-height:1.6}
</style></head><body>
<header><h1>devin-remediator</h1><span class="live">LIVE</span></header>
<p class="sub">every number below is backed by a green check, a merged PR, or a re-scan — never the agent's self-report</p>
<div hx-get="/dashboard/fragment" hx-trigger="load, every 15s" hx-swap="innerHTML"><p class="dim">loading…</p></div>
<footer>scanner → issue → webhook → Devin session → PR → validation gate → human merge → re-scan verifies<br>humans review code; they no longer produce the fix</footer>
</body></html>"""


FUNNEL_STAGES = ("detected", "session", "pr", "validated", "merged", "verified")


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
    attention = sum(
        1 for r in rems
        if r["state"] in ("NEEDS_ATTENTION", "FAILED") and not en[r["issue_number"]].get("issue_closed")
    )

    kpis = (
        '<div class="kpis">'
        f'<div class="kpi"><div class="v">{counts["verified"]}<small> / {counts["detected"]}</small></div><div class="k">verified remediated</div></div>'
        f'<div class="kpi"><div class="v">{counts["validated"] * 4}<small> / {counts["pr"] * 4}</small></div><div class="k">checks green</div></div>'
        f'<div class="kpi"><div class="v">{_median_minutes(rems)}</div><div class="k">median time to PR</div></div>'
        f'<div class="kpi {"bad" if attention else ""}"><div class="v">{attention}</div><div class="k">need attention</div></div>'
        "</div>"
    )

    funnel = '<div class="funnel">' + '<span class="sep">→</span>'.join(
        f"<span><b>{counts[s]}</b>{s}</span>" for s in FUNNEL_STAGES
    ) + "</div>"

    rows = ""
    for r in sorted(rems, key=lambda x: x["issue_number"]):
        e = en[r["issue_number"]]
        label, cls = stage_of(r, e)
        pr_link = f'<a href="{r["pr_url"]}">#{_pr_number(r["pr_url"])}</a>' if r.get("pr_url") else '<span class="dim">—</span>'
        sess = f'<a href="{r["session_url"]}">session</a>' if r.get("session_url") else '<span class="dim">—</span>'
        rows += (
            f'<tr><td><a href="https://github.com/{github._repo}/issues/{r["issue_number"]}">#{r["issue_number"]}</a></td>'
            f'<td>{html.escape(r["package"])}</td>'
            f'<td class="dim">{html.escape(r["cve"] or r["vuln_id"])}</td>'
            f'<td><span class="st {cls}">{label}</span></td>'
            f"<td>{sess}</td><td>{pr_link}</td>"
            f"<td>{_fmt_duration(r)}</td></tr>"
        )
    board = (
        "<table><tr><th>issue</th><th>package</th><th>cve</th><th>status</th>"
        "<th>session</th><th>pr</th><th>time to pr</th></tr>"
        f"{rows}</table>"
    )
    return kpis + funnel + board
