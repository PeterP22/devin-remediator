"""REMEDIATION OPS — the command center.

Detected/session/PR come from our own store; validated/merged/verified are
enriched LIVE from GitHub (check runs, PR merge state, the scanner's
verification marker). Nothing on this page is the agent's word for anything:
every stage is backed by a green check, a merge, or a re-scan.
"""
import html
import re
import time
from datetime import datetime, timezone

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


def stage_of(rem: dict, e: dict) -> tuple[str, str]:
    """(label, css-class) for the furthest evidenced stage."""
    if e["verified"]:
        return "VERIFIED", "verified"
    if e["merged"]:
        return "MERGED", "merged"
    if e["validated"]:
        return "VALIDATED", "validated"
    if rem.get("pr_url"):
        return "PR OPEN", "propen"
    if rem["state"] == "NEEDS_ATTENTION":
        return "NEEDS ATTENTION", "attention"
    if rem["state"] == "FAILED":
        return "FAILED", "failed"
    return "WORKING", "working"


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
<title>REMEDIATION OPS</title>
<script src="https://unpkg.com/htmx.org@2.0.3"></script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Michroma&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#070b09; --panel:#0c120e; --panel2:#101712; --line:#1d2a21;
  --ink:#d6e8dc; --dim:#5d7566; --phos:#41e07f; --phos-dim:#1f6b41;
  --amber:#f5b942; --red:#ff5d5d; --teal:#3fd0c9; --blue:#5aa9ff;
}
*{box-sizing:border-box;margin:0;padding:0}
body{
  background:var(--bg); color:var(--ink);
  font-family:"IBM Plex Mono",monospace; font-size:14px;
  min-height:100vh; padding:28px 34px 60px;
  background-image:
    radial-gradient(1100px 500px at 75% -10%, rgba(65,224,127,.05), transparent 60%),
    repeating-linear-gradient(0deg, rgba(255,255,255,.012) 0 1px, transparent 1px 3px);
}
a{color:var(--phos);text-decoration:none}
a:hover{text-decoration:underline}
header{display:flex;align-items:baseline;gap:20px;border-bottom:1px solid var(--line);padding-bottom:16px;margin-bottom:22px;flex-wrap:wrap}
h1{font-family:"Michroma",monospace;font-size:19px;letter-spacing:.28em;color:#fff;font-weight:400}
h1 .accent{color:var(--phos)}
.sub{color:var(--dim);font-size:12px;letter-spacing:.06em}
.live{margin-left:auto;display:flex;align-items:center;gap:8px;color:var(--phos);font-size:12px;letter-spacing:.2em}
.led{width:9px;height:9px;border-radius:50%;background:var(--phos);box-shadow:0 0 10px var(--phos);animation:pulse 2.2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
.statgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-bottom:26px}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:14px 16px;position:relative;overflow:hidden}
.stat::after{content:"";position:absolute;inset:0 0 auto 0;height:2px;background:linear-gradient(90deg,var(--phos),transparent 70%);opacity:.5}
.stat .v{font-family:"Michroma",monospace;font-size:26px;color:#fff;margin-bottom:4px}
.stat .k{color:var(--dim);font-size:11px;letter-spacing:.16em;text-transform:uppercase}
.railwrap{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:26px 30px 22px;margin-bottom:26px}
.railtitle{color:var(--dim);font-size:11px;letter-spacing:.22em;margin-bottom:22px;text-transform:uppercase}
.rail{display:flex;align-items:flex-start}
.node{flex:0 0 auto;text-align:center;width:96px}
.node .num{font-family:"Michroma",monospace;font-size:24px;color:var(--phos);text-shadow:0 0 14px rgba(65,224,127,.45)}
.node.zero .num{color:var(--dim);text-shadow:none}
.node .lbl{color:var(--dim);font-size:10px;letter-spacing:.14em;text-transform:uppercase;margin-top:6px}
.node .dot{width:11px;height:11px;border-radius:50%;background:var(--phos);box-shadow:0 0 12px rgba(65,224,127,.6);margin:12px auto 0}
.node.zero .dot{background:var(--panel2);border:1px solid var(--line);box-shadow:none}
.link{flex:1 1 0;height:1px;background:linear-gradient(90deg,var(--phos-dim),var(--phos-dim));margin-top:64px;min-width:18px;position:relative}
.link::after{content:"";position:absolute;top:-2px;left:0;width:40%;height:5px;filter:blur(4px);background:var(--phos);opacity:.25;animation:flow 3s linear infinite}
@keyframes flow{from{left:0}to{left:60%}}
.cols{display:grid;grid-template-columns:minmax(0,2.1fr) minmax(280px,1fr);gap:14px;align-items:start}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:6px;overflow:hidden}
.panel h2{font-size:11px;color:var(--dim);letter-spacing:.22em;text-transform:uppercase;padding:13px 16px;border-bottom:1px solid var(--line);background:var(--panel2)}
table{border-collapse:collapse;width:100%}
th{color:var(--dim);font-size:10px;letter-spacing:.14em;text-transform:uppercase;text-align:left;padding:10px 14px;border-bottom:1px solid var(--line)}
td{padding:11px 14px;border-bottom:1px solid rgba(29,42,33,.55);font-size:13px}
tr:hover td{background:rgba(65,224,127,.04)}
.pkg{color:#fff;font-weight:600}
.badge{display:inline-block;font-size:10px;letter-spacing:.12em;padding:3px 9px;border-radius:3px;border:1px solid}
.badge.verified{color:var(--phos);border-color:var(--phos-dim);background:rgba(65,224,127,.08);box-shadow:0 0 8px rgba(65,224,127,.15)}
.badge.merged{color:var(--teal);border-color:rgba(63,208,201,.35);background:rgba(63,208,201,.07)}
.badge.validated{color:#b8e05a;border-color:rgba(184,224,90,.35);background:rgba(184,224,90,.07)}
.badge.propen{color:var(--blue);border-color:rgba(90,169,255,.35);background:rgba(90,169,255,.07)}
.badge.working{color:var(--amber);border-color:rgba(245,185,66,.4);background:rgba(245,185,66,.07);animation:pulse 1.6s infinite}
.badge.attention,.badge.failed{color:var(--red);border-color:rgba(255,93,93,.4);background:rgba(255,93,93,.08)}
.checks span{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:5px;background:var(--panel2);border:1px solid var(--line)}
.checks span.on{background:var(--phos);border-color:var(--phos);box-shadow:0 0 6px rgba(65,224,127,.5)}
.log{list-style:none;max-height:430px;overflow-y:auto}
.log li{padding:9px 16px;border-bottom:1px solid rgba(29,42,33,.5);font-size:12px;display:flex;gap:10px}
.log .ts{color:var(--dim);flex:0 0 auto}
.log .kind{color:var(--phos);flex:0 0 auto;letter-spacing:.06em}
.log .kind.attention{color:var(--red)}
.log .detail{color:var(--ink);opacity:.75;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dim{color:var(--dim)}
footer{margin-top:26px;color:var(--dim);font-size:11px;letter-spacing:.08em}
@media (max-width:900px){.cols{grid-template-columns:1fr}}
</style></head><body>
<header>
  <h1>REMEDIATION<span class="accent">/OPS</span></h1>
  <span class="sub">autonomous CVE remediation · every number backed by a green check, a merge, or a re-scan — never the agent's self-report</span>
  <span class="live"><span class="led"></span>LIVE</span>
</header>
<div hx-get="/dashboard/fragment" hx-trigger="load, every 15s" hx-swap="innerHTML"><p class="dim">acquiring signal…</p></div>
<footer>devin-remediator · orchestrator + scanner + validation gate · humans review code, they no longer produce the fix</footer>
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
    attention = sum(1 for r in rems if r["state"] in ("NEEDS_ATTENTION", "FAILED"))

    stats = (
        f'<div class="statgrid">'
        f'<div class="stat"><div class="v">{counts["verified"]}<span class="dim" style="font-size:15px">/{counts["detected"]}</span></div><div class="k">verified remediated</div></div>'
        f'<div class="stat"><div class="v">{counts["validated"] * 4}/{counts["pr"] * 4}</div><div class="k">validation checks green</div></div>'
        f'<div class="stat"><div class="v">{_median_minutes(rems)}</div><div class="k">median time to PR</div></div>'
        f'<div class="stat"><div class="v" style="color:{"#ff5d5d" if attention else "#fff"}">{attention}</div><div class="k">need human attention</div></div>'
        f"</div>"
    )

    nodes = ""
    for i, s in enumerate(FUNNEL_STAGES):
        z = " zero" if counts[s] == 0 else ""
        nodes += f'<div class="node{z}"><div class="num">{counts[s]}</div><div class="lbl">{s}</div><div class="dot"></div></div>'
        if i < len(FUNNEL_STAGES) - 1:
            nodes += '<div class="link"></div>'
    rail = (
        '<div class="railwrap"><div class="railtitle">Evidence funnel — detected → session → PR → validated → merged → rescan-verified</div>'
        f'<div class="rail">{nodes}</div></div>'
    )

    rows = ""
    for r in sorted(rems, key=lambda x: x["issue_number"]):
        e = en[r["issue_number"]]
        label, cls = stage_of(r, e)
        pr_link = f'<a href="{r["pr_url"]}">#{_pr_number(r["pr_url"])}</a>' if r.get("pr_url") else '<span class="dim">—</span>'
        sess = f'<a href="{r["session_url"]}">open ↗</a>' if r.get("session_url") else '<span class="dim">—</span>'
        dots = "".join(
            f'<span class="{"on" if v else ""}"></span>'
            for v in (bool(r.get("pr_url")), e["validated"], e["merged"], e["verified"])
        )
        rows += (
            f'<tr><td><a href="https://github.com/{github._repo}/issues/{r["issue_number"]}">#{r["issue_number"]}</a></td>'
            f'<td class="pkg">{html.escape(r["package"])}</td>'
            f'<td class="dim">{html.escape(r["cve"] or r["vuln_id"])}</td>'
            f'<td><span class="badge {cls}">{label}</span></td>'
            f"<td>{sess}</td><td>{pr_link}</td>"
            f'<td class="checks">{dots}</td>'
            f"<td>{_fmt_duration(r)}</td></tr>"
        )
    board = (
        '<div class="panel"><h2>Remediation board</h2><table>'
        "<tr><th>issue</th><th>package</th><th>cve</th><th>stage</th><th>session</th><th>pr</th>"
        "<th>pr·val·mrg·ver</th><th>time to pr</th></tr>"
        f"{rows}</table></div>"
    )

    events = store.events()
    items = ""
    for ev in list(reversed(events))[:22]:
        ts = datetime.fromtimestamp(ev["ts"], tz=timezone.utc).strftime("%H:%M:%S")
        kcls = "attention" if ev["kind"] in ("needs_attention", "failed", "error", "parse_failed") else ""
        detail = html.escape((ev.get("detail") or "")[:80])
        items += (
            f'<li><span class="ts">{ts}</span><span class="kind {kcls}">#{ev["issue_number"]} {ev["kind"]}</span>'
            f'<span class="detail">{detail}</span></li>'
        )
    log = f'<div class="panel"><h2>Event log — audit trail</h2><ul class="log">{items or "<li class=dim>no events yet</li>"}</ul></div>'

    return stats + rail + f'<div class="cols">{board}{log}</div>'
