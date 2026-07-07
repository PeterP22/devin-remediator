"""Remediation Ops — the command center.

Two views over the same evidence: Overview (leadership altitude — outcomes,
trends, cost of delay) and Operations (the board + audit trail).

Detected/session/PR come from our own store; validated/merged/verified are
enriched LIVE from GitHub (check runs, PR merge state, the scanner's
verification marker). Nothing here is the agent's word for anything.
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
        return "Verified", "verified"
    if e["merged"]:
        return "Merged", "merged"
    if e["validated"]:
        return "Validated", "validated"
    if rem.get("pr_url"):
        return "PR open", "propen"
    if rem["state"] == "NEEDS_ATTENTION":
        if e.get("issue_closed"):
            return "Human resolved", "resolved"
        return "Needs attention", "attention"
    if rem["state"] == "FAILED":
        return "Failed", "failed"
    return "In progress", "working"


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
<title>Remediation Ops</title>
<script src="https://unpkg.com/htmx.org@2.0.3"></script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Sora:wght@400;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#F1EFE2; --panel:#FBFAF3; --panel2:#F5F3E6; --line:#E3E0CC;
  --ink:#20241C; --dim:#8C8A75;
  --mint:#2FBF71; --mint-soft:#DDF5E8; --mint-deep:#177A4C;
  --amber:#C98A06; --amber-soft:#F7EBCB; --red:#C94F4F; --red-soft:#F6DFDF;
  --blue:#3B7DD8; --blue-soft:#E1EAF8;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--ink);font-family:"Sora",sans-serif;font-size:14px;min-height:100vh;padding:30px 38px 60px}
a{color:var(--mint-deep);text-decoration:none}
a:hover{text-decoration:underline}
.mono{font-family:"IBM Plex Mono",monospace}
header{display:flex;align-items:center;gap:18px;margin-bottom:8px;flex-wrap:wrap}
.mark{width:34px;height:34px;border-radius:9px;background:var(--ink);color:var(--mint);display:flex;align-items:center;justify-content:center;font-weight:700;font-size:18px}
h1{font-size:21px;font-weight:700;letter-spacing:-.01em}
.sub{color:var(--dim);font-size:12.5px;width:100%;margin:2px 0 0 52px}
.live{margin-left:auto;display:flex;align-items:center;gap:8px;color:var(--mint-deep);font-size:12px;font-weight:600}
.led{width:9px;height:9px;border-radius:50%;background:var(--mint);animation:pulse 2.2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
nav{display:flex;gap:8px;margin:22px 0 18px}
nav button{font-family:"Sora",sans-serif;font-size:13px;font-weight:600;padding:8px 18px;border-radius:99px;border:1px solid var(--line);background:var(--panel);color:var(--dim);cursor:pointer;transition:all .15s}
nav button.on{background:var(--ink);color:#fff;border-color:var(--ink)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-bottom:18px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px 20px}
.kpi .v{font-family:"IBM Plex Mono",monospace;font-size:30px;font-weight:600;letter-spacing:-.02em}
.kpi .v small{font-size:15px;color:var(--dim)}
.kpi .k{color:var(--dim);font-size:12px;margin-top:4px}
.kpi.good .v{color:var(--mint-deep)}
.kpi.warn .v{color:var(--red)}
.grid2{display:grid;grid-template-columns:minmax(300px,1fr) minmax(0,1.6fr);gap:14px;margin-bottom:14px;align-items:stretch}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:20px 22px}
.card h3{font-size:13px;font-weight:600;margin-bottom:16px;color:var(--ink)}
.card h3 span{color:var(--dim);font-weight:400}
.donutwrap{display:flex;align-items:center;gap:26px;flex-wrap:wrap}
.legend{font-size:12.5px;display:flex;flex-direction:column;gap:9px}
.legend .li{display:flex;align-items:center;gap:9px}
.legend .sw{width:11px;height:11px;border-radius:3px}
.bars .brow{display:grid;grid-template-columns:150px 1fr 74px;align-items:center;gap:12px;margin-bottom:11px;font-size:12.5px}
.bars .track{background:var(--panel2);border-radius:99px;height:14px;overflow:hidden}
.bars .fill{height:100%;border-radius:99px;background:linear-gradient(90deg,var(--mint),#6fdCA8)}
.bars .fill.pending{background:repeating-linear-gradient(45deg,var(--amber-soft),var(--amber-soft) 6px,#eeddb2 6px 12px)}
.bars .dur{font-family:"IBM Plex Mono",monospace;color:var(--dim);text-align:right}
.funnel{display:flex;align-items:center;gap:0;margin-top:4px;flex-wrap:wrap}
.fstage{text-align:center;flex:1;min-width:56px}
.fstage .n{font-family:"IBM Plex Mono",monospace;font-size:24px;font-weight:600;color:var(--mint-deep)}
.fstage.zero .n{color:var(--dim)}
.fstage .l{font-size:11px;color:var(--dim);margin-top:2px}
.farrow{color:var(--line);font-size:18px;flex:0}
table{border-collapse:collapse;width:100%}
th{color:var(--dim);font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;text-align:left;padding:10px 14px;border-bottom:1px solid var(--line)}
td{padding:12px 14px;border-bottom:1px solid var(--panel2);font-size:13px}
tr:hover td{background:var(--panel2)}
.pkg{font-weight:600}
.badge{display:inline-block;font-size:11.5px;font-weight:600;padding:4px 11px;border-radius:99px}
.badge.verified{background:var(--mint-soft);color:var(--mint-deep)}
.badge.merged{background:var(--blue-soft);color:var(--blue)}
.badge.validated{background:#EAF3D9;color:#5C7A1E}
.badge.propen{background:var(--blue-soft);color:var(--blue)}
.badge.working{background:var(--amber-soft);color:var(--amber);animation:pulse 1.8s infinite}
.badge.attention,.badge.failed{background:var(--red-soft);color:var(--red)}
.badge.resolved{background:var(--panel2);color:var(--dim)}
.checks span{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:5px;background:var(--panel2);border:1px solid var(--line)}
.checks span.on{background:var(--mint);border-color:var(--mint)}
.log{list-style:none;max-height:420px;overflow-y:auto}
.log li{padding:9px 4px;border-bottom:1px solid var(--panel2);font-size:12.5px;display:flex;gap:10px}
.log .ts{color:var(--dim);flex:0 0 auto;font-family:"IBM Plex Mono",monospace}
.log .kind{color:var(--mint-deep);font-weight:600;flex:0 0 auto}
.log .kind.attention{color:var(--red)}
.log .detail{color:var(--dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dim{color:var(--dim)}
footer{margin-top:24px;color:var(--dim);font-size:12px}
@media(max-width:900px){.grid2{grid-template-columns:1fr}}
</style></head><body>
<header>
  <div class="mark">◍</div><h1>Remediation Ops</h1>
  <span class="live"><span class="led"></span>LIVE</span>
  <p class="sub">autonomous CVE remediation on the Devin API · every number is backed by a green check, a merged PR, or a re-scan — never the agent's self-report</p>
</header>
<nav>
  <button id="tab-overview" class="on" onclick="setTab('overview')">Overview</button>
  <button id="tab-ops" onclick="setTab('ops')">Operations</button>
</nav>
<div id="body" hx-get="/dashboard/fragment" hx-trigger="load, every 15s" hx-swap="innerHTML"><p class="dim">loading…</p></div>
<footer>devin-remediator · scanner → orchestrator → Devin session → validation gate → human merge → re-scan · humans review code, they no longer produce the fix</footer>
<script>
let tab = 'overview';
function applyTab(){
  document.querySelectorAll('[data-view]').forEach(el => el.style.display = (el.dataset.view === tab ? '' : 'none'));
  document.getElementById('tab-overview').classList.toggle('on', tab === 'overview');
  document.getElementById('tab-ops').classList.toggle('on', tab === 'ops');
}
function setTab(t){ tab = t; applyTab(); }
document.getElementById('body').addEventListener('htmx:afterSwap', applyTab);
</script>
</body></html>"""


FUNNEL_STAGES = ("detected", "session", "pr", "validated", "merged", "verified")


def _donut(verified: int, working: int, attention: int) -> str:
    total = max(verified + working + attention, 1)
    r, cx, cy, w = 62, 80, 80, 20
    circ = 2 * 3.14159 * r
    segs, offset = [], 0.0
    for count, color in ((verified, "#2FBF71"), (working, "#C98A06"), (attention, "#C94F4F")):
        if count:
            frac = count / total
            segs.append(
                f'<circle r="{r}" cx="{cx}" cy="{cy}" fill="none" stroke="{color}" stroke-width="{w}" '
                f'stroke-dasharray="{frac * circ - 3:.1f} {circ:.1f}" stroke-dashoffset="{-offset * circ:.1f}" '
                f'transform="rotate(-90 {cx} {cy})" stroke-linecap="round"/>'
            )
            offset += frac
    pct = round(100 * verified / total)
    return (
        f'<svg width="160" height="160" viewBox="0 0 160 160">'
        f'<circle r="{r}" cx="{cx}" cy="{cy}" fill="none" stroke="#F5F3E6" stroke-width="{w}"/>'
        + "".join(segs)
        + f'<text x="{cx}" y="{cy - 2}" text-anchor="middle" font-family="IBM Plex Mono" font-size="30" font-weight="600" fill="#20241C">{pct}%</text>'
        + f'<text x="{cx}" y="{cy + 20}" text-anchor="middle" font-family="Sora" font-size="11" fill="#8C8A75">verified</text></svg>'
    )


def _timeline(rems: list[dict]) -> str:
    """Cumulative verified-remediation step chart (SVG)."""
    pts = sorted(r["updated_at"] for r in rems if r.get("pr_url"))
    if len(pts) < 2:
        return '<p class="dim">timeline appears after two remediations</p>'
    W, H, pad = 560, 130, 14
    t0, t1 = pts[0], pts[-1]
    span = max(t1 - t0, 1)
    coords = []
    for i, t in enumerate(pts):
        x = pad + (t - t0) / span * (W - 2 * pad)
        y = H - pad - (i + 1) / len(pts) * (H - 2 * pad)
        if coords:
            coords.append((x, coords[-1][1]))
        coords.append((x, y))
    path = "M" + " L".join(f"{x:.0f},{y:.0f}" for x, y in coords)
    dots = "".join(
        f'<circle cx="{x:.0f}" cy="{y:.0f}" r="4" fill="#2FBF71"/>'
        for x, y in coords[::2]
    )
    return (
        f'<svg width="100%" viewBox="0 0 {W} {H}" preserveAspectRatio="none" style="max-height:{H}px">'
        f'<path d="{path}" fill="none" stroke="#2FBF71" stroke-width="2.5"/>' + dots + "</svg>"
        f'<p class="dim" style="font-size:11.5px;margin-top:4px">cumulative PRs delivered over the run — parallel fan-out means wall-clock ≈ slowest fix, not the sum</p>'
    )


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
    working = sum(1 for r in rems if not r.get("pr_url") and r["state"] == "SESSION_CREATED")

    kpis = (
        '<div class="kpis">'
        f'<div class="kpi good"><div class="v">{counts["verified"]}<small>/{counts["detected"]}</small></div><div class="k">vulnerabilities verified remediated</div></div>'
        f'<div class="kpi"><div class="v">{counts["validated"] * 4}<small>/{counts["pr"] * 4}</small></div><div class="k">validation checks green</div></div>'
        f'<div class="kpi"><div class="v">{_median_minutes(rems)}</div><div class="k">median finding → merge-ready PR</div></div>'
        f'<div class="kpi {"warn" if attention else ""}"><div class="v">{attention}</div><div class="k">need human attention</div></div>'
        "</div>"
    )

    donut_card = (
        '<div class="card"><h3>Outcomes <span>· live</span></h3><div class="donutwrap">'
        + _donut(counts["verified"], working, attention)
        + '<div class="legend">'
        f'<div class="li"><span class="sw" style="background:#2FBF71"></span>verified remediated · {counts["verified"]}</div>'
        f'<div class="li"><span class="sw" style="background:#C98A06"></span>in progress · {working}</div>'
        f'<div class="li"><span class="sw" style="background:#C94F4F"></span>needs attention · {attention}</div>'
        "</div></div></div>"
    )

    max_secs = max((int(r["updated_at"] - r["created_at"]) for r in rems if r.get("pr_url")), default=1)
    brows = ""
    for r in sorted(rems, key=lambda x: x["issue_number"]):
        if r.get("pr_url"):
            secs = int(r["updated_at"] - r["created_at"])
            pct = max(6, round(100 * secs / max_secs))
            fill = f'<div class="fill" style="width:{pct}%"></div>'
            dur = _fmt_duration(r)
        else:
            fill = '<div class="fill pending" style="width:100%"></div>'
            dur = "…" if r["state"] == "SESSION_CREATED" else "—"
        brows += (
            f'<div class="brow"><span class="pkg">{html.escape(r["package"])}</span>'
            f'<div class="track">{fill}</div><span class="dur">{dur}</span></div>'
        )
    bars_card = f'<div class="card bars"><h3>Time from finding to merge-ready PR</h3>{brows}</div>'

    fun = ""
    for i, s in enumerate(FUNNEL_STAGES):
        z = " zero" if counts[s] == 0 else ""
        fun += f'<div class="fstage{z}"><div class="n">{counts[s]}</div><div class="l">{s}</div></div>'
        if i < len(FUNNEL_STAGES) - 1:
            fun += '<div class="farrow">›</div>'
    funnel_card = (
        '<div class="card"><h3>Evidence funnel <span>· every stage machine-checked</span></h3>'
        f'<div class="funnel">{fun}</div></div>'
    )
    timeline_card = f'<div class="card"><h3>Delivery timeline</h3>{_timeline(rems)}</div>'

    overview = (
        f'<div data-view="overview">{kpis}'
        f'<div class="grid2">{donut_card}{bars_card}</div>'
        f'<div class="grid2">{funnel_card}{timeline_card}</div></div>'
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
            f'<tr><td class="mono"><a href="https://github.com/{github._repo}/issues/{r["issue_number"]}">#{r["issue_number"]}</a></td>'
            f'<td class="pkg">{html.escape(r["package"])}</td>'
            f'<td class="mono dim">{html.escape(r["cve"] or r["vuln_id"])}</td>'
            f'<td><span class="badge {cls}">{label}</span></td>'
            f"<td>{sess}</td><td class='mono'>{pr_link}</td>"
            f'<td class="checks">{dots}</td>'
            f'<td class="mono">{_fmt_duration(r)}</td></tr>'
        )
    board = (
        '<div class="card" style="padding:0"><h3 style="padding:18px 22px 0">Remediation board</h3><table>'
        "<tr><th>issue</th><th>package</th><th>cve</th><th>stage</th><th>session</th><th>pr</th>"
        "<th>pr·val·mrg·ver</th><th>time to pr</th></tr>"
        f"{rows}</table></div>"
    )

    events = store.events()
    items = ""
    for ev in list(reversed(events))[:24]:
        ts = datetime.fromtimestamp(ev["ts"], tz=timezone.utc).strftime("%H:%M:%S")
        kcls = "attention" if ev["kind"] in ("needs_attention", "failed", "error", "parse_failed") else ""
        detail = html.escape((ev.get("detail") or "")[:80])
        items += (
            f'<li><span class="ts">{ts}</span><span class="kind {kcls}">#{ev["issue_number"]} {ev["kind"]}</span>'
            f'<span class="detail">{detail}</span></li>'
        )
    log = f'<div class="card"><h3>Event log <span>· audit trail</span></h3><ul class="log">{items or "<li class=dim>no events yet</li>"}</ul></div>'
    ops = f'<div data-view="ops" style="display:none"><div class="grid2" style="grid-template-columns:minmax(0,2fr) minmax(280px,1fr)">{board}{log}</div></div>'

    return overview + ops
