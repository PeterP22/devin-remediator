"""Scanner: audit the fork's pinned requirements against OSV, file issues,
and close the loop on remediated ones.

One run does three things:
  1. AUDIT   — parse name==version pins from the fork's requirements files
               (fetched at the fork's current default branch) and batch-query OSV.
  2. FILE    — new finding w/ an available fix → structured issue with the
               `devin-remediate` label (dedupe key: vuln id, searched across
               open AND closed issues). Findings with NO fixed release are
               reported in the summary, never filed (nothing to remediate).
  3. VERIFY  — open scanner-filed issue whose vuln id is no longer reported →
               close as 'verified remediated' with a comment. This is the
               final stage of the evidence funnel.

Run modes: one-shot (default, for cron/Actions) or --loop N seconds.
"""
import argparse
import json
import logging
import re
import sys
import urllib.request

sys.path.insert(0, ".")  # allow `python scanner/scan.py` from repo root

from orchestrator.config import settings  # noqa: E402
from orchestrator.github_client import GitHubClient  # noqa: E402
from orchestrator.issue_format import MARKER, render  # noqa: E402

log = logging.getLogger("scanner")

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{}"
PIN_RE = re.compile(r"^([A-Za-z0-9_.-]+)(?:\[[A-Za-z0-9_,-]+\])?==([A-Za-z0-9_.!+-]+)")

REQUIREMENTS_FILES = ["requirements/base.txt", "requirements/development.txt"]


def parse_pins(text: str) -> list[tuple[str, str]]:
    pins = []
    for line in text.splitlines():
        m = PIN_RE.match(line.strip())
        if m:
            pins.append((m.group(1).lower(), m.group(2)))
    return pins


def _post_json(url: str, payload: dict) -> dict:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def _get_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=60) as r:
        return json.load(r)


def fixed_version(vuln: dict, package: str) -> str | None:
    """Highest 'fixed' event for the package, or None if unfixed."""
    fixes = []
    for aff in vuln.get("affected", []):
        if aff.get("package", {}).get("name", "").lower() != package:
            continue
        for rng in aff.get("ranges", []):
            fixes.extend(ev["fixed"] for ev in rng.get("events", []) if "fixed" in ev)
    if not fixes:
        return None
    return sorted(fixes, key=lambda v: [int(x) for x in re.findall(r"\d+", v)])[-1]


def classify(pinned: str, fixed: str) -> str:
    """Major-version jump => hero (breaking changes expected), else baseline."""
    try:
        if int(pinned.split(".")[0]) != int(fixed.split(".")[0]):
            return "hero"
    except ValueError:
        pass
    return "baseline"


def audit(pins_by_file: dict[str, list[tuple[str, str]]]) -> list[dict]:
    """Returns findings: one per (package, vuln id) with fix info + file list."""
    all_pins: dict[tuple[str, str], list[str]] = {}
    for path, pins in pins_by_file.items():
        for name, ver in pins:
            all_pins.setdefault((name, ver), []).append(path)

    keys = sorted(all_pins)
    queries = [{"package": {"name": n, "ecosystem": "PyPI"}, "version": v} for n, v in keys]
    results = _post_json(OSV_BATCH, {"queries": queries})["results"]

    findings = []
    for (name, ver), res in zip(keys, results):
        for hit in res.get("vulns", []):
            detail = _get_json(OSV_VULN.format(hit["id"]))
            cves = [a for a in detail.get("aliases", []) if a.startswith("CVE-")]
            fixed = fixed_version(detail, name)
            findings.append({
                "package": name,
                "pinned": ver,
                "vuln_id": hit["id"],
                "cve": cves[0] if cves else hit["id"],
                "fixed": fixed,
                "summary": (detail.get("summary") or "").strip(),
                "req_files": all_pins[(name, ver)],
            })
    return findings


def run_scan(github: GitHubClient, dry_run: bool = False) -> dict:
    s = settings()
    pins_by_file = {}
    for path in REQUIREMENTS_FILES:
        pins_by_file[path] = parse_pins(github.get_file_raw(path))
    findings = audit(pins_by_file)

    existing = github.list_issues(labels=s.remediate_label, state="all")
    by_vuln: dict[str, dict] = {}
    for issue in existing:
        if MARKER not in (issue.get("body") or ""):
            continue
        m = re.search(r"^Vuln-Id:\s*(\S+)", issue["body"], re.M)
        if m:
            by_vuln[m.group(1)] = issue

    report = {"findings": len(findings), "filed": [], "unfixable": [], "verified_closed": [], "already_tracked": []}
    current_vuln_ids = set()

    for f in findings:
        current_vuln_ids.add(f["vuln_id"])
        if f["vuln_id"] in by_vuln:
            report["already_tracked"].append(f["vuln_id"])
            continue
        if not f["fixed"]:
            report["unfixable"].append(f"{f['package']}=={f['pinned']} ({f['vuln_id']}) — no fixed release")
            continue
        klass = classify(f["pinned"], f["fixed"])
        title = f"CVE remediation: {f['package']} {f['pinned']} → {f['fixed']} ({f['cve']})"
        body = render(f["package"], f["pinned"], f["fixed"], f["vuln_id"], f["cve"],
                      f["req_files"], klass, f["summary"])
        if not dry_run:
            issue = github.create_issue(title, body, labels=[s.remediate_label, f"class:{klass}"])
            report["filed"].append({"issue": issue["number"], "vuln_id": f["vuln_id"], "class": klass})
        else:
            report["filed"].append({"issue": None, "vuln_id": f["vuln_id"], "class": klass, "dry_run": True})

    # VERIFY: open tracked issues whose finding is gone → close as remediated
    for vuln_id, issue in by_vuln.items():
        if issue["state"] == "open" and vuln_id not in current_vuln_ids:
            if not dry_run:
                github.comment(
                    issue["number"],
                    f"✅ Re-scan no longer reports {vuln_id} on the default branch — "
                    f"**verified remediated**. Closing.",
                )
                github.close_issue(issue["number"])
            report["verified_closed"].append(issue["number"])

    return report


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true", help="report only; file/close nothing")
    ap.add_argument("--loop", type=int, metavar="SECONDS", help="rescan on an interval")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

    github = GitHubClient()
    while True:
        report = run_scan(github, dry_run=args.dry_run)
        print(json.dumps(report, indent=2))
        if not args.loop:
            break
        import time
        time.sleep(args.loop)


if __name__ == "__main__":
    main()
