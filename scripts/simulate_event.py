#!/usr/bin/env python3
"""Fire a signed, realistic `issues.labeled` webhook at a local orchestrator.

For reviewers: run the orchestrator with SIMULATE=1 (no credentials needed
beyond dummy values), then run this script. You'll see the full path execute
in the logs — signature verify, contract parse, idempotency, prompt assembly,
and the (simulated) Devin session — without touching GitHub or Devin.

  SIMULATE=1 uvicorn --factory orchestrator.app:build_app --port 8000 &
  python scripts/simulate_event.py
  python scripts/simulate_event.py            # replay: deduped by delivery GUID
  python scripts/simulate_event.py --issue 43 # different issue → new 'session'

Only WEBHOOK_SECRET must match the server's .env value.
"""
import argparse
import hashlib
import hmac
import json
import os
import sys
import urllib.request
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestrator.issue_format import render  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target", default="http://127.0.0.1:8000/webhook/github")
    ap.add_argument("--issue", type=int, default=42)
    ap.add_argument("--delivery", default=None, help="delivery GUID (default: random; reuse to test dedupe)")
    args = ap.parse_args()

    secret = os.environ.get("WEBHOOK_SECRET", "")
    if not secret:
        sys.exit("Set WEBHOOK_SECRET (must match the orchestrator's .env)")

    body = render(
        package="example-lib", pinned="1.2.3", fixed="1.2.9",
        vuln_id="GHSA-simu-late-0001", cve="CVE-2026-00000",
        req_files=["requirements/base.txt"], klass="baseline",
        summary="Simulated finding for reviewing the pipeline without credentials.",
    )
    payload = json.dumps({
        "action": "labeled",
        "label": {"name": os.environ.get("REMEDIATE_LABEL", "devin-remediate")},
        "issue": {"number": args.issue, "body": body},
    }).encode()

    sig = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    req = urllib.request.Request(args.target, data=payload, method="POST", headers={
        "Content-Type": "application/json",
        "X-Hub-Signature-256": sig,
        "X-GitHub-Event": "issues",
        "X-GitHub-Delivery": args.delivery or str(uuid.uuid4()),
    })
    with urllib.request.urlopen(req, timeout=30) as r:
        print(f"HTTP {r.status}: {r.read().decode()}")
    print("Now check the orchestrator logs / the dashboard at http://127.0.0.1:8000")


if __name__ == "__main__":
    main()
