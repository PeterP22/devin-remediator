"""Webhook receiver: the single automation boundary.

GitHub `issues.labeled` (label = devin-remediate) → Devin session.

Three idempotency layers, in order:
  1. delivery GUID  — GitHub redelivers webhooks; same GUID = same event
  2. issue number   — a remediation row is UNIQUE per issue
  3. (implicit)     — parse failures never create sessions

Signature verification uses the raw request body; parse only after HMAC.
"""
import hashlib
import hmac
import logging

from .config import settings
from .db import Store
from .devin_client import DevinClient
from .github_client import GitHubClient
from .issue_format import parse as parse_issue
from .prompts import STRUCTURED_OUTPUT_SCHEMA, build_prompt

log = logging.getLogger("orchestrator.webhook")


def verify_signature(raw_body: bytes, signature_header: str | None, secret: str) -> bool:
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature_header.removeprefix("sha256="), expected)


class WebhookHandler:
    def __init__(self, store: Store, devin: DevinClient, github: GitHubClient):
        self.store = store
        self.devin = devin
        self.github = github

    def handle(self, event: str, delivery_guid: str, payload: dict) -> dict:
        """Returns a small dict describing what happened (also the HTTP body)."""
        s = settings()

        if event != "issues" or payload.get("action") != "labeled":
            return {"outcome": "ignored", "reason": "not an issues.labeled event"}
        if (payload.get("label") or {}).get("name") != s.remediate_label:
            return {"outcome": "ignored", "reason": "different label"}

        issue = payload["issue"]
        issue_number = issue["number"]

        if not self.store.record_delivery(delivery_guid):
            return {"outcome": "duplicate", "reason": "delivery GUID already processed"}

        finding = parse_issue(issue_number, issue.get("body") or "")
        if finding is None:
            self.store.log(issue_number, "parse_failed", "label present but body is not a structured finding")
            self.github.comment(
                issue_number,
                "⚠️ `devin-remediate` label found, but this issue body is not a "
                "structured finding — no session started. File findings via the scanner, "
                "or match the structured format.",
            )
            return {"outcome": "parse_failed", "issue": issue_number}

        if not self.store.create_remediation(issue_number, finding.package, finding.vuln_id, finding.cve):
            return {"outcome": "duplicate", "reason": f"issue #{issue_number} already has a remediation"}
        self.store.log(issue_number, "detected", f"{finding.package} {finding.pinned} -> {finding.fixed} [{finding.klass}]")

        prompt = build_prompt(finding, repo=s.github_repo)
        session = self.devin.create_session(
            prompt=prompt,
            title=f"Remediate {finding.package} {finding.pinned}→{finding.fixed} (issue #{issue_number})",
            tags=["auto", f"issue-{issue_number}", finding.klass, finding.package],
            repos=[s.github_repo],
            max_acu_limit=s.max_acu_limit,
            structured_output_schema=STRUCTURED_OUTPUT_SCHEMA,
        )
        self.store.set_session(issue_number, session["session_id"], session["url"])
        self.store.log(issue_number, "session_created", session["url"])

        self.github.comment(
            issue_number,
            f"🤖 Remediation session started: {session['url']}\n\n"
            f"- class: `{finding.klass}` · ACU cap: {s.max_acu_limit}\n"
            f"- a PR will be linked here when opened; the "
            f"`remediation-validation` workflow is the gate.",
        )
        return {"outcome": "session_created", "issue": issue_number, "session_id": session["session_id"]}
