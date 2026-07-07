"""Tests for the pure logic: signature, idempotency, contract round-trip, prompts."""
import hashlib
import hmac
import json
import os

import pytest

os.environ.setdefault("DEVIN_API_KEY", "cog_test")
os.environ.setdefault("DEVIN_ORG_ID", "org-test")
os.environ.setdefault("GITHUB_TOKEN", "ghp_test")
os.environ.setdefault("GITHUB_REPO", "owner/repo")
os.environ.setdefault("WEBHOOK_SECRET", "s3cret")

from orchestrator import issue_format  # noqa: E402
from orchestrator.db import Store  # noqa: E402
from orchestrator.prompts import Finding, build_prompt  # noqa: E402
from orchestrator.webhook import WebhookHandler, verify_signature  # noqa: E402


# ---------------------------------------------------------------- fakes
class FakeDevin:
    def __init__(self):
        self.created = []

    def create_session(self, **kw):
        self.created.append(kw)
        n = len(self.created)
        return {"session_id": f"sess-{n}", "url": f"https://app.devin.ai/sessions/sess-{n}"}

    def get_session(self, session_id):
        return {"session_id": session_id, "status": "running", "status_detail": "working", "pull_requests": []}


class FakeGitHub:
    def __init__(self):
        self.comments = []

    def comment(self, issue_number, body):
        self.comments.append((issue_number, body))
        return {}


@pytest.fixture()
def store(tmp_path):
    return Store(str(tmp_path / "test.db"))


@pytest.fixture()
def handler(store):
    return WebhookHandler(store, FakeDevin(), FakeGitHub())


def issue_payload(number=7, body=None, label="devin-remediate", action="labeled"):
    if body is None:
        body = issue_format.render(
            "flask", "2.3.3", "3.1.3", "GHSA-68rp-wp8r-4726", "CVE-2026-27205",
            ["requirements/base.txt"], "hero", "test summary",
        )
    return {"action": action, "label": {"name": label}, "issue": {"number": number, "body": body}}


# ---------------------------------------------------------------- signature
def test_signature_roundtrip():
    body = b'{"x": 1}'
    sig = "sha256=" + hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()
    assert verify_signature(body, sig, "s3cret")
    assert not verify_signature(body, sig, "wrong")
    assert not verify_signature(b'{"x": 2}', sig, "s3cret")
    assert not verify_signature(body, None, "s3cret")
    assert not verify_signature(body, "sha1=abc", "s3cret")


# ---------------------------------------------------------------- contract round-trip
def test_issue_body_roundtrip():
    body = issue_format.render(
        "pytest", "7.4.4", "9.0.3", "GHSA-6w46-j5rx-g56g", "CVE-2025-71176",
        ["requirements/development.txt"], "hero", "tmpdir handling",
    )
    f = issue_format.parse(12, body)
    assert f is not None
    assert (f.package, f.pinned, f.fixed) == ("pytest", "7.4.4", "9.0.3")
    assert f.klass == "hero"
    assert f.issue_number == 12


def test_parse_rejects_foreign_bodies():
    assert issue_format.parse(1, "just some words") is None
    assert issue_format.parse(1, "") is None
    # marker present but fields missing
    assert issue_format.parse(1, issue_format.MARKER + "\nPackage: x") is None


# ---------------------------------------------------------------- prompts
def test_prompt_contains_contract_and_escape_hatch():
    f = Finding(3, "flask", "2.3.3", "3.1.3", "GHSA-x", "CVE-2026-27205", "requirements/base.txt", "hero")
    p = build_prompt(f, repo="owner/repo")
    assert "Remediation-CVE: CVE-2026-27205" in p
    assert "Validation-Tests:" in p
    assert "ESCAPE HATCH" in p
    assert "Closes #3" in p
    baseline = build_prompt(Finding(4, "a", "1.0", "1.1", "G", "C", "r.txt", "baseline"), repo="owner/repo")
    assert "ESCAPE HATCH" not in baseline


# ---------------------------------------------------------------- webhook idempotency
def test_labeled_issue_creates_session(handler):
    out = handler.handle("issues", "guid-1", issue_payload())
    assert out["outcome"] == "session_created"
    assert len(handler.devin.created) == 1
    created = handler.devin.created[0]
    assert created["repos"] == ["owner/repo"]
    assert "issue-7" in created["tags"]
    assert handler.github.comments  # session link commented on the issue


def test_redelivery_is_deduped_by_guid(handler):
    handler.handle("issues", "guid-1", issue_payload())
    out = handler.handle("issues", "guid-1", issue_payload())
    assert out["outcome"] == "duplicate"
    assert len(handler.devin.created) == 1


def test_relabel_is_deduped_by_issue(handler):
    handler.handle("issues", "guid-1", issue_payload())
    out = handler.handle("issues", "guid-2", issue_payload())  # new GUID, same issue
    assert out["outcome"] == "duplicate"
    assert len(handler.devin.created) == 1


def test_other_labels_ignored(handler):
    out = handler.handle("issues", "guid-1", issue_payload(label="bug"))
    assert out["outcome"] == "ignored"
    assert not handler.devin.created


def test_unstructured_body_never_creates_session(handler):
    out = handler.handle("issues", "guid-1", issue_payload(body="free text issue"))
    assert out["outcome"] == "parse_failed"
    assert not handler.devin.created
    assert handler.github.comments  # explains why on the issue


# ---------------------------------------------------------------- scanner logic
def test_classify_major_vs_minor():
    from scanner.scan import classify, parse_pins
    assert classify("2.3.3", "3.1.3") == "hero"
    assert classify("7.4.4", "9.0.3") == "hero"
    assert classify("0.0.29", "0.0.31") == "baseline"
    assert classify("6.0.1", "6.1.0") == "baseline"
    pins = parse_pins("flask==2.3.3\n# comment\n-e ./superset-core\napache-superset[dev]==1.0\n")
    assert ("flask", "2.3.3") in pins
    assert ("apache-superset", "1.0") in pins
    assert len(pins) == 2
