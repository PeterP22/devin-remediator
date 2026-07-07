"""Session poller — observes Devin sessions and narrates transitions to the issue.

Policy (per plan): blocked sessions are SURFACED, never auto-answered.
The poller comments once per transition (state changes are recorded in the
store, so redundant comments are structurally impossible).
"""
import logging

from .db import Store
from .devin_client import DevinClient
from .github_client import GitHubClient

log = logging.getLogger("orchestrator.poller")


def poll_once(store: Store, devin: DevinClient, github: GitHubClient) -> int:
    """Poll all active remediations once. Returns number polled."""
    active = store.active()
    for rem in active:
        issue_number = rem["issue_number"]
        try:
            session = devin.get_session(rem["session_id"])
        except Exception as exc:  # noqa: BLE001 — keep polling others
            log.warning("poll failed for session %s: %s", rem["session_id"], exc)
            continue

        prs = session.get("pull_requests") or []
        detail = session.get("status_detail")

        if prs and rem["state"] != "PR_OPENED":
            pr_url = prs[0]["pr_url"]
            store.set_pr(issue_number, pr_url)
            store.log(issue_number, "pr_opened", pr_url)
            github.comment(
                issue_number,
                f"🔀 Devin opened {pr_url} — the `remediation-validation` workflow "
                f"is now the gate. Review and merge when green.",
            )
        elif detail in ("blocked", "waiting_for_user") and not prs and rem["state"] == "SESSION_CREATED":
            store.set_state(issue_number, "NEEDS_ATTENTION")
            store.log(issue_number, "needs_attention", f"status_detail={detail}")
            explanation = ""
            try:
                msgs = [m for m in devin.get_messages(rem["session_id"]) if m.get("source") == "devin"]
                if msgs:
                    explanation = f"\n\nDevin's last report:\n> " + msgs[-1]["message"][:900].replace("\n", "\n> ")
            except Exception:  # noqa: BLE001 — the comment is still useful without it
                pass
            github.comment(
                issue_number,
                f"🖐️ The session needs human attention (`{detail}`, no PR yet): "
                f"{rem['session_url']}\n\nPer policy this pipeline never auto-answers "
                f"a blocked session — please review it directly.{explanation}",
            )
        elif session.get("status") in ("stopped", "expired", "failed") and not prs and rem["state"] != "FAILED":
            store.set_state(issue_number, "FAILED")
            store.log(issue_number, "failed", f"session status={session.get('status')}")
            github.comment(
                issue_number,
                f"❌ Session ended without a PR ({session.get('status')}): {rem['session_url']}",
            )
    return len(active)
