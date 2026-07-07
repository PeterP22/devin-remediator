"""Simulate mode — logging stand-ins for the Devin and GitHub clients.

Lets a reviewer run the full orchestrator (webhook → parse → idempotency →
prompt assembly → 'session' → poller) with zero credentials and zero cost.
Enabled with SIMULATE=1. Never used in the real pipeline.
"""
import itertools
import logging

log = logging.getLogger("orchestrator.simulate")
_counter = itertools.count(1)


class SimDevinClient:
    def create_session(self, *, prompt: str, title: str, **kw) -> dict:
        n = next(_counter)
        log.info("[SIMULATE] would create Devin session %d: %s", n, title)
        log.info("[SIMULATE] assembled prompt (%d chars):\n%s", len(prompt), prompt)
        return {"session_id": f"sim-session-{n}",
                "url": f"https://app.devin.ai/sessions/sim-{n}"}

    def get_session(self, session_id: str) -> dict:
        # after one poll, pretend the session opened a PR so the state machine advances
        return {"session_id": session_id, "status": "running",
                "status_detail": "working",
                "pull_requests": [{"pr_url": f"https://github.com/example/repo/pull/{session_id[-1]}",
                                   "pr_state": "open"}]}

    def send_message(self, session_id: str, message: str) -> dict:
        log.info("[SIMULATE] would message session %s: %s", session_id, message)
        return {}

    def archive_session(self, session_id: str) -> dict:
        log.info("[SIMULATE] would archive session %s", session_id)
        return {}


class SimGitHubClient:
    _repo = "example/repo"

    def comment(self, issue_number: int, body: str) -> dict:
        log.info("[SIMULATE] would comment on issue #%d:\n%s", issue_number, body)
        return {}

    def list_comments(self, issue_number: int) -> list[dict]:
        return []
