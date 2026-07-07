"""Devin v3 API client.

Only verified-working parameters are used (calibrated 7 Jul 2026):
  prompt, title, tags, repos, max_acu_limit, structured_output_schema.
The v3 API silently accepts unknown fields — never add a param here without
verifying its behavior, not just the status code.
"""
import httpx

from .config import settings


class DevinClient:
    def __init__(self, client: httpx.Client | None = None):
        s = settings()
        self._base = s.devin_org_base
        self._client = client or httpx.Client(
            headers={"Authorization": f"Bearer {s.devin_api_key}"},
            timeout=30.0,
        )

    def create_session(self, *, prompt: str, title: str, tags: list[str],
                       repos: list[str], max_acu_limit: int,
                       structured_output_schema: dict | None = None) -> dict:
        payload: dict = {
            "prompt": prompt,
            "title": title,
            "tags": tags,
            "repos": repos,
            "max_acu_limit": max_acu_limit,
        }
        if structured_output_schema is not None:
            payload["structured_output_schema"] = structured_output_schema
            payload["structured_output_required"] = True
        r = self._client.post(f"{self._base}/sessions", json=payload)
        r.raise_for_status()
        return r.json()

    def get_session(self, session_id: str) -> dict:
        r = self._client.get(f"{self._base}/sessions/{session_id}")
        r.raise_for_status()
        return r.json()

    def get_messages(self, session_id: str) -> list[dict]:
        r = self._client.get(f"{self._base}/sessions/{session_id}/messages")
        r.raise_for_status()
        return r.json().get("items", [])

    def send_message(self, session_id: str, message: str) -> dict:
        r = self._client.post(f"{self._base}/sessions/{session_id}/messages", json={"message": message})
        r.raise_for_status()
        return r.json()

    def archive_session(self, session_id: str) -> dict:
        r = self._client.post(f"{self._base}/sessions/{session_id}/archive")
        r.raise_for_status()
        return r.json()
