"""Minimal GitHub REST client — issue comments, labels, close/open, search."""
import httpx

from .config import settings


class GitHubClient:
    def __init__(self, client: httpx.Client | None = None):
        s = settings()
        self._repo = s.github_repo
        self._client = client or httpx.Client(
            base_url="https://api.github.com",
            headers={
                "Authorization": f"Bearer {s.github_token}",
                "Accept": "application/vnd.github+json",
            },
            timeout=30.0,
        )

    def comment(self, issue_number: int, body: str) -> dict:
        r = self._client.post(f"/repos/{self._repo}/issues/{issue_number}/comments", json={"body": body})
        r.raise_for_status()
        return r.json()

    def create_issue(self, title: str, body: str, labels: list[str]) -> dict:
        r = self._client.post(f"/repos/{self._repo}/issues", json={"title": title, "body": body, "labels": labels})
        r.raise_for_status()
        return r.json()

    def close_issue(self, issue_number: int, reason: str = "completed") -> dict:
        r = self._client.patch(f"/repos/{self._repo}/issues/{issue_number}", json={"state": "closed", "state_reason": reason})
        r.raise_for_status()
        return r.json()

    def list_comments(self, issue_number: int) -> list[dict]:
        r = self._client.get(f"/repos/{self._repo}/issues/{issue_number}/comments", params={"per_page": 100})
        r.raise_for_status()
        return r.json()

    def list_issues(self, labels: str, state: str = "all") -> list[dict]:
        out: list[dict] = []
        page = 1
        while True:
            r = self._client.get(
                f"/repos/{self._repo}/issues",
                params={"labels": labels, "state": state, "per_page": 100, "page": page},
            )
            r.raise_for_status()
            batch = r.json()
            # the issues API returns PRs too; filter them out
            out.extend(i for i in batch if "pull_request" not in i)
            if len(batch) < 100:
                return out
            page += 1

    def get_file_raw(self, path: str, ref: str = "master") -> str:
        r = self._client.get(
            f"/repos/{self._repo}/contents/{path}",
            params={"ref": ref},
            headers={"Accept": "application/vnd.github.raw+json"},
        )
        r.raise_for_status()
        return r.text
