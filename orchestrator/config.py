"""Configuration — everything comes from the environment, nothing is hardcoded.

Required:
  DEVIN_API_KEY     service-user credential (cog_...)
  DEVIN_ORG_ID      org-scoped v3 API (org-...)
  GITHUB_TOKEN      token able to comment on / close issues in GITHUB_REPO
  GITHUB_REPO       e.g. PeterP22/superset
  WEBHOOK_SECRET    shared secret for GitHub webhook HMAC
"""
import os
from dataclasses import dataclass, field


def _require(name: str) -> str:
    val = os.environ.get(name, "")
    if not val:
        raise RuntimeError(f"Missing required env var: {name}")
    return val


@dataclass(frozen=True)
class Settings:
    devin_api_key: str = field(default_factory=lambda: _require("DEVIN_API_KEY"))
    devin_org_id: str = field(default_factory=lambda: _require("DEVIN_ORG_ID"))
    github_token: str = field(default_factory=lambda: _require("GITHUB_TOKEN"))
    github_repo: str = field(default_factory=lambda: _require("GITHUB_REPO"))
    webhook_secret: str = field(default_factory=lambda: _require("WEBHOOK_SECRET"))

    remediate_label: str = field(default_factory=lambda: os.environ.get("REMEDIATE_LABEL", "devin-remediate"))
    max_acu_limit: int = field(default_factory=lambda: int(os.environ.get("MAX_ACU_LIMIT", "15")))
    poll_interval_seconds: int = field(default_factory=lambda: int(os.environ.get("POLL_INTERVAL_SECONDS", "60")))
    db_path: str = field(default_factory=lambda: os.environ.get("DB_PATH", "remediator.db"))
    devin_base_url: str = field(default_factory=lambda: os.environ.get("DEVIN_BASE_URL", "https://api.devin.ai"))

    @property
    def devin_org_base(self) -> str:
        return f"{self.devin_base_url}/v3/organizations/{self.devin_org_id}"


_settings: Settings | None = None


def settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
