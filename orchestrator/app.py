"""FastAPI wiring: webhook endpoint + background poll loop + status endpoints."""
import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse

from . import dashboard
from .config import settings
from .db import Store
from .devin_client import DevinClient
from .github_client import GitHubClient
from .poller import poll_once
from .simulate_stubs import SimDevinClient, SimGitHubClient
from .webhook import WebhookHandler, verify_signature

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("orchestrator")


def build_app(store: Store | None = None,
              devin: DevinClient | None = None,
              github: GitHubClient | None = None,
              start_poller: bool = True) -> FastAPI:
    s = settings()
    simulate = os.environ.get("SIMULATE") == "1"
    store = store or Store(s.db_path)
    devin = devin or (SimDevinClient() if simulate else DevinClient())
    github = github or (SimGitHubClient() if simulate else GitHubClient())
    handler = WebhookHandler(store, devin, github)
    if simulate:
        log.warning("SIMULATE=1 — Devin/GitHub calls are logged, not made")

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        task = None
        if start_poller:
            async def loop():
                while True:
                    try:
                        n = await asyncio.to_thread(poll_once, store, devin, github)
                        log.debug("polled %d active remediations", n)
                    except Exception:  # noqa: BLE001
                        log.exception("poll loop iteration failed")
                    await asyncio.sleep(s.poll_interval_seconds)
            task = asyncio.create_task(loop())
        yield
        if task:
            task.cancel()

    app = FastAPI(title="devin-remediator", lifespan=lifespan)

    @app.post("/webhook/github")
    async def github_webhook(
        request: Request,
        background: BackgroundTasks,
        x_hub_signature_256: str | None = Header(default=None),
        x_github_event: str = Header(default=""),
        x_github_delivery: str = Header(default=""),
    ):
        raw = await request.body()
        if not verify_signature(raw, x_hub_signature_256, s.webhook_secret):
            raise HTTPException(status_code=401, detail="bad signature")
        payload = await request.json()

        # Fast-ack: GitHub times webhooks out at 10s; session creation happens
        # in the background and failures are surfaced on the issue + event log.
        def run():
            try:
                result = handler.handle(x_github_event, x_github_delivery, payload)
                log.info("webhook %s: %s", x_github_delivery, result)
            except Exception:  # noqa: BLE001
                log.exception("webhook handling failed")
                issue = (payload.get("issue") or {}).get("number")
                if issue:
                    store.log(issue, "error", "webhook handling failed — see orchestrator logs")

        background.add_task(run)
        return {"accepted": True}

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    @app.get("/", response_class=HTMLResponse)
    def index():
        return dashboard.PAGE

    @app.get("/dashboard/fragment", response_class=HTMLResponse)
    def dashboard_fragment():
        return dashboard.render_fragment(store, github)

    @app.get("/remediations")
    def remediations():
        return store.all()

    @app.get("/events")
    def events():
        return store.events()

    return app


def main():
    import uvicorn
    uvicorn.run(build_app(), host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
