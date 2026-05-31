"""FastAPI web dashboard for CyberSecurity Agent."""

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

import yaml
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

logger = logging.getLogger("hacking_agent.web")

app_state: dict = {}


def _load_config() -> dict:
    config_path = os.environ.get("_HACKING_CONFIG_PATH", "config.yaml")
    if Path(config_path).exists():
        with open(config_path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    config = _load_config()
    from core.database import Database
    from core.credentials import CredentialManager

    db_path = config.get("database", {}).get("path", "./data/hacking_agent.db")
    db = Database(db_path)
    await db.connect()
    cred_mgr = CredentialManager(db)

    app_state.update({
        "config": config, "db": db, "cred_mgr": cred_mgr,
    })
    logger.info("Web dashboard initialized (db=%s)", db_path)
    yield
    if app_state.get("db"):
        await app_state["db"].close()
    logger.info("Web dashboard shutdown")


def create_app() -> FastAPI:
    app = FastAPI(title="CyberSecurity Agent", version="1.0.0", lifespan=lifespan)
    app.add_middleware(CORSMiddleware, allow_origins=["*"],
                       allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

    static_dir = Path(__file__).parent / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    from .routes import dashboard, targets, recon, vulnerabilities, exploits
    from .routes import web_security, cloud_security, compliance
    from .routes import reports, settings, chat
    from .routes import network, forensics, threat_intel
    from .routes import playbooks, ad_security, api_security, automation
    from .routes import wireless, containers, osint, secrets
    from .routes import email_security, notifications, social_eng
    from .routes import vuln_chains, evidence_routes, c2, mobile
    from .routes import tool_api

    app.include_router(dashboard.router)
    app.include_router(targets.router)
    app.include_router(recon.router)
    app.include_router(vulnerabilities.router)
    app.include_router(exploits.router)
    app.include_router(web_security.router)
    app.include_router(cloud_security.router)
    app.include_router(compliance.router)
    app.include_router(reports.router)
    app.include_router(settings.router)
    app.include_router(chat.router)
    app.include_router(network.router)
    app.include_router(forensics.router)
    app.include_router(threat_intel.router)
    app.include_router(playbooks.router)
    app.include_router(ad_security.router)
    app.include_router(api_security.router)
    app.include_router(automation.router)
    app.include_router(wireless.router)
    app.include_router(containers.router)
    app.include_router(osint.router)
    app.include_router(secrets.router)
    app.include_router(email_security.router)
    app.include_router(notifications.router)
    app.include_router(social_eng.router)
    app.include_router(vuln_chains.router)
    app.include_router(evidence_routes.router)
    app.include_router(c2.router)
    app.include_router(mobile.router)
    app.include_router(tool_api.router)

    @app.get("/")
    async def index():
        return FileResponse(str(static_dir / "index.html"))

    return app
