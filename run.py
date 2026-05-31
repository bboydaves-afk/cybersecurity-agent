"""CyberSecurity Agent - AI-Powered Penetration Testing & Security Assessment.

Usage:
    python run.py init    Initialize database and configuration
    python run.py cli     Start the CLI interface
    python run.py web     Start the web dashboard (port 8084)
    python run.py chat    Start the AI chat interface
"""

import asyncio
import logging
import os
import sys
from pathlib import Path

import yaml

logger = logging.getLogger("hacking_agent")


def load_config() -> dict:
    config_path = os.environ.get("_HACKING_CONFIG_PATH", "config.yaml")
    if Path(config_path).exists():
        with open(config_path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


def setup_logging(config: dict):
    level = config.get("agent", {}).get("log_level", "INFO")
    log_file = config.get("agent", {}).get("log_file", "./data/logs/hacking_agent.log")
    Path(log_file).parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(log_file, encoding="utf-8"),
        ],
    )


async def init_database(config: dict):
    from core.database import Database
    db_path = config.get("database", {}).get("path", "./data/hacking_agent.db")
    data_dirs = ["logs", "reports", "captures", "exports", "wordlists", "forensics", "report_templates"]
    for d in data_dirs:
        Path(f"./data/{d}").mkdir(parents=True, exist_ok=True)
    db = Database(db_path)
    await db.connect()
    await db.close()
    print("[+] Database initialized successfully")
    print(f"    Path: {db_path}")
    print(f"    Data dirs: {', '.join(data_dirs)}")


def run_cli(config: dict):
    from interfaces.cli.app import app
    app()


async def run_web(config: dict):
    import uvicorn
    from interfaces.web.app import create_app
    app = create_app()
    host = config.get("web", {}).get("host", "0.0.0.0")
    port = config.get("web", {}).get("port", 8084)
    ssl_kwargs = {}
    ssl_cert = os.environ.get("VOLTSYS_SSL_CERT")
    ssl_key = os.environ.get("VOLTSYS_SSL_KEY")
    if ssl_cert and ssl_key and os.path.isfile(ssl_cert) and os.path.isfile(ssl_key):
        ssl_kwargs = {"ssl_certfile": ssl_cert, "ssl_keyfile": ssl_key}

    config_uvicorn = uvicorn.Config(app, host=host, port=port, log_level="info", **ssl_kwargs)
    server = uvicorn.Server(config_uvicorn)
    await server.serve()


async def run_chat(config: dict, voice: bool = False):
    from interfaces.ai_agent.chat import ChatSession
    session = ChatSession(config=config, voice=voice)
    await session.start()


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    os.chdir(Path(__file__).parent)
    command = sys.argv[1].lower()
    config = load_config()
    setup_logging(config)

    sys.argv = [sys.argv[0]] + sys.argv[2:]

    try:
        if command == "init":
            asyncio.run(init_database(config))
        elif command == "cli":
            run_cli(config)
        elif command == "web":
            asyncio.run(run_web(config))
        elif command == "chat":
            voice_flag = "--voice" in sys.argv
            asyncio.run(run_chat(config, voice=voice_flag))
        else:
            print(f"Unknown command: {command}")
            print(__doc__)
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
    except Exception as e:
        logger.error("Fatal error: %s", e, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
