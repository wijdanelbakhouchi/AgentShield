"""Run the local AgentShield API with migration-safe development defaults.

This launcher is intentionally separate from the container/production server
entry point.  Local Windows development uses a loopback port that does not
assume port 8000 is available, while Docker continues to use its compose
network and port mapping.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv


ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8001


def development_settings() -> tuple[str, int]:
    """Return validated local bind settings, with safe loopback defaults."""

    host = (os.getenv("AGENTSHIELD_DEV_HOST") or DEFAULT_HOST).strip()
    if not host:
        host = DEFAULT_HOST

    raw_port = os.getenv("AGENTSHIELD_DEV_PORT") or str(DEFAULT_PORT)
    try:
        port = int(raw_port)
    except (TypeError, ValueError) as exc:
        raise ValueError("AGENTSHIELD_DEV_PORT must be an integer between 1 and 65535") from exc
    if not 1 <= port <= 65535:
        raise ValueError("AGENTSHIELD_DEV_PORT must be an integer between 1 and 65535")
    return host, port


def main() -> None:
    """Apply Alembic migrations once, then run the FastAPI application."""

    os.chdir(ROOT_DIR)
    load_dotenv(ROOT_DIR / ".env")

    # Use the repository's migration-managed database helper.  It invokes
    # ``alembic upgrade head`` and records the URL so api.server does not run
    # the same idempotent upgrade a second time during import.
    from storage.db import run_migrations

    host, port = development_settings()
    print("Applying database migrations (alembic upgrade head)...")
    run_migrations()

    from api.server import app
    import uvicorn

    base_url = f"http://{host}:{port}"
    print(f"AgentShield backend: {base_url}")
    print(f"Health: {base_url}/api/v1/health")
    print(f"Provider status: {base_url}/api/v1/providers/status")
    print("Frontend dev server: http://localhost:3000")
    uvicorn.run(app, host=host, port=port, reload=False)


if __name__ == "__main__":
    main()
