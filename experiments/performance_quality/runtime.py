"""Runtime availability probes used by Phase 16.

Probes are observational.  They never change the pinned semantic model,
attack corpus, threshold, provider selection, or security configuration.
"""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_json(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def git_sha(repo: Path) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def probe_semantic(*, timeout_seconds: float = 60.0) -> dict[str, Any]:
    """Try the exact pinned singleton without installing or substituting models."""

    result: dict[str, Any] = {"status": "unavailable", "classification": "SEMANTIC_UNAVAILABLE"}
    completed = threading.Event()

    def worker() -> None:
        try:
            from analyzer.semantic_similarity import get_semantic_detector

            result.update(get_semantic_detector().status())
        except Exception as exc:  # pragma: no cover - host dependent
            result.update({"status": "unavailable", "error": exc.__class__.__name__})
        finally:
            completed.set()

    started = time.perf_counter()
    thread = threading.Thread(target=worker, name="phase16-semantic-probe", daemon=True)
    thread.start()
    completed.wait(max(0.1, float(timeout_seconds)))
    if not completed.is_set():
        result.update({"status": "unavailable", "error": "probe_timeout"})
    result["probe_ms"] = round((time.perf_counter() - started) * 1000.0, 3)
    ready = bool(result.get("semantic_similarity_enabled")) and result.get("status") in {"ready", "fixture"}
    result["classification"] = "SEMANTIC_READY" if ready else "SEMANTIC_UNAVAILABLE"
    result["ready"] = ready
    return result


def provider_status() -> dict[str, Any]:
    """Read provider configuration/status without using demo output as evidence."""

    try:
        from providers.service import get_provider_status

        status = get_provider_status(probe=False)
    except Exception as exc:  # pragma: no cover - import depends on environment
        return {"real_llm": False, "active_provider": "none", "error": exc.__class__.__name__}
    active = status.get("active_provider")
    snapshot = (status.get("providers") or {}).get(active, {}) if active else {}
    return {
        "active_provider": active or "none",
        "active_status": status.get("active_status"),
        "mode": status.get("mode"),
        "real_llm": bool(status.get("real_llm")) and bool(snapshot.get("runtime_verified")),
        "provider": active or "none",
        "model": snapshot.get("model"),
        "providers": status.get("providers", {}),
    }


def python_metadata() -> dict[str, str]:
    return {"version": sys.version, "implementation": platform.python_implementation(), "platform": platform.platform()}
