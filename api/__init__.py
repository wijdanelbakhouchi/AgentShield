"""
api/__init__.py
===============
AgentShield Phase 6 — REST API Package Initializer
"""

import logging as _logging
import os as _os

# Uvicorn imports the standard-library logging package before loading api.server.
# Expose AgentShield's telemetry submodules through that package path so imports
# remain valid on every supported launcher (the local logging bridge handles the
# inverse ordering when the application is imported directly).
_LOCAL_LOGGING_DIR = _os.path.abspath(
    _os.path.join(_os.path.dirname(__file__), _os.pardir, "logging")
)
if hasattr(_logging, "__path__") and _LOCAL_LOGGING_DIR not in _logging.__path__:
    _logging.__path__.append(_LOCAL_LOGGING_DIR)

from api.server import app, run_server  # noqa: E402  (logging path must be bridged first)

__all__ = ["app", "run_server"]
