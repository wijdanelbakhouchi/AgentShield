"""
logging/__init__.py
===================
AgentShield Phase 5 & 6 — Logging Package Initializer & Standard Library Bridge

Bridges Python standard library `logging` so standard logging functions continue to work
everywhere, while exposing AgentShield Telemetry components.
"""

import os
import sys
import importlib
import importlib.util

# 1. Capture local directory path BEFORE importing stdlib logging
_LOCAL_LOGGING_DIR = os.path.dirname(os.path.abspath(__file__))

# 2. Load Python standard library logging module cleanly under module name 'logging'
_orig_path = list(sys.path)
_clean_path = [
    p for p in sys.path
    if p and p != "." and p != os.getcwd() and "agent_shield" not in p.lower()
]

if "logging" in sys.modules:
    _mod = sys.modules["logging"]
    _local_init = os.path.abspath(os.path.join(_LOCAL_LOGGING_DIR, "__init__.py"))
    if (
        hasattr(_mod, "__file__")
        and _mod.__file__
        and os.path.abspath(_mod.__file__) == _local_init
    ):
        del sys.modules["logging"]

sys.path = _clean_path
_std_log = importlib.import_module("logging")
sys.path = _orig_path

# Register standard logging module in sys.modules
sys.modules["logging"] = _std_log
if hasattr(_std_log, "__path__"):
    if _LOCAL_LOGGING_DIR not in _std_log.__path__:
        _std_log.__path__.append(_LOCAL_LOGGING_DIR)
    __path__ = list(_std_log.__path__)
else:
    __path__ = [_LOCAL_LOGGING_DIR]

# Populate globals with stdlib logging attributes (excluding dunder module metadata)
for _k, _v in list(_std_log.__dict__.items()):
    if not _k.startswith("__"):
        globals()[_k] = _v

# 3. Dynamically load AgentShield Telemetry submodules from local directory
def _load_local(submod_name: str, filename: str):
    filepath = os.path.join(_LOCAL_LOGGING_DIR, filename)
    spec = importlib.util.spec_from_file_location(f"logging.{submod_name}", filepath)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[f"logging.{submod_name}"] = mod
    spec.loader.exec_module(mod)
    return mod


def __getattr__(name: str):
    if name == "EventLogger":
        mod = _load_local("event_logger", "event_logger.py")
        val = getattr(mod, "EventLogger")
        globals()["EventLogger"] = val
        setattr(_std_log, "EventLogger", val)
        return val
    elif name == "MetricsCollector":
        mod = _load_local("metrics", "metrics.py")
        val = getattr(mod, "MetricsCollector")
        globals()["MetricsCollector"] = val
        setattr(_std_log, "MetricsCollector", val)
        return val
    elif name == "AlertEngine":
        mod = _load_local("alerting", "alerting.py")
        val = getattr(mod, "AlertEngine")
        globals()["AlertEngine"] = val
        setattr(_std_log, "AlertEngine", val)
        return val
    elif name in ("dashboard_sync", "event_logger", "metrics", "alerting"):
        mod = _load_local(name, f"{name}.py")
        globals()[name] = mod
        return mod
    elif hasattr(_std_log, name):
        return getattr(_std_log, name)
    raise AttributeError(f"module 'logging' has no attribute '{name}'")


__all__ = [
    "EventLogger",
    "MetricsCollector",
    "AlertEngine",
]
