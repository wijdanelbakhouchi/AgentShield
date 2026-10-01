"""Provenance-aware prompt annotation for the frozen multi-agent testbed.

The security layer appends explicit derived-from metadata to the existing
``<agent_data>`` / external-data wrappers when provenance is available.  This
does not change agent behavior: it makes the trust status of each data block
visible to the receiving model, exactly as the tagged wrappers already do.  The
annotation is the prompt-level half of trust-aware security; the runtime half
is the provenance-aware risk adjustment in ``hooks.inter_agent_guard``.
"""

from __future__ import annotations

from typing import Any, Mapping
from html import escape


def escape_untrusted(value: str) -> str:
    """Prevent supplied data from closing the application's prompt delimiters."""
    return escape(str(value), quote=False)


def provenance_annotation(
    state: Mapping[str, Any],
    field: str,
) -> str:
    """Return an attribute string (or empty) describing a field's provenance.

    Example output: `` derived_from_untrusted="true" depth="2"
    origins="user,agent,tool"``.  Returns ``""`` when provenance tracking is
    disabled or the field has no registered provenance.
    """
    try:
        from config import PROVENANCE_ENABLED
    except Exception:
        PROVENANCE_ENABLED = False
    if not PROVENANCE_ENABLED:
        return ""
    provenance_by_field = state.get("provenance_by_field") or {}
    record = provenance_by_field.get(field)
    if not record or not isinstance(record, dict):
        return ""
    parts: list[str] = []
    if record.get("tainted"):
        parts.append('derived_from_untrusted="true"')
    depth = record.get("propagation_depth")
    if depth:
        parts.append(f'depth="{int(depth)}"')
    origins = record.get("origins")
    if origins:
        joined = escape(",".join(str(item) for item in origins), quote=True)
        parts.append(f'origins="{joined}"')
    if not parts:
        return ""
    return " " + " ".join(parts)


__all__ = ["provenance_annotation"]
