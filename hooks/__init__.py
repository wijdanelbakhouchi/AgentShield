"""
hooks/__init__.py
=================
AgentShield Phase 4 — Hooks Package Initializer

Exposes the primary Phase 4 security hook APIs at the package level.

Usage:
    from hooks import InterAgentGuard, guarded_node
    from hooks import ToolGuard, guarded_tool, ToolBlockedError
    from hooks import AGENT_HANDOFF_AUDIT_LOG, TOOL_EXECUTION_AUDIT_LOG
    from hooks import reset_handoff_audit_log, reset_tool_audit_log
"""

from hooks.inter_agent_guard import (
    AGENT_HANDOFF_AUDIT_LOG,
    HandoffBlockedError,
    InterAgentGuard,
    guarded_node,
    reset_handoff_audit_log,
)
from hooks.tool_guard import (
    TOOL_EXECUTION_AUDIT_LOG,
    ToolBlockedError,
    ToolGuard,
    guarded_tool,
    get_current_identity,
    reset_current_identity,
    reset_tool_audit_log,
    set_current_identity,
)
from security.tool_security import (
    ACTIVE_TOOL_REGISTRY,
    AuthenticatedIdentity,
    ArgumentSecurityScanner,
    Identity,
    Role,
    RBACPolicy,
    SecureToolExecutor,
    ToolExecutor,
    ToolRequest,
    ToolResult,
    ToolRole,
    ToolSandbox,
    ToolSecurityPolicy,
    execute_tool_request,
    resolve_server_identity,
)

__all__ = [
    # Inter-Agent Guard
    "InterAgentGuard",
    "guarded_node",
    "HandoffBlockedError",
    "AGENT_HANDOFF_AUDIT_LOG",
    "reset_handoff_audit_log",
    # Tool Guard
    "ToolGuard",
    "guarded_tool",
    "ToolBlockedError",
    "TOOL_EXECUTION_AUDIT_LOG",
    "reset_tool_audit_log",
    "set_current_identity",
    "get_current_identity",
    "reset_current_identity",
    # Phase 10 tool-security service
    "Identity",
    "AuthenticatedIdentity",
    "Role",
    "ToolRole",
    "ToolRequest",
    "ToolResult",
    "ToolSandbox",
    "ToolSecurityPolicy",
    "RBACPolicy",
    "ArgumentSecurityScanner",
    "SecureToolExecutor",
    "ToolExecutor",
    "ACTIVE_TOOL_REGISTRY",
    "execute_tool_request",
    "resolve_server_identity",
]
