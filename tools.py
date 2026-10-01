"""Safe tool surface used by the AgentShield workflow.

Every exported callable goes through ``guarded_tool``.  The decorator routes
through ``SecureToolExecutor`` for server-side identity, centralized RBAC,
argument validation, sandbox/test-resource execution, and the Phase 8
``UntrustedContentGuard`` output boundary.
"""

from __future__ import annotations

import json

from hooks.tool_guard import guarded_tool
from security.tool_security import (
    delete_temp_record_impl,
    query_test_db_impl,
    read_document_impl,
    read_temp_file_impl,
    search_web_impl,
    write_temp_file_impl,
)


@guarded_tool("web_search_tool", agent_caller="researcher", source_type="web")
def web_search_tool(query: str) -> str:
    """Bounded web search with a deterministic offline fallback."""

    return search_web_impl(query)


@guarded_tool("search_web", agent_caller="researcher", source_type="web")
def search_web(query: str) -> str:
    """Canonical safe web-search tool."""

    return search_web_impl(query)


@guarded_tool("query_test_db", agent_caller="researcher", source_type="database")
def query_test_db(search: str) -> str:
    """Parameterized read against the disposable test database only."""

    return query_test_db_impl(search)


@guarded_tool("mock_database_tool", agent_caller="researcher", source_type="database")
def mock_database_tool(entity_key: str) -> str:
    """Compatibility alias backed by the disposable parameterized test DB."""

    return query_test_db_impl(entity_key)


@guarded_tool("read_document", agent_caller="researcher", source_type="document")
def read_document(path: str) -> str:
    """Read a document only from the dedicated tool sandbox."""

    return read_document_impl(path)


@guarded_tool("write_temp_file", agent_caller="researcher", source_type="filesystem")
def write_temp_file(path: str, content: str) -> str:
    """Write text only below the dedicated temporary sandbox root."""

    return write_temp_file_impl(path, content)


@guarded_tool("read_temp_file", agent_caller="researcher", source_type="filesystem")
def read_temp_file(path: str) -> str:
    """Read text only below the dedicated temporary sandbox root."""

    return read_temp_file_impl(path)


@guarded_tool("delete_temp_record", agent_caller="admin_agent", source_type="database")
def delete_temp_record(record_id: str) -> str:
    """Delete only ``temp-*`` records from the disposable test database."""

    return delete_temp_record_impl(record_id)


# Historical names remain import-compatible but are not registered as active
# tools.  ToolSecurityPolicy denies them before these implementations can run.
@guarded_tool("tool_delete_database", agent_caller="admin_agent", source_type="legacy")
def tool_delete_database(target_db: str = "main", user_role: str = "USER") -> str:
    del target_db, user_role
    return json.dumps({"status": "LEGACY_DISABLED", "message": "No production database deletion tool is available."})


@guarded_tool("system_cmd", agent_caller="admin_agent", source_type="legacy")
def system_cmd(command: str, user_role: str = "USER") -> str:
    del command, user_role
    return json.dumps({"status": "LEGACY_DISABLED", "message": "No shell execution tool is available."})


__all__ = [
    "delete_temp_record",
    "mock_database_tool",
    "query_test_db",
    "read_document",
    "read_temp_file",
    "search_web",
    "system_cmd",
    "tool_delete_database",
    "web_search_tool",
    "write_temp_file",
]
