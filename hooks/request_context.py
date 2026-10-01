"""Request-local security context shared by guarded runtime boundaries.

The API executes synchronous graph nodes in worker threads and can serve
multiple requests concurrently.  Context variables keep identity, request
correlation, and in-memory audit records isolated without changing the public
event schemas or legacy imports.
"""

from __future__ import annotations

from contextvars import ContextVar
from typing import Generic, Iterator, TypeVar, overload


T = TypeVar("T")


class ContextAuditLog(Generic[T]):
    """List-like compatibility wrapper backed by a request-local ContextVar."""

    def __init__(self, name: str) -> None:
        self._var: ContextVar[list[T] | None] = ContextVar(name, default=None)

    def _items(self) -> list[T]:
        items = self._var.get()
        if items is None:
            items = []
            self._var.set(items)
        return items

    def append(self, item: T) -> None:
        self._items().append(item)

    def clear(self) -> None:
        self._var.set([])

    def snapshot(self) -> list[T]:
        return list(self._items())

    def __iter__(self) -> Iterator[T]:
        return iter(self._items())

    def __len__(self) -> int:
        return len(self._items())

    def __bool__(self) -> bool:
        return bool(self._items())

    def __contains__(self, item: object) -> bool:
        return item in self._items()

    @overload
    def __getitem__(self, index: int) -> T: ...

    @overload
    def __getitem__(self, index: slice) -> list[T]: ...

    def __getitem__(self, index: int | slice) -> T | list[T]:
        return self._items()[index]


_request_id: ContextVar[str] = ContextVar("agentshield_request_id", default="req-default")
_identity: ContextVar[object | None] = ContextVar("agentshield_identity", default=None)


def set_request_id(value: str) -> None:
    _request_id.set(str(value))


def current_request_id() -> str:
    return _request_id.get()


def reset_request_id() -> None:
    _request_id.set("req-default")


def set_identity(value: object) -> None:
    _identity.set(value)


def current_identity() -> object | None:
    return _identity.get()


def reset_identity() -> None:
    _identity.set(None)

