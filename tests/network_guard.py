"""Process-wide guard: the offline suite can never open a real socket.

``tests/__init__.py`` installs it, so every way of running the suite that
imports the ``tests`` package is covered (``python -m unittest discover -s
tests -t .`` or ``python -m unittest tests.test_x``). The guard raises
``NetworkAccessForbidden``, a ``BaseException`` subclass: the gateway turns
any ``Exception`` raised inside a provider into a journaled
``transport_failed``, which would silently absorb an ``AssertionError``.
Every refused call is also recorded in ``attempts``. Tests that need a
transport use the fakes in ``tests/fakes.py``, which never reach these
functions.
"""
from __future__ import annotations

import socket
import ssl
from typing import Any, Callable


class NetworkAccessForbidden(BaseException):
    """A test tried to resolve, connect or wrap a real socket."""


#: (owner, attribute, label) triples replaced by ``install``.
GUARDED: tuple[tuple[Any, str, str], ...] = (
    (socket.socket, "connect", "socket.socket.connect"),
    (socket.socket, "connect_ex", "socket.socket.connect_ex"),
    (socket, "create_connection", "socket.create_connection"),
    (socket, "getaddrinfo", "socket.getaddrinfo"),
    (ssl.SSLContext, "wrap_socket", "ssl.SSLContext.wrap_socket"),
)

#: Labels of every refused call, in order. Tests that probe the guard on
#: purpose remove their own entries.
attempts: list[str] = []


def _blocked(label: str) -> Callable[..., Any]:
    def refuse(*args: Any, **kwargs: Any) -> Any:
        attempts.append(label)
        # Arguments may name hosts or carry request data; never echo them.
        raise NetworkAccessForbidden(f"offline test suite: {label} is forbidden")
    refuse.network_guard = True  # type: ignore[attr-defined]
    return refuse


def install() -> None:
    """Idempotent; replaces every guarded attribute with a refusing stub."""
    for owner, name, label in GUARDED:
        if not getattr(getattr(owner, name), "network_guard", False):
            setattr(owner, name, _blocked(label))


def active() -> bool:
    return all(getattr(getattr(owner, name), "network_guard", False)
               for owner, name, _ in GUARDED)
