"""Offline fixtures and deterministic regressions; never live accuracy evidence.

Importing this package installs the network guard (``tests/network_guard.py``)
before any test module loads. Run the suite with
``python -m unittest discover -s tests -t .`` so the package init always runs.
"""
from tests import network_guard as _network_guard

_network_guard.install()
