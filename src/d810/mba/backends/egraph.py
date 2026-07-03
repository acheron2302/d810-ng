"""Compatibility shim for ``d810.backends.mba.egraph``.

The canonical (placeholder) implementation lives in
:mod:`d810.backends.mba.egraph`. This module re-exports its (currently
empty) public surface so external scripts, tests, and persisted plugin
code that import the legacy path keep working.

Do not add new logic here. New code must import from
``d810.backends.mba.egraph`` directly.
"""
from __future__ import annotations

from d810.backends.mba.egraph import *  # noqa: F401,F403  (placeholder has empty __all__)

__all__ = []  # placeholder module currently has no public symbols