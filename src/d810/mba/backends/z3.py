"""Compatibility shim for ``d810.backends.mba.z3``.

The canonical implementation lives in :mod:`d810.backends.mba.z3`. This
module re-exports its public surface so external scripts, tests, and
persisted plugin code that import the legacy path keep working.

Do not add new logic here. New code must import from
``d810.backends.mba.z3`` directly.
"""
from __future__ import annotations

from d810.backends.mba.z3 import (  # noqa: F401
    Z3VerificationEngine,
    Z3VerificationProvider,
    Z3VerificationVisitor,
    constraint_to_z3,
    create_z3_variables,
    prove_equivalence,
    requires_z3_installed,
    verify_rule,
)

__all__ = [
    "Z3VerificationEngine",
    "Z3VerificationProvider",
    "Z3VerificationVisitor",
    "constraint_to_z3",
    "create_z3_variables",
    "prove_equivalence",
    "requires_z3_installed",
    "verify_rule",
]