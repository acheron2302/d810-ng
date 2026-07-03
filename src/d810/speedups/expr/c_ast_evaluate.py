"""DEPRECATED compatibility shim for ``d810.speedups.expr.c_ast_evaluate``.

This module used to host ``AstEvaluator``, a duplicated Cython
implementation of the concrete microcode AST evaluator.  It has been
superseded by :class:`d810.speedups.evaluator.c_concrete.CythonConcreteEvaluator`
(see ``docs/plans/2026-02-18-evaluator-package-refactor.md``, Phase 5).

The module is preserved as a thin re-export so any remaining direct
imports of ``d810.speedups.expr.c_ast_evaluate.AstEvaluator`` continue to
work and point users at the canonical implementation.
"""

from __future__ import annotations

import warnings


_DEPRECATION_MESSAGE = (
    "d810.speedups.expr.c_ast_evaluate is deprecated and will be removed "
    "in a future release. Use "
    "d810.speedups.evaluator.c_concrete.CythonConcreteEvaluator instead."
)


warnings.warn(_DEPRECATION_MESSAGE, DeprecationWarning, stacklevel=2)


try:
    from d810.speedups.evaluator.c_concrete import (
        CythonConcreteEvaluator as AstEvaluator,
    )
except ImportError:  # pragma: no cover - speedups not built
    AstEvaluator = None


__all__ = ["AstEvaluator"]