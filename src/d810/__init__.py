__version__ = "0.6.6"

# Bootstrap the speedups path so isolated optional dependencies (e.g. a
# user-local z3 install) are importable before any other d810 sub-module
# tries to load them.  Failures are logged but do not prevent the package
# from importing: speedups are an optional optimisation.
try:
    from d810.speedups.bootstrap import ensure_speedups_on_path

    ensure_speedups_on_path()
except Exception as exc:  # pragma: no cover - defensive logging
    import logging

    logging.getLogger(__name__).debug(
        "speedups bootstrap skipped: %s", exc, exc_info=True
    )
