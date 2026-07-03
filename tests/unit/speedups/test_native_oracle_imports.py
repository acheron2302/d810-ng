"""Unit tests for ``d810.cfg.contracts.native_oracle``.

This module has historically wrapped a Cython extension
``_cblock_oracle`` that was never implemented, leading to silent
``ImportError`` swallowing.  These tests pin the new, explicit stub
behaviour:

* ``NATIVE_ORACLE_AVAILABLE`` is always ``False`` unless a real
  ``_cblock_oracle`` module is installed.
* ``oracle_available()`` reflects that flag.
* Both ``check_mba_native`` and ``check_block_native`` return empty
  lists without raising.
"""

from __future__ import annotations


class TestNativeOracleStub:
    """The native oracle is a documented stub until somebody ports it."""

    def test_native_oracle_available_is_false(self):
        from d810.cfg.contracts import native_oracle

        assert native_oracle.NATIVE_ORACLE_AVAILABLE is False

    def test_oracle_available_returns_false(self):
        from d810.cfg.contracts import native_oracle

        assert native_oracle.oracle_available() is False

    def test_check_mba_native_returns_empty_list(self):
        from d810.cfg.contracts import native_oracle

        assert native_oracle.check_mba_native(None) == []

    def test_check_block_native_returns_empty_list(self):
        from d810.cfg.contracts import native_oracle

        assert native_oracle.check_block_native(None) == []

    def test_public_api_is_exported(self):
        from d810.cfg.contracts import native_oracle

        for name in (
            "NATIVE_ORACLE_AVAILABLE",
            "oracle_available",
            "check_mba_native",
            "check_block_native",
        ):
            assert hasattr(native_oracle, name), (
                f"native_oracle is missing expected symbol: {name}"
            )

    def test_module_does_not_try_to_import_missing_cython(self):
        """The old code tried to import ``_cblock_oracle`` and silently
        failed.  That import is now gone, so the module must remain
        importable even when a fake ``_cblock_oracle`` is installed
        with no real implementation.  We assert that the import path
        does not appear in ``native_oracle.__dict__`` to lock the
        decision down."""
        from d810.cfg.contracts import native_oracle

        # The placeholder module path must not be reachable via the
        # package; if someone re-introduces the import, they will have
        # to update this test and document why.
        assert "oracle_check_mba" not in native_oracle.__dict__
        assert "oracle_check_block" not in native_oracle.__dict__