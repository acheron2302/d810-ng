"""Regression tests for cfg_utils CFG safety guards.

These tests run with lightweight fake IDA modules and focus on crash-prone CFG helpers:
1. ensure_child_has_an_unconditional_father() default-child handling
2. create_block(is_0_way=True) goto cleanup
"""

from __future__ import annotations

import json
import sys
from types import SimpleNamespace

import pytest


class _FakeSet(list):
    def push_back(self, value):
        self.append(value)

    def _del(self, value):
        if value in self:
            self.remove(value)


class _FakeMBA:
    def __init__(self, qty: int = 12):
        self.qty = qty
        self.entry_ea = 0x1000
        self.maturity = 0
        self.blocks: dict[int, _FakeBlock] = {}
        self.marked_dirty = 0
        self.verify_error: RuntimeError | None = None

    def get_mblock(self, serial: int):
        return self.blocks[serial]

    def mark_chains_dirty(self):
        self.marked_dirty += 1

    def verify(self, _always: bool):
        if self.verify_error is not None:
            raise self.verify_error


class _FakeBlock:
    def __init__(
        self,
        serial: int,
        mba: _FakeMBA,
        succs: list[int] | None = None,
        preds: list[int] | None = None,
        tail=None,
    ):
        self.serial = serial
        self.mba = mba
        self.succset = _FakeSet(succs or [])
        self.predset = _FakeSet(preds or [])
        self.tail = tail
        self.type = 1
        self.flags = 0
        self.marked_dirty = 0
        self.nopped: list[object] = []
        mba.blocks[serial] = self

    def nsucc(self) -> int:
        return len(self.succset)

    def mark_lists_dirty(self):
        self.marked_dirty += 1

    def make_nop(self, ins):
        self.nopped.append(ins)


@pytest.fixture(autouse=True)
def _mock_cfg_utils_import_deps():
    """Load cfg_utils with minimal fake IDA/transitive Hex-Rays deps."""
    mock_hexrays = SimpleNamespace(
        BLT_0WAY=0,
        BLT_1WAY=1,
        BLT_2WAY=2,
        MBL_GOTO=0x20,
        m_goto=0x37,
    )
    mock_idaapi = SimpleNamespace()

    class _Printer:
        def get_block_mc(self):
            return ""

    modules_to_mock = {
        "ida_hexrays": mock_hexrays,
        "idaapi": mock_idaapi,
        "d810.hexrays.hexrays_formatters": SimpleNamespace(block_printer=lambda: _Printer()),
        "d810.hexrays.hexrays_helpers": SimpleNamespace(CONDITIONAL_JUMP_OPCODES=frozenset()),
    }

    # Ensure cfg_utils imports against this fixture's module mocks.
    popped = {}
    for mod_name in (
        "d810.hexrays.cfg_utils",
        "d810.hexrays.hexrays_formatters",
        "d810.hexrays.hexrays_helpers",
    ):
        if mod_name in sys.modules:
            popped[mod_name] = sys.modules.pop(mod_name)

    # Temporarily inject mock modules into sys.modules
    original_modules = {}
    for mod_name, mod_obj in modules_to_mock.items():
        original_modules[mod_name] = sys.modules.get(mod_name)
        sys.modules[mod_name] = mod_obj

    try:
        yield
    finally:
        # Restore original sys.modules state
        for mod_name in modules_to_mock:
            if original_modules[mod_name] is None:
                sys.modules.pop(mod_name, None)
            else:
                sys.modules[mod_name] = original_modules[mod_name]

        # Restore previously cached modules
        for mod_name, mod in popped.items():
            sys.modules[mod_name] = mod


def test_ensure_child_skips_default_child_rewrite(monkeypatch):
    """Default-child path must not create helper blocks (orphan risk / INTERR 50856)."""
    from d810.hexrays import cfg_utils

    mba = _FakeMBA(qty=20)
    father = _FakeBlock(
        3,
        mba,
        succs=[4, 5],
        tail=SimpleNamespace(d=SimpleNamespace(b=4)),
    )
    child = _FakeBlock(5, mba, succs=[])

    calls = {"insert": 0, "c1": 0, "c2": 0}
    monkeypatch.setattr(
        cfg_utils,
        "insert_nop_blk",
        lambda *_a, **_k: calls.__setitem__("insert", calls["insert"] + 1),
    )
    monkeypatch.setattr(
        cfg_utils,
        "change_1way_block_successor",
        lambda *_a, **_k: calls.__setitem__("c1", calls["c1"] + 1),
    )
    monkeypatch.setattr(
        cfg_utils,
        "change_2way_block_conditional_successor",
        lambda *_a, **_k: calls.__setitem__("c2", calls["c2"] + 1),
    )
    monkeypatch.setattr(
        cfg_utils,
        "create_standalone_block",
        lambda *_a, **_k: pytest.fail("create_standalone_block should not be called"),
    )

    changed = cfg_utils.ensure_child_has_an_unconditional_father(
        father,
        child,
        verify=False,
    )

    assert changed == 0
    assert calls == {"insert": 0, "c1": 0, "c2": 0}


def test_ensure_child_conditional_path_rewires_via_helper_block(monkeypatch):
    """Conditional-child path should still perform the helper-block rewrite."""
    from d810.hexrays import cfg_utils

    mba = _FakeMBA(qty=120)
    father = _FakeBlock(
        10,
        mba,
        succs=[11, 12],
        tail=SimpleNamespace(d=SimpleNamespace(b=33)),
    )
    child = _FakeBlock(33, mba, succs=[])
    new_father = _FakeBlock(77, mba, succs=[11])

    calls = {"standalone": None, "c2": None}

    def _change_2way(blk, serial, verify=True):
        calls["c2"] = (blk.serial, serial, verify)
        return True

    def _create_standalone(ref_blk, blk_ins, target_serial, is_0_way, verify=True):
        calls["standalone"] = (
            ref_blk.serial,
            list(blk_ins),
            target_serial,
            is_0_way,
            verify,
        )
        return new_father

    monkeypatch.setattr(cfg_utils, "create_standalone_block", _create_standalone)
    monkeypatch.setattr(cfg_utils, "change_2way_block_conditional_successor", _change_2way)

    changed = cfg_utils.ensure_child_has_an_unconditional_father(
        father,
        child,
        verify=False,
    )

    assert changed == 1
    assert calls["standalone"] == (10, [], 33, False, False)
    assert calls["c2"] == (10, 77, False)


@pytest.mark.parametrize(
    "father_factory",
    [
        lambda mba: None,
        lambda mba: _FakeBlock(1, mba, succs=[2], tail=SimpleNamespace(d=SimpleNamespace(b=2))),
        lambda mba: _FakeBlock(2, mba, succs=[3, 4, 5], tail=SimpleNamespace(d=SimpleNamespace(b=5))),
        lambda mba: _FakeBlock(3, mba, succs=[4, 5], tail=None),
    ],
)
def test_ensure_child_guard_paths_noop(father_factory, monkeypatch):
    """Guard clauses should no-op without touching CFG rewrite helpers."""
    from d810.hexrays import cfg_utils

    mba = _FakeMBA(qty=20)
    child = _FakeBlock(9, mba, succs=[])
    father = father_factory(mba)

    monkeypatch.setattr(
        cfg_utils,
        "insert_nop_blk",
        lambda *_a, **_k: pytest.fail("insert_nop_blk should not be called"),
    )
    monkeypatch.setattr(
        cfg_utils,
        "create_standalone_block",
        lambda *_a, **_k: pytest.fail("create_standalone_block should not be called"),
    )
    monkeypatch.setattr(
        cfg_utils,
        "change_1way_block_successor",
        lambda *_a, **_k: pytest.fail("change_1way_block_successor should not be called"),
    )
    monkeypatch.setattr(
        cfg_utils,
        "change_2way_block_conditional_successor",
        lambda *_a, **_k: pytest.fail("change_2way_block_conditional_successor should not be called"),
    )

    changed = cfg_utils.ensure_child_has_an_unconditional_father(
        father,
        child,
        verify=False,
    )
    assert changed == 0


def test_create_block_0way_clears_goto_and_edges(monkeypatch):
    """0-way created blocks must not keep insert_nop_blk's goto (INTERR 50856 regression)."""
    from d810.hexrays import cfg_utils

    mba = _FakeMBA(qty=12)
    prev_succ = _FakeBlock(7, mba, succs=[], preds=[6])
    ref_blk = _FakeBlock(2, mba, succs=[7])
    new_blk = _FakeBlock(
        6,
        mba,
        succs=[7],
        preds=[],
        tail=SimpleNamespace(opcode=cfg_utils.ida_hexrays.m_goto),
    )
    new_blk.flags = cfg_utils.ida_hexrays.MBL_GOTO

    monkeypatch.setattr(cfg_utils, "insert_nop_blk", lambda _blk: new_blk)

    result = cfg_utils.create_block(
        ref_blk,
        blk_ins=[],
        is_0_way=True,
        verify=False,
    )

    assert result is new_blk
    assert new_blk.type == cfg_utils.ida_hexrays.BLT_0WAY
    assert (new_blk.flags & cfg_utils.ida_hexrays.MBL_GOTO) == 0
    assert new_blk.nopped == [new_blk.tail]
    assert list(new_blk.succset) == []
    assert 6 not in prev_succ.predset
    assert prev_succ.marked_dirty == 1
    assert new_blk.marked_dirty == 1
    assert mba.marked_dirty == 1


def test_safe_verify_persists_failure_artifact(tmp_path, monkeypatch):
    """safe_verify should emit a JSON artifact with focused block capture."""
    from d810.hexrays import cfg_utils

    mba = _FakeMBA(qty=6)
    _FakeBlock(0, mba, succs=[1], preds=[])
    _FakeBlock(
        1,
        mba,
        succs=[2],
        preds=[0],
        tail=SimpleNamespace(
            ea=0x1234,
            opcode=0x37,
            l=SimpleNamespace(t=0, b=2),
            d=SimpleNamespace(t=0, b=3),
        ),
    )
    _FakeBlock(2, mba, succs=[3], preds=[1])
    mba.verify_error = RuntimeError("Unknown exception")

    monkeypatch.setenv("D810_VERIFY_CAPTURE", "1")
    monkeypatch.setenv("D810_VERIFY_CAPTURE_DIR", str(tmp_path))

    with pytest.raises(RuntimeError):
        cfg_utils.safe_verify(
            mba,
            "unit-test verify failure",
            capture_blocks=[1],
            capture_metadata={"rule": "unit_test_rule", "mod_index": 7},
        )

    artifacts = list(tmp_path.glob("verify_fail_*.json"))
    assert len(artifacts) == 1

    payload = json.loads(artifacts[0].read_text(encoding="utf-8"))
    assert payload["context"] == "verify failure after unit-test verify failure"
    assert payload["error_type"] == "RuntimeError"
    assert payload["metadata"]["rule"] == "unit_test_rule"
    assert 1 in payload["focus_blocks"]
    captured_serials = {blk["serial"] for blk in payload["captured_blocks"]}
    assert 1 in captured_serials


def test_verify_failure_analyzer_contract_matches_capture_artifact(tmp_path, monkeypatch, capsys):
    """Analyzer contract should accept payloads produced by safe_verify/capture_failure_artifact."""
    from d810.hexrays import cfg_utils
    from tools import analyze_verify_failures as avf

    mba = _FakeMBA(qty=7)
    _FakeBlock(0, mba, succs=[1], preds=[])
    _FakeBlock(
        1,
        mba,
        succs=[2, 3],
        preds=[0],
        tail=SimpleNamespace(
            ea=0x2222,
            opcode=0x44,
            l=SimpleNamespace(t=0, b=2),
            d=SimpleNamespace(t=0, b=3),
        ),
    )
    _FakeBlock(2, mba, succs=[4], preds=[1])
    _FakeBlock(3, mba, succs=[4], preds=[1])
    _FakeBlock(4, mba, succs=[], preds=[2, 3])
    mba.verify_error = RuntimeError("Unknown exception")

    monkeypatch.setenv("D810_VERIFY_CAPTURE", "1")
    monkeypatch.setenv("D810_VERIFY_CAPTURE_DIR", str(tmp_path))

    with pytest.raises(RuntimeError):
        cfg_utils.safe_verify(
            mba,
            "unit-test analyzer contract",
            capture_blocks=[1, 2],
            capture_metadata={
                "phase": "incremental_verify",
                "modification": {
                    "mod_type": "BLOCK_GOTO_CHANGE",
                    "block_serial": 1,
                    "new_target": 4,
                    "description": "unit-test change",
                },
            },
        )

    artifacts = sorted(tmp_path.glob("verify_fail_*.json"))
    assert len(artifacts) == 1
    payload = avf._load_artifact(artifacts[0])

    # Contract check: analyzer-required shape should be present in real captures.
    contract_warnings = avf._validate_capture_contract(payload)
    assert contract_warnings == []

    # Heuristic APIs should consume captured payload without fallback contract warnings.
    hypotheses = avf._infer_hypotheses(payload)
    assert hypotheses
    assert not any("Artifact contract warnings:" in h for h in hypotheses)
    formatted = avf._format_entry(payload, artifacts[0])
    assert "Contract warnings:" not in formatted

    # CLI JSON mode should include contract_warnings=[] for this artifact.
    rc = avf.main([str(tmp_path), "--latest", "1", "--json"])
    assert rc == 0
    out = capsys.readouterr().out
    rendered = json.loads(out)
    assert rendered["count"] == 1
    assert rendered["artifacts"][0]["contract_warnings"] == []


# ---------------------------------------------------------------------------
# Verify-failure diagnostics (plan: verify-diagnostics)
# ---------------------------------------------------------------------------


class _FakeContract:
    """Minimal stand-in for IDACfgContract used by diagnostic tests."""

    def __init__(self, violations=None, exc=None):
        self._violations = list(violations or [])
        self._exc = exc
        self.calls: list[dict] = []

    def verify(self, mba, plan=None, **kwargs):
        self.calls.append({"mba": mba, "plan": plan, **kwargs})
        if self._exc is not None:
            raise self._exc
        if self._violations:
            from d810.cfg.contracts.ida_contract import CfgContractViolationError

            raise CfgContractViolationError(
                phase=kwargs.get("phase", "post"), violations=self._violations
            )
        return ()


def _make_violation(code: str, serial: int | None = None, msg: str = "boom"):
    from d810.cfg.contracts.report import InvariantViolation

    return InvariantViolation(
        code=code,
        message=msg,
        phase="post",
        block_serial=serial,
    )


def test_collect_cfg_verify_diagnostics_serializes_violations(monkeypatch):
    """collect_cfg_verify_diagnostics should return dicts with code/block_serial."""
    from d810.hexrays.mutation import cfg_verify

    mba = _FakeMBA(qty=10)
    fake = _FakeContract(
        violations=[
            _make_violation("CFG_50860_SUCC_MISMATCH", serial=4, msg="mismatch"),
        ]
    )
    # Patch the import target used inside collect_cfg_verify_diagnostics.
    import d810.cfg.contracts.ida_contract as ida_contract_mod

    monkeypatch.setattr(ida_contract_mod, "IDACfgContract", lambda: fake)

    diagnostics = cfg_verify.collect_cfg_verify_diagnostics(mba)
    assert len(diagnostics) == 1
    d = diagnostics[0]
    assert d["code"] == "CFG_50860_SUCC_MISMATCH"
    assert d["block_serial"] == 4
    assert d["message"] == "mismatch"
    assert fake.calls and fake.calls[0]["scope"] == "full"


def test_collect_cfg_verify_diagnostics_handles_internal_failure(monkeypatch):
    """An exception inside the contract should produce CFG_DIAGNOSTIC_FAILED."""
    from d810.hexrays.mutation import cfg_verify

    mba = _FakeMBA(qty=4)
    fake = _FakeContract(exc=RuntimeError("boom"))
    import d810.cfg.contracts.ida_contract as ida_contract_mod

    monkeypatch.setattr(ida_contract_mod, "IDACfgContract", lambda: fake)

    diagnostics = cfg_verify.collect_cfg_verify_diagnostics(mba)
    assert len(diagnostics) == 1
    assert diagnostics[0]["code"] == "CFG_DIAGNOSTIC_FAILED"
    assert "boom" in diagnostics[0]["message"]


def test_safe_verify_runs_python_diagnostics_and_merges_capture_blocks(
    tmp_path, monkeypatch, caplog
):
    """safe_verify should run diagnostics and include diagnostic serials in capture_blocks."""
    from d810.hexrays.mutation import cfg_verify

    mba = _FakeMBA(qty=8)
    _FakeBlock(0, mba, succs=[1], preds=[])
    _FakeBlock(1, mba, succs=[2], preds=[0])
    _FakeBlock(2, mba, succs=[3], preds=[1])
    mba.verify_error = RuntimeError("Unknown exception")

    fake = _FakeContract(
        violations=[_make_violation("CFG_50860_SUCC_MISMATCH", serial=2)]
    )
    import d810.cfg.contracts.ida_contract as ida_contract_mod

    monkeypatch.setattr(ida_contract_mod, "IDACfgContract", lambda: fake)

    monkeypatch.setenv("D810_VERIFY_CAPTURE", "1")
    monkeypatch.setenv("D810_VERIFY_CAPTURE_DIR", str(tmp_path))

    caplog.set_level("ERROR", logger="d810.hexrays.mutation.cfg_verify")

    with pytest.raises(RuntimeError):
        cfg_verify.safe_verify(
            mba,
            "unit-test diagnostic",
            capture_blocks=[1],
        )

    artifacts = list(tmp_path.glob("verify_fail_*.json"))
    assert len(artifacts) == 1
    payload = json.loads(artifacts[0].read_text(encoding="utf-8"))

    # Diagnostic block serials are included in the captured blocks.
    captured_serials = {blk["serial"] for blk in payload["captured_blocks"]}
    assert 2 in captured_serials

    # Violation metadata is present.
    meta = payload["metadata"]
    assert "cfg_diagnostic_violations" in meta
    assert meta["cfg_diagnostic_violations"][0]["code"] == "CFG_50860_SUCC_MISMATCH"
    assert meta["diagnostic_block_serials"] == [2]

    # Diagnostic summary is logged.
    assert any("Python CFG diagnostics found" in rec.message for rec in caplog.records)
    assert any("CFG_50860_SUCC_MISMATCH" in rec.message for rec in caplog.records)


def test_safe_verify_emits_cfg_diagnostic_failed_when_collection_breaks(
    tmp_path, monkeypatch, caplog
):
    """Diagnostic collection failure must produce CFG_DIAGNOSTIC_FAILED, not raise."""
    from d810.hexrays.mutation import cfg_verify

    mba = _FakeMBA(qty=4)
    _FakeBlock(0, mba, succs=[1], preds=[])
    _FakeBlock(1, mba, succs=[], preds=[0])
    mba.verify_error = RuntimeError("Unknown exception")

    fake = _FakeContract(exc=ValueError("contract exploded"))
    import d810.cfg.contracts.ida_contract as ida_contract_mod

    monkeypatch.setattr(ida_contract_mod, "IDACfgContract", lambda: fake)

    monkeypatch.setenv("D810_VERIFY_CAPTURE", "1")
    monkeypatch.setenv("D810_VERIFY_CAPTURE_DIR", str(tmp_path))

    caplog.set_level("ERROR", logger="d810.hexrays.mutation.cfg_verify")

    with pytest.raises(RuntimeError):
        cfg_verify.safe_verify(mba, "unit-test diagnostic failure")

    artifacts = list(tmp_path.glob("verify_fail_*.json"))
    assert len(artifacts) == 1
    payload = json.loads(artifacts[0].read_text(encoding="utf-8"))
    meta = payload["metadata"]
    assert meta["cfg_diagnostic_violations"][0]["code"] == "CFG_DIAGNOSTIC_FAILED"


def test_change_2way_block_conditional_successor_uses_safe_verify(monkeypatch):
    """The 2-way mutation helper should delegate verification to safe_verify."""
    from d810.hexrays import cfg_utils
    from d810.hexrays.mutation import cfg_mutations
    from d810.hexrays.mutation import cfg_verify

    # The helper does `blk.tail.d = ida_hexrays.mop_t()` then make_blkref.
    # Replace mop_t in cfg_mutations' ida_hexrays module with a fake that
    # returns an object exposing make_blkref.
    class _FakeMop:
        def __init__(self):
            self.b: int | None = None

        def make_blkref(self, b: int) -> None:
            self.b = int(b)

        def erase(self) -> None:
            self.b = None

    fake_mop_t = _FakeMop
    # cfg_mutations does `import ida_hexrays`; patch the symbol it uses.
    monkeypatch.setattr(cfg_mutations.ida_hexrays, "mop_t", fake_mop_t)
    # Also patch the original module in case cfg_mutations re-reads it.
    monkeypatch.setattr(cfg_verify.ida_hexrays, "mop_t", fake_mop_t)

    mba = _FakeMBA(qty=12)
    # tail.d must expose .b for the existing helper's first read of
    # previous_blk_conditional_successor_serial.
    tail = SimpleNamespace(
        ea=0x4000,
        opcode=0x99,
        l=SimpleNamespace(t=0, b=7),
        d=SimpleNamespace(b=7),
    )
    blk = _FakeBlock(5, mba, succs=[7, 8], preds=[3], tail=tail)
    _FakeBlock(7, mba, succs=[], preds=[5])
    _FakeBlock(8, mba, succs=[], preds=[5])
    _FakeBlock(3, mba, succs=[5], preds=[])
    _FakeBlock(9, mba, succs=[], preds=[])

    captured = {}

    def _fake_safe_verify(mba_arg, ctx, **kwargs):
        captured["ctx"] = ctx
        captured["kwargs"] = kwargs

    monkeypatch.setattr(cfg_mutations, "safe_verify", _fake_safe_verify)
    monkeypatch.setattr(cfg_verify, "safe_verify", _fake_safe_verify)

    # The helper should call safe_verify even though the underlying verify
    # would normally pass.
    result = cfg_mutations.change_2way_block_conditional_successor(
        blk, 9, verify=True
    )
    assert result is True
    assert captured["ctx"] == "change_2way_block_conditional_successor"
    meta = captured["kwargs"]["capture_metadata"]
    assert meta["operation"] == "change_2way_block_conditional_successor"
    assert meta["source_block_serial"] == 5
    assert meta["old_conditional_target"] == 7
    assert meta["new_conditional_target"] == 9
    assert 5 in captured["kwargs"]["capture_blocks"]
