"""Shared recon CFG snapshot builder.

Constructs a portable :class:`FlowGraph` from a live ``mba_t`` once per
(func_ea, maturity) so that multiple recon collectors can read the same
topology without each walking ``get_mblock`` / ``succset`` independently.

Collected per block:
    * ``serial``             block serial number
    * ``block_type``         from ``blk.type`` (preferred) or ``blk.block_type``
    * ``succs``              tuple of successor serials
    * ``preds``              tuple of predecessor serials
    * ``start_ea``           block start effective address (or 0)
    * ``tail_opcode``        opcode of ``blk.tail`` (or 0)

Instructions are intentionally omitted by default; collectors that need
them (e.g. ``OpcodeDistributionCollector``) keep scanning the live MBA.

No IDA imports at module level - the helpers duck-type ``mba_t`` /
``mblock_t``.
"""
from __future__ import annotations

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph


def build_recon_flow_graph(mba, *, include_insns: bool = False) -> FlowGraph:
    """Build a portable :class:`FlowGraph` snapshot from a live MBA.

    Args:
        mba: Live ``mba_t`` (or any object exposing ``qty`` and
            ``get_mblock(idx)``).
        include_insns: Reserved for future use; currently ignored so we
            keep snapshot construction cheap.

    Returns:
        A :class:`FlowGraph` with block topology + tail opcodes only.
    """
    _ = include_insns  # currently always excluded
    blocks: dict[int, BlockSnapshot] = {}
    succs_map: dict[int, list[int]] = {}
    qty = int(getattr(mba, "qty", 0) or 0)
    for i in range(qty):
        blk = mba.get_mblock(i)
        if blk is None:
            continue
        serial = int(getattr(blk, "serial", i))
        # IDA mblock_t normally exposes ``type``; some test fixtures use
        # ``block_type`` instead. Fall back so we accept both.
        block_type = int(
            getattr(blk, "type", getattr(blk, "block_type", 0)) or 0
        )
        succs = tuple(int(s) for s in getattr(blk, "succset", ()))
        succs_map[serial] = list(succs)
        start_ea = int(getattr(blk, "start_ea", 0) or 0)
        tail = getattr(blk, "tail", None)
        tail_opcode = int(getattr(tail, "opcode", 0) or 0) if tail else 0
        blocks[serial] = BlockSnapshot(
            serial=serial,
            block_type=block_type,
            succs=succs,
            preds=(),  # filled below
            flags=int(getattr(blk, "flags", 0) or 0),
            start_ea=start_ea,
            insn_snapshots=(),
            tail_opcode=tail_opcode,
        )

    # Backfill preds from succs_map.
    pred_map: dict[int, set[int]] = {s: set() for s in blocks}
    for src, succs in succs_map.items():
        for dst in succs:
            if dst in pred_map:
                pred_map[dst].add(src)
    enriched: dict[int, BlockSnapshot] = {}
    for serial, blk in blocks.items():
        if serial in pred_map:
            enriched[serial] = BlockSnapshot(
                serial=serial,
                block_type=blk.block_type,
                succs=blk.succs,
                preds=tuple(sorted(pred_map[serial])),
                flags=blk.flags,
                start_ea=blk.start_ea,
                insn_snapshots=(),
                tail_opcode=blk.tail_opcode,
            )
        else:
            enriched[serial] = blk

    func_ea = int(getattr(mba, "entry_ea", 0) or 0)
    entry_serial = int(getattr(mba, "entry_serial", 0) or 0)
    if not entry_serial or entry_serial not in enriched:
        entry_serial = min(enriched) if enriched else 0

    return FlowGraph(
        blocks=enriched,
        entry_serial=entry_serial,
        func_ea=func_ea,
    )


# Collectors that already operate on FlowGraph-style targets and can safely
# consume a shared snapshot instead of the live MBA.
SNAPSHOT_COMPATIBLE_COLLECTORS: frozenset[str] = frozenset({
    "CFGShapeCollector",
    "DispatchPatternCollector",
    "compare_chain",
    "flow_profile_classifier",
})


__all__ = [
    "build_recon_flow_graph",
    "SNAPSHOT_COMPATIBLE_COLLECTORS",
]
