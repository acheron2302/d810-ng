"""Single-iteration loop unflattener.

Handles residual loops after main unflattening:

    Block 1: mov #INIT, state  ->  Block 2
    Block 2: jnz state, #CHECK, @exit  ->  Block 3 (body) or Block 4 (exit)
    Block 3: body; mov #UPDATE, state; goto @2

If INIT == CHECK and UPDATE != CHECK, this loop runs exactly once.
"""

import ida_hexrays

from d810.hexrays.utils.hexrays_helpers import (
    append_mop_if_not_in_list,
    equal_mops_ignore_size,
)
from d810.optimizers.microcode.flow.flattening.generic import (
    GenericDispatcherBlockInfo,
    GenericDispatcherCollector,
    GenericDispatcherInfo,
    GenericDispatcherUnflatteningRule,
)
from d810.optimizers.microcode.handler import ConfigParam

# Default: accept any large constant as potential state variable
# These can be overridden via config
DEFAULT_MIN_MAGIC = 0x1000  # Skip small constants (likely not state vars)
DEFAULT_MAX_MAGIC = 0xFFFFFFFF


class SingleIterationBlockInfo(GenericDispatcherBlockInfo):
    pass


class SingleIterationDispatcherInfo(GenericDispatcherInfo):
    """Dispatcher info for simple jnz-based residual loops."""

    # Configurable magic constant range
    min_magic: int = DEFAULT_MIN_MAGIC
    max_magic: int = DEFAULT_MAX_MAGIC

    def _is_magic_constant(self, val: int) -> bool:
        """Check if value is within the magic constant range."""
        # Handle both signed and unsigned interpretations
        unsigned_val = val & 0xFFFFFFFF
        return self.min_magic <= unsigned_val <= self.max_magic

    def _extract_jnz_state_and_const(
        self,
        insn: ida_hexrays.minsn_t,
    ) -> tuple[ida_hexrays.mop_t | None, int | None]:
        """Extract the state mop and comparison constant from a jnz instruction.

        Returns ``(state_mop, check_const)`` only when exactly one operand is a
        numeric constant.  Otherwise returns ``(None, None)`` so the caller can
        cheaply reject non-state patterns such as ``jnz #A, #B``.
        """
        if insn is None or insn.r is None or insn.l is None:
            return None, None
        right_is_num = insn.r.t == ida_hexrays.mop_n
        left_is_num = insn.l.t == ida_hexrays.mop_n
        if right_is_num and not left_is_num:
            return insn.l, insn.r.signed_value()
        if left_is_num and not right_is_num:
            return insn.r, insn.l.signed_value()
        return None, None

    def explore(self, blk: ida_hexrays.mblock_t) -> bool:
        self.reset()

        # Cheap structural rejection before any parsing work.
        if blk.tail is None or blk.tail.opcode != ida_hexrays.m_jnz:
            return False
        if blk.nsucc() != 2:
            return False

        state_mop, check_const = self._extract_jnz_state_and_const(blk.tail)
        if state_mop is None or check_const is None:
            return False
        if not self._is_magic_constant(check_const):
            return False

        # Scan successors for a state update to a different magic value.
        successor_infos: list[SingleIterationBlockInfo] = []
        comparison_values: list[int] = [check_const]
        for succ_serial in blk.succset:
            succ_blk = blk.mba.get_mblock(succ_serial)
            if succ_blk is None:
                return False
            val = self._find_magic_assignment(succ_blk, state_mop)
            if val is not None and val not in comparison_values:
                comparison_values.append(val)
            successor_infos.append(
                SingleIterationBlockInfo(succ_blk)
            )

        # Need at least two distinct magic values (init/check and update).
        if len(comparison_values) < 2:
            return False

        # All checks passed - commit accepted candidate state.
        self.mop_compared = state_mop
        self.comparison_values = comparison_values

        self.entry_block = SingleIterationBlockInfo(blk)
        self.entry_block.parse()
        for used_mop in self.entry_block.use_list:
            append_mop_if_not_in_list(used_mop, self.entry_block.assume_def_list)
        self.dispatcher_internal_blocks.append(self.entry_block)

        for exit_block in successor_infos:
            exit_block.register_father(self.entry_block)
            self.dispatcher_exit_blocks.append(exit_block)

        return True

    def _find_magic_assignment(
        self,
        blk: ida_hexrays.mblock_t,
        state_mop: ida_hexrays.mop_t,
    ) -> int | None:
        """Find a magic constant assignment to ``state_mop`` in ``blk``.

        Walks the block backwards from ``blk.tail`` looking for a
        ``mov #magic, state_mop`` instruction.  Backwards traversal matches
        the typical placement of state updates just before the backedge.
        """
        if state_mop is None:
            return None
        insn = blk.tail
        while insn is not None:
            if (
                insn.opcode == ida_hexrays.m_mov
                and insn.l is not None
                and insn.l.t == ida_hexrays.mop_n
                and equal_mops_ignore_size(insn.d, state_mop)
            ):
                val = insn.l.signed_value()
                if self._is_magic_constant(val):
                    return val
            insn = insn.prev
        return None


class SingleIterationCollector(GenericDispatcherCollector):
    DISPATCHER_CLASS = SingleIterationDispatcherInfo
    DEFAULT_DISPATCHER_MIN_COMPARISON_VALUE = 2
    DEFAULT_DISPATCHER_MIN_EXIT_BLOCK = 2
    DEFAULT_DISPATCHER_MIN_INTERNAL_BLOCK = 1

    def __init__(self):
        super().__init__()
        self.min_magic: int = DEFAULT_MIN_MAGIC
        self.max_magic: int = DEFAULT_MAX_MAGIC

    def configure(self, kwargs):
        super().configure(kwargs)
        if "min_magic" in kwargs:
            self.min_magic = int(kwargs["min_magic"])
        if "max_magic" in kwargs:
            self.max_magic = int(kwargs["max_magic"])

    def visit_minsn(self):
        # Mirrors GenericDispatcherCollector.visit_minsn but injects the
        # rule's min_magic/max_magic into the dispatcher info.  The generic
        # implementation has no factory hook and would call
        # ``disp_info.explore(self.blk, **kwargs)`` which our explore() does
        # not accept, so we override here.
        if self.blk.serial in self.explored_blk_serials:
            return 0
        self.explored_blk_serials.append(self.blk.serial)

        disp_info = self.DISPATCHER_CLASS(self.blk.mba)
        disp_info.min_magic = self.min_magic
        disp_info.max_magic = self.max_magic

        if not disp_info.explore(self.blk):
            return 0
        if not self.specific_checks(disp_info):
            return 0
        self.dispatcher_list.append(disp_info)
        return 0


class SingleIterationLoopUnflattener(GenericDispatcherUnflatteningRule):
    DESCRIPTION = "Remove residual single-iteration loops"
    DEFAULT_UNFLATTENING_MATURITIES = [ida_hexrays.MMAT_GLBOPT1]
    DEFAULT_MAX_PASSES = 3
    DEFAULT_MAX_DUPLICATION_PASSES = 5

    CONFIG_SCHEMA = GenericDispatcherUnflatteningRule.CONFIG_SCHEMA + (
        ConfigParam(
            "min_magic",
            int,
            DEFAULT_MIN_MAGIC,
            "Minimum magic state constant for single-iteration detection",
        ),
        ConfigParam(
            "max_magic",
            int,
            DEFAULT_MAX_MAGIC,
            "Maximum magic state constant for single-iteration detection",
        ),
    )

    @property
    def DISPATCHER_COLLECTOR_CLASS(self):
        return SingleIterationCollector
