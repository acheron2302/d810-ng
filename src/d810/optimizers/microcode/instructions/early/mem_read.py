from d810.core.typing import Any, Optional

import ida_hexrays
import idaapi

from d810.hexrays.expr.ast import AstConstant, AstLeaf, AstNode
from d810.hexrays.utils.ida_utils import (
    is_never_written_var,
    is_read_only_inited_var,
    segment_is_read_only,
)
from d810.optimizers.microcode.handler import ConfigParam
from d810.optimizers.microcode.instructions.early.handler import EarlyRule
from d810.core import getLogger

early_rule_logger = getLogger("D810.early_rule")


class ReplaceReadonlyAddressOfWithImmediate2(EarlyRule):
    CATEGORY = "Early Transforms"
    CONFIG_SCHEMA = EarlyRule.CONFIG_SCHEMA + (
        ConfigParam(
            "ro_dword_min_ea", str, "", "Minimum address for RO data range (hex)"
        ),
        ConfigParam(
            "ro_dword_max_ea", str, "", "Maximum address for RO data range (hex)"
        ),
    )
    DESCRIPTION = "Replace mov &($sym[+off]), dst with immediate addr if in ro_dword_min_ea to ro_dword_max_ea"

    @property
    def PATTERN(self) -> AstNode:
        """Return the pattern to match."""
        return AstNode(ida_hexrays.m_mov, AstLeaf("ro_dword"))

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(ida_hexrays.m_mov, AstConstant("val_res"))

    def __init__(self):
        super().__init__()
        early_rule_logger.info("Initialize ReplaceReadonlyAddressOfWithImmediate2")
        self.ro_dword_min_ea: Optional[int] = None
        self.ro_dword_max_ea: Optional[int] = None
        self.maturities = [ida_hexrays.MMAT_PREOPTIMIZED]

    def configure(self, config_dict=None, **kwargs):
        # Let parent handle config_dict merging
        super().configure(config_dict=config_dict, **kwargs)

        self.ro_dword_min_ea = None
        self.ro_dword_max_ea = None
        # Use self.config which is set by parent class InstructionOptimizationRule
        if "ro_dword_min_ea" in self.config:
            raw_min = self.config["ro_dword_min_ea"]
            self.ro_dword_min_ea = int(raw_min, 16)
        if "ro_dword_max_ea" in self.config:
            raw_max = self.config["ro_dword_max_ea"]
            self.ro_dword_max_ea = int(raw_max, 16)
        return True

    def _generate_pattern_variations(self) -> list[AstNode]:
        if self.PATTERN is None:
            return []
        return [self.PATTERN]

    def _resolve_address_from_mop(
        self, mop_obj: ida_hexrays.mop_t | None
    ) -> int | None:
        if mop_obj is None:
            return None
        t = mop_obj.t
        if t == ida_hexrays.mop_v:
            global_addr = getattr(mop_obj, "g", None)
            if global_addr is None:
                return None
            value = int.from_bytes(idaapi.get_bytes(global_addr, mop_obj.size), 'little')

            return value

        return None

    def check_candidate(self, candidate) -> bool:
        if (self.ro_dword_min_ea is None) or (self.ro_dword_max_ea is None):
            return False
        leaf = candidate["ro_dword"]
        if leaf is None:
            return False
        mop = leaf.mop
        if mop is None:
            return False
        mop_t = getattr(mop, "t", None)
        if mop_t != ida_hexrays.mop_v:
            return False
        mem_read_address = getattr(mop, "g", None)
        if mem_read_address is None:
            return False
        if not (self.ro_dword_min_ea <= mem_read_address <= self.ro_dword_max_ea):
            return False

        num = self._resolve_address_from_mop(mop)
        if num is None:
            return False
        size = mop.size or 0
        if size == 0:
            return False
        early_rule_logger.info(f"Found candidate and changing num to size: {num}:{size}")
        candidate.add_constant_leaf("val_res", num, size)
        return True


class SetGlobalValueImm(EarlyRule):
    CATEGORY = "Early Transforms"
    CONFIG_SCHEMA = EarlyRule.CONFIG_SCHEMA + (
        ConfigParam(
            "ro_dword_min_ea", str, "", "Minimum address for RO data range (hex)"
        ),
        ConfigParam(
            "ro_dword_max_ea", str, "", "Maximum address for RO data range (hex)"
        ),
    )
    DESCRIPTION = "This rule can be used to patch memory read"

    @property
    def PATTERN(self) -> AstNode:
        """Return the pattern to match."""
        return AstNode(ida_hexrays.m_mov, AstLeaf("ro_dword"))

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(ida_hexrays.m_mov, AstConstant("val_res"))

    def __init__(self):
        super().__init__()
        self.ro_dword_min_ea: Optional[int] = None
        self.ro_dword_max_ea: Optional[int] = None

    def configure(self, config_dict=None, **kwargs):
        super().configure(config_dict=config_dict, **kwargs)
        self.ro_dword_min_ea = None
        self.ro_dword_max_ea = None
        early_rule_logger.debug(
            f"[SetGlobalValueImm] configure() called with config_dict={config_dict}, kwargs={kwargs}, self.config={self.config}"
        )
        if "ro_dword_min_ea" in self.config:
            self.ro_dword_min_ea = int(self.config["ro_dword_min_ea"], 16)
            early_rule_logger.debug(
                f"[SetGlobalValueImm] ro_dword_min_ea parsed: 0x{self.ro_dword_min_ea:X}"
            )
        if "ro_dword_max_ea" in self.config:
            self.ro_dword_max_ea = int(self.config["ro_dword_max_ea"], 16)
            early_rule_logger.debug(
                f"[SetGlobalValueImm] ro_dword_max_ea parsed: 0x{self.ro_dword_max_ea:X}"
            )
        return True

    def _generate_pattern_variations(self) -> list[AstNode]:
        if self.PATTERN is None:
            return []
        return [self.PATTERN]

    def check_candidate(self, candidate) -> bool:
        if (self.ro_dword_min_ea is None) or (self.ro_dword_max_ea is None):
            return False
        leaf = candidate["ro_dword"]
        if leaf is None:
            return False
        mop = leaf.mop
        if mop is None:
            return False
        if getattr(mop, "t", None) != ida_hexrays.mop_v:
            return False
        mem_read_address = getattr(mop, "g", None)
        if mem_read_address is None:
            return False
        if not (self.ro_dword_min_ea <= mem_read_address <= self.ro_dword_max_ea):
            return False

        candidate.add_constant_leaf("val_res", 0, mop.size)
        return True


class SetGlobalVariablesToZeroIfDetectedReadOnly(EarlyRule):
    DESCRIPTION = "WARNING: Use it only if you know what you are doing as it may patch data not related to obfuscation"

    @property
    def PATTERN(self) -> AstNode:
        """Return the pattern to match."""
        return AstNode(ida_hexrays.m_mov, AstLeaf("ro_dword"))

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(ida_hexrays.m_mov, AstConstant("val_res"))

    def __init__(self):
        super().__init__()
        self.maturities = [ida_hexrays.MMAT_PREOPTIMIZED]

    def _generate_pattern_variations(self) -> list[AstNode]:
        if self.PATTERN is None:
            return []
        return [self.PATTERN]

    def check_candidate(self, candidate) -> bool:
        """
        Replace reads from read-only initialized variables with zero.

        This rule detects mov instructions that read from global variables
        in read-only segments (.rdata/.rodata) and replaces the read with
        an immediate zero value. This is useful for defeating obfuscation
        techniques that use initialized read-only globals as opaque constants.

        The check uses is_read_only_inited_var() which verifies:
        - The address is in a read-only segment
        - The address is not an imported symbol
        - No write xrefs exist to this address

        WARNING: This may incorrectly patch non-zero read-only data.
        Use with caution and verify results manually.
        """
        leaf = candidate["ro_dword"]
        if leaf is None:
            return False
        mop = leaf.mop
        if mop is None:
            return False
        mem_read_address: Optional[int] = None
        if mop.t == ida_hexrays.mop_v:
            mem_read_address = mop.g
        elif mop.t == ida_hexrays.mop_a and mop.a is not None:
            inner = mop.a
            if inner.t == ida_hexrays.mop_v:
                mem_read_address = inner.g

        if mem_read_address is None:
            return False

        if not is_read_only_inited_var(mem_read_address):
            return False
        candidate.add_constant_leaf("val_res", 0, mop.size)
        return True


class ReplaceReadonlyAddressOfWithImmediate(EarlyRule):
    DESCRIPTION = (
        "Replace mov &($sym[+off]), dst with immediate addr if in .rdata/.rodata"
    )

    @property
    def PATTERN(self) -> AstNode:
        return AstNode(ida_hexrays.m_mov, AstLeaf("ro_addr"))

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(ida_hexrays.m_mov, AstConstant("val_res"))

    def __init__(self) -> None:
        super().__init__()
        self.maturities = [ida_hexrays.MMAT_PREOPTIMIZED]

    def _generate_pattern_variations(self) -> list[AstNode]:
        if self.PATTERN is None:
            return []
        return [self.PATTERN]

    def _resolve_address_from_mop(
        self, mop_obj: ida_hexrays.mop_t | None
    ) -> int | None:
        if mop_obj is None:
            return None
        t = mop_obj.t
        if t == ida_hexrays.mop_a:
            inner = mop_obj.a
            if inner is None:
                return None
            it = inner.t
            if it == ida_hexrays.mop_v:
                return inner.g
            if it == ida_hexrays.mop_S:
                return getattr(inner.s, "off", None) or getattr(
                    inner.s, "start_ea", None
                )
        elif t == ida_hexrays.mop_v:
            return mop_obj.g
        return None

    def check_candidate(self, candidate) -> bool:
        leaf = candidate["ro_addr"]
        if leaf is None:
            return False
        mop_obj: ida_hexrays.mop_t | None = leaf.mop
        if mop_obj is None:
            return False
        addr = self._resolve_address_from_mop(mop_obj)
        if addr is None:
            return False
        if not segment_is_read_only(addr):
            return False
        size = mop_obj.size or 0
        if size == 0:
            return False
        candidate.add_constant_leaf("val_res", addr, size)
        return True
