import abc
import dataclasses
import time
from d810.core import typing

import ida_hexrays

from d810.core import getLogger
from d810.hexrays.expr.ast import AstBase, AstNode, AstNodeProtocol
from d810.hexrays.ir.minsn_utils import minsn_to_ast
from d810.hexrays.utils.hexrays_formatters import format_minsn_t
from d810.optimizers.microcode.instructions.handler import (
    GenericPatternRule,
    InstructionOptimizationRule,
    InstructionOptimizer,
)

optimizer_logger = getLogger("D810.optimizer")
early_rule_logger = getLogger("D810.early_rule")

if typing.TYPE_CHECKING:
    from d810.core import OptimizationStatistics


@dataclasses.dataclass
class CompiledRuleView:
    """Cached compiled state for an optimizer's rule set.

    This dataclass represents the compiled view of all active rules,
    including opcode filters and pattern storage. It includes a generation
    counter to detect when invalidation is needed.

    Attributes:
        generation: Monotonically increasing counter incremented on each mutation.
        allowed_opcodes: Frozenset of opcodes used by registered patterns.
        rule_count: Number of rules in the compiled view.
        compiled_at: Timestamp (time.monotonic()) when view was created.
    """

    generation: int
    allowed_opcodes: frozenset[int]
    rule_count: int
    compiled_at: float  # time.monotonic()


class EarlyRule(GenericPatternRule):
    CATEGORY = "Early Transforms"
    FUZZ_PATTERN: bool = False

    def __init__(self):
        super().__init__()
        self.fuzz_pattern = self.FUZZ_PATTERN

    def configure(self, config_dict=None, **kwargs):
        # Handle both rule.configure(config_dict) and rule.configure(fuzz_pattern=..., **kwargs)
        if config_dict is not None and isinstance(config_dict, dict):
            # Called as rule.configure(config_dict) - config dict passed as first positional arg
            kwargs.update(config_dict)
        fuzz_pattern = kwargs.pop("fuzz_pattern", None)
        super().configure(kwargs)
        if fuzz_pattern is not None:
            self.fuzz_pattern = fuzz_pattern
        self._generate_pattern_candidates()
        if early_rule_logger.debug_on:
            early_rule_logger.debug(
                "Rule %s configured with %s patterns",
                self.__class__.__name__,
                len(self.pattern_candidates),
            )

    def _generate_pattern_candidates(self):
        self.fuzz_pattern = self.FUZZ_PATTERN
        if self.PATTERN is not None:
            self.PATTERN.reset_mops()
        if not self.fuzz_pattern and self.PATTERN is not None:
            self.pattern_candidates = [self.PATTERN]
        else:
            self.pattern_candidates = self._generate_pattern_variations()
        if self.PATTERNS is not None:
            self.pattern_candidates += list(self.PATTERNS)

    def _generate_pattern_variations(self) -> list[AstNode]:
        if self.PATTERN is None:
            return []
        return [self.PATTERN]

    @property
    @abc.abstractmethod
    def PATTERN(self) -> AstNode:
        """Return the pattern to match."""

    @property
    @abc.abstractmethod
    def REPLACEMENT_PATTERN(self) -> AstNode:
        """Return the replacement pattern."""

    def check_pattern_and_replace(self, candidate_pattern: AstNode, test_ast: AstNode):
        if early_rule_logger.debug_on:
            early_rule_logger.debug(
                " 1. Checking pattern: %s against %s",
                candidate_pattern.get_pattern(),
                test_ast.get_pattern(),
            )
        if not candidate_pattern.check_pattern_and_copy_mops(test_ast):
            return None
        if early_rule_logger.debug_on:
            early_rule_logger.debug(
                " 2. Pattern matched: %s",
                candidate_pattern.get_pattern(),
            )
        if not self.check_candidate(candidate_pattern):
            return None
        if early_rule_logger.debug_on:
            early_rule_logger.debug(
                " 3. Candidate check passed: %s",
                candidate_pattern.get_pattern(),
            )
        new_instruction = self.get_replacement(candidate_pattern)
        if early_rule_logger.debug_on:
            early_rule_logger.debug(
                " 4. Replacement: %s",
                None if new_instruction is None else new_instruction,
            )
        return new_instruction

    def check_candidate(self, candidate: AstNode):
        return True

    def __repr__(self):
        return f"{self.__class__.__name__}({repr(self.PATTERN)} -> {repr(self.REPLACEMENT_PATTERN)})"


class EarlyOptimizer(InstructionOptimizer):
    RULE_CLASSES = [EarlyRule]

    def __init__(
        self,
        maturities: list[int],
        stats: "OptimizationStatistics",
        log_dir=None,
    ):
        super().__init__(maturities, stats, log_dir=log_dir)
        self._allowed_root_opcodes: set[int] = set()
        self._generation: int = 0
        self._compiled_view: CompiledRuleView | None = None

    def _get_compiled_view(self) -> CompiledRuleView:
        if (
            self._compiled_view is None
            or self._compiled_view.generation != self._generation
        ):
            self._compiled_view = self._compile_rules()
        return self._compiled_view

    def _compile_rules(self) -> CompiledRuleView:
        return CompiledRuleView(
            generation=self._generation,
            allowed_opcodes=frozenset(self._allowed_root_opcodes),
            rule_count=len(self.rules),
            compiled_at=time.monotonic(),
        )

    def invalidate(self) -> None:
        self._generation += 1

    def _add_rule_internal(self, rule) -> bool:
        if early_rule_logger.debug_on:
            early_rule_logger.debug("Adding rule %s", rule.name)
        if len(rule.maturities) == 0:
            rule.maturities = self.maturities
        self.rules.add(rule)

        if not hasattr(rule, "pattern_candidates"):
            return True
        try:
            candidates = rule.pattern_candidates
            early_rule_logger.debug(
                f"Rule {rule.name} has {len(candidates)} pattern candidates"
            )
        except Exception as e:
            early_rule_logger.error(f"Rule {rule.name} pattern_candidates failed: {e}")
            return False
        for pattern in candidates:
            if early_rule_logger.debug_on:
                early_rule_logger.debug(
                    "[EarlyOptimizer] Adding pattern: %s",
                    str(pattern),
                )
            try:
                if isinstance(pattern, AstNodeProtocol) and pattern.opcode is not None:
                    self._allowed_root_opcodes.add(int(pattern.opcode))
            except Exception:
                pass

        self._generation += 1
        return True

    def add_rule(self, rule: EarlyRule) -> bool:
        is_ok = super().add_rule(rule)
        if not is_ok:
            return False
        if not hasattr(rule, "pattern_candidates"):
            return True
        for pattern in rule.pattern_candidates:
            if early_rule_logger.debug_on:
                early_rule_logger.debug(
                    "[EarlyOptimizer.add_rule] Adding pattern: %s",
                    str(pattern),
                )
            try:
                if isinstance(pattern, AstNodeProtocol) and pattern.opcode is not None:
                    self._allowed_root_opcodes.add(int(pattern.opcode))
            except Exception:
                pass

        self._generation += 1
        return True

    def get_optimized_instruction(
        self,
        blk: ida_hexrays.mblock_t,
        ins: ida_hexrays.minsn_t,
        *,
        allowed_rule_names: frozenset[str] | None = None,
    ) -> ida_hexrays.minsn_t | None:
        if blk is not None:
            self.cur_maturity = blk.mba.maturity
        if self.cur_maturity not in self.maturities:
            early_rule_logger.debug(
                f"[EarlyOptimizer.get_optimized_instruction] maturity {self.cur_maturity} not in {self.maturities}, skipping"
            )
            return None
        if len(self.rules) == 0:
            if early_rule_logger.debug_on:
                early_rule_logger.debug(
                    "[EarlyOptimizer.get_optimized_instruction] No rules configured, skipping"
                )
            return None

        # Lazy populate _allowed_root_opcodes if empty (handles case where add_rule ran before configure)
        if not self._allowed_root_opcodes:
            early_rule_logger.debug(
                "[EarlyOptimizer.get_optimized_instruction] _allowed_root_opcodes is empty, repopulating from rules"
            )
            for rule in self.rules:
                if hasattr(rule, "pattern_candidates"):
                    for pattern in rule.pattern_candidates:
                        try:
                            if (
                                isinstance(pattern, AstNodeProtocol)
                                and pattern.opcode is not None
                            ):
                                self._allowed_root_opcodes.add(int(pattern.opcode))
                        except Exception:
                            pass

        try:
            if ins.opcode not in self._allowed_root_opcodes:
                early_rule_logger.debug(
                    f"[EarlyOptimizer.get_optimized_instruction] opcode {ins.opcode} not in allowed opcodes {self._allowed_root_opcodes}"
                )
                return None
        except Exception:
            pass

        tmp = minsn_to_ast(ins)
        if tmp is None:
            early_rule_logger.debug(
                "[EarlyOptimizer.get_optimized_instruction] minsn_to_ast returned None, skipping"
            )
            return None

        # Log what minsn_to_ast returned for debugging
        # Check if we got a constant instead of a node - this indicates minsn_to_ast failed to build proper AST
        if hasattr(tmp, "is_constant") and tmp.is_constant() and hasattr(tmp, "name"):
            early_rule_logger.debug(
                f"[EarlyOptimizer.get_optimized_instruction] minsn_to_ast returned a constant with name='{tmp.name}' (expected instruction AST), skipping"
            )
            return None

        for rule in self.rules:
            if allowed_rule_names is not None and rule.name not in allowed_rule_names:
                continue
            if self.cur_maturity not in rule.maturities:
                continue
            if early_rule_logger.debug_on:
                early_rule_logger.debug(
                    "[EarlyOptimizer.get_optimized_instruction] Trying rule: %s",
                    rule.name,
                )
            for candidate_pattern in rule.pattern_candidates:
                try:
                    new_ins = rule.check_pattern_and_replace(candidate_pattern, tmp)
                    if new_ins is not None:
                        if early_rule_logger.info_on:
                            early_rule_logger.info(
                                "Rule %s matched in maturity %s:",
                                rule.name,
                                self.cur_maturity,
                            )
                            early_rule_logger.info("  orig: %s", format_minsn_t(ins))
                            early_rule_logger.info(
                                "  new : %s",
                                format_minsn_t(new_ins),
                            )
                        if self.stats is not None:
                            self.stats.record_rule_fired(
                                rule=rule,
                                optimizer=self.name,
                                maturity=self.cur_maturity,
                            )
                        return new_ins
                except RuntimeError as e:
                    early_rule_logger.error(
                        "Runtime error during rule %s for instruction %s: %s",
                        rule.name,
                        format_minsn_t(ins),
                        e,
                        exc_info=True,
                    )
        return None
