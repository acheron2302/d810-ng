import ida_hexrays

from d810.core import typing
from d810.core import getLogger
from d810.errors import AstEvaluationException
from d810.hexrays.expr.ast import AstConstant, AstNode, AstProxy
from d810.hexrays.ir.minsn_utils import minsn_to_ast
from d810.backends.ast.z3 import Z3MopProver
from d810.hexrays.utils.hexrays_formatters import format_minsn_t
from d810.optimizers.microcode.instructions.z3.handler import Z3Rule

logger = getLogger(__name__)


class Z3ConstantOptimization(Z3Rule):
    DESCRIPTION = "Detect and replace obfuscated constants"

    def __init__(self):
        super().__init__()
        self.min_nb_opcode = 3
        self.min_nb_constant = 3

    @property
    def PATTERN(self) -> AstNode | None:
        """Pattern-less rule; runs against every candidate instruction.

        Returning ``None`` here is intentional and means: do not pre-filter
        the candidate list with a structural pattern -- the rule itself will
        decide whether to act on each ``minsn_t``.
        """
        return None

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(ida_hexrays.m_mov, AstConstant("c_res"))

    @typing.override
    def configure(self, kwargs):
        super().configure(kwargs)
        if "min_nb_opcode" in kwargs.keys():
            self.min_nb_opcode = kwargs["min_nb_opcode"]
        if "min_nb_constant" in kwargs.keys():
            self.min_nb_constant = kwargs["min_nb_constant"]

    @typing.override
    def check_and_replace(self, blk: ida_hexrays.mblock_t, instruction: ida_hexrays.minsn_t) -> ida_hexrays.minsn_t | None:
        # Single try/except covers both ``minsn_to_ast``/``get_information``
        # and the Z3 evaluation: previously ``tmp.get_information()`` was
        # called before the ``try`` and an ``AttributeError`` from a malformed
        # proxy leaked out across the SWIG director boundary, aborting the
        # IDA decompile callback.
        try:
            tmp = minsn_to_ast(instruction)
            if tmp is None:
                return None
            leaf_info_list, cst_leaf_values, opcodes = tmp.get_information()
            leaf_num = len(leaf_info_list)

            if (
                leaf_num > 1
                or len(opcodes) < self.min_nb_opcode
                or len(cst_leaf_values) < self.min_nb_constant
            ):
                return None

            if logger.debug_on:
                logger.debug("Found candidate: %s", format_minsn_t(instruction))

            from d810.evaluator.evaluators import probe_is_constant

            is_const, val_0 = probe_is_constant(tmp, leaf_info_list)
            if logger.debug_on:
                logger.debug("  is_const: %s, val_0: %s", is_const, val_0)
            if not is_const or tmp.mop is None:
                return None

            # ``tmp.mop.size`` may be 0 for some mop_t flavors; guard so the
            # resulting ``make_number`` call always receives a positive size.
            cst_size = tmp.mop.size or 1

            # TODO(w00tzenheimer): if we're evaluating (evaluate_with_leaf_info) and the results are equal,
            #   why do we need to run the z3 equality check?
            #   why can't this simply be:
            #   if val_0 != val_1 or tmp.mop is None:
            #       return None
            #   tmp.add_constant_leaf("c_res", val_0, cst_size)
            #   tmp.compute_sub_ast()
            #   new_instruction = self.get_replacement(typing.cast(AstNode, tmp))
            #   return new_instruction
            c_res_mop = ida_hexrays.mop_t()
            c_res_mop.make_number(val_0, cst_size)
            if not Z3MopProver().are_equal(tmp.mop, c_res_mop):
                return None
            if logger.debug_on:
                logger.debug("  Z3MopProver.are_equal confirmed equality")

            tmp.add_constant_leaf("c_res", val_0, cst_size)

            # ``tmp`` may be an ``AstProxy`` wrapping the real candidate.  In
            # that case the leaf we just added lives on the proxy's private
            # clone, and ``compute_sub_ast`` must be re-run on that clone so
            # ``leafs_by_name`` and ``sub_ast_info_by_index`` stay consistent
            # before asking the rule to emit a replacement.
            candidate_ast = tmp._target if isinstance(tmp, AstProxy) else tmp
            candidate_ast.compute_sub_ast()

            new_instruction = self.get_replacement(
                typing.cast(AstNode, candidate_ast)
            )
            return new_instruction
        except ZeroDivisionError:
            logger.error("ZeroDivisionError while evaluating %s", instruction, exc_info=True)
            return None
        except AstEvaluationException as e:
            logger.error("Error while evaluating %s: %s", instruction, e, exc_info=True)
            return None
        except Exception:
            # Safety net: never let an unexpected exception escape this rule.
            # Without this, ``AttributeError`` and friends cross the SWIG
            # director boundary and abort the entire decompile callback with
            # ``Exception in SwigDirector_optinsn_t::func``.
            logger.exception(
                "Z3ConstantOptimization failed for %s",
                format_minsn_t(instruction),
            )
            return None

    @typing.override
    def check_candidate(self, candidate: AstNode) -> bool:
        """Return True if the candidate matches the rule, otherwise False."""
        return True
