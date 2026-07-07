"""Flattening flow rules.

Import concrete rule modules here so their FlowOptimizationRule subclasses
register through Registrant side effects when the package is loaded in IDA.

This makes rule registration deterministic: ``import
d810.optimizers.microcode.flow`` is sufficient to make the OLLVM
``Unflattener``, the Hodur ``HodurUnflattener``, ``UnflattenControlFlowRule``,
``UnflattenerSwitchCase``, ``UnflattenerTigressIndirect`` and every other
concrete flattening rule listed below visible in
``FlowOptimizationRule.registry``, in ``D810State.known_blk_rules``, and
therefore in the rule UI.

Rules listed here are concrete ``FlowOptimizationRule`` subclasses whose
``Registrant.__init_subclass__`` registration must run during plugin
startup so that user-facing configs (e.g. ``hodur_deobfuscation2.json``,
``test_unflattener.json``) can bind to them.  Lazy imports are reserved
for coordinator services (e.g. ``unflattener_refactored.py``) and other
modules that are only instantiated at ``optimize`` time, not at class
registration time.
"""

from d810.optimizers.microcode.flow.flattening import block_merge  # noqa: F401
from d810.optimizers.microcode.flow.flattening import fix_pred_cond_jump_block  # noqa: F401
from d810.optimizers.microcode.flow.flattening import mba_state_preconditioner  # noqa: F401
from d810.optimizers.microcode.flow.flattening import unflattener  # noqa: F401
from d810.optimizers.microcode.flow.flattening import unflattener_badwhile_loop  # noqa: F401
from d810.optimizers.microcode.flow.flattening import unflattener_cf  # noqa: F401
from d810.optimizers.microcode.flow.flattening import unflattener_fake_jump  # noqa: F401
from d810.optimizers.microcode.flow.flattening import unflattener_hodur  # noqa: F401
from d810.optimizers.microcode.flow.flattening import unflattener_indirect  # noqa: F401
from d810.optimizers.microcode.flow.flattening import unflattener_single_iteration  # noqa: F401
from d810.optimizers.microcode.flow.flattening import unflattener_switch_case  # noqa: F401