"""Flow optimizer package.

Import rule modules here so their FlowOptimizationRule subclasses register
eagerly via Registrant metaclass side effects.
"""

try:
    import ida_hexrays  # noqa: F401
except ImportError:
    # Allow package import in non-IDA environments.
    pass
else:
    # Importing the ``flattening`` package is sufficient to register every
    # stable concrete flattening flow rule (Unflattener, HodurUnflattener,
    # UnflattenerSwitchCase, UnflattenerTigressIndirect, ...).  Other flow
    # rule modules register themselves below.
    from d810.optimizers.microcode.flow import flattening  # noqa: F401
    from d810.optimizers.microcode.flow.constant_prop import global_const_inline  # noqa: F401
    from d810.optimizers.microcode.flow.jumps import indirect_branch  # noqa: F401
    from d810.optimizers.microcode.flow.jumps import indirect_call  # noqa: F401
    from d810.optimizers.microcode.flow import identity_call  # noqa: F401