"""Real-IDA tests for the composition-based unflattening services.

The pure-Python mock-based coordinator tests live in
:mod:`tests.unit.optimizers.microcode.flow.flattening.test_unflattener_coordinator`.
This file used to host those tests but was rewritten to redirect to the
executable suite; the executable tests cover the same scenarios (no
dispatchers, non-entry block, single/multiple predecessors, unresolvable
target, missing predecessor, patch failure, exception isolation,
change-count behavior) using mocks so they run in any environment.

End-to-end tests against real obfuscated binaries still live in
:mod:`tests.system.runtime.optimizers.microcode.flow.flattening.test_services_integration`,
which exercises :class:`OLLVMDispatcherFinder` and friends against the
``libobfuscated`` IDB.
"""