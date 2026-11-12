#!/usr/bin/env python3
"""One-lifetime early retirement seal for the local Tidal queue fixture.

Keep the 47 operation/allocation redirects, with both original session close
gates extended under their checked session mutex. After session identity and
zero WRITER/BORROWS validation, a bounded atomic claim changes the separate
queue gate from FREE to SEALED before CLOSING or any native teardown call.
A busy operation refuses that close through the existing pure outer epilogue.
The session mutex is never held while a native queue operation runs.

The selected operation wrappers refuse a nonzero gate before reading ring
storage. Thus an earlier admitted POST or a previously loaded ring pointer
cannot enter the selected operation after the seal, even after native free.
The gate stays sealed through raw failure, ordinary finish and publication.
No reopening or queue-generation reset is provided. Activation is coherent
and begins with a zeroed gate and a valid first native queue lifetime.

This closes admission to selected operations, not every lifetime obligation.
Unconnected aliases, native CLEAR/DESTROY/startup overlap, opaque teardown
progress and the native worker-stop/masked-operation completion remain
premises. No firmware image or device action is supplied by this fixture.
"""

import reveal_tidal_queue_operations_mips as operations
import reveal_tidal_response_reader_bridge_mips as session


SEALED = 2


def assemble(mutex_address, code_base, *, queue_gate_address):
    if session.QUEUE_SEALED != SEALED or session.QUEUE_CLAIM_ATTEMPTS != operations.MAX_ATTEMPTS:
        raise ValueError('queue close and operation admission protocols differ')
    return operations.assemble(mutex_address, code_base,
                               queue_gate_address=queue_gate_address, _seal_on_close=True)
