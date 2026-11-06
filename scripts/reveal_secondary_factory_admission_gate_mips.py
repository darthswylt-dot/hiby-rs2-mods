#!/usr/bin/env python3
"""Admission of47D4A0 after checking its wrapper and sole upper caller.

Native4F87C8 checks a NULL result before H+5C access. Wrapper4F8760 returns it
after its existing UI work; sole encoded upper caller4A326C discards it before
calling477600 with fresh arguments. Unknown computed callers and all other
native aliases remain outside that NULL policy.

The shared emitter's F568/private192, Q lifetime/coherence, native buffer/ABI,
quiescent activation and progress premises still apply. Entry replay saves S1,
not RA; incoming fifth/sixth arguments at oldSP+10/+14 are never relocated.
QF4A distinguishes this frame from the preceding47D720 frame. The native body
and startup remain unbounded, and quarantine does not cancel an in-flight body.
No installer, firmware image, player operation or runtime guard reset is added.
"""

import reveal_factory_admission_gate_mips as shared
from reveal_factory_admission_gate_mips import (
    FRAME, HI, LO, FACTORY_FRAME, OWNER, FUTURE_OWNER, READY, BUSY,
    QUARANTINED, SYNC, CONTROLLER_BYTES, MUTEX_BYTES, NATIVE_RX, SAVE)


OWNERSTAMP = int.from_bytes(b'QF4A', 'little')
HOOKS = {
    'enter': (0x47D4A0, (0x27BDFDC8, 0xAFB10224)),
    'early_leave': (0x47D4F8, (0x8FB10224, 0x8FB00220)),
    'created_leave': (0x47D6E8, (0x8FB10224, 0x8FB00220)),
}
CHECKED_CALLERS, CHECKED_WRAPPER_CALLERS = (0x4F87C0,), (0x4A326C,)


def hook_words(labels):
    """Return the secondary factory's three pinned native pairs."""
    return shared._hook_words(labels, HOOKS)


def assemble(controller_address, registry_mutex_address, code_base, guard_address,
             *, retry_limit=8, protected_code=None, extra_protected_data=()):
    """Emit the checked secondary layout through the uncached shared body."""
    return shared._assemble(
        controller_address, registry_mutex_address, code_base, guard_address,
        retry_limit=retry_limit, protected_code=protected_code,
        extra_protected_data=extra_protected_data, hooks=HOOKS, owner_stamp=OWNERSTAMP)
