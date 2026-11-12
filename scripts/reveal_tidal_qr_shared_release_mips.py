#!/usr/bin/env python3
"""Stop the QR destructor from treating its shared-session alias as ownership.

Compose the retained-reader fixture with one native instruction-pair redirect.
The QR payload and optional side payload remain owned by the dialog and are
freed by the native tail. The global response pair remains under the pair and
cleanup protocol. Dismissing QR does not schedule cleanup or discard that pair.

The redirect skips the complete session-alias read/release/clear span, without
reading the alias or dereferencing a possibly retired/reused session address.
For known ordinary QR, payload+18C is zero and the same native owned-payload
tail executes. Timer aliases, their construction-time generation transport,
dialog/payload lifetime and all other readers remain separate work.
This composer is local only; it adds no firmware builder or device operation.
"""

from build_reveal_bridge_diag import b
import reveal_tidal_retained_readers_mips as retained


SITE, ORIGINAL = 0x500D10, (0x8E32018C, 0x12400007)
ORIGINAL_DELAY, RESUME = 0, 0x500D34


def assemble(mutex_address, code_base):
    """Return the retained-reader code and one additional destructor redirect."""
    code, patches = retained.assemble(mutex_address, code_base)
    patches[SITE] = ORIGINAL, (b.j_type(2, RESUME), 0)
    return code, patches
