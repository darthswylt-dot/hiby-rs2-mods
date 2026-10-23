#!/usr/bin/env python3
"""Private, passive ancestry for action delivery and its queued paint request.

capture(a0=kind, a1=parent, a2=owned seventeen-word metadata) returns a fresh
non-reused ID or zero. validate(a0=ID, a1=kind) returns its private record or
zero, checking the complete bounded ancestry and the external private BIRTH
receipt for BIRTH_LINK. Native-looking values are scalars, never pointers
dereferenced by this core. No clock, current state, setter or native call is
used. Explicit IDs observe invocation ancestry, not coherent media identity,
retention of queued records, complete coverage or permission to reveal a row.

Metadata is WORKER, QUEUE, RECORD, SOURCE_FRAME, FRAME, SITE, CALLER, ACTION,
PARAM1, PARAM2, RESOURCE, NODE, CONTROLLER, ENGINE, INPUT, METADATA, BIRTH.
Only the owned block, private journals and own stack are accessed. Bounded
LL/SC allocation is terminal on loss; publication is magic-last. A global
fault wins even if an already-checked publisher subsequently stores magic.
"""

from build_reveal_bridge_diag import Asm, b
import reveal_queue_birth_mips as birth


HEADER, RECORD_BYTES = 16, 96
RECORD_SIZE = RECORD_BYTES
STATE, FAULT = 0, 0xFFFFFFFF
MAGIC_OFFSET, MAGIC = 0, int.from_bytes(b'LALI', 'little')
KIND, PARENT, ORIGIN, SEQ = 4, 8, 12, 16
WORKER, QUEUE, RECORD, SOURCE_FRAME, FRAME, SITE, CALLER = range(20, 48, 4)
ACTION, PARAM1, PARAM2, RESOURCE, NODE, CONTROLLER = range(48, 72, 4)
ENGINE, INPUT, METADATA, BIRTH = range(72, 88, 4)
METADATA_FIELDS = tuple(range(WORKER, BIRTH + 4, 4))
RESERVED = (88, 92)
SOURCE, DELIVERY, EXPLORER, PAINT, PAINT_DELIVERY, BIRTH_LINK = range(1, 7)
SOURCE_SITE, DELIVERY_SITE, EXPLORER_SITE = 0x4BACBC, 0x4BA96C, 0x4909A4
PAINT_SITE, PAINT_DELIVERY_SITE, BIRTH_SITE = 0x43C868, 0x4399E8, 0x8B428C
PAINT_CALLERS = (0x490A10, 0x490A60)
DEFAULT_CAPACITY, RETRIES, METADATA_WORDS = 1024, 8, 17
MAX_CAPACITY = (0x100000000 - HEADER) // RECORD_BYTES
CALL_FRAME, VALIDATE_FRAME, SYNC = 0xB0, 0x50, 0xF


def memory_bytes(capacity=DEFAULT_CAPACITY):
    if type(capacity) is not int or not 1 <= capacity <= MAX_CAPACITY:
        raise ValueError('capacity must fit a nonempty unsigned-32 action journal')
    return HEADER + RECORD_BYTES * capacity


def assemble(journal_address, birth_address, birth_entries, code_base,
             capacity=DEFAULT_CAPACITY):
    """Emit private capture/validate/reserve/invalidate entries without I/O.

    The caller separately proves that the complete external BIRTH allocation
    and code do not overlap: only its header and validate entry are known here.
    """
    size = memory_bytes(capacity)
    try:
        birth_validate = birth_entries['validate']
    except (KeyError, TypeError) as error:
        raise ValueError('private birth validate entry is required') from error
    for name, value in (('journal_address', journal_address),
                        ('birth_address', birth_address), ('code_base', code_base),
                        ('birth validate', birth_validate)):
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFC or value % 4:
            raise ValueError(name + ' must be an aligned unsigned-32 address')
    if not birth_validate or birth_validate >> 28 != code_base >> 28:
        raise ValueError('private birth validate must share the MIPS jump region')
    regions = ((journal_address, size), (birth_address, birth.HEADER))
    for index, (start, length) in enumerate(regions):
        if start + length > 0x100000000:
            raise ValueError('private storage must not wrap')
        for other, count in regions[index + 1:]:
            if max(start, other) < min(start + length, other + count):
                raise ValueError('private journal and birth header overlap')
        if start <= birth_validate < start + length:
            raise ValueError('private validator overlaps known storage')

    a = Asm(code_base)

    def journal_check(target):
        a.absolute(8, journal_address)
        a.absolute(9, capacity)
        a.e(SYNC, b.lw(10, STATE, 8), b.r_type(9, 10, 11, 0x2B))
        a.branch(5, 11, 0, target)

    def aligned(reg, target):
        a.branch(4, reg, 0, target)
        a.e(b.i_type(12, reg, 15, 3))
        a.branch(5, 15, 0, target)

    def equal_constant(pointer, field, value, target):
        a.e(b.lw(11, field, pointer))
        a.absolute(12, value)
        a.branch(5, 11, 12, target)

    def equal_fields(left, left_field, right, right_field, target):
        a.e(b.lw(11, left_field, left), b.lw(12, right_field, right))
        a.branch(5, 11, 12, target)

    def extent(pointer, field, length, target):
        # Match snapshot decoding: the inclusive last byte must fit u32.
        # An extent ending exactly at 2**32 is valid; adding length itself
        # would wrongly reject that boundary. This checks a scalar only.
        a.e(b.lw(11, field, pointer), b.addiu(12, 11, length - 1),
            b.r_type(12, 11, 13, 0x2B))
        a.branch(5, 13, 0, target)

    def add_relation(left, field, delta, right, other, target):
        a.e(b.lw(11, field, left), b.addiu(12, 11, delta),
            b.r_type(12, 11, 13, 0x2B))
        a.branch(5, 13, 0, target)
        a.e(b.lw(13, other, right))
        a.branch(5, 12, 13, target)

    def schema(pointer, prefix, target):
        # This finite schema is emitted both for fresh local input and for
        # every already-published ancestor; corruption cannot bypass it.
        for field in (WORKER, RECORD, SOURCE_FRAME, FRAME):
            a.e(b.lw(11, field, pointer))
            aligned(11, target)
        a.e(b.lw(14, KIND, pointer))
        for kind in range(1, 6):
            a.e(b.addiu(11, 0, kind))
            a.branch(4, 14, 11, prefix + '_' + str(kind))
        equal_constant(pointer, SITE, BIRTH_SITE, target)
        equal_constant(pointer, CALLER, 0x45987C, target)
        equal_constant(pointer, QUEUE, 0, target)
        extent(pointer, FRAME, 0x68, target)
        for field in (RESOURCE, NODE, CONTROLLER, ENGINE, INPUT, BIRTH):
            a.e(b.lw(11, field, pointer))
            if field == BIRTH:
                a.branch(4, 11, 0, target)
            else:
                aligned(11, target)
        a.jump(prefix + '_done')
        a.label(prefix + '_1')
        a.e(b.lw(11, QUEUE, pointer))
        aligned(11, target)
        equal_constant(pointer, PARENT, 0, target)
        equal_fields(pointer, SOURCE_FRAME, pointer, FRAME, target)
        add_relation(pointer, FRAME, 0x18, pointer, RECORD, target)
        equal_constant(pointer, SITE, SOURCE_SITE, target)
        extent(pointer, FRAME, 0x40, target)
        equal_constant(pointer, CALLER, 0x42D61C, target)
        equal_constant(pointer, ACTION, 1, target)
        equal_constant(pointer, PARAM2, 0, target)
        for field in (RESOURCE, NODE, CONTROLLER, ENGINE, INPUT, METADATA, BIRTH):
            equal_constant(pointer, field, 0, target)
        a.jump(prefix + '_done')
        a.label(prefix + '_2')
        a.e(b.lw(11, QUEUE, pointer))
        aligned(11, target)
        equal_constant(pointer, SITE, DELIVERY_SITE, target)
        equal_constant(pointer, CALLER, 0, target)
        for field in (RESOURCE, NODE, CONTROLLER, ENGINE, INPUT, METADATA, BIRTH):
            equal_constant(pointer, field, 0, target)
        a.jump(prefix + '_done')
        a.label(prefix + '_3')
        a.e(b.lw(11, QUEUE, pointer))
        aligned(11, target)
        equal_constant(pointer, SITE, EXPLORER_SITE, target)
        extent(pointer, FRAME, 0x40, target)
        equal_constant(pointer, CALLER, 0x4BAA68, target)
        for field in (RESOURCE, NODE):
            a.e(b.lw(11, field, pointer))
            aligned(11, target)
        for field in (CONTROLLER, ENGINE, INPUT, METADATA, BIRTH):
            equal_constant(pointer, field, 0, target)
        a.jump(prefix + '_done')
        a.label(prefix + '_4')
        equal_constant(pointer, SITE, PAINT_SITE, target)
        extent(pointer, FRAME, 0x68, target)
        a.e(b.lw(11, CALLER, pointer))
        a.absolute(12, PAINT_CALLERS[0])
        a.branch(4, 11, 12, prefix + '_paint_caller')
        equal_constant(pointer, CALLER, PAINT_CALLERS[1], target)
        a.label(prefix + '_paint_caller')
        add_relation(pointer, FRAME, 0x18, pointer, RECORD, target)
        add_relation(pointer, FRAME, 0x58, pointer, INPUT, target)
        a.jump(prefix + '_paint_shared')
        a.label(prefix + '_5')
        equal_constant(pointer, SITE, PAINT_DELIVERY_SITE, target)
        equal_constant(pointer, CALLER, 0x43C918, target)
        extent(pointer, RECORD, 0x24, target)
        add_relation(pointer, RECORD, 0xC, pointer, INPUT, target)
        a.label(prefix + '_paint_shared')
        equal_constant(pointer, QUEUE, 0, target)
        for field in (RESOURCE, NODE, CONTROLLER, ENGINE, INPUT):
            a.e(b.lw(11, field, pointer))
            aligned(11, target)
        equal_fields(pointer, ENGINE, pointer, NODE, target)
        equal_constant(pointer, METADATA, 0, target)
        equal_constant(pointer, BIRTH, 0, target)
        a.label(prefix + '_done')
        for field in RESERVED:
            equal_constant(pointer, field, 0, target)

    def relation(child, parent, prefix, target):
        # Origin and payload words never come from a current-state lookup.
        for field in (ORIGIN, WORKER, SOURCE_FRAME, ACTION, PARAM1, PARAM2):
            equal_fields(child, field, parent, field, target)
        a.e(b.lw(14, KIND, child))
        for kind in (DELIVERY, EXPLORER, PAINT, PAINT_DELIVERY):
            a.e(b.addiu(11, 0, kind))
            a.branch(4, 14, 11, prefix + '_' + str(kind))
        # BIRTH_LINK inherits the exact selected paint record and its scalars.
        for field in (QUEUE, RECORD, RESOURCE, NODE, CONTROLLER, ENGINE, INPUT, METADATA):
            equal_fields(child, field, parent, field, target)
        add_relation(child, FRAME, 0x68, parent, FRAME, target)
        a.jump(prefix + '_done')
        a.label(prefix + '_2')
        equal_fields(child, QUEUE, parent, QUEUE, target)
        a.jump(prefix + '_done')
        a.label(prefix + '_3')
        for field in (QUEUE, RECORD):
            equal_fields(child, field, parent, field, target)
        add_relation(child, FRAME, 0x40, parent, FRAME, target)
        a.jump(prefix + '_done')
        a.label(prefix + '_4')
        for field in (RESOURCE, NODE):
            equal_fields(child, field, parent, field, target)
        add_relation(child, FRAME, 0x40, parent, FRAME, target)
        a.jump(prefix + '_done')
        a.label(prefix + '_5')
        for field in (QUEUE, RESOURCE, NODE, CONTROLLER, ENGINE, METADATA):
            equal_fields(child, field, parent, field, target)
        a.label(prefix + '_done')

    def check_birth(pointer, saved_pointer, target, prefix):
        # Caller saves pointer across the sole external PRIVATE call.
        a.e(b.sw(pointer, saved_pointer, 29), b.lw(4, BIRTH, pointer),
            b.addiu(5, 0, birth.BIRTH))
        a.jump(birth_validate, True)
        a.branch(4, 2, 0, target)
        a.e(b.lw(10, saved_pointer, 29))
        for own, other in ((ENGINE, birth.ENGINE), (INPUT, birth.INPUT),
                           (METADATA, birth.METADATA), (FRAME, birth.FRAME)):
            equal_fields(10, own, 2, other, target)

    # Capture locals: kind10,parent14,origin18,slot1C,id20,candidate30..8F.
    a.label('capture')
    a.e(b.addiu(29, 29, -CALL_FRAME), b.sw(31, 0xAC, 29),
        b.sw(4, 0x10, 29), b.sw(5, 0x14, 29))
    a.branch(4, 4, 0, 'capture_fault')
    a.e(b.i_type(11, 4, 8, BIRTH_LINK + 1))
    a.branch(4, 8, 0, 'capture_fault')
    a.e(b.addiu(8, 0, SOURCE))
    a.branch(4, 4, 8, 'capture_source_parent')
    a.branch(4, 5, 0, 'capture_ignored')
    a.jump('capture_input')
    a.label('capture_source_parent')
    a.branch(5, 5, 0, 'capture_fault')
    a.label('capture_input')
    a.branch(4, 6, 0, 'capture_fault')
    a.e(b.i_type(12, 6, 8, 3))
    a.branch(5, 8, 0, 'capture_fault')
    a.e(b.addiu(8, 6, (METADATA_WORDS - 1) * 4), b.r_type(8, 6, 9, 0x2B))
    a.branch(5, 9, 0, 'capture_fault')
    journal_check('capture_fault')
    a.e(b.addiu(10, 29, 0x30), b.lw(8, 0x10, 29), b.sw(8, KIND, 10),
        b.lw(8, 0x14, 29), b.sw(8, PARENT, 10), b.sw(0, ORIGIN, 10))
    for index in range(METADATA_WORDS):
        a.e(b.lw(8, 4 * index, 6), b.sw(8, WORKER + 4 * index, 10))
    for field in RESERVED:
        a.e(b.sw(0, field, 10))
    schema(10, 'capture_schema', 'capture_fault')
    a.e(b.lw(5, 0x10, 29), b.addiu(8, 0, SOURCE))
    a.branch(4, 5, 8, 'capture_bound')
    a.e(b.lw(4, 0x14, 29), b.addiu(5, 5, -1))
    a.jump('validate', True)
    a.branch(4, 2, 0, 'capture_fault')
    a.e(b.addiu(10, 29, 0x30), b.lw(8, ORIGIN, 2), b.sw(8, ORIGIN, 10))
    relation(10, 2, 'capture_relation', 'capture_fault')
    a.e(b.lw(8, 0x10, 29), b.addiu(9, 0, BIRTH_LINK))
    a.branch(5, 8, 9, 'capture_bound')
    check_birth(10, 0x24, 'capture_fault', 'capture_birth')
    a.label('capture_bound')
    a.jump('reserve', True)
    a.branch(4, 2, 0, 'capture_ignored')
    a.e(b.sw(2, 0x1C, 29), b.sw(3, 0x20, 29),
        b.addiu(10, 29, 0x30), b.lw(8, KIND, 10), b.addiu(9, 0, SOURCE))
    a.branch(5, 8, 9, 'capture_copy')
    a.e(b.sw(3, ORIGIN, 10))
    a.label('capture_copy')
    a.e(b.sw(3, SEQ, 10))
    for field in range(KIND, RECORD_BYTES, 4):
        a.e(b.lw(8, field, 10), b.sw(8, field, 2))
    a.label('capture_publish')
    journal_check('capture_fault')
    a.e(b.lw(2, 0x1C, 29), SYNC)
    a.absolute(8, MAGIC)
    a.label('capture_magic_store')
    a.e(b.sw(8, MAGIC_OFFSET, 2), SYNC, b.lw(2, 0x20, 29))
    a.jump('capture_done')
    a.label('capture_fault')
    a.jump('invalidate', True)
    a.label('capture_ignored')
    a.e(b.move(2, 0))
    a.label('capture_done')
    a.e(b.lw(31, 0xAC, 29), b.addiu(29, 29, CALL_FRAME),
        b.r_type(31, 0, 0, 8), 0)

    # Validate locals: currentID10,kind14,first18,child1C,current20,RA4C.
    a.label('validate')
    a.e(b.addiu(29, 29, -VALIDATE_FRAME), b.sw(31, 0x4C, 29),
        b.sw(4, 0x10, 29), b.sw(5, 0x14, 29), b.sw(0, 0x1C, 29))
    a.branch(4, 4, 0, 'validate_fault')
    a.branch(4, 5, 0, 'validate_fault')
    a.e(b.i_type(11, 5, 8, BIRTH_LINK + 1))
    a.branch(4, 8, 0, 'validate_fault')
    a.label('validate_loop')
    journal_check('validate_fault')
    a.e(b.lw(4, 0x10, 29), b.r_type(10, 4, 11, 0x2B))
    a.branch(5, 11, 0, 'validate_fault')
    a.e(b.addiu(12, 4, -1), (12 << 16) | (11 << 11) | (6 << 6),
        (12 << 16) | (12 << 11) | (5 << 6), b.r_type(11, 12, 12, 0x21),
        b.r_type(8, 12, 10, 0x21), b.addiu(10, 10, HEADER),
        b.sw(10, 0x20, 29))
    a.absolute(11, MAGIC)
    a.e(b.lw(12, MAGIC_OFFSET, 10))
    a.branch(5, 11, 12, 'validate_fault')
    a.e(b.lw(11, SEQ, 10))
    a.branch(5, 4, 11, 'validate_fault')
    a.e(b.lw(11, KIND, 10), b.lw(12, 0x14, 29))
    a.branch(5, 11, 12, 'validate_fault')
    schema(10, 'validate_schema', 'validate_fault')
    a.e(b.lw(8, 0x1C, 29))
    a.branch(4, 8, 0, 'validate_first')
    relation(8, 10, 'validate_relation', 'validate_fault')
    a.jump('validate_after_relation')
    a.label('validate_first')
    a.e(b.sw(10, 0x18, 29))
    a.label('validate_after_relation')
    a.e(b.lw(8, KIND, 10), b.addiu(9, 0, BIRTH_LINK))
    a.branch(5, 8, 9, 'validate_after_birth')
    check_birth(10, 0x20, 'validate_fault', 'validate_birth')
    a.label('validate_after_birth')
    a.e(b.lw(8, KIND, 10), b.addiu(9, 0, SOURCE))
    a.branch(4, 8, 9, 'validate_source')
    a.e(b.lw(11, PARENT, 10), b.lw(12, SEQ, 10))
    a.branch(4, 11, 0, 'validate_fault')
    a.e(b.r_type(11, 12, 13, 0x2B))
    a.branch(4, 13, 0, 'validate_fault')
    a.e(b.sw(11, 0x10, 29), b.addiu(8, 8, -1), b.sw(8, 0x14, 29),
        b.sw(10, 0x1C, 29))
    a.jump('validate_loop')
    a.label('validate_source')
    equal_fields(10, ORIGIN, 10, SEQ, 'validate_fault')
    journal_check('validate_fault')
    a.e(b.lw(2, 0x18, 29))
    a.jump('validate_done')
    a.label('validate_fault')
    a.jump('invalidate', True)
    a.label('validate_done')
    a.e(b.lw(31, 0x4C, 29), b.addiu(29, 29, VALIDATE_FRAME),
        b.r_type(31, 0, 0, 8), 0)

    a.label('reserve')
    a.absolute(8, journal_address)
    a.absolute(9, capacity)
    a.e(b.addiu(14, 0, RETRIES), SYNC)
    a.label('reserve_ll')
    a.e(b.i_type(0x30, 8, 10, STATE), b.r_type(10, 9, 11, 0x2B))
    a.branch(4, 11, 0, 'reserve_fault')
    a.e(b.addiu(3, 10, 1), b.move(11, 3))
    a.label('reserve_sc')
    a.e(b.i_type(0x38, 8, 11, STATE))
    a.branch(5, 11, 0, 'reserve_success')
    a.e(b.addiu(14, 14, -1))
    a.branch(5, 14, 0, 'reserve_ll')
    a.jump('reserve_fault')
    a.label('reserve_success')
    a.e((10 << 16) | (11 << 11) | (6 << 6),
        (10 << 16) | (12 << 11) | (5 << 6), b.r_type(11, 12, 11, 0x21),
        b.r_type(8, 11, 2, 0x21), b.addiu(2, 2, HEADER), SYNC,
        b.lw(11, MAGIC_OFFSET, 2))
    a.branch(5, 11, 0, 'reserve_fault')
    a.e(b.lw(10, STATE, 8), b.r_type(9, 10, 11, 0x2B))
    a.branch(5, 11, 0, 'reserve_fault')
    a.e(SYNC, b.r_type(31, 0, 0, 8), 0)
    a.label('invalidate')
    a.absolute(8, journal_address)
    a.label('reserve_fault')
    a.e(b.addiu(11, 0, -1), SYNC)
    a.label('fault_store')
    a.e(b.sw(11, STATE, 8), SYNC, b.move(2, 0), b.move(3, 0),
        b.r_type(31, 0, 0, 8), 0)

    code = a.finish()
    end = code_base + len(code)
    if end > 0x100000000 or code_base >> 28 != (end - 1) >> 28:
        raise ValueError('action code must fit one MIPS jump region')
    if code_base <= birth_validate < end:
        raise ValueError('external private birth validator overlaps action code')
    for start, length in regions:
        if max(start, code_base) < min(start + length, end):
            raise ValueError('private storage and action code overlap')
    return code, a.labels
