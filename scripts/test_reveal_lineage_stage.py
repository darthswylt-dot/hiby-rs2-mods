#!/usr/bin/env python3
"""Execute the offline lineage image, not device lifetime/concurrency claims.

Stock list instructions below exercise actual segmented indexing/copying.
Allocator and external query bodies are bounded hostile-ABI stubs; this is
not a CPU, scheduler, SQL-completion or retained-native-owner simulator.
"""
import hashlib
import struct
import unittest

import build_reveal_lineage_stage as stage
from test_folderfollow_reveal_static_contract import SOURCE
from test_reveal_bridge_hooks import HookMachine, STACK, RETURN, MASK


HOOK_PCS = {0x490758, 0x48F1D0, 0x48F40C, 0x48EB40,
            0x48D1B8, 0x6ED624}
STRIDE_PCS = (0x48F3BC, 0x48F3CC)
PREFIX_PCS = (0x48F1B4, 0x48F3EC)
HEAP = 0x3000000
VIEW, PANEL, THREAD = 0x1800000, 0x1900000, 0x1A00000
JOB, DESTINATION, STATEMENT = 0x1B00000, 0x1C00000, 0x1D00000


def signed(value):
    return value - 0x100000000 if value & 0x80000000 else value


class LineageMachine(HookMachine):
    """Small instruction harness, fetching from the actual emitted image."""
    def __init__(self, image, meta):
        self.image, self.meta = image, meta
        self.base, self.state = meta['code_base'], meta['buffer']
        self.code = image[meta['code_offset']:]
        self.labels = meta['labels']
        self.regions, self.reads, self.writes = {}, [], []
        self.version, self.reservation = 0, None
        self.map(self.state, meta['memory_bytes'])
        self.map(0x2000000, 0xC000)
        self.map(HEAP, 0x80000)
        self.next_allocation = HEAP
        self.freed, self.calls = [], []
        self.callback, self.before_instruction = None, None
        self.sc_failures = 0
        self.r = [0] + [0x11000000 + reg for reg in range(1, 32)]
        self.r[29], self.r[31] = STACK, RETURN
        self.hi, self.lo = 0x13579BDF, 0x2468ACE0

    def put(self, address, value, size):
        self.writes.append((address, value & ((1 << (size * 8)) - 1), size))
        super().put(address, value, size)
        self.version += 1

    def word(self, pc):
        if self.base <= pc < self.base + len(self.code):
            return struct.unpack_from('<I', self.code, pc - self.base)[0]
        offset = pc - stage.BASE
        if pc % 4 or not 0 <= offset <= len(self.image) - 4:
            raise AssertionError('unexpected code fetch ' + hex(pc))
        return struct.unpack_from('<I', self.image, offset)[0]

    def plain(self, word):
        op = word >> 26
        rs, rt, rd = (word >> 21) & 31, (word >> 16) & 31, (word >> 11) & 31
        fn, shift, imm = word & 63, (word >> 6) & 31, word & 0xFFFF
        simm = imm - 0x10000 if imm & 0x8000 else imm
        address = (self.r[rs] + simm) & MASK
        if op == 0x30:
            self.r[rt] = self.get(address, 4)
            self.reservation = address, self.version
        elif op == 0x38:
            success = self.reservation == (address, self.version)
            self.reservation = None
            if self.sc_failures:
                self.sc_failures -= 1
                success = False
            if success:
                self.put(address, self.r[rt], 4)
            self.r[rt] = int(success)
        elif op == 0 and fn in (2, 3):
            self.r[rd] = ((self.r[rt] >> shift) if fn == 2 else
                          signed(self.r[rt]) >> shift) & MASK
        elif op == 0 and fn in (0x23, 0x26, 0x2A, 0x2B):
            left, right = self.r[rs], self.r[rt]
            self.r[rd] = {0x23: lambda: (left - right) & MASK,
                          0x26: lambda: left ^ right,
                          0x2A: lambda: int(signed(left) < signed(right)),
                          0x2B: lambda: int(left < right)}[fn]()
        elif op == 0 and fn in (0x0A, 0x0B):
            if (self.r[rt] == 0) == (fn == 0x0A):
                self.r[rd] = self.r[rs]
        elif op == 0 and fn in (0x1A, 0x1B):
            left, right = self.r[rs], self.r[rt]
            if fn == 0x1A:
                left, right = signed(left), signed(right)
            if not right:
                raise AssertionError('stock division by zero')
            quotient = abs(left) // abs(right)
            if (left < 0) != (right < 0):
                quotient = -quotient
            self.lo, self.hi = quotient & MASK, (left - quotient * right) & MASK
        elif op == 0 and fn == 0x34:
            if self.r[rs] == self.r[rt]:
                raise AssertionError('stock TEQ trap')
        elif op == 0x1C and fn == 2:
            self.r[rd] = (self.r[rs] * self.r[rt]) & MASK
        elif op == 10:
            self.r[rt] = int(signed(self.r[rs]) < simm)
        else:
            return super().plain(word)
        self.r[0] = 0

    def allocation(self, size):
        address = (self.next_allocation + 15) & -16
        self.next_allocation = address + size + 16
        self.put(address, size, 4)
        return address + 4

    def external(self, target):
        self.calls.append(target)
        if self.callback is not None and self.callback(target):
            return
        if target == 0x4669E0:
            result = self.allocation(self.r[4])
        elif target == 0x466A80:
            self.freed.append(self.r[4])
            result = 0
        elif target == 0xA5B440:
            data, offset = self.region(self.r[5], self.r[6])
            self.bytes(self.r[4], bytes(data[offset:offset + self.r[6]]))
            result = self.r[4]
        elif target == 0xA5BC60:
            self.bytes(self.r[4], bytes([self.r[5] & 255]) * self.r[6])
            result = self.r[4]
        else:
            raise AssertionError('unexpected external call ' + hex(target))
        self.hostile_result(result)

    def run_at(self, pc, stop):
        for _ in range(100000):
            if pc == stop:
                return
            if self.before_instruction is not None:
                self.before_instruction(pc)
            word = self.word(pc)
            op, rs, rt = word >> 26, (word >> 21) & 31, (word >> 16) & 31
            if op in (1, 4, 5, 6, 7, 20, 21, 22, 23):
                if op == 1:
                    if rt not in (0, 1):
                        raise AssertionError('unsupported REGIMM branch')
                    taken = (signed(self.r[rs]) < 0) == (rt == 0)
                elif op in (4, 5, 20, 21):
                    taken = (self.r[rs] == self.r[rt]) == (op in (4, 20))
                else:
                    taken = (signed(self.r[rs]) <= 0) == (op in (6, 22))
                offset = word & 65535
                offset -= 65536 if offset & 32768 else 0
                if taken or op not in (20, 21, 22, 23):
                    self.plain(self.word(pc + 4))
                pc = pc + 4 + offset * 4 if taken else pc + 8
            elif op in (2, 3) or (op == 0 and word & 63 in (8, 9)):
                target = (((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
                          if op in (2, 3) else self.r[rs])
                linked = op == 3 or (op == 0 and word & 63 == 9)
                if linked:
                    self.r[31 if op == 3 else (word >> 11) & 31] = pc + 8
                self.plain(self.word(pc + 4))
                # Only these native list bodies run inside the harness.
                internal = (self.base <= target < self.base + len(self.code)
                            or 0x4557C0 <= target < 0x455DC0
                            or 0x456C40 <= target < 0x456E80
                            or 0x466B20 <= target < 0x466B74)
                if linked and not internal:
                    self.external(target)
                    pc = self.r[31]
                else:
                    pc = target
            else:
                self.plain(word)
                pc += 4
        raise AssertionError('execution budget exceeded')

    def site(self, name):
        pc, _ = stage.HOOKS[name]
        self.run_at(pc, pc + 8)

    def stock(self, address, *args):
        self.r[4:4 + len(args)] = args
        self.r[31] = RETURN
        self.run_at(address, RETURN)
        return self.r[2]


class RevealLineageStageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_bytes()
        cls.golden, _ = stage.normalize_source(cls.source)
        cls.image, cls.meta = stage.build(cls.source)

    def machine(self):
        return LineageMachine(self.image, self.meta)

    def record(self, m, token):
        c = stage.core
        self.assertGreater(token, 0)
        address = m.state + c.HEADER + (token - 1) * c.RECORD
        self.assertEqual(m.get(address, 4), c.MAGIC)
        return {name: m.get(address + getattr(c, name), 4)
                for name in ('KIND', 'ORIGIN', 'PARENT', 'VIEW', 'PANEL',
                             'JOB', 'DEST', 'SITE', 'STACK', 'OFFSET', 'REQUEST', 'STMT')}

    def render(self, m, view=VIEW, panel=PANEL):
        m.r[29], m.r[2], m.r[18] = STACK, view, panel
        before = m.r.copy(), m.hi, m.lo
        m.site('render')
        expected = before[0]
        expected[16], expected[4] = view, view + 0x38AC
        self.assertEqual((m.r, m.hi, m.lo), (expected, before[1], before[2]))
        token = m.get(STACK + stage.RENDER_TICKET, 4)
        return token

    def stamp(self, m, *, initial=False, caller=None, callback=0x48D280,
              view=VIEW, panel=PANEL, template=None, caller_sp=STACK):
        m.map(THREAD, 0x150)
        master = 0x1E00000
        m.map(master, 0x38)
        m.put(THREAD + 0x130, master, 4)
        m.put(master + 0x18, 0x455DA0, 4)
        m.put(master + 0x24, 0x4557C0, 4)
        sp = caller_sp - (0x2F8 if initial else 0x2F0)
        m.r[29], m.r[16] = sp, THREAD
        m.r[19 if initial else 17] = view + 0x38A4 if template is None else template
        m.put(sp + 0x18 + 0x2B0, panel, 4)
        m.put(sp + 0x18 + 0x2B4, view, 4)
        m.put(sp + 0x18 + 0x2C0, callback, 4)
        m.put(sp + stage.LOCAL_TAIL, 0xDEADBEEF, 4)
        m.put(sp + (0x2F4 if initial else 0x2EC),
              (0x492A38 if initial else 0x490814) if caller is None else caller, 4)
        before = m.r.copy(), m.hi, m.lo
        m.site('initial_stamp' if initial else 'enqueue_stamp')
        expected = before[0]
        expected[4], expected[25] = master, 0x455DA0 if initial else 0x4557C0
        self.assertEqual((m.r, m.hi, m.lo), (expected, before[1], before[2]))
        return m.get(sp + stage.LOCAL_TAIL, 4)

    def borrow(self, m, origin, *, job=JOB, worker_sp=STACK):
        if THREAD not in m.regions:
            m.map(THREAD, 0x150)
        try:
            m.region(job, stage.ELEMENT)
        except AssertionError:
            m.map(job, stage.ELEMENT)
        m.put(THREAD + 0x10, 0x12345678, 4)
        m.put(job + stage.TAIL, origin, 4)
        m.r[29], m.r[16], m.r[17] = worker_sp, THREAD, job
        m.put(worker_sp + stage.WORKER_BORROW, 0xDEADBEEF, 4)
        before = m.r.copy(), m.hi, m.lo
        m.site('borrow')
        expected = before[0]
        expected[4], expected[22] = 0x12345678, 1
        self.assertEqual((m.r, m.hi, m.lo), (expected, before[1], before[2]))
        return m.get(worker_sp + stage.WORKER_BORROW, 4)

    def producer(self, m, query_sp, *, offset=0, requested=512, mode=0,
                 destination=DESTINATION, caller=0x6F8BF4, saved_query_return=None,
                 magic=None, token=None, frame_delta=0):
        if frame_delta:
            old_sp = query_sp
            query_sp += frame_delta
            for field in (stage.QUERY_TICKET, stage.QUERY_MAGIC):
                m.put(query_sp + field, m.get(old_sp + field, 4), 4)
        sp = query_sp - 0xBE0 - 0xAD0
        m.r[29], m.r[16], m.r[17] = sp, STATEMENT, requested
        m.r[18], m.r[20], m.r[22], m.r[23] = 0x9A0000, 0x9A0000, destination, mode
        m.put(sp + 0xACC, caller, 4)
        m.put(sp + 0xAD8, offset, 4)
        m.put(sp + 0xAD0 + 0xBDC,
              m.labels['query_native_return'] if saved_query_return is None else saved_query_return, 4)
        if magic is not None:
            m.put(query_sp + stage.QUERY_MAGIC, magic, 4)
        if token is not None:
            m.put(query_sp + stage.QUERY_TICKET, token, 4)
        m.put(sp + 0x18, 0xDEADBEEF, 4)
        before = m.r.copy(), m.hi, m.lo
        m.site('producer')
        expected = before[0]
        expected[18], expected[20] = 0x99B328, 0x99C540
        self.assertEqual((m.r, m.hi, m.lo), (expected, before[1], before[2]))
        return m.get(sp + 0x18, 4)

    def query(self, m, *, view=VIEW, panel=PANEL, job=JOB, offset=0,
              requested=512, mode=0, saved_fill_return=0x48EC5C,
              with_producer=False, producer_options=None, result=0x87654321):
        sp, scope = STACK - 0x40, job + 0x88
        m.r[29], m.r[16], m.r[17] = sp, scope, panel
        m.r[4:8] = [DESTINATION, offset, requested, mode]
        m.put(sp + 0x3C, saved_fill_return, 4)
        m.put(sp + 0x20, view, 4)
        m.put(sp + 0x10, 0xDEADBEEF, 4)
        observed = {}

        def native(target):
            self.assertEqual(target, 0x6F7CA0)
            self.assertEqual(m.r[4:8], [DESTINATION, offset, requested, mode])
            self.assertEqual(m.get(sp + 0x10, 4), scope)
            query_sp, native_return = m.r[29], m.r[31]
            self.assertEqual(m.get(query_sp + 0x10, 4), scope)
            observed['query'] = m.get(query_sp + stage.QUERY_TICKET, 4)
            observed['magic'] = m.get(query_sp + stage.QUERY_MAGIC, 4)
            saved_s = m.r[16:24].copy()
            if with_producer:
                options = dict(offset=offset, requested=requested, mode=mode)
                options.update(producer_options or {})
                observed['producer'] = self.producer(m, query_sp, **options)
            m.r[16:24] = saved_s
            m.r[29], m.r[31] = query_sp, native_return
            m.hostile_result(result)
            return True

        m.callback = native
        m.site('query')
        m.callback = None
        expected, hi, lo = m.after_call
        expected[29], expected[31] = sp, stage.HOOKS['query'][0] + 8
        self.assertEqual((m.r, m.hi, m.lo), (expected, hi, lo))
        self.assertEqual(m.calls, [0x6F7CA0])
        self.assertEqual(m.get(sp + 0x10, 4), scope)
        return observed

    def test_reproducible_only_six_hooks_two_strides_and_elf_layout_may_change(self):
        image, meta = stage.build(self.golden)
        self.assertEqual(image, self.image)
        self.assertEqual(meta['labels'], self.meta['labels'])
        self.assertEqual({pc for pc, _ in stage.HOOKS.values()}, HOOK_PCS)
        allowed = set()
        for label, (pc, expected) in stage.HOOKS.items():
            self.assertEqual(struct.unpack_from('<2I', self.golden, pc - stage.BASE), expected)
            allowed.update(range(pc - stage.BASE, pc - stage.BASE + 8))
            word, delay = struct.unpack_from('<2I', self.image, pc - stage.BASE)
            self.assertIn(word >> 26, (2, 3))
            target = ((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
            self.assertEqual(target, self.meta['labels'][label])
        for pc in STRIDE_PCS:
            self.assertEqual(struct.unpack_from('<I', self.golden, pc - stage.BASE)[0], 0x240502C4)
            self.assertEqual(struct.unpack_from('<I', self.image, pc - stage.BASE)[0], 0x240502C8)
            allowed.update(range(pc - stage.BASE, pc - stage.BASE + 4))
        for pc in PREFIX_PCS:
            self.assertEqual(struct.unpack_from('<I', self.image, pc - stage.BASE)[0], 0x240602C4)
        for field, size in (('memsize_offset', 4), ('phdr_offset', 32)):
            allowed.update(range(self.meta[field], self.meta[field] + size))
        changed = {i for i, (left, right) in enumerate(zip(self.golden, self.image)) if left != right}
        self.assertTrue(changed)
        self.assertFalse(changed - allowed)
        self.assertEqual(self.image[len(self.golden):self.meta['code_offset']],
                         bytes(self.meta['code_offset'] - len(self.golden)))
        self.assertEqual(hashlib.sha256(image).hexdigest(), hashlib.sha256(self.image).hexdigest())

    def test_active_reveal_unknown_source_and_already_built_input_are_refused(self):
        for enable in (True, 1, None, 'yes', 0):
            with self.subTest(enable=enable), self.assertRaises(ValueError):
                stage.build(self.source, enable_reveal=enable)
        bad = bytearray(self.source)
        bad[0x500] ^= 1
        for source in (bytes(bad), self.image, self.source[:-1]):
            with self.assertRaises(ValueError):
                stage.build(source)

    def test_renderer_and_initial_origins_are_distinct_and_preserve_native_abi(self):
        m = self.machine()
        origin = self.render(m)
        self.assertEqual(origin, 1)
        self.assertEqual(self.stamp(m), origin)
        first = self.record(m, origin)
        self.assertEqual((first['KIND'], first['ORIGIN'], first['PARENT']),
                         (stage.core.RENDER, origin, 0))
        self.assertEqual((first['VIEW'], first['PANEL'], first['JOB'], first['STACK']),
                         (VIEW, PANEL, VIEW + 0x38A4, STACK))
        initial = self.stamp(m, initial=True)
        self.assertEqual(initial, 2)
        second = self.record(m, initial)
        self.assertEqual((second['KIND'], second['ORIGIN'], second['PARENT']),
                         (stage.core.INITIAL, initial, 0))
        self.assertEqual(self.record(m, origin), first)  # Published origin immutable.
        self.assertEqual(m.calls, [])
        self.assertFalse(any(VIEW <= address < VIEW + 0x4300 or
                             PANEL <= address < PANEL + 0x500 for address, _ in m.reads))

    def test_unknown_enqueue_or_other_callback_clears_tail_without_adopting_scratch(self):
        for initial, caller, callback in (
                (False, 0x49B738, 0x48D280),
                (False, 0x4936E4, 0x48D280),
                (False, 0, 0x48D280),
                (False, 0x490814, 0x48D260),
                (True, 0x439B58, 0x48D280),
                (True, 0x492A38, 0x48D260)):
            with self.subTest(initial=initial, caller=hex(caller)):
                m = self.machine()
                self.assertEqual(self.render(m), 1)
                self.assertEqual(self.stamp(m, initial=initial, caller=caller,
                                            callback=callback), 0)
                self.assertEqual(m.get(m.state, 4), 1)

    def test_enqueue_wrong_raw_parent_or_frame_fails_closed(self):
        for options in ({'panel': PANEL + 4}, {'view': VIEW + 4},
                        {'template': VIEW + 0x38A8}, {'caller_sp': STACK + 0x100}):
            with self.subTest(options=options):
                m = self.machine()
                origin = self.render(m)
                if 'caller_sp' in options:
                    m.put(options['caller_sp'] + stage.RENDER_TICKET, origin, 4)
                self.assertEqual(self.stamp(m, **options), 0)
                self.assertEqual(m.get(m.state, 4), stage.core.FAULT)
        for options in ({'view': 0}, {'panel': 0}, {'template': VIEW + 0x38A8}):
            with self.subTest(initial=options):
                m = self.machine()
                self.assertEqual(self.stamp(m, initial=True, **options), 0)
                self.assertEqual(m.get(m.state, 4), stage.core.FAULT)

    def test_borrow_zero_untracked_or_invalid_origin_never_infers_by_job_address(self):
        m = self.machine()
        self.assertEqual(self.borrow(m, 0), 0)
        self.assertEqual(m.get(m.state, 4), 0)
        self.assertEqual(self.borrow(m, 123), 0)
        self.assertEqual(m.get(m.state, 4), stage.core.FAULT)
        self.assertEqual(self.render(m), 0)  # Sticky, no pointer-based recovery.

    def test_full_native_receipt_chain_and_query_fifth_argument_result_abi(self):
        for initial in (False, True):
            for caller in (0x6F8BF4, 0x6F8E0C):
                with self.subTest(initial=initial, caller=hex(caller)):
                    m = self.machine()
                    origin = self.stamp(m, initial=True) if initial else self.render(m)
                    if not initial:
                        self.assertEqual(self.stamp(m), origin)
                    borrowed = self.borrow(m, origin)
                    self.assertEqual(borrowed, origin + 1)
                    observation = self.query(m, offset=7, requested=23,
                                             with_producer=True,
                                             producer_options={'caller': caller})
                    query, producer = observation['query'], observation['producer']
                    self.assertEqual((query, producer), (borrowed + 1, borrowed + 2))
                    self.assertEqual(observation['magic'], stage.QUERY_FRAME_MAGIC)
                    for token, kind, parent in ((borrowed, stage.core.BORROW, origin),
                                                (query, stage.core.QUERY, borrowed),
                                                (producer, stage.core.PRODUCER, query)):
                        receipt = self.record(m, token)
                        self.assertEqual((receipt['KIND'], receipt['ORIGIN'], receipt['PARENT']),
                                         (kind, origin, parent))
                        self.assertEqual((receipt['VIEW'], receipt['PANEL'], receipt['JOB']),
                                         (VIEW, PANEL, JOB))
                    for token in (query, producer):
                        receipt = self.record(m, token)
                        self.assertEqual((receipt['DEST'], receipt['OFFSET'], receipt['REQUEST']),
                                         (DESTINATION, 7, 23))
                    self.assertEqual(self.record(m, producer)['STMT'], STATEMENT)
                    self.assertEqual(m.get(m.state, 4), producer)

    def test_query_mismatch_faults_but_calls_original_once_with_its_result(self):
        for options in ({'view': VIEW + 4}, {'panel': PANEL + 4}, {'mode': 1},
                        {'job': JOB + 0x1000}):
            with self.subTest(options=options):
                m = self.machine()
                origin = self.render(m)
                self.borrow(m, origin)
                if 'job' in options:
                    m.map(options['job'], stage.ELEMENT)
                    m.put(options['job'] + stage.TAIL, origin, 4)
                observation = self.query(m, **options, result=0xFFFFFFFF)
                self.assertEqual((observation['query'], observation['magic']), (0, 0))
                self.assertEqual(m.get(m.state, 4), stage.core.FAULT)
        m = self.machine()
        origin = self.render(m)
        borrowed = self.borrow(m, origin, worker_sp=STACK + 0x100)
        m.put(STACK + stage.WORKER_BORROW, borrowed, 4)
        self.assertEqual(self.query(m)['query'], 0)
        self.assertEqual(m.get(m.state, 4), stage.core.FAULT)

    def test_foreign_fill_gate_does_not_read_worker_receipt_or_job_tail(self):
        m = self.machine()
        observation = self.query(m, saved_fill_return=0x12345678)
        self.assertEqual((observation['query'], observation['magic']), (0, 0))
        self.assertEqual(m.get(m.state, 4), 0)
        self.assertNotIn((STACK + stage.WORKER_BORROW, 4), m.reads)
        self.assertNotIn((JOB + stage.TAIL, 4), m.reads)  # JOB deliberately unmapped.

    def test_new_origin_at_reused_job_address_cannot_adopt_old_borrow_receipt(self):
        m = self.machine()
        old_origin = self.render(m)
        new_origin = self.render(m)
        borrowed = self.borrow(m, old_origin)
        historical = self.record(m, borrowed)
        m.put(JOB + stage.TAIL, new_origin, 4)
        observation = self.query(m)
        self.assertEqual(observation['query'], 0)
        self.assertEqual(m.get(m.state, 4), stage.core.FAULT)
        self.assertEqual(self.record(m, borrowed), historical)

    def test_producer_context_mismatches_are_rejected_without_changing_native_registers(self):
        cases = ({'destination': DESTINATION + 4}, {'offset': 1}, {'requested': 511},
                 {'mode': 1}, {'token': 999}, {'frame_delta': 0x100})
        for options in cases:
            with self.subTest(options=options):
                m = self.machine()
                origin = self.render(m)
                self.borrow(m, origin)
                observation = self.query(m, with_producer=True, producer_options=options)
                self.assertEqual(observation['producer'], 0)
                self.assertEqual(m.get(m.state, 4), stage.core.FAULT)

    def test_nonmatching_producer_caller_query_return_or_magic_stays_untracked(self):
        for options in ({'caller': 0x6F81E8}, {'saved_query_return': 0x48D1C0}, {'magic': 0}):
            with self.subTest(options=options):
                m = self.machine()
                origin = self.render(m)
                self.borrow(m, origin)
                observation = self.query(m, with_producer=True, producer_options=options)
                self.assertEqual(observation['producer'], 0)
                self.assertEqual(m.get(m.state, 4), observation['query'])

    def test_same_addresses_get_fresh_origins_and_exhaustion_never_reuses_tokens(self):
        image, meta = stage.build(self.source, capacity=8)
        m = LineageMachine(image, meta)
        first = None
        for token in range(1, 9):
            self.assertEqual(self.render(m), token)
            if first is None:
                first = self.record(m, token)
        self.assertEqual(self.record(m, 1), first)
        self.assertEqual(self.render(m), 0)
        self.assertEqual(m.get(m.state, 4), stage.core.FAULT)
        self.assertEqual(self.render(m), 0)
        self.assertEqual(self.record(m, 1), first)

    def test_stamped_tail_survives_actual_master_work_copy_then_seals_producer_receipt(self):
        m = self.machine()
        origin = self.render(m)
        self.assertEqual(self.stamp(m), origin)
        local_record = STACK - 0x2F0 + 0x18
        master = m.stock(0x456E60, 16, stage.ELEMENT)
        work = m.stock(0x456E60, 16, stage.ELEMENT)
        self.assertEqual(m.stock(0x455DA0, master, local_record), 0)
        master_record = m.stock(0x4557E0, master, 0)
        self.assertEqual(m.stock(0x455DA0, work, master_record), 0)
        work_record = m.stock(0x4557E0, work, 0)
        self.assertNotEqual(work_record, master_record)
        self.assertEqual(m.get(work_record + stage.TAIL, 4), origin)
        m.stock(0x4557C0, master)
        m.put(local_record + stage.TAIL, 0xDEADBEEF, 4)
        self.assertEqual(m.get(work_record + stage.TAIL, 4), origin)
        borrowed = self.borrow(m, origin, job=work_record)
        m.calls.clear()  # Query wrapper below must call only its native query.
        observation = self.query(m, job=work_record, with_producer=True)
        self.assertEqual(self.record(m, borrowed)['JOB'], work_record)
        producer = self.record(m, observation['producer'])
        self.assertEqual((producer['ORIGIN'], producer['JOB']), (origin, work_record))

    def test_retry_failure_and_orphan_known_query_remain_fail_closed_and_preserve_stock(self):
        m = self.machine()
        m.sc_failures = stage.core.DEFAULT_RETRIES
        self.assertEqual(self.render(m), 0)
        self.assertEqual(m.get(m.state, 4), stage.core.FAULT)
        m = self.machine()
        observation = self.query(m, result=0xFFFFFFF4)
        self.assertEqual((observation['query'], observation['magic']), (0, 0))
        self.assertEqual(m.get(m.state, 4), stage.core.FAULT)
        self.assertNotIn((JOB + stage.TAIL, 4), m.reads)

    def test_actual_stock_lists_copy_tail_across_blocks_growth_and_master_to_work(self):
        m = self.machine()
        # Execute the native constructor/indexer/append/grow bodies, using
        # the actual patched element-size instruction's immediate.
        stride = struct.unpack_from('<I', self.image, STRIDE_PCS[0] - stage.BASE)[0] & 65535
        self.assertEqual(stride, 712)
        master = m.stock(0x456E60, 16, stride)
        work = m.stock(0x456E60, 16, stride)
        self.assertEqual((m.get(master + 8, 4), m.get(master + 0x10, 4),
                          m.get(master + 0x14, 4)), (20, 712, 10))
        old_table = m.get(master, 4)
        source = 0x1800000
        m.map(source, stride)
        first_record = None
        for ordinal in range(21):
            m.bytes(source, bytes([ordinal]) * 708)
            m.put(source + 708, 0x10000 + ordinal, 4)
            self.assertEqual(m.stock(0x455DA0, master, source), ordinal)
            if first_record is None:
                first_record = m.stock(0x4557E0, master, 0)
        self.assertEqual(m.get(master + 8, 4), 30)
        self.assertNotEqual(m.get(master, 4), old_table)
        self.assertIn(old_table, m.freed)
        self.assertEqual(m.stock(0x4557E0, master, 0), first_record)
        for ordinal in range(21):
            record = m.stock(0x4557E0, master, ordinal)
            self.assertEqual(m.get(record, 1), ordinal)
            self.assertEqual(m.get(record + 707, 1), ordinal)
            self.assertEqual(m.get(record + 708, 4), 0x10000 + ordinal)
        source_record = m.stock(0x4557E0, master, 20)
        self.assertEqual(m.stock(0x455DA0, work, source_record), 0)
        copied_record = m.stock(0x4557E0, work, 0)
        self.assertNotEqual(copied_record, source_record)
        self.assertEqual(m.get(copied_record + 708, 4), 0x10014)
        m.stock(0x4557C0, master)
        self.assertEqual(m.get(master + 12, 4), 0)
        self.assertEqual(m.get(copied_record + 708, 4), 0x10014)
        # This is transport only: a surviving nonce is NOT a live owner lease.


if __name__ == '__main__':
    unittest.main()
