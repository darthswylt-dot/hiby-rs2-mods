#!/usr/bin/env python3
"""Execute the generated LROW hooks; no device, SQL or live-owner proof.

The generated lineage/capture instructions run unchanged. Query, append and
statement-reset bodies are hostile-ABI stubs with explicit return/count fixtures.
The decoder consumes only bytes written by those generated instructions.
"""
import hashlib
import struct
import unittest

import build_reveal_lineage_rows_stage as stage
import test_reveal_lineage_stage as lineage_tests


STACK, RETURN = lineage_tests.STACK, lineage_tests.RETURN
VIEW, PANEL, JOB = lineage_tests.VIEW, lineage_tests.PANEL, lineage_tests.JOB
DESTINATION, STATEMENT = lineage_tests.DESTINATION, lineage_tests.STATEMENT
APPEND = 0x1777000


class RowsMachine(lineage_tests.LineageMachine):
    def site(self, name):
        pc, _ = stage.HOOKS[name]
        self.run_at(pc, pc + 8)

    def snapshot(self):
        data, offset = self.region(self.state, self.meta['memory_bytes'])
        return bytes(data[offset:offset + self.meta['memory_bytes']])


class RevealLineageRowsStageTests(unittest.TestCase):
    # Import the module, not its TestCase class into this module's globals.
    # Reuse fixture helpers only; the sixteen previous tests are not collected
    # again here or silently rebound to the new builder.
    record = lineage_tests.RevealLineageStageTests.record
    render = lineage_tests.RevealLineageStageTests.render
    stamp = lineage_tests.RevealLineageStageTests.stamp
    borrow = lineage_tests.RevealLineageStageTests.borrow
    producer = lineage_tests.RevealLineageStageTests.producer

    @classmethod
    def setUpClass(cls):
        cls.source = lineage_tests.SOURCE.read_bytes()
        cls.golden, _ = stage.normalize_source(cls.source)
        cls.image, cls.meta = stage.build(cls.source, capacity=16, row_capacity=16)

    def machine(self, row_capacity=16):
        if row_capacity == 16:
            return RowsMachine(self.image, self.meta)
        image, meta = stage.build(self.source, capacity=16, row_capacity=row_capacity)
        return RowsMachine(image, meta)

    def decode(self, m, data=None):
        from decode_reveal_lineage_rows import decode
        return decode(m.snapshot() if data is None else data,
                      capacity=m.meta['capacity'], row_capacity=m.meta['row_capacity'])

    def event_bytes(self, m, index):
        address = m.meta['row_buffer'] + stage.rows.HEADER + index * stage.rows.RECORD
        data, offset = m.region(address, stage.rows.RECORD)
        return bytes(data[offset:offset + stage.rows.RECORD])

    def event_words(self, m, index):
        return struct.unpack_from('<16I', self.event_bytes(m, index))

    def event_site(self, m, sp, name, *, ordinal, result, mode=0,
                   path='a:\\album\\track.flac', cue=0, append_result=None,
                   count=None, reset_result=0, token=None,
                   statement=STATEMENT, destination=DESTINATION):
        if destination not in m.regions:
            m.map(destination, 0x38)
        m.r[29], m.r[16], m.r[17] = sp, statement, ordinal
        m.r[22], m.r[23], m.r[2] = destination, mode, result & 0xFFFFFFFF
        if token is not None:
            m.put(sp + 0x18, token, 4)
        if count is not None:
            m.put(destination + 12, count, 4)
        if name == 'row':
            if isinstance(path, bytes):
                m.bytes(sp + 0x24, path)
            else:
                m.wide(sp + 0x24, path)
            m.put(sp + 0x444, cue, 4)
            m.r[4:6], m.r[25] = [destination, 0xDEAD0000], APPEND
        if name == 'end':
            m.put(sp + 0xAC8, 0xCAFEBABE, 4)
            m.put(sp + 0xAC4, 0x0BADF00D, 4)
        before = m.r.copy(), m.hi, m.lo
        previous_callback = m.callback
        observed = []

        def native(target):
            observed.append(target)
            if name == 'row':
                self.assertEqual(target, APPEND)
                self.assertEqual(m.r[4:6], [destination, sp + 0x20])
                if count is None:
                    m.put(destination + 12, ordinal + 1, 4)
                m.hostile_result(ordinal if append_result is None else append_result)
            elif name == 'terminal':
                self.assertEqual(target, 0x5C31C0)
                self.assertEqual(m.r[4], statement)
                # The raw SQL terminal must already have been published.
                journal_count = m.get(m.meta['row_buffer'], 4)
                if journal_count != stage.rows.FAULT and journal_count:
                    self.assertEqual(self.event_words(m, journal_count - 1)[1], stage.rows.TERMINAL)
                m.hostile_result(reset_result)
            else:
                raise AssertionError('END must not call stock')
            return True

        m.callback = native
        m.site(name)
        m.callback = previous_callback
        if name in ('row', 'terminal'):
            expected, hi, lo = m.after_call
            expected[29], expected[31] = sp, stage.HOOKS[name][0] + 8
            self.assertEqual((m.r, m.hi, m.lo), (expected, hi, lo))
            self.assertEqual(observed, [APPEND if name == 'row' else 0x5C31C0])
        else:
            expected = before[0]
            expected[30], expected[23] = 0xCAFEBABE, 0x0BADF00D
            self.assertEqual((m.r, m.hi, m.lo), (expected, before[1], before[2]))
            self.assertEqual(observed, [])

    def capture(self, rows=(), *, requested=None, offset=0, terminal=101,
                reset_result=0, end=True, append_results=None, counts=None,
                row_capacity=16, mode=0, producer_options=None, machine=None):
        m = self.machine(row_capacity) if machine is None else machine
        start_call = len(m.calls)
        origin = self.render(m)
        self.borrow(m, origin)
        m.map(DESTINATION, 0x38)
        requested = len(rows) if requested is None else requested
        fill_sp = STACK - 0x40
        m.r[29], m.r[16], m.r[17] = fill_sp, JOB + 0x88, PANEL
        m.r[4:8] = [DESTINATION, offset, requested, 0]
        m.put(fill_sp + 0x3C, 0x48EC5C, 4)
        m.put(fill_sp + 0x20, VIEW, 4)
        observed = {}

        def query(target):
            self.assertEqual(target, 0x6F7CA0)
            query_sp, native_return = m.r[29], m.r[31]
            self.assertEqual(m.get(query_sp + 0x10, 4), JOB + 0x88)
            saved_s = m.r[16:24].copy()
            options = dict(offset=offset, requested=requested)
            options.update(producer_options or {})
            producer = self.producer(m, query_sp, **options)
            observed['producer'] = producer
            sp = query_sp - 0xBE0 - 0xAD0
            observed['sp'] = sp
            for ordinal, (path, cue) in enumerate(rows):
                self.event_site(m, sp, 'row', ordinal=ordinal, result=0,
                                mode=mode, path=path, cue=cue,
                                append_result=None if append_results is None else append_results[ordinal],
                                count=None if counts is None else counts[ordinal])
            if terminal is not None:
                self.event_site(m, sp, 'terminal', ordinal=len(rows), result=terminal,
                                mode=mode, reset_result=reset_result)
            if end:
                self.event_site(m, sp, 'end', ordinal=len(rows), result=len(rows), mode=mode)
            m.r[16:24] = saved_s
            m.r[29], m.r[31] = query_sp, native_return
            m.hostile_result(0x87654321)
            return True

        m.callback = query
        m.site('query')
        m.callback = None
        expected, hi, lo = m.after_call
        expected[29], expected[31] = fill_sp, stage.HOOKS['query'][0] + 8
        self.assertEqual((m.r, m.hi, m.lo), (expected, hi, lo))
        expected_calls = [0x6F7CA0] + [APPEND] * len(rows)
        if terminal is not None:
            expected_calls.append(0x5C31C0)
        self.assertEqual(m.calls[start_call:], expected_calls)
        return m, observed

    def test_nine_hooks_two_strides_are_the_only_original_code_changes(self):
        image, meta = stage.build(self.golden, capacity=16, row_capacity=16)
        self.assertEqual(image, self.image)
        self.assertEqual(meta['labels'], self.meta['labels'])
        self.assertEqual(len(stage.HOOKS), 9)
        self.assertEqual(set(stage.HOOKS) - set(stage.lineage.HOOKS), {'row', 'terminal', 'end'})
        allowed = set()
        for name, (pc, expected) in stage.HOOKS.items():
            self.assertEqual(struct.unpack_from('<2I', self.golden, pc - stage.BASE), expected)
            patched = struct.unpack_from('<2I', image, pc - stage.BASE)
            self.assertEqual(patched[0] >> 26, 3 if name in stage.LINKED else 2)
            self.assertEqual(patched[1], expected[1] if name in stage.LINKED else 0)
            allowed.update(range(pc - stage.BASE, pc - stage.BASE + 8))
        for pc in stage.STRIDES:
            self.assertEqual(struct.unpack_from('<I', image, pc - stage.BASE)[0], 0x240502C8)
            allowed.update(range(pc - stage.BASE, pc - stage.BASE + 4))
        for key, size in (('memsize_offset', 4), ('phdr_offset', 32)):
            allowed.update(range(meta[key], meta[key] + size))
        changed = {i for i, (left, right) in enumerate(zip(self.golden, image)) if left != right}
        self.assertFalse(changed - allowed)
        self.assertEqual(image[len(self.golden):meta['code_offset']],
                         bytes(meta['code_offset'] - len(self.golden)))
        self.assertEqual(meta['row_buffer'], meta['buffer'] + meta['lineage_bytes'])
        self.assertEqual(meta['row_record_bytes'], 592)
        self.assertFalse(meta['autoscroll'])
        self.assertTrue(meta['capture_only'])
        self.assertEqual(meta['hardware'], 'UNTESTED')
        old, _ = stage.lineage.build(self.source)
        self.assertEqual(hashlib.sha256(old).hexdigest(),
                         'f31239aa544c55959e9f75686a421489c8ea6d91e1ef6d30b01955d8c75ec139')

    def test_active_reveal_rebuilt_input_and_invalid_capacities_are_refused(self):
        for enable in (True, 1, 0, None, 'yes'):
            with self.subTest(enable=enable), self.assertRaises(ValueError):
                stage.build(self.source, enable_reveal=enable)
        with self.assertRaises(ValueError):
            stage.build(self.image)
        for capacity in (0, -1, True, None, 1.5):
            with self.subTest(capacity=capacity), self.assertRaises(ValueError):
                stage.build(self.source, row_capacity=capacity)

    def test_actual_generated_rows_terminal_reset_end_decode_to_complete_window(self):
        rows = [('a:\\album\\zero.flac', 0), ('a:\\album\\cue.flac', -2147483648)]
        m, observed = self.capture(rows, offset=7, requested=23)
        self.assertEqual(m.get(m.meta['row_buffer'], 4), 5)
        raw = [self.event_words(m, index) for index in range(5)]
        self.assertEqual([words[1] for words in raw], [1, 1, 2, 3, 4])
        self.assertEqual([words[3] for words in raw], [1, 2, 3, 4, 5])
        self.assertEqual([words[10] for words in raw], [0, 1, 101, 0, 2])
        self.assertEqual([words[11] for words in raw], [0, 0x80000000, 0, 0, 0])
        self.assertEqual([words[13] for words in raw], [1, 2, 2, 2, 2])
        for words in raw:
            self.assertEqual((words[2], words[4], words[5], words[6], words[7], words[8]),
                             (observed['producer'], observed['sp'], STATEMENT, DESTINATION, 0, 7))
            self.assertEqual((words[12], words[14], words[15]), (0, 1, 0))
        report = self.decode(m)
        self.assertFalse(report['autoscroll_authorized'])
        self.assertTrue(report['limitations'])
        self.assertEqual(len(report['windows']), 1)
        window = report['windows'][0]
        self.assertTrue(window['complete'], window['reasons'])
        self.assertEqual(window['producer'], observed['producer'])
        self.assertEqual([(event['path'], event['cue']) for event in report['events'][:2]], rows)

    def test_zero_rows_and_zero_requested_are_valid_diagnostic_windows(self):
        m, _ = self.capture((), requested=0)
        report = self.decode(m)
        self.assertTrue(report['windows'][0]['complete'], report['windows'][0]['reasons'])
        self.assertEqual(report['windows'][0]['rows'], [])
        self.assertEqual([self.event_words(m, index)[1] for index in range(3)], [2, 3, 4])

    def test_actual_failed_append_bad_terminal_or_reset_never_completes(self):
        for options in ({'append_results': [-1], 'counts': [0]},
                        {'terminal': 5}, {'reset_result': 19}, {'reset_result': -1},
                        {'end': False}, {'terminal': None}, {'requested': 0}, {'offset': -1}):
            with self.subTest(options=options):
                m, _ = self.capture([('a:\\album\\one.flac', -1)], **options)
                report = self.decode(m)
                self.assertFalse(report['windows'][0]['complete'])
                self.assertTrue(report['windows'][0]['reasons'])
        m, _ = self.capture([('a:\\album\\one.flac', -1)], reset_result=19)
        self.assertEqual(self.event_words(m, 2)[10], 19)
        self.assertEqual(m.calls.count(0x5C31C0), 1)

    def test_duplicate_identity_requires_cue_as_well_as_path(self):
        path = 'a:\\album\\one.cue'
        for cues, complete in (((0, 1), True), ((0, 0), False)):
            with self.subTest(cues=cues):
                m, _ = self.capture([(path, cue) for cue in cues])
                self.assertEqual(self.decode(m)['windows'][0]['complete'], complete)

    def test_descriptor_259_units_is_accepted_but_exact_260_non_nul_is_rejected(self):
        accepted = 'a:\\' + 'x' * 256
        self.assertEqual(len(accepted), 259)
        m, _ = self.capture([(accepted, 0)])
        self.assertTrue(self.decode(m)['windows'][0]['complete'])
        path = 'a:\\' + 'x' * 257
        self.assertEqual(len(path), 260)
        m, observed = self.capture([(path, 0)])
        self.assertEqual(self.event_words(m, 0)[12], 1)
        with self.assertRaises(ValueError):
            self.decode(m)
        low, high = observed['sp'] + 0x24, observed['sp'] + 0x22C
        descriptor_reads = [(address, size) for address, size in m.reads if low <= address <= high]
        self.assertEqual(descriptor_reads, [(low + index * 2, 2) for index in range(260)])

    def test_invalid_utf16_and_empty_identity_fail_strict_decoding(self):
        for path in (b'\x00\xd8\x00\x00', ''):
            with self.subTest(path=path):
                m, _ = self.capture([(path, 0)])
                try:
                    report = self.decode(m)
                except ValueError:
                    continue
                self.assertFalse(report['windows'][0]['complete'])

    def test_mode_gate_skips_descriptor_ticket_and_count_reads_but_runs_stock_once(self):
        m = self.machine()
        sp = STACK
        m.r[29], m.r[16], m.r[17] = sp, STATEMENT, 0
        m.r[22], m.r[23], m.r[25], m.r[4] = DESTINATION, 15, APPEND, DESTINATION
        # Destination and descriptor/ticket addresses remain deliberately
        # unmapped; only current stack save areas are accessible to wrapper.
        m.put(sp + 0x18, 0xDEADBEEF, 4)
        def original(target):
            self.assertEqual(target, APPEND)
            m.hostile_result(-1)
            return True
        m.callback = original
        m.site('row')
        expected, hi, lo = m.after_call
        expected[29], expected[31] = sp, 0x6ED6F0
        self.assertEqual((m.r, m.hi, m.lo), (expected, hi, lo))
        self.assertEqual(m.calls, [APPEND])
        self.assertEqual(m.get(m.meta['row_buffer'], 4), 0)
        self.assertNotIn((sp + 0x18, 4), m.reads)
        self.assertFalse(any(sp + 0x24 <= address < sp + 0xAAC for address, _ in m.reads))

    def test_journal_exhaustion_is_sticky_without_suppressing_native_calls(self):
        m, _ = self.capture([('a:\\album\\one.flac', 0), ('a:\\album\\two.flac', 1)],
                            row_capacity=1)
        self.assertEqual(m.get(m.meta['row_buffer'], 4), stage.rows.FAULT)
        self.assertEqual(m.calls.count(APPEND), 2)
        self.assertEqual(m.calls.count(0x5C31C0), 1)
        with self.assertRaises(ValueError):
            self.decode(m)

    def test_structural_corruption_of_generated_snapshot_is_rejected(self):
        m, _ = self.capture([('a:\\album\\one.flac', 0)])
        original = m.snapshot()
        row_offset = m.meta['lineage_bytes'] + stage.rows.HEADER
        points = [0, m.meta['lineage_bytes'] + 4,
                  row_offset, row_offset + stage.rows.SEQ,
                  row_offset + stage.rows.FRAME, row_offset + stage.rows.STMT,
                  row_offset + stage.rows.DEST, row_offset + stage.rows.MODE,
                  row_offset + stage.rows.ORIGIN, row_offset + stage.rows.RESERVED,
                  row_offset + 584, row_offset + stage.rows.RECORD * 4]
        for point in points:
            with self.subTest(point=hex(point)):
                corrupted = bytearray(original)
                corrupted[point] ^= 1
                with self.assertRaises(ValueError):
                    self.decode(m, bytes(corrupted))
        for data in (original[:-1], original + b'\0'):
            with self.assertRaises(ValueError):
                self.decode(m, data)

    def test_receipt_frame_statement_destination_offset_mismatch_precedes_native_reads(self):
        for options in ({'token': 999}, {'token': 1}, {'frame_delta': 0x100},
                        {'statement': STATEMENT + 4}, {'destination': DESTINATION + 0x1000},
                        {'offset': 1}):
            with self.subTest(options=options):
                m, observed = self.capture((), terminal=None, end=False)
                sp = observed['sp'] + options.get('frame_delta', 0)
                kwargs = {key: value for key, value in options.items()
                          if key not in ('frame_delta', 'offset')}
                m.put(sp + 0x18, observed['producer'], 4)
                m.put(sp + 0xAD8, options.get('offset', 0), 4)
                m.reads.clear()
                self.event_site(m, sp, 'row', ordinal=0, result=0, **kwargs)
                self.assertEqual(m.get(m.meta['row_buffer'], 4), stage.rows.FAULT)
                self.assertNotIn((kwargs.get('destination', DESTINATION) + 12, 4), m.reads)
                self.assertNotIn((sp + 0x444, 4), m.reads)
                self.assertFalse(any(sp + 0x24 <= address < sp + 0x22C for address, _ in m.reads))
                with self.assertRaises(ValueError):
                    self.decode(m)

    def test_zero_ticket_is_untracked_but_native_append_still_runs(self):
        m = self.machine()
        self.event_site(m, STACK, 'row', ordinal=0, result=0, token=0)
        self.assertEqual(m.get(m.meta['row_buffer'], 4), 0)
        self.assertEqual(m.calls, [APPEND])
        self.assertNotIn((STACK + 0x444, 4), m.reads)
        self.assertNotIn((DESTINATION + 12, 4), m.reads)

    def test_extra_events_after_end_never_reopen_a_completed_window(self):
        m, observed = self.capture([('a:\\album\\one.flac', 0)])
        self.assertTrue(self.decode(m)['windows'][0]['complete'])
        old_record = self.event_bytes(m, 0)
        self.event_site(m, observed['sp'], 'row', ordinal=1, result=0,
                        path='a:\\album\\two.flac')
        report = self.decode(m)
        self.assertFalse(report['windows'][0]['complete'])
        self.assertTrue(report['windows'][0]['reasons'])
        self.assertEqual(self.event_bytes(m, 0), old_record)

    def test_reused_frames_and_native_addresses_still_decode_as_distinct_producers(self):
        m, first = self.capture([('a:\\album\\first.flac', 0)])
        m, second = self.capture([('a:\\album\\second.flac', 0)], machine=m)
        self.assertEqual(first['sp'], second['sp'])
        self.assertNotEqual(first['producer'], second['producer'])
        report = self.decode(m)
        self.assertEqual(len(report['windows']), 2)
        self.assertTrue(all(window['complete'] for window in report['windows']))
        self.assertEqual([window['rows'][0]['path'] for window in report['windows']],
                         ['a:\\album\\first.flac', 'a:\\album\\second.flac'])

    def test_reservation_failure_or_late_lineage_fault_cannot_authorize_a_snapshot(self):
        for late in (False, True):
            with self.subTest(late=late):
                m, observed = self.capture((), terminal=None, end=False)
                if late:
                    fired = []
                    def invalidate(pc):
                        if pc == m.labels['rows_capture_magic_store'] and not fired:
                            fired.append(pc)
                            m.put(m.state, stage.core.FAULT, 4)
                    m.before_instruction = invalidate
                else:
                    m.sc_failures = stage.rows.RETRIES
                self.event_site(m, observed['sp'], 'row', ordinal=0, result=0)
                self.assertEqual(m.calls.count(APPEND), 1)
                with self.assertRaises(ValueError):
                    self.decode(m)
                if late:
                    self.assertTrue(fired)
                    self.assertEqual(m.get(m.state, 4), stage.core.FAULT)
                else:
                    self.assertEqual(m.get(m.meta['row_buffer'], 4), stage.rows.FAULT)

    def test_exact_image_verifier_rejects_hook_stride_code_padding_header_or_other_tampering(self):
        from verify_reveal_lineage_rows_stage import verify
        report = verify(self.source, self.image, capacity=16, row_capacity=16)
        self.assertFalse(report['autoscroll'])
        self.assertTrue(report['capture_only'])
        self.assertEqual(sorted(report['external_calls']), [0x5C31C0, 0x6F7CA0])
        self.assertEqual(len(report['indirect_append_calls']), 1)
        points = [pc - stage.BASE for pc, _ in stage.HOOKS.values()]
        points += [pc - stage.BASE for pc in stage.STRIDES]
        points += [self.meta['code_offset'], self.meta['memsize_offset'],
                   self.meta['phdr_offset'] + 24, len(self.golden), 0x500,
                   0x48F1B4 - stage.BASE, 0x48F3EC - stage.BASE]
        for point in points:
            with self.subTest(point=hex(point)):
                altered = bytearray(self.image)
                altered[point] ^= 1
                with self.assertRaises(ValueError):
                    verify(self.source, bytes(altered), capacity=16, row_capacity=16)
        for candidate in (self.image[:-1], self.image + b'\0',
                          stage.lineage.build(self.source)[0]):
            with self.assertRaises(ValueError):
                verify(self.source, candidate, capacity=16, row_capacity=16)


if __name__ == '__main__':
    unittest.main()
