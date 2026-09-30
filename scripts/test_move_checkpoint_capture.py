"""Mock-device and own local subprocess tests, never real ADB or player."""
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import capture_move_checkpoint as c
from test_folderfollow_move_diag import BUFFER, Probe
from test_move_evidence_launcher import BASH

GIT_HEAD = Path('C:/Program Files/Git/usr/bin/head.exe')
HEAD = str(GIT_HEAD) if GIT_HEAD.exists() else shutil.which('head')


PID = 123
SERIAL = 'HiBy RS2'
RUN = '/mnt/sd_0/rs2_move_evidence/run_20260930T120000_108_0'
LOG = RUN + '/move.bin'
BOOT = '01234567-89ab-cdef-0123-456789abcdef'


def sample():
    machine = Probe()
    machine.timer()
    return b''.join(machine.outputs)


def metadata(size, boot=BOOT, start=777, sha=c.EXPECTED, inode=42, fd_inode=None,
             fd_path=LOG, uptime='100.25', done='0', fd_size=None):
    fields = ['S'] + ['0'] * 49
    fields[19] = str(start)
    stat = f'{PID} (system main (thread)) ' + ' '.join(fields)
    sections = {
        'boot': boot, 'uptime': uptime + ' 50.0',
        'stat_before': stat, 'exe': sha + f' /proc/{PID}/exe',
        'fd9': fd_path, 'log_stat': f'5 {inode} {size}',
        'fd_stat': f'5 {inode if fd_inode is None else fd_inode} {size if fd_size is None else fd_size}',
        'meminfo': 'MemTotal: 131072 kB\nMemFree: 65536 kB',
        'status': f'Name:\tplayer\nPid:\t{PID}\nVmRSS:\t32000 kB',
        'stat_after': stat, 'done': done,
    }
    return ''.join(f'\n@@{k}@@\n{v}\n' for k, v in sections.items()).encode()


class FakeDevice:
    def __init__(self, data, advertised=None, before=None, after=None, rc=0,
                 timed_out=False, raise_stream=False, raise_after=False):
        self.data = data
        self.size = len(data) if advertised is None else advertised
        self.before = metadata(self.size) if before is None else before
        self.after = metadata(self.size, uptime='101.25') if after is None else after
        self.rc, self.timed_out = rc, timed_out
        self.raise_stream, self.raise_after = raise_stream, raise_after
        self.calls = []

    def probe(self, script, output, timeout):
        self.calls.append(('probe', script))
        after = output.name == 'after.txt'
        if after and self.raise_after:
            raise OSError('mock connection lost after transfer')
        data = self.after if after else self.before
        output.write_bytes(data)
        output.with_suffix('.stderr').write_bytes(b'')
        return dict(returncode=0, timed_out=False, bytes=len(data))

    def stream(self, script, output, size, timeout):
        self.calls.append(('stream', script))
        output.write_bytes(self.data)
        output.with_suffix('.stderr').write_bytes(b'mock ADB stderr')
        if self.raise_stream:
            raise OSError('mock stream failed after bytes arrived')
        return dict(returncode=self.rc, timed_out=self.timed_out, bytes=len(self.data),
                    overlong=len(self.data) > size, reader_errors=[])


class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='move-collector-test-')
        self.root = Path(self.temp.name)
        self.data = sample()

    def tearDown(self):
        self.temp.cleanup()

    def capture(self, device, label='capture', **kwargs):
        output = self.root / label
        report = c.capture(device, SERIAL, PID, RUN, output, **kwargs)
        self.assertEqual(json.loads((output / 'report.json').read_text(encoding='utf-8')), report)
        return report, output

    def test_complete_checkpoint_and_binary_preservation(self):
        device = FakeDevice(self.data)
        report, output = self.capture(device)
        self.assertTrue(report['capture_accepted'])
        self.assertEqual((output / 'raw.bin').read_bytes(), self.data)
        self.assertEqual((output / 'complete_prefix.bin').read_bytes(), self.data)
        self.assertEqual(report['raw_sha256'], hashlib.sha256(self.data).hexdigest())
        self.assertEqual(len(device.calls), 3)
        self.assertIn(f'head -c {len(self.data)}', device.calls[1][1])
        for _, script in device.calls:
            self.assertNotIn('cp ', script)
            self.assertNotIn('/tmp/', script)
            self.assertNotIn('sync', script)
            self.assertNotIn('kill', script)
            self.assertNotIn('reboot', script)
        self.assertFalse((output / 'incomplete_tail.bin').exists())

    def test_partial_headers_and_payloads_saved_not_accepted(self):
        for index, tail in enumerate((b'M', b'MS', b'MSN', b'MSNP', self.data[:37])):
            with self.subTest(tail=len(tail)):
                report, output = self.capture(FakeDevice(self.data + tail), f'partial{index}')
                self.assertFalse(report['capture_accepted'])
                self.assertTrue(report['decoded_complete_prefix']['accepted_prefix'])
                self.assertEqual((output / 'complete_prefix.bin').read_bytes(), self.data)
                self.assertEqual((output / 'incomplete_tail.bin').read_bytes(), tail)
                self.assertEqual((output / 'raw.bin').read_bytes(), self.data + tail)

    def test_invalid_magic_or_record_never_resynchronized(self):
        for index, tail in enumerate((b'BAD!', b'X', b'MSNP\x03\0\0\0')):
            with self.subTest(tail=tail):
                report, output = self.capture(FakeDevice(self.data + tail), f'corrupt{index}')
                self.assertFalse(report['capture_accepted'])
                self.assertFalse((output / 'complete_prefix.bin').exists())
                self.assertEqual((output / 'raw.bin').read_bytes(), self.data + tail)

    def test_valid_unsettled_records_are_not_trimmed_to_status(self):
        machine = Probe()
        machine.refresh()
        machine.timer()  # Event exported, next confirming MSTS not yet present.
        data = b''.join(machine.outputs)
        report, output = self.capture(FakeDevice(data))
        self.assertFalse(report['capture_accepted'])
        self.assertFalse(report['decoded_complete_prefix']['accepted_prefix'])
        self.assertEqual((output / 'complete_prefix.bin').read_bytes(), data)
        self.assertEqual(report['incomplete_tail_bytes'], 0)

    def test_short_overlong_nonzero_and_timeout_streams(self):
        cases = (
            FakeDevice(self.data[:-1], advertised=len(self.data)),
            FakeDevice(self.data + b'M', advertised=len(self.data)),
            FakeDevice(self.data, rc=1),
            FakeDevice(self.data[:-7], advertised=len(self.data), rc=-9, timed_out=True),
        )
        for index, device in enumerate(cases):
            with self.subTest(index=index):
                report, output = self.capture(device, f'failed{index}')
                self.assertFalse(report['capture_accepted'])
                self.assertEqual((output / 'raw.bin').read_bytes(), device.data)
                self.assertTrue((output / 'after.txt').exists())
                self.assertEqual(len(device.calls), 3)

    def test_stream_exception_still_collects_after_and_analyzes_raw(self):
        data = self.data + b'M'
        device = FakeDevice(data, raise_stream=True)
        report, output = self.capture(device)
        self.assertFalse(report['capture_accepted'])
        self.assertTrue((output / 'after.txt').exists())
        self.assertEqual(report['raw_bytes'], len(data))
        self.assertEqual((output / 'incomplete_tail.bin').read_bytes(), b'M')
        self.assertEqual(len(device.calls), 3)

    def test_after_probe_error_does_not_lose_raw_prefix_tail(self):
        cases = (FakeDevice(self.data + b'MS', after=b'malformed'),
                 FakeDevice(self.data + b'MS', raise_after=True))
        for index, device in enumerate(cases):
            report, output = self.capture(device, f'afterfail{index}')
            self.assertFalse(report['capture_accepted'])
            self.assertFalse(report['source_coherent'])
            self.assertEqual((output / 'complete_prefix.bin').read_bytes(), self.data)
            self.assertEqual((output / 'incomplete_tail.bin').read_bytes(), b'MS')

    def test_source_identity_changes_fail_closed(self):
        changes = ({'boot': 'ffffffff-ffff-ffff-ffff-ffffffffffff'},
                   {'start': 778}, {'inode': 43}, {'fd_path': LOG + '.deleted'},
                   {'sha': '0' * 64}, {'uptime': '99.0'})
        for index, change in enumerate(changes):
            device = FakeDevice(self.data, after=metadata(len(self.data), **change))
            report, output = self.capture(device, f'identity{index}')
            self.assertFalse(report['capture_accepted'])
            self.assertFalse(report['source_coherent'])
            self.assertTrue((output / 'raw.bin').exists())
            self.assertTrue((output / 'complete_prefix.bin').exists())

    def test_append_growth_keeps_the_frozen_byte_limit(self):
        device = FakeDevice(self.data, after=metadata(len(self.data) + 100, uptime='101.25'))
        report, output = self.capture(device)
        self.assertTrue(report['capture_accepted'])
        self.assertEqual(report['raw_bytes'], len(self.data))
        self.assertEqual(report['after']['size'], len(self.data) + 100)
        self.assertEqual((output / 'raw.bin').read_bytes(), self.data)

    def test_reported_event_loss_is_not_a_successful_checkpoint(self):
        machine = Probe()
        machine.put(BUFFER + 8, 1, 4)
        machine.timer()
        report, output = self.capture(FakeDevice(b''.join(machine.outputs)))
        self.assertFalse(report['capture_accepted'])
        self.assertFalse(report['decoded_complete_prefix']['accepted_prefix'])
        self.assertTrue((output / 'complete_prefix.bin').exists())

    def test_path_and_descriptor_inode_mismatch_before_transfer(self):
        device = FakeDevice(self.data, before=metadata(len(self.data), fd_inode=43))
        report, output = self.capture(device)
        self.assertFalse(report['capture_accepted'])
        self.assertEqual(len(device.calls), 1)
        self.assertFalse((output / 'raw.bin').exists())

    def test_empty_or_large_log_refusal(self):
        for index, size in enumerate((0, 2000)):
            device = FakeDevice(self.data, advertised=size)
            report, _ = self.capture(device, f'size{index}', max_bytes=1500)
            self.assertFalse(report['capture_accepted'])
            self.assertEqual(len(device.calls), 1)

    def test_malformed_numeric_metadata_refusal(self):
        for index, bad in enumerate(('-1', '1x')):
            raw = metadata(len(self.data)).replace(f'5 42 {len(self.data)}'.encode(), f'5 42 {bad}'.encode())
            device = FakeDevice(self.data, before=raw)
            report, _ = self.capture(device, f'numeric{index}')
            self.assertFalse(report['capture_accepted'])
            self.assertEqual(len(device.calls), 1)

    def test_existing_output_refuses_before_device_call(self):
        output = self.root / 'existing'
        output.mkdir()
        (output / 'keep.txt').write_text('KEEP')
        device = FakeDevice(self.data)
        with self.assertRaises(FileExistsError):
            c.capture(device, SERIAL, PID, RUN, output)
        self.assertEqual(device.calls, [])
        self.assertEqual((output / 'keep.txt').read_text(), 'KEEP')

    def test_invalid_arguments_never_call_device(self):
        cases = (('HiBy RS2\nreboot', PID, RUN, 1000, 30),
                 (SERIAL, 0, RUN, 1000, 30),
                 (SERIAL, PID, RUN + ";reboot", 1000, 30),
                 (SERIAL, PID, RUN + '/../../tmp', 1000, 30),
                 (SERIAL, PID, RUN, 0, 30), (SERIAL, PID, RUN, 1000, 61))
        for values in cases:
            device = FakeDevice(self.data)
            with self.assertRaises(ValueError):
                c.capture(device, *values[:3], self.root / 'invalid', *values[3:])
            self.assertEqual(device.calls, [])
            self.assertFalse((self.root / 'invalid').exists())

    def test_stat_comm_with_parentheses_and_duplicate_sections(self):
        parsed = c.parse_probe(metadata(1376), PID, LOG)
        self.assertEqual(parsed['start_ticks'], 777)
        with self.assertRaises(ValueError):
            c.parse_probe(metadata(1376) + b'\n@@boot@@\n' + BOOT.encode(), PID, LOG)


class LocalTransport(c.Adb):
    def __init__(self, code):
        self.code = code

    def argv(self, script):
        return [sys.executable, '-c', self.code]


class TransportTests(unittest.TestCase):
    def test_binary_local_pipe_no_text_translation(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'raw.bin'
            data = bytes(range(256)) * 7 + b'\r\n\x00\xff'
            local = LocalTransport(f'import sys;sys.stdout.buffer.write({data!r});sys.stderr.buffer.write(b"diagnostic")')
            result = local.stream('unused', path, len(data), 3)
            self.assertEqual(result['returncode'], 0)
            self.assertEqual(path.read_bytes(), data)
            self.assertEqual(path.with_suffix('.stderr').read_bytes(), b'diagnostic')

    def test_overlong_stdout_is_bounded_with_extra_byte(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'raw.bin'
            result = LocalTransport('import sys;sys.stdout.buffer.write(b"X"*100000)').stream('unused', path, 100, 3)
            self.assertTrue(result['overlong'])
            self.assertEqual(len(path.read_bytes()), 101)

    def test_stderr_and_metadata_bounded_during_read(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'before.txt'
            result = LocalTransport('import sys;sys.stderr.buffer.write(b"X"*400000)').probe('unused', path, 3)
            self.assertTrue(result['stderr_overlong'])
            self.assertEqual(len(path.with_suffix('.stderr').read_bytes()), c.MAX_METADATA + 1)

    def test_metadata_stdout_is_bounded_during_read(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'before.txt'
            result = LocalTransport('import sys;sys.stdout.buffer.write(b"X"*400000)').probe('unused', path, 3)
            self.assertTrue(result['overlong'])
            self.assertEqual(len(path.read_bytes()), c.MAX_METADATA + 1)

    @unittest.skipUnless(BASH and HEAD, 'local POSIX shell/head unavailable')
    def test_local_head_exact_nonblock_prefix_and_probe_syntax(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'source.bin'
            data = bytes(range(256)) * 20
            path.write_bytes(data)
            # Local fixture only; never execute the production remote script.
            import shlex
            command = 'exec ' + shlex.quote(Path(HEAD).as_posix()) + ' -c 1376 ' + shlex.quote(path.as_posix()) + ' 2>/dev/null'
            result = subprocess.run([BASH, '--posix', '-c', command], capture_output=True, timeout=3)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, data[:1376])
            syntax = subprocess.run([BASH, '--posix', '-n'], input=c.probe_script(PID, LOG).encode(), capture_output=True, timeout=3)
            self.assertEqual(syntax.returncode, 0, syntax.stderr)

    def test_timeout_retains_partial_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'raw.bin'
            local = LocalTransport('import sys,time;sys.stdout.buffer.write(b"PART");sys.stdout.buffer.flush();time.sleep(5)')
            result = local.stream('unused', path, 100, 1)
            self.assertTrue(result['timed_out'])
            self.assertEqual(path.read_bytes(), b'PART')

    def test_adb_command_uses_argv_and_quoted_remote_script(self):
        argv = c.Adb('adb.exe', SERIAL).argv('exec head -c 1376 ' + LOG + ' 2>/dev/null')
        self.assertEqual(argv[:4], ['adb.exe', '-s', SERIAL, 'exec-out'])
        self.assertTrue(argv[4].startswith("sh -c '"))


if __name__ == '__main__':
    unittest.main()
