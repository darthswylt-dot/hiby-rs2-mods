"""Mock metadata and isolated local-shell tests; never ADB or a live player."""
import copy
import hashlib
import json
import os
import re
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import capture_move_checkpoint as base
import capture_move_legacy_checkpoint as legacy
from test_move_checkpoint_capture import (
    BOOT, LOG, PID, RUN, SERIAL, FakeDevice as NativeFakeDevice,
    metadata as native_metadata, sample,
)
from test_move_evidence_launcher import BASH


NONCE = 'a' * 32
ROOT = Path(__file__).resolve().parents[1]
ROOT_MOUNT = '20 1 0:1 / / rw - rootfs rootfs rw'
CARD_MOUNT = '31 20 179:1 / /mnt/sd_0 rw,relatime - vfat /dev/mmcblk0p1 rw'
MOUNTS = ROOT_MOUNT + '\n' + CARD_MOUNT


def process_stat(pid=PID, start=777):
    fields = ['S'] + ['0'] * 49
    fields[19] = str(start)
    return f'{pid} (system main (thread)) ' + ' '.join(fields)


def file_stat(path, size, inode=42, mode='-rw-r--r--'):
    return f'{inode} {mode} 1 0 0 {size} Sep 30 12:00 {path}'


def metadata(size, *, inode=42, fd_inode=None, fd_size=None, start=777,
             uptime='100.25', nonce=NONCE, **changes):
    sections = {
        'boot': BOOT, 'uptime': None if uptime is None else uptime + ' 50.0',
        'stat_before': process_stat(start=start),
        'exe': base.EXPECTED + f' /proc/{PID}/exe', 'fd9': LOG,
        'mounts': MOUNTS, 'player_mounts': MOUNTS,
        'same_before': 'same', 'log_stat': file_stat(LOG, size, inode),
        'fd_stat': file_stat(f'/proc/{PID}/fd/9', size if fd_size is None else fd_size,
                             inode if fd_inode is None else fd_inode),
        'same_after': 'same',
        'meminfo': 'MemTotal: 131072 kB\nMemFree: 65536 kB',
        'status': f'Name:\tplayer\nPid:\t{PID}\nVmRSS:\t32000 kB',
        'stat_after': process_stat(start=start), 'done_' + nonce: '0',
    }
    sections.update(changes)
    return ''.join(f'\n@@{key}@@\n{value}\n' for key, value in sections.items()
                   if value is not None).encode('ascii')


class FakeDevice(NativeFakeDevice):
    """Record production commands but return fixture bytes directly to the host."""
    def __init__(self, data, advertised=None, before=None, after=None, **kwargs):
        size = len(data) if advertised is None else advertised
        super().__init__(data, advertised=advertised,
                         before=metadata(size) if before is None else before,
                         after=metadata(size, uptime='101.25') if after is None else after,
                         **kwargs)


class MetadataTests(unittest.TestCase):
    def setUp(self):
        self.protocol = legacy.LegacyProtocol(NONCE)

    def parse(self, data):
        return self.protocol.parse_probe(data, PID, LOG)

    def test_complete_numeric_regular_file_evidence(self):
        parsed = self.parse(metadata(1376, fd_size=1400))
        self.assertEqual(parsed, dict(
            boot=BOOT, pid=PID, start_ticks=777, exe_sha256=base.EXPECTED,
            fd9=LOG, file_device='179:1', file_inode=42,
            mount=dict(mount_id=31, parent_id=20, device='179:1', root='/',
                       mountpoint='/mnt/sd_0', filesystem='vfat', source='/dev/mmcblk0p1'),
            size=1376, fd_size=1400, uptime=100.25,
        ))
        # Terminal CR/LF normalization never affects binary evidence itself.
        self.assertEqual(self.parse(metadata(1376).replace(b'\n', b'\r\n'))['size'], 1376)

    def test_boot_pid_starttime_hash_fdpath_and_same_file_gates(self):
        cases = (
            {'boot': 'not-a-boot-id'}, {'boot': ''},
            {'stat_before': process_stat(pid=PID + 1)},
            {'stat_before': process_stat(start='bad')},
            {'stat_after': process_stat(start=778)},
            {'stat_after': process_stat(pid=PID + 1)},
            {'exe': '0' * 64 + f' /proc/{PID}/exe'},
            {'exe': base.EXPECTED + f' /proc/{PID + 1}/exe'},
            {'fd9': LOG + ' (deleted)'}, {'fd9': LOG + '.replacement'},
            {'same_before': 'different'}, {'same_after': 'different'},
            {'same_before': 'same\nsame'},
            {'uptime': '-1'}, {'uptime': 'NaN'},
            {'status': f'Pid:\t{PID + 1}'}, {'meminfo': 'MemTotal: unknown'},
        )
        for change in cases:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.parse(metadata(1376, **change))

    def test_inode_size_and_regular_file_gates(self):
        cases = [metadata(1376, fd_inode=43), metadata(1376, fd_size=1375)]
        for section, path in (('log_stat', LOG), ('fd_stat', f'/proc/{PID}/fd/9')):
            for mode in ('drwxr-xr-x', 'lrwxrwxrwx', 'prw-r--r--', '-rw-r--r-?', '-rw-r--r--+'):
                cases.append(metadata(1376, **{section: file_stat(path, 1376, mode=mode)}))
            for inode in (0, -1, 'not-an-inode'):
                cases.append(metadata(1376, **{section: file_stat(path, 1376, inode=inode)}))
            for size in (-1, '1376x'):
                cases.append(metadata(1376, **{section: file_stat(path, size)}))
            cases.append(metadata(1376, **{section: file_stat(path + '.other', 1376)}))
            cases.append(metadata(1376, **{section: file_stat(path, 1376) + '\nextra'}))
            for old, new in ((' 1 0 0 ', ' 0 0 0 '), (' 1 0 0 ', ' 1 root 0 '),
                             (' 1 0 0 ', ' 1 0 wheel ')):
                cases.append(metadata(1376, **{section: file_stat(path, 1376).replace(old, new)}))
        for index, data in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.parse(data)

    def test_direct_vfat_mount_and_namespace_gates(self):
        invalid_mounts = (
            '', 'malformed mountinfo', ROOT_MOUNT,
            MOUNTS + '\n' + CARD_MOUNT,
            MOUNTS + f'\n32 31 179:1 / {RUN} rw - vfat /dev/mmcblk0p1 rw',
            MOUNTS + f'\n32 31 179:1 / {LOG} rw - vfat /dev/mmcblk0p1 rw',
            MOUNTS.replace(' / /mnt/sd_0 ', ' /bound /mnt/sd_0 '),
            MOUNTS.replace(' - vfat ', ' - ext4 '),
            MOUNTS.replace('31 20 179:1', 'bad 20 179:1'),
            MOUNTS.replace('31 20 179:1', '31 bad 179:1'),
            MOUNTS.replace('31 20 179:1', '31 20 bad'),
        )
        for mounts in invalid_mounts:
            with self.subTest(mounts=mounts), self.assertRaises(ValueError):
                self.parse(metadata(1376, mounts=mounts, player_mounts=mounts))
        for old, new in (('31 20', '32 20'), ('179:1', '179:2'),
                         ('/dev/mmcblk0p1', '/dev/mmcblk1p1')):
            with self.subTest(namespace=new), self.assertRaises(ValueError):
                self.parse(metadata(1376, player_mounts=MOUNTS.replace(old, new)))

    def test_missing_duplicate_unexpected_and_wrong_nonce_markers(self):
        valid = metadata(1376)
        for section in legacy.sections(valid):
            with self.subTest(missing=section), self.assertRaises(ValueError):
                self.parse(metadata(1376, **{section: None}))
        invalid = (
            valid + b'\n@@boot@@\n' + BOOT.encode(),
            valid + b'\n@@unexpected@@\n0\n', b'prompt$\n' + valid,
            valid.replace(NONCE.encode(), b'b' * 32),
            metadata(1376, **{'done_' + NONCE: '1'}),
            metadata(1376, **{'done_' + NONCE: '0\n0'}),
            valid + b'\xff', b' ' * (base.MAX_METADATA + 1),
        )
        for index, data in enumerate(invalid):
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.parse(data)

    def test_nonce_validation(self):
        for nonce in ('', 'a' * 31, 'a' * 33, 'A' * 32, 'g' * 32, ';' * 32):
            with self.subTest(nonce=nonce), self.assertRaises(ValueError):
                legacy.LegacyProtocol(nonce)
        self.assertRegex(legacy.LegacyProtocol().nonce, r'^[0-9a-f]{32}$')

    def test_coherence_all_identity_fields_mount_changes_and_growth(self):
        before = self.parse(metadata(1376, fd_size=1400))
        after = self.parse(metadata(1500, uptime='101.25'))
        self.assertTrue(self.protocol.coherent(before, after))
        changes = dict(boot='ffffffff-ffff-ffff-ffff-ffffffffffff', pid=124,
                       start_ticks=778, exe_sha256='0' * 64, fd9=LOG + '.old',
                       file_device='179:2', file_inode=43, uptime=99.0, size=1399)
        for key, value in changes.items():
            changed = dict(after, **{key: value})
            with self.subTest(key=key):
                self.assertFalse(self.protocol.coherent(before, changed))
        for key, value in dict(mount_id=32, parent_id=21, source='/dev/mmcblk1p1').items():
            changed = copy.deepcopy(after)
            changed['mount'][key] = value
            with self.subTest(mount_key=key):
                self.assertFalse(self.protocol.coherent(before, changed))


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='legacy-checkpoint-test-')
        self.root = Path(self.temp.name)
        self.data = sample()
        self.protocol = legacy.LegacyProtocol(NONCE)

    def tearDown(self):
        self.temp.cleanup()

    def capture(self, device, label='capture', **kwargs):
        output = self.root / label
        report = base.capture(device, SERIAL, PID, RUN, output, protocol=self.protocol, **kwargs)
        self.assertEqual(json.loads((output / 'report.json').read_text(encoding='utf-8')), report)
        return report, output

    def test_complete_capture_uses_generated_production_commands(self):
        device = FakeDevice(self.data)
        report, output = self.capture(device)
        self.assertTrue(report['capture_accepted'], report['errors'])
        self.assertTrue(report['source_coherent'])
        self.assertEqual((output / 'raw.bin').read_bytes(), self.data)
        self.assertEqual((output / 'complete_prefix.bin').read_bytes(), self.data)
        self.assertEqual(report['raw_sha256'], hashlib.sha256(self.data).hexdigest())
        self.assertEqual(report['limits'], self.protocol.limits)
        self.assertEqual(device.calls, [
            ('probe', self.protocol.probe_script(PID, LOG)),
            ('stream', self.protocol.stream_script(PID, LOG, len(self.data), report['before'])),
            ('probe', self.protocol.probe_script(PID, LOG)),
        ])

    def test_append_growth_preserves_frozen_read_limit(self):
        size = len(self.data)
        device = FakeDevice(self.data, before=metadata(size, fd_size=size + 32),
                            after=metadata(size + 96, uptime='101.25'))
        report, output = self.capture(device)
        self.assertTrue(report['capture_accepted'], report['errors'])
        self.assertEqual(report['after']['size'], size + 96)
        self.assertIn(f'od -An -v -tx1 -N {size} <&8', device.calls[1][1])
        self.assertEqual((output / 'raw.bin').read_bytes(), self.data)

    def test_rejected_preflight_never_starts_stream(self):
        cases = (metadata(len(self.data), fd_inode=43),
                 metadata(len(self.data), **{'done_' + NONCE: '1'}),
                 metadata(len(self.data), nonce='b' * 32),
                 metadata(len(self.data), same_after='different'),
                 metadata(0), metadata(3000))
        for index, before in enumerate(cases):
            device = FakeDevice(self.data, before=before)
            report, output = self.capture(device, f'preflight{index}', max_bytes=2000)
            self.assertFalse(report['capture_accepted'])
            self.assertEqual(len(device.calls), 1)
            self.assertFalse((output / 'raw.bin').exists())

    def test_postflight_identity_change_retains_evidence(self):
        size = len(self.data)
        cases = (
            metadata(size, boot='ffffffff-ffff-ffff-ffff-ffffffffffff'),
            metadata(size, start=778), metadata(size, inode=43),
            metadata(size, fd9=LOG + ' (deleted)'), metadata(size, uptime='99.0'),
            metadata(size, mounts=MOUNTS.replace('31 20', '32 20'),
                     player_mounts=MOUNTS.replace('31 20', '32 20')),
            metadata(size, **{'done_' + NONCE: None}),
        )
        for index, after in enumerate(cases):
            report, output = self.capture(FakeDevice(self.data, after=after), f'changed{index}')
            self.assertFalse(report['capture_accepted'])
            self.assertFalse(report['source_coherent'])
            self.assertEqual((output / 'raw.bin').read_bytes(), self.data)
            self.assertEqual((output / 'complete_prefix.bin').read_bytes(), self.data)

    def test_partial_and_invalid_records_are_retained_without_acceptance(self):
        for index, tail in enumerate((b'M', b'MSNP', self.data[:37])):
            report, output = self.capture(FakeDevice(self.data + tail), f'partial{index}')
            self.assertFalse(report['capture_accepted'])
            self.assertEqual((output / 'raw.bin').read_bytes(), self.data + tail)
            self.assertEqual((output / 'complete_prefix.bin').read_bytes(), self.data)
            self.assertEqual((output / 'incomplete_tail.bin').read_bytes(), tail)
        for index, tail in enumerate((b'BAD!', b'X', b'MSNP\x03\0\0\0')):
            report, output = self.capture(FakeDevice(self.data + tail), f'invalid{index}')
            self.assertFalse(report['capture_accepted'])
            self.assertEqual((output / 'raw.bin').read_bytes(), self.data + tail)
            self.assertFalse((output / 'complete_prefix.bin').exists())

    def test_failed_transfer_and_after_probe_preserve_prefix_and_tail(self):
        cases = (
            FakeDevice(self.data, rc=91), FakeDevice(self.data, timed_out=True),
            FakeDevice(self.data[:-1], advertised=len(self.data)),
            FakeDevice(self.data + b'M', advertised=len(self.data)),
            FakeDevice(self.data + b'MS', raise_stream=True),
            FakeDevice(self.data + b'MS', raise_after=True),
            FakeDevice(self.data + b'MS', after=b'incomplete metadata'),
        )
        for index, device in enumerate(cases):
            report, output = self.capture(device, f'transfer{index}')
            self.assertFalse(report['capture_accepted'])
            self.assertEqual((output / 'raw.bin').read_bytes(), device.data)
            self.assertEqual(len(device.calls), 3)
            self.assertTrue((output / 'complete_prefix.bin').exists())
            if device.data.endswith(b'MS'):
                self.assertEqual((output / 'incomplete_tail.bin').read_bytes(), b'MS')

    def test_protocol_specific_disk_budget_checked_before_transport(self):
        device = FakeDevice(self.data)
        space = type('Space', (), {'free': 4 * 1024 * 1024 + 5 * 2000})()
        with mock.patch.object(base.shutil, 'disk_usage', return_value=space):
            report, _ = self.capture(device, max_bytes=2000)
        self.assertFalse(report['capture_accepted'])
        self.assertEqual(device.calls, [])

    def test_invalid_wire_encoding_rejected_even_with_complete_decoded_bytes(self):
        device = FakeDevice(self.data)
        original_stream = device.stream

        def invalid_stream(*args):
            return dict(original_stream(*args), encoding_valid=False)

        device.stream = invalid_stream
        report, output = self.capture(device)
        self.assertTrue(report['source_coherent'])
        self.assertFalse(report['capture_accepted'])
        self.assertEqual((output / 'raw.bin').read_bytes(), self.data)
        self.assertEqual((output / 'complete_prefix.bin').read_bytes(), self.data)

    def test_native_protocol_remains_default_and_explicitly_usable(self):
        native = base.NativeProtocol()
        self.assertEqual(native.probe_script(PID, LOG), base.probe_script(PID, LOG))
        parsed = native.parse_probe(native_metadata(len(self.data)), PID, LOG)
        self.assertEqual(parsed, base.parse_probe(native_metadata(len(self.data)), PID, LOG))
        self.assertEqual(native.stream_script(PID, LOG, 1376, parsed),
                         f'exec head -c 1376 {LOG} 2>/dev/null')
        for index, options in enumerate(({}, {'protocol': native})):
            device = NativeFakeDevice(self.data)
            report = base.capture(device, SERIAL, PID, RUN, self.root / f'native{index}', **options)
            self.assertTrue(report['capture_accepted'], report['errors'])
            self.assertEqual(report['limits'], native.limits)
            self.assertIn('exec head -c', device.calls[1][1])


class ScriptTests(unittest.TestCase):
    def setUp(self):
        self.protocol = legacy.LegacyProtocol(NONCE)
        self.before = self.protocol.parse_probe(metadata(1376), PID, LOG)

    def test_bounded_read_only_commands_and_starttime_expansion(self):
        probe = self.protocol.probe_script(PID, LOG)
        stream = self.protocol.stream_script(PID, LOG, 1376, self.before)
        self.assertIn('"${20}" = 777', stream)
        self.assertNotIn('"$20"', stream)
        self.assertIn('S=${S##*) }', stream)
        self.assertIn(f'exec 8<{LOG}', stream)
        self.assertIn('od -An -v -tx1 -N 1376 <&8', stream)
        self.assertNotIn('<&9', stream)
        self.assertIn(f'[ {LOG} -ef /proc/{PID}/fd/9 ]', probe)
        self.assertIn(f'[ /proc/{PID}/fd/9 -ef /proc/$$/fd/8 ]', stream)
        self.assertIn('check || RC=91', stream)
        self.assertIn(f'@@{NONCE}:END:%s@@', stream)
        for command in (probe, stream):
            # Includes the enclosing sh -c argument in the old ADB payload budget.
            self.assertLess(len(('sh -c ' + shlex.quote(command)).encode('ascii')), 4096)
            self.assertNotRegex(command, r'\b(?:cp|mv|rm|dd|touch|mkdir|kill|killall|reboot|sync|tee)\b')
            self.assertNotIn('>', command)
            self.assertNotIn('/tmp/', command)

    @unittest.skipUnless(BASH, 'local POSIX shell unavailable')
    def test_production_scripts_parse_in_posix_bash(self):
        for script in (self.protocol.probe_script(PID, LOG),
                       self.protocol.stream_script(PID, LOG, 1376, self.before)):
            result = subprocess.run([BASH, '--posix', '-n'], input=script.encode('ascii'),
                                    capture_output=True, timeout=3)
            self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(BASH, 'local POSIX shell unavailable')
    def test_isolated_stream_pins_and_reads_only_requested_prefix(self):
        # Only disposable host files are opened. Every production /proc path and
        # card file operand is replaced before execution; /dev/fd/8 denotes this
        # local test shell's descriptor, never a player descriptor. The card
        # pathname remains only as awk input for the synthetic mount tables.
        with tempfile.TemporaryDirectory(prefix='legacy-shell-fixture-') as folder:
            root = Path(folder)
            source, boot, stat, link = (root / name for name in ('source.bin', 'boot', 'stat', 'fd9'))
            mounts, player_mounts = root / 'mounts', root / 'player_mounts'
            link_target = root / 'fd9_target'
            data = bytes(range(256)) * 8
            source.write_bytes(data)
            boot.write_text(BOOT + '\n', encoding='ascii')
            stat.write_text(process_stat() + '\n', encoding='ascii')
            mounts.write_text(MOUNTS + '\n', encoding='ascii')
            player_mounts.write_text(MOUNTS + '\n', encoding='ascii')
            qsource = shlex.quote(source.as_posix())
            capability = subprocess.run(
                [BASH, '--posix', '-c', f'exec 8<{qsource}; [ {qsource} -ef /dev/fd/8 ] && '
                 'LC_ALL=C ls -Lndi --color=never /dev/fd/8'], capture_output=True, timeout=3)
            if capability.returncode:
                self.skipTest('local shell does not expose a readable /dev/fd/8 alias')
            inode = int(capability.stdout.split()[0])
            # Native Windows symlink creation is privilege-dependent and Git
            # Bash may silently copy instead. A real hardlink exercises -ef;
            # only readlink's pathname result is provided by a fixture function.
            os.link(source, link)
            link_target.write_text(source.as_posix() + '\n', encoding='ascii')
            readlink_fixture = (
                f'readlink() {{ [ "$1" = {shlex.quote(link.as_posix())} ] && '
                f'cat {shlex.quote(link_target.as_posix())}; }}; '
            )
            before = dict(self.before, file_inode=inode)
            replacements = {
                '/proc/sys/kernel/random/boot_id': shlex.quote(boot.as_posix()),
                f'/proc/{PID}/stat': shlex.quote(stat.as_posix()),
                f'/proc/{PID}/fd/9': shlex.quote(link.as_posix()),
                '/proc/self/mountinfo': shlex.quote(mounts.as_posix()),
                f'/proc/{PID}/mountinfo': shlex.quote(player_mounts.as_posix()),
                '/proc/$$/fd/8': '/dev/fd/8', LOG: qsource,
            }

            def fixture_script(evidence=before):
                script = self.protocol.stream_script(PID, LOG, 1376, evidence)
                # Keep mountok's pathname value unchanged while redirecting all
                # actual file operands to the disposable fixture directory.
                script = script.replace(f'-v p={LOG}', '-v p=FIXTURE_LOG_LITERAL')
                for old, new in replacements.items():
                    script = script.replace(old, new)
                self.assertNotIn('/proc/', script)
                self.assertNotIn(LOG, script)
                return readlink_fixture + script.replace('FIXTURE_LOG_LITERAL', shlex.quote(LOG))

            def run(script):
                result = subprocess.run([BASH, '--posix', '-c', script],
                                        capture_output=True, timeout=3)
                self.assertEqual(result.returncode, 0, result.stderr)
                begin, payload = result.stdout.split(b'\n', 1)
                body, end = payload.rsplit(b'\n@@', 1)
                self.assertEqual(begin, f'@@{NONCE}:BEGIN@@'.encode())
                return bytes.fromhex(body.decode('ascii')), end.strip()

            def assert_preflight_rejected(script):
                body, end = run(script)
                self.assertEqual(end, f'{NONCE}:END:90@@'.encode())
                self.assertEqual(body, b'')

            script = fixture_script()
            body, end = run(script)
            self.assertEqual(end, f'{NONCE}:END:0@@'.encode())
            self.assertEqual(body, data[:1376])
            self.assertEqual(source.read_bytes(), data)
            # Wrong field 22 fails before od; ${20} must not be parsed as $2 + 0.
            stat.write_text(process_stat(start=778) + '\n', encoding='ascii')
            assert_preflight_rejected(script)
            stat.write_text(process_stat() + '\n', encoding='ascii')
            boot.write_text('ffffffff-ffff-ffff-ffff-ffffffffffff\n', encoding='ascii')
            assert_preflight_rejected(script)
            boot.write_text(BOOT + '\n', encoding='ascii')
            link_target.write_text(source.as_posix() + '.replaced\n', encoding='ascii')
            assert_preflight_rejected(script)
            link_target.write_text(source.as_posix() + '\n', encoding='ascii')
            assert_preflight_rejected(fixture_script(dict(before, file_inode=inode + 1)))
            source.write_bytes(data[:1375])
            assert_preflight_rejected(script)
            source.write_bytes(data)
            # Same pathname text is insufficient when the simulated player FD
            # points at a different file, even if bytes and lengths are equal.
            link.unlink()
            link.write_bytes(data)
            assert_preflight_rejected(script)
            link.unlink()
            os.link(source, link)
            for table in (mounts, player_mounts):
                for bad in (MOUNTS.replace('31 20', '32 20'),
                            MOUNTS.replace('179:1', '179:2'),
                            MOUNTS.replace(' / /mnt/sd_0 ', ' /bound /mnt/sd_0 '),
                            MOUNTS + '\n' + CARD_MOUNT,
                            MOUNTS + f'\n32 31 179:1 / {RUN} rw - vfat /dev/mmcblk0p1 rw'):
                    with self.subTest(table=table.name, mountinfo=bad):
                        table.write_text(bad + '\n', encoding='ascii')
                        assert_preflight_rejected(script)
                table.write_text(MOUNTS + '\n', encoding='ascii')
            # Mutate only a disposable metadata fixture after od succeeds. The
            # production post-read check must reject, retaining all read bytes.
            mutate = (f'od() {{ command od "$@"; result=$?; '
                      f'printf "changed\\n" > {shlex.quote(boot.as_posix())}; '
                      'return "$result"; }; ')
            body, end = run(mutate + script)
            self.assertEqual(body, data[:1376])
            self.assertEqual(end, f'{NONCE}:END:91@@'.encode())
            self.assertEqual(source.read_bytes(), data)


if __name__ == '__main__':
    unittest.main()
