"""Host-only metadata and local shell tests; never invoke ADB or a player."""
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import capture_move_checkpoint as base
import check_legacy_adb_transport as compat
import check_move_launcher_preflight as preflight
from capture_move_legacy_checkpoint import sections
from legacy_adb_transport import LegacyAdb, MAX_COMMAND_BYTES
from test_move_evidence_launcher import BASH, SOURCE


NONCE = '0123456789abcdef0123456789abcdef'
PID = 116
BOOT = 'd20f9fb3-9038-445a-961b-02f1cd17f03b'
MOUNTS = ('11 1 0:11 / / rw,relatime - ubifs ubi0:rootfs rw\n'
          '19 11 179:1 / /mnt/sd_0 rw,relatime - vfat /dev/mmcblk0p1 rw')


def envelope(mapping):
    return ''.join(f'\n@@{key}@@\n{value}\n' for key, value in mapping.items()
                   if value is not None).encode('ascii')


def process_stat(pid=PID, start=349):
    fields = ['S'] + ['0'] * 49
    fields[19] = str(start)
    return f'{pid} (system main (thread)) ' + ' '.join(fields)


def file_stat(path, size=7973184, inode=142):
    return f'{inode} -rw-r--r-- 1 0 0 {size} Sep 30 12:00 {path}'


def syntax_evidence(payload=b'echo ok\n', status=0, nonce=NONCE, **changes):
    values = dict(hash=hashlib.sha256(payload).hexdigest(), bytes=str(len(payload)),
                  diagnostics='', **{'status_' + nonce: str(status)})
    values.update(changes)
    return envelope(values)


def stock_evidence(**changes):
    values = {
        'boot': BOOT, 'stat': process_stat(),
        'exe': f'{compat.STOCK} /proc/{PID}/exe', 'flag': 'absent',
        'installed': f'{preflight.INSTALLED} /ui_data/player\n{base.EXPECTED} /data/hiby_player_sortfix',
        'closed_log': f'{compat.REFERENCE} {compat.CLOSED_LOG}',
        'log_identity': file_stat(compat.CLOSED_LOG),
        'meminfo': 'MemTotal: 58308 kB\nMemFree: 904 kB',
        'status': f'Name:\tplayer\nPid:\t{PID}\nVmRSS:\t19088 kB',
        'done_' + NONCE: '0',
    }
    values.update(changes)
    return envelope(values)


def prereq_evidence(**changes):
    values = {
        'commands': '\n'.join('/bin/' + name for name in preflight.COMMANDS),
        'mounts': MOUNTS, 'player_mounts': MOUNTS,
        'df': 'Filesystem 1024-blocks Used Available Capacity Mounted on\n'
              '/dev/mmcblk0p1 1000000 1000 999000 1% /mnt/sd_0',
        'available': '999000', 'access': 'ok',
        'stock_wrapper': '#!/bin/sh\nexec /usr/bin/hiby_player\n',
        'installed_syntax': 'ok', 'launcher_stat': file_stat('/ui_data/player', 817, 2613),
        'stack': '8192', 'stamp': '20261001T120000',
        'processes': f'  PID USER COMMAND\n  {PID} root /usr/bin/hiby_player',
        'kernel': 'mock kernel ring', 'child_proc': 'checked',
        'done_' + NONCE: '0',
    }
    values.update(changes)
    return envelope(values)


class SyntaxTests(unittest.TestCase):
    def parse(self, data, payload=b'echo ok\n', status=0):
        return preflight.parse_syntax(data, NONCE, hashlib.sha256(payload).hexdigest(),
                                      len(payload), status)

    def test_complete_syntax_evidence_and_terminal_newlines(self):
        expected = dict(sha256=hashlib.sha256(b'echo ok\n').hexdigest(), bytes=8,
                        remote_status=0, diagnostics='')
        for newline in (b'\n', b'\r\n', b'\r\r\n'):
            with self.subTest(newline=newline):
                self.assertEqual(self.parse(syntax_evidence().replace(b'\n', newline)), expected)

    def test_invalid_syntax_status_is_explicit_not_host_status(self):
        raw = syntax_evidence(b'if then\n', status=2, diagnostics='syntax error')
        parsed = self.parse(raw, b'if then\n', status=2)
        self.assertEqual(parsed['remote_status'], 2)
        self.assertEqual(parsed['diagnostics'], 'syntax error')
        with self.assertRaises(ValueError):
            self.parse(raw, b'if then\n', status=0)

    def test_exact_hash_size_status_and_silent_success_required(self):
        cases = ({'hash': '0' * 64}, {'hash': hashlib.sha256(b'echo ok').hexdigest()},
                 {'bytes': '7'}, {'bytes': '08'}, {'bytes': '8\n8'},
                 {'status_' + NONCE: '1'}, {'status_' + NONCE: '0\n0'},
                 {'status_' + NONCE: '00'}, {'status_' + NONCE: '-1'},
                 {'diagnostics': 'MUST_NOT_EXECUTE'})
        for change in cases:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.parse(syntax_evidence(**change))

    def test_exact_sections_nonce_duplicate_and_prelude_required(self):
        valid = syntax_evidence()
        for key in sections(valid):
            with self.subTest(missing=key), self.assertRaises(ValueError):
                self.parse(syntax_evidence(**{key: None}))
        for invalid in (valid + b'\n@@extra@@\n0\n', valid + b'\n@@hash@@\n0\n',
                        b'prompt$\n' + valid, valid.replace(NONCE.encode(), b'f' * 32),
                        valid + b'\xff', b' ' * (base.MAX_METADATA + 1)):
            with self.subTest(invalid=invalid[:100]), self.assertRaises(ValueError):
                self.parse(invalid)

    def test_payload_nonce_and_legacy_command_limit(self):
        for nonce in ('', NONCE[:-1], NONCE.upper(), NONCE + '0', None, ';' * 32):
            with self.subTest(nonce=nonce):
                for function, args in ((preflight.syntax_script, (b'echo ok\n', nonce)),
                                       (preflight.prereq_script, (PID, nonce)),
                                       (preflight.runtime_script, (nonce,))):
                    with self.assertRaises(ValueError):
                        function(*args)
        for payload in (b'', b'\0', b'echo ok\0\n', b'\xff\n'):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                preflight.syntax_script(payload, NONCE)
        # Deterministic ASCII with poor compression must be refused locally.
        large = b''.join(hashlib.sha256(str(i).encode()).hexdigest().encode()
                         for i in range(500))
        with self.assertRaises(ValueError):
            preflight.syntax_script(large, NONCE)

    def test_pinned_full_launcher_fits_legacy_argv_without_execution(self):
        source = SOURCE.read_bytes()
        self.assertEqual(hashlib.sha256(source).hexdigest(), preflight.LAUNCHER)
        script = preflight.syntax_script(source, NONCE)
        argv = LegacyAdb('unused-adb', 'HiBy RS2', NONCE).argv(script)
        self.assertLessEqual(len(argv[-1].encode()), MAX_COMMAND_BYTES)
        self.assertIn('uudecode -o - | gzip -dc', script)
        self.assertIn('printf %s "$S" | sh -n;', script)
        self.assertNotIn('sh -c "$S"', script)
        self.assertNotIn('eval ', script)
        self.assertNotIn('killall', script)
        self.assertNotIn('/data/hiby_player_sortfix', script)


class StockTests(unittest.TestCase):
    def parse(self, data):
        return preflight.stock_snapshot(data, PID, NONCE)

    def test_complete_stock_identity(self):
        parsed = self.parse(stock_evidence())
        self.assertEqual(parsed, dict(boot=BOOT, pid=PID, start_ticks=349,
                                     exe=compat.STOCK, installed=preflight.INSTALLED,
                                     candidate=base.EXPECTED, flag='absent',
                                     log_sha256=compat.REFERENCE, log_inode=142,
                                     log_size=7973184))

    def test_stock_identity_hashes_flag_log_and_memory_gates(self):
        cases = ({'boot': 'bad'}, {'stat': process_stat(pid=PID + 1)},
                 {'stat': process_stat(start='bad')}, {'exe': f'{base.EXPECTED} /proc/{PID}/exe'},
                 {'exe': f'{compat.STOCK} /proc/{PID + 1}/exe'}, {'flag': 'present'},
                 {'installed': f'{preflight.INSTALLED} /ui_data/player'},
                 {'installed': f'{preflight.LAUNCHER} /ui_data/player\n{base.EXPECTED} /data/hiby_player_sortfix'},
                 {'closed_log': f'{compat.REFERENCE} {compat.CLOSED_LOG}.other'},
                 {'log_identity': file_stat(compat.CLOSED_LOG, size=0)},
                 {'log_identity': file_stat(compat.CLOSED_LOG + '.other')},
                 {'meminfo': 'MemTotal: unknown'}, {'status': f'Pid:\t{PID + 1}'},
                 {'done_' + NONCE: '1'})
        for change in cases:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.parse(stock_evidence(**change))

    def test_stock_exact_sections(self):
        valid = stock_evidence()
        for key in sections(valid):
            with self.subTest(missing=key), self.assertRaises(ValueError):
                self.parse(stock_evidence(**{key: None}))
        for invalid in (valid + b'\n@@extra@@\n0', valid + b'\n@@boot@@\n' + BOOT.encode(),
                        valid.replace(NONCE.encode(), b'f' * 32), b'prompt\n' + valid):
            with self.assertRaises(ValueError):
                self.parse(invalid)


class PrerequisiteTests(unittest.TestCase):
    def parse(self, data):
        return preflight.parse_prereqs(data, PID, NONCE)

    def test_complete_prerequisites_are_observations_not_write_validation(self):
        parsed = self.parse(prereq_evidence())
        self.assertEqual(parsed['available_kib'], 999000)
        self.assertEqual(parsed['stack_kib'], 8192)
        self.assertEqual(parsed['card_mount']['mountpoint'], '/mnt/sd_0')
        self.assertTrue(parsed['permission_checks_only'])

    def test_missing_failed_duplicate_and_wrong_nonce_sections(self):
        valid = prereq_evidence()
        for key in sections(valid):
            with self.subTest(missing=key), self.assertRaises(ValueError):
                self.parse(prereq_evidence(**{key: None}))
        for invalid in (prereq_evidence(**{'done_' + NONCE: '1'}),
                        valid + b'\n@@access@@\nok', valid + b'\n@@extra@@\n0',
                        valid.replace(NONCE.encode(), b'f' * 32), b'prompt\n' + valid):
            with self.assertRaises(ValueError):
                self.parse(invalid)

    def test_commands_and_mount_namespace_must_agree(self):
        commands = '\n'.join('/bin/' + name for name in preflight.COMMANDS)
        cases = ({'commands': commands.replace('/bin/sh\n', '')},
                 {'commands': commands.replace('/bin/sh\n', '/bin/wrong\n')},
                 {'commands': commands + '\n/bin/extra'},
                 {'mounts': MOUNTS.replace(' rw,relatime ', ' ro,relatime ')},
                 {'player_mounts': MOUNTS.replace(' rw,relatime ', ' ro,relatime ')},
                 {'player_mounts': MOUNTS.replace('19 11', '20 11')},
                 {'mounts': MOUNTS.replace(' - vfat ', ' - ext4 ')},
                 {'mounts': MOUNTS + '\n20 19 179:1 / /mnt/sd_0/rs2_move_evidence rw - vfat /dev/mmcblk0p1 rw'})
        for change in cases:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.parse(prereq_evidence(**change))

    def test_space_df_access_syntax_and_observation_gates(self):
        cases = ({'available': '65535'}, {'available': 'unknown'},
                 {'available': '-1'}, {'available': '999001'},
                 {'df': 'Filesystem\n/dev/mmcblk1p1 1000000 1000 999000 1% /mnt/sd_0'},
                 {'df': 'Filesystem\n/dev/mmcblk0p1 1000000 1000 999000 1% /mnt/sd_1'},
                 {'df': 'Filesystem\n/dev/mmcblk0p1 1000000 1000 999000 1% /mnt/sd_0\nextra'},
                 {'access': 'failed'}, {'installed_syntax': 'failed'},
                 {'child_proc': 'failed'}, {'stack': 'unlimited'}, {'stack': '-1'},
                 {'launcher_stat': file_stat('/ui_data/player', 0)},
                 {'launcher_stat': file_stat('/ui_data/player', 65537)},
                 {'launcher_stat': file_stat('/ui_data/player.other', 817)},
                 {'stamp': 'unknown'}, {'stamp': '2026-10-01T120000'},
                 {'stock_wrapper': 'not a shebang'}, {'processes': 'no matching player'})
        for change in cases:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.parse(prereq_evidence(**change))

    def test_generated_prerequisites_fit_and_only_query_dangerous_commands(self):
        script = preflight.prereq_script(PID, NONCE)
        argv = LegacyAdb('unused', 'HiBy RS2', NONCE).argv(script)
        self.assertLessEqual(len(argv[-1].encode()), MAX_COMMAND_BYTES)
        for name in ('rm', 'mkdir', 'sync', 'killall', 'reboot', 'sleep'):
            self.assertEqual(script.count(name), 1, name)
            self.assertIn('command -v ' + name, script)
        self.assertNotIn('>>', script)
        self.assertNotIn('RS2_SORTFIX_TEST', script)


class RunnerTests(unittest.TestCase):
    def test_changed_local_launcher_refused_before_transport_or_output(self):
        with tempfile.TemporaryDirectory(prefix='preflight-refusal-') as directory:
            root = Path(directory)
            launcher = root / 'changed.sh'
            launcher.write_bytes(b'#!/bin/sh\nexit 0\n')
            with mock.patch.object(preflight, 'LegacyAdb') as transport:
                with self.assertRaisesRegex(ValueError, 'pinned reviewed draft'):
                    preflight.run_check('unused-adb', 'HiBy RS2', PID, launcher, root / 'output')
                transport.assert_not_called()
            self.assertFalse((root / 'output').exists())

    def test_failure_retains_raw_outputs_and_always_attempts_after_snapshot(self):
        backup = b'#!/bin/sh\nexit 0\n'
        controls = {
            'nonexecuting': (b'printf "MUST_NOT_EXECUTE\\n"; exit 37\n', 0),
            'invalid': (b'if then\n', 2),
        }
        for failure in ('metadata', 'transport', 'remote_status', 'backup'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(prefix='preflight-runner-') as directory:
                calls = []
                raw = {}

                class FakeTransport:
                    def __init__(self, executable, serial, nonce):
                        self.real = LegacyAdb(executable, serial, nonce)

                    def argv(self, script):
                        return self.real.argv(script)

                    def probe(self, script, output, timeout):
                        label = output.stem
                        calls.append(label)
                        if label in ('before', 'after'):
                            data = stock_evidence()
                        elif label == 'prerequisites':
                            data = (b'partial unframed evidence' if failure == 'metadata' else
                                    prereq_evidence(launcher_stat=file_stat('/ui_data/player', len(backup), 2613)))
                        else:
                            payload, status = controls[label]
                            if label == 'invalid' and failure == 'remote_status':
                                status = 0
                            data = syntax_evidence(payload, status=status)
                        raw[label] = data
                        output.write_bytes(data)
                        output.with_suffix('.stderr').write_bytes(b'mock preserved stderr')
                        return dict(returncode=0, timed_out=failure == 'transport' and label == 'invalid',
                                    bytes=len(data), overlong=False, stderr_overlong=False, reader_errors=[])

                    def stream(self, script, output, size, timeout):
                        calls.append('backup')
                        data = b'X' * len(backup) if failure == 'backup' else backup
                        output.write_bytes(data)
                        output.with_suffix('.hex').write_bytes(data.hex().encode())
                        output.with_suffix('.stderr').write_bytes(b'mock backup stderr')
                        return dict(returncode=0, timed_out=False, bytes=len(data), overlong=False,
                                    stderr_overlong=False, reader_errors=[], encoding_valid=True,
                                    remote_returncode=0)

                output = Path(directory) / 'output'
                with mock.patch.object(preflight, 'LegacyAdb', FakeTransport), \
                        mock.patch.object(preflight.secrets, 'token_hex', return_value=NONCE), \
                        mock.patch.object(preflight, 'INSTALLED', hashlib.sha256(backup).hexdigest()):
                    report = preflight.run_check('unused-adb', 'HiBy RS2', PID, SOURCE, output)
                self.assertFalse(report['readonly_preflight_passed'])
                self.assertFalse(report['launcher_executed'])
                self.assertFalse(report['live_move_validated'])
                self.assertTrue(report['stock_state_preserved'])
                self.assertTrue(report['errors'])
                self.assertEqual(calls[-1], 'after')
                self.assertNotIn('launcher', calls)
                self.assertNotIn('runtime', calls)
                self.assertEqual(json.loads((output / 'report.json').read_text()), report)
                for label, data in raw.items():
                    self.assertEqual((output / (label + '.txt')).read_bytes(), data)
                    self.assertEqual((output / (label + '.stderr')).read_bytes(), b'mock preserved stderr')
                if failure != 'metadata':
                    self.assertTrue((output / 'installed_launcher.bin').exists())
                    self.assertTrue((output / 'installed_launcher.hex').exists())


@unittest.skipUnless(BASH, 'local POSIX-compatible shell unavailable')
class LocalSyntaxTests(unittest.TestCase):
    # Git Bash has base64/gzip, but no uudecode. This narrow local fixture checks
    # the exact uu envelope/options then decodes to stdout; real RS2 validation
    # separately exercises its actual uudecode applet.
    DECODER = r'''uudecode() {
    [ "$#" = 2 ] && [ "$1" = -o ] && [ "$2" = - ] || return 30
    IFS= read -r header && IFS= read -r body && IFS= read -r footer || return 31
    [ "$header" = 'begin-base64 600 -' ] && [ "$footer" = ==== ] || return 32
    printf %s "$body" | base64 -d
}
'''

    def run_local(self, payload, decoder=None):
        script = self.DECODER if decoder is None else decoder
        script += preflight.syntax_script(payload, NONCE)
        return subprocess.run([BASH, '--noprofile', '--norc', '--posix', '-c', script],
                              capture_output=True, timeout=15)

    def parse(self, result, payload, status=0):
        self.assertEqual(result.returncode, 0, result.stderr)
        return preflight.parse_syntax(result.stdout, NONCE, hashlib.sha256(payload).hexdigest(),
                                      len(payload), status)

    def test_full_launcher_exact_bytes_are_only_parsed(self):
        source = SOURCE.read_bytes()
        result = self.run_local(source)
        self.parse(result, source)
        self.assertEqual(result.stderr, b'')

    def test_command_substitution_preserves_all_trailing_lf(self):
        for payload in (b':', b':\n', b':\n\n\n', b'# quote \' " $() `not executed`\n:\n\n'):
            with self.subTest(payload=payload):
                result = self.run_local(payload)
                self.parse(result, payload)
                self.assertEqual(result.stderr, b'')

    def test_valid_payload_with_side_effect_is_not_executed(self):
        with tempfile.TemporaryDirectory(prefix='preflight-noexec-') as directory:
            marker = Path(directory) / 'must_not_exist'
            payload = ('printf DANGER > "' + marker.as_posix() + '"\n'
                       'printf MUST_NOT_EXECUTE\nexit 37\n').encode('ascii')
            self.parse(self.run_local(payload), payload)
            self.assertFalse(marker.exists())

    def test_invalid_payload_produces_explicit_status_and_diagnostic(self):
        payload = b'if then\n'
        result = self.run_local(payload)
        self.parse(result, payload, status=2)
        self.assertIn(b'syntax error', result.stderr.lower())

    def test_failed_decoder_cannot_be_mistaken_for_empty_valid_syntax(self):
        result = self.run_local(b'echo ok\n', 'uudecode() { return 37; }\n')
        self.assertEqual(result.returncode, 0)
        parsed = sections(result.stdout)
        self.assertEqual(parsed['status_' + NONCE], '98')
        self.assertEqual(parsed['bytes'], '0')
        with self.assertRaises(ValueError):
            self.parse(result, b'echo ok\n')

    def test_runtime_controls_use_only_transient_shell_and_readonly_fds(self):
        result = subprocess.run([BASH, '--noprofile', '--norc', '--posix', '-c',
                                 preflight.runtime_script(NONCE)],
                                capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout.decode('ascii'),
                         rf'@@runtime_{NONCE}@@\s+wait=37 failed_open=[1-9]\d* fd_control=0 outer=continued\s*$')


if __name__ == '__main__':
    unittest.main()
