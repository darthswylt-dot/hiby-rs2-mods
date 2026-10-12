"""Host-only bridge preflight fixtures: never contact ADB or a player."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import capture_move_checkpoint as base
import check_reveal_bridge_preflight as preflight
from capture_move_legacy_checkpoint import sections
from legacy_adb_transport import LegacyAdb, MAX_COMMAND_BYTES


NONCE = '0123456789abcdef0123456789abcdef'
PID = 116
BOOT = 'd20f9fb3-9038-445a-961b-02f1cd17f03b'
LAUNCHER_PATH = Path(__file__).with_name('rs2_reveal_bridge_launcher.sh')
MOUNTS = ('11 1 0:11 / / rw,relatime - ubifs ubi0:rootfs rw\n'
          '19 11 179:1 / /mnt/sd_0 rw,relatime - vfat /dev/mmcblk0p1 rw\n'
          '20 11 0:15 / /data rw,relatime - ubifs ubi0:data rw')


def envelope(mapping):
    return ''.join(f'\n@@{key}@@\n{value}\n' for key, value in mapping.items()
                   if value is not None).encode('ascii')


def process_stat(pid=PID, start=349, parent=1):
    fields = ['S'] + ['0'] * 49
    fields[1] = str(parent)
    fields[19] = str(start)
    return f'{pid} (system main (thread)) ' + ' '.join(fields)


def file_stat(size=817, inode=2613, path='/ui_data/player'):
    return f'{inode} -rw-r--r-- 1 0 0 {size} Oct 8 12:00 {path}'


def stock_evidence(**changes):
    values = dict(
        boot=BOOT, stat_before=process_stat(), stat_after=process_stat(),
        exe=f'{preflight.STOCK} /proc/{PID}/exe', players=str(PID),
        old_flag='absent', flag='absent', target='absent',
        installed=(f'{preflight.INSTALLED} /ui_data/player\n'
                   f'{preflight.OLD_CANDIDATE} /data/hiby_player_sortfix\n'
                   f'{preflight.STOCK} /usr/bin/hiby_player\n'
                   f'{preflight.STOCK_WRAPPER} /usr/bin/hiby_player.sh'),
        launcher_stat=file_stat(), meminfo='MemTotal: 58308 kB\nMemFree: 904 kB',
        status=f'Name:\tplayer\nPid:\t{PID}\nVmRSS:\t19088 kB',
        **{'done_' + NONCE: '0'})
    values.update(changes)
    return envelope(values)


def df(source, path, available):
    return ('Filesystem 1024-blocks Used Available Capacity Mounted on\n'
            f'{source} 1000000 1000 {available} 1% {path}')


def prereq_evidence(**changes):
    values = dict(
        commands='\n'.join('/bin/' + name for name in preflight.COMMANDS),
        mounts=MOUNTS, player_mounts=MOUNTS,
        card_df=df('/dev/mmcblk0p1', '/mnt/sd_0', 999000),
        data_df=df('ubi0:data', '/data', 999000),
        access='ok', syntax='ok', same_exe='same',
        stock_wrapper='#!/bin/sh\nexec /usr/bin/hiby_player\n',
        stack='8192', stamp='20261008T120000', uptime='351.23 222.90',
        processes=f'  PID USER COMMAND\n  {PID} root /usr/bin/hiby_player',
        **{'done_' + NONCE: '0'})
    values.update(changes)
    return envelope(values)


def syntax_evidence(payload, status=0):
    return envelope(dict(hash=hashlib.sha256(payload).hexdigest(), bytes=str(len(payload)),
                         diagnostics='', **{'status_' + NONCE: str(status)}))


class StateTests(unittest.TestCase):
    def parse(self, raw):
        return preflight.stock_snapshot(raw, PID, NONCE)

    def reject(self, *changes):
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.parse(stock_evidence(**change))

    def test_complete_stock_identity_and_backup_budget(self):
        self.assertEqual(self.parse(stock_evidence()), dict(
            boot=BOOT, pid=PID, start_ticks=349, parent_pid=1, exe=preflight.STOCK,
            installed=preflight.INSTALLED, old_candidate=preflight.OLD_CANDIDATE,
            stock_wrapper=preflight.STOCK_WRAPPER, old_flag='absent', flag='absent',
            target='absent', launcher_inode=2613, launcher_size=817))
        for size in (1, 65536):
            self.assertEqual(self.parse(stock_evidence(launcher_stat=file_stat(size=size)))['launcher_size'], size)

    def test_boot_pid_and_start_ticks_must_be_stable(self):
        self.reject({'boot': 'bad'}, {'boot': BOOT.upper()},
                    {'stat_before': process_stat(pid=PID + 1)},
                    {'stat_after': process_stat(pid=PID + 1)},
                    {'stat_before': process_stat(start='bad')},
                    {'stat_after': process_stat(start=350)},
                    {'stat_after': process_stat(start='bad')},
                    {'stat_before': process_stat(parent='bad')},
                    {'stat_after': process_stat(parent=2)})

    def test_exactly_one_live_original_player(self):
        self.reject({'exe': f'{preflight.CANDIDATE} /proc/{PID}/exe'},
                    {'exe': f'{preflight.STOCK} /proc/{PID + 1}/exe'},
                    {'exe': f'{preflight.STOCK} /proc/{PID}/exe\nextra'},
                    {'players': ''}, {'players': f'{PID} {PID + 1}'},
                    {'players': str(PID + 1)}, {'players': f'0{PID}'})

    def test_flags_and_unused_target_must_all_be_absent(self):
        for key in ('old_flag', 'flag', 'target'):
            self.reject({key: 'present'}, {key: ''}, {key: 'absent\nabsent'})

    def test_all_installed_paths_and_hashes_are_pinned(self):
        installed = sections(stock_evidence())['installed']
        for digest in (preflight.INSTALLED, preflight.OLD_CANDIDATE,
                       preflight.STOCK, preflight.STOCK_WRAPPER):
            self.reject({'installed': installed.replace(digest, '0' * 64)})
        for path in ('/ui_data/player', '/data/hiby_player_sortfix',
                     '/usr/bin/hiby_player', '/usr/bin/hiby_player.sh'):
            self.reject({'installed': installed.replace(path, path + '.other')})
        self.reject({'installed': '\n'.join(reversed(installed.splitlines()))},
                    {'installed': installed + '\nextra'})

    def test_backup_identity_and_bound_are_not_optional(self):
        self.reject({'launcher_stat': file_stat(size=0)},
                    {'launcher_stat': file_stat(size=65537)},
                    {'launcher_stat': file_stat(inode=0)},
                    {'launcher_stat': file_stat(path='/ui_data/player.other')},
                    {'launcher_stat': file_stat().replace('-rw-r--r--', 'lrwxrwxrwx')})

    def test_memory_and_selected_process_are_recorded(self):
        self.reject({'meminfo': 'MemTotal: 0 kB'}, {'meminfo': 'MemTotal: unknown'},
                    {'status': f'Pid:\t{PID + 1}'}, {'status': 'Pid: unknown'})

    def test_exact_sections_nonce_completion_and_framing(self):
        valid = stock_evidence()
        for key in sections(valid):
            self.reject({key: None})
        for bad in (valid + b'\n@@extra@@\n0', valid + b'\n@@boot@@\n' + BOOT.encode(),
                    valid.replace(NONCE.encode(), b'f' * 32), b'prompt\n' + valid,
                    valid + b'\xff', b' ' * (base.MAX_METADATA + 1),
                    stock_evidence(**{'done_' + NONCE: '1'})):
            with self.subTest(bad=bad[:80]), self.assertRaises(ValueError):
                self.parse(bad)

    def test_legacy_terminal_newline_expansion_is_harmless(self):
        expected = self.parse(stock_evidence())
        for newline in (b'\r\n', b'\r\r\n'):
            self.assertEqual(self.parse(stock_evidence().replace(b'\n', newline)), expected)


class PrerequisiteTests(unittest.TestCase):
    def parse(self, raw):
        return preflight.parse_prereqs(raw, PID, NONCE)

    def reject(self, *changes):
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.parse(prereq_evidence(**change))

    def test_complete_observations_are_not_claimed_as_write_validation(self):
        parsed = self.parse(prereq_evidence())
        self.assertEqual(parsed['card_available_kib'], 999000)
        self.assertEqual(parsed['data_available_kib'], 999000)
        self.assertEqual(parsed['stack_kib'], 8192)
        self.assertEqual(parsed['data_mount'], (20, '0:15', 'ubi0:data'))
        self.assertEqual(parsed['card_mount']['mountpoint'], '/mnt/sd_0')
        self.assertTrue(parsed['permission_checks_only'])

    def test_exact_sections_nonce_and_completion(self):
        valid = prereq_evidence()
        for key in sections(valid):
            self.reject({key: None})
        for bad in (valid + b'\n@@access@@\nok', valid + b'\n@@extra@@\n0',
                    valid.replace(NONCE.encode(), b'f' * 32), b'prompt\n' + valid,
                    prereq_evidence(**{'done_' + NONCE: '1'})):
            with self.assertRaises(ValueError):
                self.parse(bad)

    def test_all_commands_in_exact_order(self):
        commands = sections(prereq_evidence())['commands']
        self.reject({'commands': commands.replace('/bin/sh\n', '')},
                    {'commands': commands.replace('/bin/sh\n', '/bin/not_sh\n')},
                    {'commands': commands + '\n/bin/extra'},
                    {'commands': '\n'.join(reversed(commands.splitlines()))})

    def test_direct_vfat_card_and_same_namespace_required(self):
        self.reject({'mounts': MOUNTS.replace(' - vfat ', ' - ext4 ')},
                    {'mounts': MOUNTS.replace('179:1 / /mnt/sd_0', '179:1 /bind /mnt/sd_0')},
                    {'player_mounts': MOUNTS.replace('19 11', '21 11')},
                    {'player_mounts': MOUNTS.replace('179:1', '179:2')},
                    {'mounts': MOUNTS + '\n21 19 179:1 / /mnt/sd_0/rs2_reveal_bridge_evidence rw - vfat /dev/mmcblk0p1 rw'})

    def test_rw_mount_and_superblock_options_for_both_namespaces(self):
        for key in ('mounts', 'player_mounts'):
            for old, new in (('/mnt/sd_0 rw,relatime', '/mnt/sd_0 ro,relatime'),
                             ('/dev/mmcblk0p1 rw', '/dev/mmcblk0p1 ro'),
                             ('/data rw,relatime', '/data ro,relatime'),
                             ('ubi0:data rw', 'ubi0:data ro')):
                self.reject({key: MOUNTS.replace(old, new)})

    def test_direct_ubifs_data_and_same_namespace_required(self):
        self.reject({'mounts': MOUNTS.replace(' - ubifs ubi0:data', ' - ext4 ubi0:data')},
                    {'mounts': MOUNTS.replace('0:15 / /data', '0:15 /bind /data')},
                    {'mounts': '\n'.join(MOUNTS.splitlines()[:-1])},
                    {'mounts': MOUNTS + '\n21 11 0:15 / /data rw - ubifs ubi0:data rw'},
                    {'player_mounts': MOUNTS.replace('20 11', '21 11')},
                    {'player_mounts': MOUNTS.replace('0:15', '0:16')},
                    {'player_mounts': MOUNTS.replace('ubi0:data', 'ubi1:data')})

    def test_exact_minimum_space_on_both_filesystems(self):
        parsed = self.parse(prereq_evidence(card_df=df('/dev/mmcblk0p1', '/mnt/sd_0', 65536),
                                          data_df=df('ubi0:data', '/data', 16384)))
        self.assertEqual(parsed['card_available_kib'], 65536)
        self.assertEqual(parsed['data_available_kib'], 16384)
        self.reject({'card_df': df('/dev/mmcblk0p1', '/mnt/sd_0', 65535)},
                    {'data_df': df('ubi0:data', '/data', 16383)})

    def test_df_source_path_and_numbers_must_match_mount(self):
        for key, source, path in (('card_df', '/dev/mmcblk0p1', '/mnt/sd_0'),
                                  ('data_df', 'ubi0:data', '/data')):
            self.reject({key: df(source + '.other', path, 999000)},
                        {key: df(source, path + '.other', 999000)},
                        {key: df(source, path, 'unknown')},
                        {key: df(source, path, '-1')},
                        {key: df(source, path, 999000) + '\nextra'}, {key: ''})

    def test_access_syntax_same_exe_and_process_observations(self):
        self.reject({'access': 'failed'}, {'syntax': 'failed'}, {'same_exe': 'different'},
                    {'same_exe': ''}, {'stack': 'unlimited'}, {'stack': '1023'},
                    {'stack': '-1'}, {'stamp': 'unknown'}, {'stamp': '2026-10-08T120000'},
                    {'uptime': 'unknown'}, {'uptime': '35.1'},
                    {'stock_wrapper': 'not a shebang'}, {'processes': 'no matching player'})


class ScriptTests(unittest.TestCase):
    def test_invalid_nonce_and_pid_rejected_before_script_generation(self):
        for nonce in ('', NONCE[:-1], NONCE.upper(), NONCE + '0', None, ';' * 32):
            for builder in (preflight.state_script, preflight.prereq_script):
                with self.subTest(nonce=nonce, builder=builder), self.assertRaises(ValueError):
                    builder(PID, nonce)
        for pid in (0, -1, 4194305, True, False, '116', None):
            for builder in (preflight.state_script, preflight.prereq_script):
                with self.subTest(pid=pid, builder=builder), self.assertRaises(ValueError):
                    builder(pid, NONCE)

    def test_all_generated_queries_fit_legacy_limit(self):
        for script in (preflight.state_script(PID, NONCE), preflight.prereq_script(PID, NONCE),
                       preflight.runtime_script(NONCE),
                       preflight.syntax_script(LAUNCHER_PATH.read_bytes(), NONCE)):
            argv = LegacyAdb('unused-adb', 'HiBy RS2', NONCE).argv(script)
            self.assertLessEqual(len(argv[-1].encode()), MAX_COMMAND_BYTES)
        with self.assertRaises(ValueError):
            preflight.script_sections({'large': 'x' * MAX_COMMAND_BYTES}, NONCE)

    def test_complete_new_launcher_is_parsed_not_executed(self):
        script = preflight.syntax_script(LAUNCHER_PATH.read_bytes(), NONCE)
        self.assertIn('printf %s "$S" | sh -n;', script)
        self.assertIn('uudecode -o - | gzip -dc', script)
        self.assertNotIn('eval ', script)
        self.assertNotIn('sh -c "$S"', script)
        self.assertNotIn('MUST_NOT_EXECUTE', script)

    def test_queries_do_not_write_arm_signal_or_reboot(self):
        state = preflight.state_script(PID, NONCE)
        self.assertIn('test -L ' + preflight.FLAG, state)
        self.assertIn('test -L ' + preflight.PATCH, state)
        self.assertIn(f'cat /proc/{PID}/stat', state)
        self.assertEqual(state.count(f'cat /proc/{PID}/stat;'), 2)
        script = preflight.prereq_script(PID, NONCE)
        self.assertIn(f'test /proc/{PID}/exe -ef /usr/bin/hiby_player', script)
        for name in ('rm', 'mkdir', 'sync', 'reboot', 'sleep', 'kill'):
            self.assertIn('command -v ' + name + ' || RC=1', script)
        for text in (state, script):
            self.assertNotIn('>>', text)
            self.assertNotIn('killall', text)
            self.assertNotIn('chmod', text)
            self.assertNotIn('touch ', text)
            self.assertNotIn(' >', text)

    def test_identity_helpers_are_exact_readonly_slice_of_pinned_source(self):
        payload = LAUNCHER_PATH.read_bytes()
        with mock.patch.object(preflight, 'LAUNCHER', hashlib.sha256(payload).hexdigest()):
            script = preflight.identity_script(payload, PID, NONCE)
        source = payload.decode('ascii')
        expected = 'field() {' + source.split('\nfield() {', 1)[1].split('\ndigest() {', 1)[0]
        self.assertTrue(script.startswith('PROC=/proc\n' + expected + '\n'))
        self.assertIn(f'start {PID};', script)
        self.assertIn(f'FIELD=parent field {PID};', script)
        self.assertLessEqual(len(LegacyAdb('unused', 'HiBy RS2', NONCE).argv(script)[-1].encode()),
                             MAX_COMMAND_BYTES)
        self.assertNotIn('digest() {', script)
        self.assertNotIn(preflight.PATCH, script)
        self.assertNotIn(preflight.FLAG, script)
        self.assertNotIn('kill ', script)

    def test_unpinned_or_ambiguous_identity_helper_source_is_refused(self):
        payload = LAUNCHER_PATH.read_bytes()
        with mock.patch.object(preflight, 'LAUNCHER', '0' * 64), self.assertRaises(ValueError):
            preflight.identity_script(payload, PID, NONCE)
        for data in (payload.replace(b'\nfield() {', b'\nmissing() {'),
                     payload.replace(b'\ndigest() {', b'\nmissing() {'),
                     payload + b'\nfield() { :; }\n', payload + b'\ndigest() { :; }\n'):
            with mock.patch.object(preflight, 'LAUNCHER', hashlib.sha256(data).hexdigest()), \
                    self.subTest(data=data[-60:]), self.assertRaises(ValueError):
                preflight.identity_script(data, PID, NONCE)

    def test_every_transport_failure_flag_is_fatal(self):
        good = dict(returncode=0, timed_out=False, overlong=False,
                    stderr_overlong=False, reader_errors=[])
        self.assertTrue(preflight.transport_ok(good))
        for key in good:
            with self.subTest(key=key):
                bad = dict(good, **{key: ['reader failed'] if key == 'reader_errors' else 1})
                self.assertFalse(preflight.transport_ok(bad))


class RunnerTests(unittest.TestCase):
    LAUNCHER = b'#!/bin/sh\nfield() { :; }\nstart() { field "$1"; }\ndigest() { :; }\nexit 0\n'
    CANDIDATE = b'fake locally verified ELF'
    SOURCE = b'fake reference ELF'
    BACKUP = b'#!/bin/sh\nexec /usr/bin/hiby_player.sh\n'

    def files(self, root):
        paths = [root / name for name in ('launcher.sh', 'source.bin', 'candidate.bin')]
        for path, data in zip(paths, (self.LAUNCHER, self.SOURCE, self.CANDIDATE)):
            path.write_bytes(data)
        return paths

    def patches(self):
        return mock.patch.multiple(preflight, LAUNCHER=hashlib.sha256(self.LAUNCHER).hexdigest(),
                                   CANDIDATE=hashlib.sha256(self.CANDIDATE).hexdigest(),
                                   CANDIDATE_SIZE=len(self.CANDIDATE),
                                   INSTALLED=hashlib.sha256(self.BACKUP).hexdigest())

    def test_local_refusals_happen_before_transport_and_output(self):
        for failure in ('launcher', 'candidate_hash', 'candidate_size', 'source', 'serial', 'pid', 'syntax_limit'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(prefix='bridge-local-') as directory:
                root = Path(directory)
                launcher, source, candidate = self.files(root)
                serial, pid = 'HiBy RS2', PID
                if failure == 'launcher':
                    launcher.write_bytes(b'changed')
                if failure == 'candidate_hash':
                    candidate.write_bytes(b'X' * len(self.CANDIDATE))
                if failure == 'candidate_size':
                    candidate.write_bytes(self.CANDIDATE + b'X')
                if failure == 'serial':
                    serial = 'bad;serial'
                if failure == 'pid':
                    pid = True
                with self.patches(), mock.patch.object(preflight, 'LegacyAdb') as transport, \
                        mock.patch.object(preflight, 'verify', return_value={'checked': True}) as verifier, \
                        mock.patch.object(preflight, 'syntax_script', return_value=':') as syntax:
                    if failure == 'source':
                        verifier.side_effect = ValueError('invalid local source')
                    if failure == 'syntax_limit':
                        syntax.side_effect = ValueError('legacy limit')
                    with self.assertRaises(ValueError):
                        preflight.run_check('unused-adb', serial, pid, launcher, source, candidate, root / 'output')
                    transport.assert_not_called()
                self.assertFalse((root / 'output').exists())

    def test_existing_output_directory_is_not_reused(self):
        with tempfile.TemporaryDirectory(prefix='bridge-existing-') as directory:
            root = Path(directory)
            launcher, source, candidate = self.files(root)
            output = root / 'output'
            output.mkdir()
            marker = output / 'keep'
            marker.write_bytes(b'prior evidence')
            with self.patches(), mock.patch.object(preflight, 'LegacyAdb') as transport, \
                    mock.patch.object(preflight, 'verify', return_value={'checked': True}), \
                    mock.patch.object(preflight, 'identity_script', return_value=':'):
                with self.assertRaises(FileExistsError):
                    preflight.run_check('unused-adb', 'HiBy RS2', PID, launcher, source, candidate, output)
                transport.assert_not_called()
            self.assertEqual(marker.read_bytes(), b'prior evidence')

    def run_fixture(self, failure=None):
        calls, raws = [], {}
        backup = self.BACKUP
        controls = {'nonexecuting': (b'printf "MUST_NOT_EXECUTE\\n"; exit 37\n', 0),
                    'invalid': (b'if then\n', 2), 'launcher': (self.LAUNCHER, 0)}

        class FakeTransport:
            def __init__(self, executable, serial, nonce):
                self.real = LegacyAdb(executable, serial, nonce)

            def argv(self, script):
                return self.real.argv(script)

            def probe(self, script, output, timeout):
                label = output.stem
                calls.append(label)
                if label in ('before', 'after'):
                    changes = {'launcher_stat': file_stat(size=len(backup))}
                    if failure == 'after_changed' and label == 'after':
                        changes['stat_before'] = changes['stat_after'] = process_stat(start=350)
                    data = stock_evidence(**changes)
                    if failure == 'before_metadata' and label == 'before':
                        data = b'partial before'
                elif label == 'prerequisites':
                    data = b'partial prerequisites' if failure == 'metadata' else prereq_evidence()
                elif label == 'runtime':
                    data = (f'@@runtime_{NONCE}@@\nwait=37 failed_open=1 fd_control=0 outer=continued\n').encode()
                    if failure == 'runtime':
                        data = data.replace(b'wait=37', b'wait=0')
                elif label == 'identity_helpers':
                    data = envelope(dict(start='349', parent='1', **{'done_' + NONCE: '0'}))
                    if failure == 'identity_helpers':
                        data = data.replace(b'349', b'350')
                else:
                    payload, status = controls[label]
                    if failure == 'remote_status' and label == 'invalid':
                        status = 0
                    data = syntax_evidence(payload, status)
                raws[label] = data
                output.write_bytes(data)
                output.with_suffix('.stderr').write_bytes(b'mock stderr preserved')
                return dict(returncode=0, timed_out=failure == 'transport' and label == 'invalid',
                            bytes=len(data), overlong=False, stderr_overlong=False, reader_errors=[])

            def stream(self, script, output, size, timeout):
                calls.append('backup')
                if 'exec 8</ui_data/player' not in script or f'-N {len(backup)}' not in script:
                    raise AssertionError('backup must be a bounded read through an open FD')
                data = b'X' * len(backup) if failure == 'backup' else backup
                output.write_bytes(data)
                output.with_suffix('.hex').write_bytes(data.hex().encode())
                output.with_suffix('.stderr').write_bytes(b'mock backup stderr')
                result = dict(returncode=0, timed_out=False, bytes=len(data), overlong=False,
                              stderr_overlong=False, reader_errors=[], encoding_valid=True,
                              remote_returncode=0)
                if failure == 'backup_encoding':
                    result['encoding_valid'] = False
                if failure == 'backup_remote':
                    result['remote_returncode'] = 1
                if failure == 'backup_bytes':
                    result['bytes'] -= 1
                return result

        with tempfile.TemporaryDirectory(prefix='bridge-runner-') as directory:
            root = Path(directory)
            launcher, source, candidate = self.files(root)
            output = root / 'output'
            with self.patches(), mock.patch.object(preflight, 'LegacyAdb', FakeTransport), \
                    mock.patch.object(preflight.secrets, 'token_hex', return_value=NONCE), \
                    mock.patch.object(preflight, 'verify', return_value={'checked': True}) as verifier:
                report = preflight.run_check('unused-adb', 'HiBy RS2', PID, launcher, source, candidate, output)
                verifier.assert_called_once_with(self.SOURCE, self.CANDIDATE)
            self.assertEqual(calls[-1], 'after')
            self.assertFalse(report['launcher_executed'])
            self.assertFalse(report['device_files_written'])
            self.assertFalse(report['hardware_validated'])
            self.assertEqual(json.loads((output / 'report.json').read_text()), json.loads(json.dumps(report)))
            for label, data in raws.items():
                self.assertEqual((output / (label + '.txt')).read_bytes(), data)
                self.assertEqual((output / (label + '.stderr')).read_bytes(), b'mock stderr preserved')
            if 'backup' in calls:
                self.assertTrue((output / 'installed_launcher.bin').exists())
                self.assertTrue((output / 'installed_launcher.hex').exists())
            return report, calls

    def test_success_is_readonly_preflight_not_hardware_validation(self):
        report, calls = self.run_fixture()
        self.assertTrue(report['readonly_preflight_passed'])
        self.assertTrue(report['stock_state_preserved'])
        self.assertFalse(report['errors'])
        self.assertEqual(calls, ['before', 'prerequisites', 'backup', 'nonexecuting',
                                 'invalid', 'launcher', 'runtime', 'identity_helpers', 'after'])

    def test_failures_retain_raw_data_and_always_capture_after_state(self):
        for failure in ('metadata', 'transport', 'remote_status', 'backup', 'backup_encoding',
                        'backup_remote', 'backup_bytes', 'runtime', 'identity_helpers'):
            with self.subTest(failure=failure):
                report, calls = self.run_fixture(failure)
                self.assertFalse(report['readonly_preflight_passed'])
                self.assertTrue(report['stock_state_preserved'])
                self.assertTrue(report['errors'])
                if failure not in ('runtime', 'identity_helpers'):
                    self.assertNotIn('launcher', calls)
                    self.assertNotIn('runtime', calls)

    def test_failed_first_snapshot_still_attempts_after_but_cannot_claim_preserved(self):
        report, calls = self.run_fixture('before_metadata')
        self.assertEqual(calls, ['before', 'after'])
        self.assertIn('after', report)
        self.assertFalse(report['stock_state_preserved'])
        self.assertFalse(report['readonly_preflight_passed'])

    def test_changed_after_identity_refuses_success(self):
        report, _ = self.run_fixture('after_changed')
        self.assertFalse(report['stock_state_preserved'])
        self.assertFalse(report['readonly_preflight_passed'])
        self.assertIn('stock/source state changed or unconfirmed', report['errors'])


if __name__ == '__main__':
    unittest.main()
