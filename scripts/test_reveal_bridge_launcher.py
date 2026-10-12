"""Isolated bridge launcher fixtures. No ADB, real player or device signals."""
import hashlib
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import time
import unittest

from check_move_launcher_preflight import syntax_script
from legacy_adb_transport import LegacyAdb

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'scripts/rs2_reveal_bridge_launcher.sh'
GIT_BASH = Path('C:/Program Files/Git/bin/bash.exe')
BASH = str(GIT_BASH) if GIT_BASH.exists() else shutil.which('bash')
EXPECTED = '7cc98a67a32dabce3b4d22b50b8dc847f5462d99d70d0ee04254a0ec272439a9'


@unittest.skipUnless(BASH, 'POSIX shell unavailable')
class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='bridge-launcher-', dir=ROOT / 'artifacts')
        self.root = Path(self.temp.name)
        self.card = self.root / 'card'
        self.proc = self.root / 'proc'
        self.card.mkdir()
        self.proc.mkdir()
        (self.proc / 'sys/kernel/random').mkdir(parents=True)
        (self.proc / 'sys/kernel/random/boot_id').write_text('mock-boot\n')
        (self.proc / 'mounts').write_text(f'card {self.card.as_posix()} vfat rw 0 0\n')
        (self.proc / 'uptime').write_text('1.0 1.0\n')
        (self.proc / 'meminfo').write_text('MemTotal: 58308 kB\nMemFree: 1000 kB\n')
        self.flag = self.card / 'RS2_REVEAL_BRIDGE_ONCE'
        self.flag.touch()
        self.patch = self.root / 'mock_player.sh'
        self.patch.write_text('''#!/bin/sh
printf MOCK >&9
printf stdout_message
printf stderr_message >&2
for fd in 5 6 7 8; do
    if (eval "printf LEAK >&$fd") 2>/dev/null; then printf AUX_LEAK >&2; fi
done
case "$MOCK_MODE" in
 timeout|ignore_term|child_identity_lost|parent_identity_lost|child_start_missing)
   sleep 0.3 ;;
esac
: > "$TEST_BASE/child_gone"
exit "${MOCK_EXIT:-0}"
''')
        self.patch.chmod(0o755)
        self.stock = self.root / 'mock_stock.sh'
        self.stock.write_text('#!/bin/sh\nprintf "stock\\n" >> "$TEST_BASE/actions"\n')
        self.stock.chmod(0o755)

    def tearDown(self):
        self.temp.cleanup()

    def run_fixture(self, mode='', rc=0):
        source = SOURCE.read_text()
        changes = {
            'CARD=/mnt/sd_0': ('CARD', self.card),
            'FLAG=/mnt/sd_0/RS2_REVEAL_BRIDGE_ONCE': ('FLAG', self.flag),
            'PATCH=/data/hiby_player_reveal_bridge_7cc98a67': ('PATCH', self.patch),
            'STOCK=/usr/bin/hiby_player.sh': ('STOCK', self.stock),
            'PROC=/proc': ('PROC', self.proc),
            'BASE=/mnt/sd_0/rs2_reveal_bridge_evidence': ('BASE', self.card / 'evidence'),
        }
        for old, (name, value) in changes.items():
            self.assertEqual(source.count(old + '\n'), 1)
            source = source.replace(old + '\n', name + '=' + shlex.quote(value.as_posix()) + '\n')
        mocks = r'''
action() { printf '%s\n' "$*" >> "$TEST_BASE/actions"; }
field() { if [ "$MOCK_MODE" = manual ]; then printf '99\n'; else printf '1\n'; fi; }
start() {
    if [ "$1" = "$$" ]; then printf '100\n';
    elif [ "$MOCK_MODE" = child_start_missing ]; then return 1;
    else printf '200\n'; fi
}
digest() {
    if [ "$1" = "$PATCH" ]; then
        if [ "$MOCK_MODE" = wrong_hash ]; then printf 'bad\n'; else printf '%s\n' "$EXPECTED"; fi
    else printf 'shell-hash\n'; fi
}
same() {
    if [ "$1" = "$PARENT" ]; then
        [ "$MOCK_MODE" != parent_identity_lost ] && [ ! -f "$TEST_BASE/parent_gone" ]
    else
        [ "$MOCK_MODE" != child_identity_lost ] && [ "$2" = 200 ] && [ ! -f "$TEST_BASE/child_gone" ]
    fi
}
pidof() { if [ "$MOCK_MODE" = pidof_error ]; then return 2; fi; [ "$MOCK_MODE" = existing_player ]; }
wc() { if [ "$MOCK_MODE" = wrong_size ]; then printf '1\n'; else printf '7146848\n'; fi; }
date() { printf '20261008T120000\n'; }
df() {
    printf 'Filesystem 1024-blocks Used Available Capacity Mounted\n'
    if [ "$MOCK_MODE" = low_space ]; then printf 'card 10000 9000 1000 90%% mock\n';
    else printf 'card 1000000 1000 999000 1%% mock\n'; fi
}
sync() { action sync; }
sleep() { command sleep 0.025; }
kill() {
    if (printf WD_LEAK >&9) 2>/dev/null; then action fd9_leak; fi
    action "signal $*"
    if [ "$1" = -TERM ] && [ "$MOCK_MODE" != ignore_term ]; then : > "$TEST_BASE/child_gone"; fi
}
reboot() {
    if (printf WD_LEAK >&9) 2>/dev/null; then action fd9_leak; fi
    action reboot
    : > "$TEST_BASE/parent_gone"
    [ "$MOCK_MODE" != reboot_fail ]
}
rm() { if [ "$MOCK_MODE" = flag_fail ]; then return 1; fi; command rm "$@"; }
mkdir() {
    case "$*" in *run_*)
      if [ "$MOCK_MODE" = all_collisions ]; then return 1; fi
      command mkdir "$@" || return 1
      if [ "$MOCK_MODE" = open_fail ]; then command mkdir "$1/player.stdout"; fi
      if [ "$MOCK_MODE" = marker_fail ]; then command mkdir "$1/child.exit"; fi
      return 0 ;;
    esac
    command mkdir "$@"
}
'''
        source = source.replace('# ARM GATE:', mocks + '\n# ARM GATE:', 1)
        target = self.root / 'isolated_launcher.sh'
        target.write_text(source)
        env = dict(os.environ, TEST_BASE=self.root.as_posix(), MOCK_MODE=mode, MOCK_EXIT=str(rc))
        result = subprocess.run([BASH, '--noprofile', '--norc', '--posix', str(target)],
                                env=env, capture_output=True, text=True, timeout=10)
        # A fixture watchdog has closed all pipes; let its bounded mocked
        # sleeps finish before removing its disposable directory.
        time.sleep(0.2)
        actions = (self.root / 'actions').read_text().splitlines() if (self.root / 'actions').exists() else []
        runs = list((self.card / 'evidence').glob('run_*'))
        self.assertNotIn('fd9_leak', actions)
        return result, actions, runs

    def test_source_syntax_and_legacy_command_budget(self):
        source = SOURCE.read_bytes()
        script = syntax_script(source, 'a' * 32)
        self.assertLessEqual(len(LegacyAdb('adb', 'serial', 'a' * 32).argv(script)[-1].encode()), 4000)
        checked = subprocess.run([BASH, '--posix', '-n'], input=source, capture_output=True)
        self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_unarmed_boot_stock_only(self):
        self.flag.unlink()
        result, actions, runs = self.run_fixture()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(actions, ['stock'])
        self.assertFalse(runs)

    def test_manual_invocation_refuses_without_stock_or_flag_change(self):
        result, actions, runs = self.run_fixture('manual')
        self.assertEqual(result.returncode, 75)
        self.assertEqual(actions, [])
        self.assertTrue(self.flag.exists())
        self.assertFalse(runs)

    def test_existing_player_refuses_without_signal_or_stock(self):
        result, actions, _ = self.run_fixture('existing_player')
        self.assertEqual(result.returncode, 75)
        self.assertEqual(actions, [])
        self.assertTrue(self.flag.exists())

    def test_pidof_error_refuses_without_consuming_flag(self):
        result, actions, _ = self.run_fixture('pidof_error')
        self.assertEqual(result.returncode, 75)
        self.assertEqual(actions, [])
        self.assertTrue(self.flag.exists())

    def test_old_arm_refuses_without_consuming_old_flag(self):
        old = self.card / 'RS2_SORTFIX_TEST'
        old.touch()
        _, actions, runs = self.run_fixture()
        self.assertTrue(old.exists())
        self.assertFalse(self.flag.exists())
        self.assertEqual(actions, ['sync', 'stock'])
        self.assertFalse(runs)

    def test_normal_exit_preserves_fd_and_status_no_delayed_signal(self):
        result, actions, runs = self.run_fixture()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.flag.exists())
        run = runs[0]
        self.assertEqual((run / 'bridge.bin').read_bytes(), b'MOCK')
        self.assertEqual((run / 'player.stdout').read_text(), 'stdout_message')
        self.assertEqual((run / 'player.stderr').read_text(), 'stderr_message')
        self.assertIn('raw_wait_status=0', (run / 'child.exit').read_text())
        self.assertEqual(actions.count('reboot'), 1)
        self.assertFalse(any(x.startswith('signal ') for x in actions))
        self.assertNotIn('stock', actions)

    def test_wrong_hash_and_size_never_start_candidate(self):
        for mode in ('wrong_hash', 'wrong_size'):
            with self.subTest(mode=mode):
                self.flag.touch()
                _, actions, runs = self.run_fixture(mode)
                self.assertIn('stock', actions)
                self.assertNotIn('reboot', actions)
                self.assertTrue(any((r / 'preparation.failed').exists() for r in runs))
                self.assertFalse(any((r / 'child.exit').exists() for r in runs))

    def test_flag_failure_keeps_flag_and_no_reboot(self):
        _, actions, _ = self.run_fixture('flag_fail')
        self.assertEqual(actions, ['stock'])
        self.assertTrue(self.flag.exists())

    def test_unmounted_card_refuses(self):
        (self.proc / 'mounts').write_text('')
        _, actions, runs = self.run_fixture()
        self.assertEqual(actions, ['sync', 'stock'])
        self.assertFalse(runs)

    def test_readonly_card_refuses(self):
        (self.proc / 'mounts').write_text(f'card {self.card.as_posix()} vfat ro 0 0\n')
        _, actions, runs = self.run_fixture()
        self.assertEqual(actions, ['sync', 'stock'])
        self.assertFalse(runs)

    def test_low_space_and_collision_failures_never_launch(self):
        for mode in ('low_space', 'all_collisions'):
            with self.subTest(mode=mode):
                self.flag.touch()
                _, actions, _ = self.run_fixture(mode)
                self.assertNotIn('reboot', actions)
                self.assertIn('stock', actions)

    def test_open_failure_before_launch_allows_stock(self):
        _, actions, runs = self.run_fixture('open_fail')
        self.assertIn('stock', actions)
        self.assertNotIn('reboot', actions)
        self.assertIn('child_not_launched=1', (runs[0] / 'preparation.failed').read_text())

    def test_marker_failure_after_launch_never_starts_stock(self):
        _, actions, runs = self.run_fixture('marker_fail')
        self.assertIn('reboot', actions)
        self.assertNotIn('stock', actions)
        self.assertIn('supervisor_status=73', (runs[0] / 'recovery.txt').read_text())

    def test_raw_exit_status_not_signal_inference(self):
        _, actions, runs = self.run_fixture(rc=137)
        self.assertIn('raw_wait_status=137', (runs[0] / 'child.exit').read_text())
        self.assertNotIn('stock', actions)

    def test_deadline_term_and_recovery(self):
        _, actions, runs = self.run_fixture('timeout')
        self.assertTrue(any(x.startswith('signal -TERM ') for x in actions))
        self.assertFalse(any(x.startswith('signal -KILL ') for x in actions))
        self.assertGreaterEqual(actions.count('reboot'), 1)
        self.assertNotIn('stock', actions)

    def test_ignored_term_escalates_only_captured_child(self):
        _, actions, runs = self.run_fixture('ignore_term')
        terms = [x.split()[-1] for x in actions if x.startswith('signal -TERM ')]
        kills = [x.split()[-1] for x in actions if x.startswith('signal -KILL ')]
        self.assertEqual(len(terms), 1)
        self.assertEqual(kills, terms)

    def test_lost_child_identity_skips_signals_but_recovers(self):
        _, actions, runs = self.run_fixture('child_identity_lost')
        self.assertFalse(any(x.startswith('signal ') for x in actions))
        self.assertGreaterEqual(actions.count('reboot'), 1)

    def test_missing_child_start_never_authorizes_signal(self):
        _, actions, runs = self.run_fixture('child_start_missing')
        self.assertFalse(any(x.startswith('signal ') for x in actions))
        self.assertGreaterEqual(actions.count('reboot'), 1)
        self.assertIn('child_start=unavailable', (runs[0] / 'supervisor.txt').read_text())

    def test_lost_parent_identity_revokes_watchdog(self):
        _, actions, runs = self.run_fixture('parent_identity_lost')
        self.assertFalse(any(x.startswith('signal ') for x in actions))
        self.assertFalse((runs[0] / 'watchdog.txt').exists())
        self.assertEqual(actions.count('reboot'), 1)

    def test_reboot_failure_never_restarts_stock_or_rearms(self):
        result, actions, runs = self.run_fixture('reboot_fail')
        self.assertEqual(result.returncode, 74)
        self.assertEqual(actions.count('reboot'), 1)
        self.assertNotIn('stock', actions)
        self.assertFalse(self.flag.exists())
        self.assertIn('reboot_command_failed=1', (runs[0] / 'recovery.txt').read_text())

    def test_real_identity_helpers_reject_mismatch_and_parse_comm(self):
        prefix = SOURCE.read_text().split('# ARM GATE:')[0]
        prefix = prefix.replace('PROC=/proc\n', 'PROC=' + shlex.quote(self.proc.as_posix()) + '\n')
        proc = self.proc / '123'
        proc.mkdir()
        # comm may contain spaces and a closing parenthesis.
        fields = ['S', '1'] + ['0'] * 17 + ['456']
        (proc / 'stat').write_text('123 (odd ) comm) ' + ' '.join(fields) + '\n')
        (proc / 'exe').write_bytes(b'mock image')
        digest = hashlib.sha256(b'mock image').hexdigest()
        command = prefix + f'\nstart 123; FIELD=parent field 123; same 123 456 {digest}; echo good=$?; same 123 457 {digest}; echo wrong_start=$?; same 123 456 bad; echo wrong_hash=$?\n'
        result = subprocess.run([BASH, '--posix', '-c', command], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.stdout.splitlines(), ['456', '1', 'good=0', 'wrong_start=1', 'wrong_hash=1'])

    def test_identity_guard_rechecks_start_after_hash(self):
        prefix = SOURCE.read_text().split('# ARM GATE:')[0]
        counter = shlex.quote((self.root / 'identity_counter').as_posix())
        command = prefix + f'''
start() {{ if [ -f {counter} ]; then printf '457\\n'; else : > {counter}; printf '456\\n'; fi; }}
digest() {{ printf expected; }}
same 123 456 expected
printf 'result=%s\\n' "$?"
'''
        result = subprocess.run([BASH, '--posix', '-c', command], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.stdout, 'result=1\n')

    def test_watchdog_has_no_card_io_or_stock_fallback(self):
        source = SOURCE.read_text()
        watchdog = source.split('watchdog() (', 1)[1].split('\nsupervise()', 1)[0]
        self.assertNotIn('$RUN/', watchdog)
        self.assertNotIn('sync', '\n'.join(line for line in watchdog.splitlines() if not line.strip().startswith('#')))
        self.assertNotIn('fallback', watchdog)
        self.assertNotIn('killall', source)


if __name__ == '__main__':
    unittest.main()
