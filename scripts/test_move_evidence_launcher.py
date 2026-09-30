"""Execute a locally isolated supervisor with mocked RS2 tools, never a device."""
import os
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'scripts/rs2_folderfollow_move_evidence_launcher.sh'
GIT_BASH = Path('C:/Program Files/Git/bin/bash.exe')
BASH = str(GIT_BASH) if GIT_BASH.exists() else shutil.which('bash')
EXPECTED = '15cf4457e829692a52482c0b64a8b478f426f014b7cb31099ed6325a496c3f07'


@unittest.skipUnless(BASH, 'POSIX-compatible shell not available')
class Tests(unittest.TestCase):
    def setUp(self):
        # Only disposable fixtures, not real artifacts or production paths.
        (ROOT / 'artifacts').mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='launcher-fixture-', dir=ROOT / 'artifacts')
        self.root = Path(self.temp.name)
        self.card = self.root / 'card'
        self.proc = self.root / 'proc'
        self.card.mkdir()
        self.proc.mkdir()
        self.flag = self.card / 'RS2_SORTFIX_TEST'
        self.flag.touch()
        (self.proc / 'mounts').write_text(f'card {self.card.as_posix()} vfat rw 0 0\n')
        (self.proc / 'uptime').write_text('12.3 8.0\n')
        (self.proc / 'meminfo').write_text('MemTotal: 131072 kB\nMemFree: 65536 kB\n')
        self.patch = self.root / 'mock_player.sh'
        self.patch.write_text('#!/bin/sh\nprintf stdout_message\nprintf stderr_message >&2\nprintf MOCK >&9\nexit "${MOCK_EXIT:-0}"\n')
        self.patch.chmod(0o755)
        self.stock = self.root / 'mock_stock.sh'
        self.stock.write_text('#!/bin/sh\nprintf "stock\\n" >> "$TEST_BASE/actions"\nexit 0\n')
        self.stock.chmod(0o755)
        self.batd = self.root / 'mock_batd.sh'  # Absent by default.

    def tearDown(self):
        self.temp.cleanup()

    def run_fixture(self, mode='', rc=0):
        source = SOURCE.read_text()
        changes = {
            'CARD=/mnt/sd_0': ('CARD', self.card),
            'FLAG=/mnt/sd_0/RS2_SORTFIX_TEST': ('FLAG', self.flag),
            'PATCH=/data/hiby_player_sortfix': ('PATCH', self.patch),
            'STOCK=/usr/bin/hiby_player.sh': ('STOCK', self.stock),
            'BATD=/usr/bin/batd': ('BATD', self.batd),
            'PROC=/proc': ('PROC', self.proc),
            'BASE=/mnt/sd_0/rs2_move_evidence': ('BASE', self.card / 'rs2_move_evidence'),
        }
        for old, (name, value) in changes.items():
            self.assertEqual(source.count(old + '\n'), 1)
            source = source.replace(old + '\n', name + '=' + shlex.quote(value.as_posix()) + '\n')
        # Functions mock operations that would affect device state. Real mkdir,
        # cat and awk operate only on the disposable fixture paths above.
        mocks = '''
action() { printf '%s\n' "$*" >> "$TEST_BASE/actions"; }
fd_check() { if (printf HELPER_LEAK >&9) 2>/dev/null; then action fd9_leak; fi; }
sync() {
    fd_check
    if [ -n "$RUN" ]; then printf '%s\n' "$RUN" > "$TEST_BASE/fixture_run_path"; fi
    if [ -n "$RUN" ] && [ -f "$RUN/child.exit" ] && [ ! -f "$RUN/after.state" ]; then action exit_flushed_before_after; fi
    action sync
}
killall() { fd_check; action "killall $*"; }
sleep() { action sleep; }
wait() { if [ "$MOCK_MODE" = wait_message ]; then printf mock_wait_diagnostic >&2; fi; command wait "$@"; }
date() { printf '20260930T120000\n'; }
    ps() { fd_check; printf 'mock processes\n'; }
dmesg() {
    fd_check
    if [ "$MOCK_MODE" = dmesg_fail ]; then printf unavailable >&2; return 1; fi
    printf 'mock kernel ring\n'
}
sha256sum() {
    fd_check
    if [ "$MOCK_MODE" = wrong_hash ]; then printf 'bad %s\n' "$1"; else printf '%s %s\n' "$MOCK_SHA" "$1"; fi
}
df() {
    printf 'Filesystem 1024-blocks Used Available Capacity Mounted\n'
    case "$MOCK_MODE" in
      low_space) printf 'card 10000 9000 1000 90%% mock\n' ;;
      bad_df) return 1 ;;
      *) printf 'card 1000000 1000 999000 1%% mock\n' ;;
    esac
}
rm() { if [ "$MOCK_MODE" = flag_fail ]; then return 1; fi; command rm "$@"; }
mkdir() {
    case "$*" in
      *run_*)
        if [ "$MOCK_MODE" = all_collisions ]; then return 1; fi
        if [ "$MOCK_MODE" = one_collision ] && [ ! -f "$TEST_BASE/collision" ]; then
            : > "$TEST_BASE/collision"
            command mkdir "$@" || return 1
            printf KEEP > "$1/old_evidence"
            return 1
        fi
        command mkdir "$@" || return 1
        if [ "$MOCK_MODE" = open_fail ]; then command mkdir "$1/player.stdout"; fi
        if [ "$MOCK_MODE" = exit_marker_fail ]; then command mkdir "$1/child.exit"; fi
        if [ "$MOCK_MODE" = marker_vanish ]; then command mkdir "$1/child.exit"; fi
        return 0 ;;
    esac
    command mkdir "$@"
}
reboot() {
    fd_check
    # In a normal path, wait evidence must exist before the reboot command.
    case "$MOCK_MODE" in exit_marker_fail|marker_vanish) : ;; *) if [ ! -f "$RUN/child.exit" ]; then action exit_missing; fi ;; esac
    if [ ! -f "$RUN/recovery.txt" ]; then action recovery_missing; fi
    action reboot
    [ "$MOCK_MODE" != reboot_fail ]
}
'''
        target = self.root / 'isolated_launcher.sh'
        target.write_text(mocks + source)
        env = dict(os.environ, TEST_BASE=self.root.as_posix(), MOCK_MODE=mode,
                   MOCK_EXIT=str(rc), MOCK_SHA=EXPECTED)
        result = subprocess.run([BASH, '--noprofile', '--norc', '--posix', str(target)],
                                env=env, capture_output=True, text=True, timeout=15)
        actions = (self.root / 'actions').read_text().splitlines() if (self.root / 'actions').exists() else []
        runs = list((self.card / 'rs2_move_evidence').glob('run_*')) if (self.card / 'rs2_move_evidence').exists() else []
        self.assertNotIn('fd9_leak', actions)
        return result, actions, runs

    def test_unarmed_stock_only(self):
        self.flag.unlink()
        result, actions, runs = self.run_fixture()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(actions, ['stock'])
        self.assertEqual(runs, [])

    def test_normal_exit_evidence_and_recovery(self):
        result, actions, runs = self.run_fixture()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.flag.exists())
        self.assertEqual(len(runs), 1)
        run = runs[0]
        self.assertEqual((run / 'move.bin').read_bytes(), b'MOCK')
        self.assertEqual((run / 'player.stdout').read_text(), 'stdout_message')
        self.assertEqual((run / 'player.stderr').read_text(), 'stderr_message')
        self.assertIn('raw_wait_status=0', (run / 'child.exit').read_text())
        self.assertIn('MemFree: 65536', (run / 'before.state').read_text())
        self.assertIn('unavailable_or_exited', (run / 'after.state').read_text())
        self.assertIn('supervisor_completed=1', (run / 'recovery.txt').read_text())
        self.assertEqual(actions[-3:], ['sync', 'sleep', 'reboot'])
        self.assertIn('exit_flushed_before_after', actions)
        self.assertNotIn('stock', actions)
        self.assertNotIn('exit_missing', actions)
        self.assertNotIn('recovery_missing', actions)

    def test_nonzero_raw_status(self):
        result, actions, runs = self.run_fixture(rc=137)
        self.assertEqual(result.returncode, 0)
        self.assertIn('raw_wait_status=137', (runs[0] / 'child.exit').read_text())
        self.assertNotIn('OOM', (runs[0] / 'child.exit').read_text())
        self.assertIn('reboot', actions)

    def test_missing_candidate_consumes_flag_and_falls_back(self):
        self.patch.unlink()
        _, actions, runs = self.run_fixture()
        self.assertFalse(self.flag.exists())
        self.assertEqual(actions, ['sync', 'stock'])
        self.assertFalse(runs)

    def test_wrong_candidate_hash_no_shutdown(self):
        _, actions, runs = self.run_fixture('wrong_hash')
        self.assertIn('stock', actions)
        self.assertFalse(any(x.startswith('killall') for x in actions))
        self.assertNotIn('reboot', actions)
        self.assertIn('candidate_hash', (runs[0] / 'supervisor.txt').read_text())

    def test_space_and_mount_preflight_fail_closed(self):
        (self.proc / 'mounts').write_text('')
        _, actions, runs = self.run_fixture()
        self.assertEqual(actions, ['sync', 'stock'])
        self.assertFalse(runs)

    def test_low_space_fallback(self):
        _, actions, runs = self.run_fixture('low_space')
        self.assertEqual(actions, ['sync', 'stock'])
        self.assertFalse(runs)

    def test_flag_removal_failure_does_not_launch(self):
        _, actions, runs = self.run_fixture('flag_fail')
        self.assertTrue(self.flag.exists())
        self.assertEqual(actions, ['stock'])
        self.assertFalse(runs)

    def test_open_failure_outer_stock_fallback(self):
        result, actions, runs = self.run_fixture('open_fail')
        self.assertEqual(result.returncode, 0)
        self.assertIn('stock', actions)
        self.assertFalse(any(x.startswith('killall') for x in actions))
        self.assertNotIn('reboot', actions)
        self.assertIn('child_not_launched=1', (runs[0] / 'preparation.failed').read_text())
        self.assertFalse((runs[0] / 'recovery.txt').exists())

    def test_collision_preserves_existing_directory(self):
        _, actions, runs = self.run_fixture('one_collision')
        self.assertEqual(len(runs), 2)
        old = next(r for r in runs if (r / 'old_evidence').exists())
        self.assertEqual((old / 'old_evidence').read_text(), 'KEEP')
        self.assertFalse((old / 'move.bin').exists())
        self.assertIn('reboot', actions)

    def test_exhausted_collisions_fallback(self):
        _, actions, runs = self.run_fixture('all_collisions')
        self.assertEqual(actions, ['sync', 'stock'])
        self.assertFalse(runs)

    def test_optional_dmesg_failure_keeps_exit_status(self):
        result, _, runs = self.run_fixture('dmesg_fail', 7)
        self.assertEqual(result.returncode, 0)
        self.assertIn('raw_wait_status=7', (runs[0] / 'child.exit').read_text())
        self.assertIn('unavailable', (runs[0] / 'after.dmesg.errors').read_text())

    def test_marker_failure_after_launch_reboots_not_stock(self):
        _, actions, runs = self.run_fixture('exit_marker_fail')
        self.assertIn('reboot', actions)
        self.assertNotIn('stock', actions)
        self.assertIn('raw_supervisor_status=73', (runs[0] / 'recovery.txt').read_text())

    def test_failed_reboot_does_not_start_duplicate_player(self):
        result, actions, runs = self.run_fixture('reboot_fail')
        self.assertEqual(result.returncode, 74)
        self.assertNotIn('stock', actions)
        self.assertIn('reboot_command_failed=1', (runs[0] / 'recovery.txt').read_text())

    def test_df_failure_fallback(self):
        _, actions, runs = self.run_fixture('bad_df')
        self.assertEqual(actions, ['sync', 'stock'])
        self.assertFalse(runs)

    def test_raw_126_and_127(self):
        for rc in (126, 127):
            with self.subTest(rc=rc):
                self.flag.touch()
                result, actions, runs = self.run_fixture(rc=rc)
                self.assertEqual(result.returncode, 0)
                completed = [r for r in runs if (r / 'child.exit').exists()]
                self.assertTrue(any(f'raw_wait_status={rc}\n' in (r / 'child.exit').read_text() for r in completed))
                self.assertIn('reboot', actions)

    def test_child_signal_shell_diagnostic_is_retained(self):
        self.patch.write_text('#!/bin/sh\nprintf started >&9\nprintf before_signal >&2\nkill -TERM "$$"\n')
        self.patch.chmod(0o755)
        result, actions, runs = self.run_fixture()
        self.assertEqual(result.returncode, 0)
        self.assertIn('raw_wait_status=143', (runs[0] / 'child.exit').read_text())
        # A shell is not obliged to print a message for every signal, and a
        # very fast exit can be noticed before wait. Raw status is mandatory.
        self.assertTrue((runs[0] / 'wait.errors').exists())
        self.assertEqual((runs[0] / 'player.stderr').read_text(), 'before_signal')
        self.assertIn('reboot', actions)

    def test_wait_stderr_redirection_without_status_loss(self):
        _, _, runs = self.run_fixture('wait_message', 7)
        self.assertEqual((runs[0] / 'wait.errors').read_text(), 'mock_wait_diagnostic')
        self.assertIn('raw_wait_status=7', (runs[0] / 'child.exit').read_text())

    def test_child_has_no_auxiliary_evidence_descriptors(self):
        self.patch.write_text('''#!/bin/sh
for fd in 5 6 7 8; do
    if (eval "printf LEAK >&$fd") 2>/dev/null; then printf AUX_LEAK >&2; fi
done
printf MOCK >&9
exit 0
''')
        self.patch.chmod(0o755)
        _, _, runs = self.run_fixture()
        self.assertEqual((runs[0] / 'player.stderr').read_text(), '')
        self.assertEqual((runs[0] / 'move.bin').read_bytes(), b'MOCK')

    def test_missing_disk_marker_cannot_authorize_stock_after_launch(self):
        # Remove only a disposable fixture marker after mock launch, then force
        # an exit-marker failure. Recovery must not infer no child from SD.
        self.patch.write_text('''#!/bin/sh
IFS= read -r FIXTURE_RUN < "$TEST_BASE/fixture_run_path"
case "$FIXTURE_RUN" in
  "$TEST_BASE"/card/rs2_move_evidence/run_*) command rm -f "$FIXTURE_RUN/launch.requested" ;;
  *) exit 90 ;;
esac
printf MOCK >&9
exit 0
''')
        self.patch.chmod(0o755)
        _, actions, runs = self.run_fixture('marker_vanish')
        self.assertFalse((runs[0] / 'launch.requested').exists())
        self.assertNotIn('stock', actions)
        self.assertIn('reboot', actions)

    def test_batd_does_not_inherit_fd9(self):
        self.batd.write_text('''#!/bin/sh
if (printf BATD_LEAK >&9) 2>/dev/null; then printf batd_fd9_leak >> "$TEST_BASE/actions"; fi
exit 0
''')
        self.batd.chmod(0o755)
        _, actions, runs = self.run_fixture()
        self.assertNotIn('batd_fd9_leak', actions)
        self.assertEqual((runs[0] / 'move.bin').read_bytes(), b'MOCK')


if __name__ == '__main__':
    unittest.main()
