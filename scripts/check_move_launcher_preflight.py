#!/usr/bin/env python3
"""Read-only stock RS2 launcher prerequisites and exact full-text sh -n check.

Never installs, sources or executes the launcher. All artifacts are host-only.
No device output files, flags, signals, sync, reboot or firmware execution.
"""
import argparse
import base64
import gzip
import hashlib
import json
import re
import secrets
from pathlib import Path

import capture_move_checkpoint as base
import check_legacy_adb_transport as compat
from capture_move_legacy_checkpoint import card_mount, file_identity, sections
from legacy_adb_transport import LegacyAdb

LAUNCHER = '1cdfed5423da735895993ae18755526cf0395b2c88ad82c138d29ba803f24f6e'
INSTALLED = '522f0b1bf6e064d52ae1965a7b2724ea4723a4c89f5d250ff1f50e52e38edf4b'
COMMANDS = ('sh', 'awk', 'df', 'date', 'cat', 'ps', 'dmesg', 'sha256sum',
            'readlink', 'od', 'ls', 'uudecode', 'gzip', 'rm', 'mkdir', 'sync',
            'killall', 'reboot', 'sleep')


def valid_nonce(nonce):
    if not isinstance(nonce, str) or not re.fullmatch('[0-9a-f]{32}', nonce):
        raise ValueError('invalid nonce')


def syntax_script(data, nonce):
    valid_nonce(nonce)
    if not data or not data.isascii() or b'\0' in data:
        raise ValueError('syntax payload must be nonempty ASCII without NUL')
    digest = hashlib.sha256(data).hexdigest()
    encoded = base64.b64encode(gzip.compress(data, mtime=0)).decode('ascii')
    # uudecode -o - forces stdout, ignoring the archive filename. The sentinel
    # preserves every terminal newline in command substitution. The exact hash
    # gate detects a failed/partial decoding pipeline before any syntax check.
    script = (
        f"S=$(printf 'begin-base64 600 -\\n{encoded}\\n====\\n' | uudecode -o - | gzip -dc; printf x); "
        'S=${S%x}; H=$(printf %s "$S" | sha256sum); H=${H%% *}; '
        'printf "\\n@@hash@@\\n%s\\n@@bytes@@\\n%s\\n@@diagnostics@@\\n" "$H" "${#S}"; '
        f'if [ "$H" = {digest} ] && [ "${{#S}}" = {len(data)} ]; then '
        'printf %s "$S" | sh -n; R=$?; else R=98; fi; '
        f'printf "\\n@@status_{nonce}@@\\n%s\\n" "$R"'
    )
    # Enforce the limit locally before a device or artifact is touched.
    LegacyAdb('unused', 'unused', nonce).argv(script)
    return script


def parse_syntax(data, nonce, expected_hash, expected_size, expected_rc):
    valid_nonce(nonce)
    s = sections(data)
    status = 'status_' + nonce
    if set(s) != {'hash', 'bytes', 'diagnostics', status}:
        raise ValueError('incomplete or unexpected syntax evidence')
    if s['hash'] != expected_hash or s['bytes'] != str(expected_size):
        raise ValueError('syntax payload bytes/hash mismatch')
    if s[status] != str(expected_rc):
        raise ValueError('unexpected remote syntax status')
    if expected_rc == 0 and s['diagnostics']:
        raise ValueError('successful syntax check produced unexpected output')
    return dict(sha256=s['hash'], bytes=expected_size, remote_status=expected_rc,
                diagnostics=s['diagnostics'])


def stock_snapshot(data, pid, nonce):
    valid_nonce(nonce)
    s = sections(data)
    expected = {'boot', 'stat', 'exe', 'flag', 'installed', 'closed_log',
                'log_identity', 'meminfo', 'status', 'done_' + nonce}
    if set(s) != expected or s['done_' + nonce] != '0':
        raise ValueError('stock evidence incomplete')
    if not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', s['boot']):
        raise ValueError('invalid boot identity')
    if s['exe'].split() != [compat.STOCK, f'/proc/{pid}/exe'] or s['flag'] != 'absent':
        raise ValueError('requires original stock and absent test flag')
    if s['installed'].split() != [INSTALLED, '/ui_data/player', base.EXPECTED, '/data/hiby_player_sortfix']:
        raise ValueError('installed launcher/candidate differ from preserved versions')
    if s['closed_log'].split() != [compat.REFERENCE, compat.CLOSED_LOG]:
        raise ValueError('old log differs from preserved recovery')
    inode, size = file_identity(s['log_identity'], compat.CLOSED_LOG)
    if not size or not re.search(r'^MemTotal:\s+\d+ kB$', s['meminfo'], re.M):
        raise ValueError('missing log/memory evidence')
    if not re.search(rf'^Pid:\s+{pid}$', s['status'], re.M):
        raise ValueError('missing player status')
    return dict(boot=s['boot'], pid=pid, start_ticks=base.process_identity(s['stat'], pid),
                exe=compat.STOCK, installed=INSTALLED, candidate=base.EXPECTED,
                flag=s['flag'], log_sha256=compat.REFERENCE, log_inode=inode, log_size=size)


def prereq_script(pid, nonce):
    valid_nonce(nonce)
    commands = {
        'commands': '; '.join(f'command -v {name} || RC=1' for name in COMMANDS),
        'mounts': 'cat /proc/self/mountinfo',
        'player_mounts': f'cat /proc/{pid}/mountinfo',
        'df': 'df -Pk /mnt/sd_0',
        'available': "df -Pk /mnt/sd_0 | awk 'NR == 2 { print $4 }'",
        'access': 'test -d /mnt/sd_0 && test -w /mnt/sd_0 && test -x /mnt/sd_0 '
                  '&& test -x /usr/bin/hiby_player.sh && test -x /data/hiby_player_sortfix '
                  '&& if test -f /usr/bin/batd; then test -x /usr/bin/batd; else :; fi '
                  '&& if test -e /mnt/sd_0/rs2_move_evidence; then '
                  'test -d /mnt/sd_0/rs2_move_evidence && test -w /mnt/sd_0/rs2_move_evidence; else :; fi '
                  '&& echo ok',
        'stock_wrapper': 'cat /usr/bin/hiby_player.sh',
        'installed_syntax': 'sh -n /usr/bin/hiby_player.sh && sh -n /ui_data/player && echo ok',
        'launcher_stat': 'LC_ALL=C ls -Lndi --color=never /ui_data/player',
        'stack': 'ulimit -s',
        'stamp': 'date +%Y%m%dT%H%M%S',
        'processes': 'ps',
        'kernel': 'dmesg',
        'child_proc': f'for I in statm maps limits; do test -r /proc/{pid}/$I || RC=1; done; echo checked',
    }
    parts = ['RC=0']
    for name, command in commands.items():
        parts += [f'printf "\\n@@{name}@@\\n"', f'{{ {command}; }} || RC=1']
    parts += [f'printf "\\n@@done_{nonce}@@\\n%s\\n" "$RC"']
    return '; '.join(parts)


def parse_prereqs(data, pid, nonce):
    valid_nonce(nonce)
    s = sections(data)
    expected = {'commands', 'mounts', 'player_mounts', 'df', 'available', 'access',
                'stock_wrapper', 'installed_syntax', 'launcher_stat', 'stack', 'stamp', 'processes',
                'kernel', 'child_proc', 'done_' + nonce}
    if set(s) != expected or s['done_' + nonce] != '0':
        raise ValueError('prerequisites incomplete or failed')
    paths = s['commands'].splitlines()
    if len(paths) != len(COMMANDS) or any(Path(p).name != n for p, n in zip(paths, COMMANDS)):
        raise ValueError('required command unavailable')
    log = '/mnt/sd_0/rs2_move_evidence/run_unknown_1_0/move.bin'
    mount = card_mount(s['mounts'], log)
    if card_mount(s['player_mounts'], log) != mount:
        raise ValueError('mount namespace disagreement')
    for table in ('mounts', 'player_mounts'):
        row = next(row for row in s[table].splitlines() if row.split()[0] == str(mount['mount_id']))
        super_options = row.partition(' - ')[2].split()[2].split(',')
        if 'rw' not in row.split()[5].split(',') or 'rw' not in super_options:
            raise ValueError('card mount is read-only')
    available = s['available']
    if not available.isdigit() or int(available) < 65536:
        raise ValueError('insufficient or unknown free card space')
    rows = s['df'].splitlines()
    fields = rows[1].split() if len(rows) == 2 else []
    if len(fields) != 6 or fields[0] != mount['source'] or fields[3] != available or fields[-1] != '/mnt/sd_0':
        raise ValueError('df evidence disagrees with mounted card')
    if s['access'] != 'ok' or s['installed_syntax'] != 'ok' or s['child_proc'] != 'checked':
        raise ValueError('executable/access/syntax prerequisites failed')
    if not s['stack'].isdigit() or not re.fullmatch(r'\d{8}T\d{6}', s['stamp']):
        raise ValueError('stack/date evidence unavailable')
    if not s['stock_wrapper'].startswith('#!') or not re.search(rf'^\s*{pid}\s', s['processes'], re.M):
        raise ValueError('stock wrapper/process evidence unavailable')
    inode, size = file_identity(s['launcher_stat'], '/ui_data/player')
    if not 0 < size <= 65536:
        raise ValueError('installed launcher size outside bounded backup budget')
    return dict(card_mount=mount, available_kib=int(available), stack_kib=int(s['stack']),
                command_paths=paths, launcher_inode=inode, launcher_size=size,
                permission_checks_only=True)


def runtime_script(nonce):
    valid_nonce(nonce)
    # Only a transient shell child exits. The failed read is within a subshell;
    # this never opens an output file or sends a signal to any process.
    return (
        "sh -c 'exit 37' & P=$!; if wait \"$P\"; then W=0; else W=$?; fi; "
        'isolate() ( exec 8</proc/self/rs2_missing_readonly_probe; exit 0 ); '
        'if isolate; then F=0; else F=$?; fi; '
        '(exec 9</proc/uptime; sh -c \'test -r /proc/$$/fd/9\' && '
        'sh -c \'test ! -e /proc/$$/fd/9\' 9>&-); D=$?; '
        f'printf "\\n@@runtime_{nonce}@@\\nwait=%s failed_open=%s fd_control=%s outer=continued\\n" "$W" "$F" "$D"'
    )


def run_check(adb, serial, pid, launcher, output):
    base.validate(serial, pid, '/mnt/sd_0/rs2_move_evidence/run_unknown_1_0', 65536, 30)
    source = Path(launcher).read_bytes()
    if hashlib.sha256(source).hexdigest() != LAUNCHER:
        raise ValueError('launcher differs from pinned reviewed draft')
    nonce = secrets.token_hex(16)
    full_script = syntax_script(source, nonce)
    transport = LegacyAdb(adb, serial, nonce)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    report = dict(readonly_preflight_passed=False, launcher_executed=False,
                  live_move_validated=False, errors=[], nonce=nonce)

    def probe(label, script):
        path = output / (label + '.txt')
        result = transport.probe(script, path, 30)
        report[label + '_transport'] = result
        if (result['returncode'] or result['timed_out'] or result['overlong']
                or result['stderr_overlong'] or result['reader_errors']):
            raise ValueError(label + ' transport failed')
        return path.read_bytes()

    before = None
    try:
        before = stock_snapshot(probe('before', compat.state_script(pid, nonce)), pid, nonce)
        report['before'] = before
        report['prerequisites'] = parse_prereqs(probe('prerequisites', prereq_script(pid, nonce)), pid, nonce)
        size = report['prerequisites']['launcher_size']
        backup_script = (
            f'printf "@@{nonce}:BEGIN@@\\n"; '
            'if exec 8</ui_data/player; then '
            f'od -An -v -tx1 -N {size} <&8; R=$?; else R=98; fi; '
            f'printf "\\n@@{nonce}:END:%s@@\\n" "$R"'
        )
        backup_path = output / 'installed_launcher.bin'
        result = transport.stream(backup_script, backup_path, size, 30)
        report['installed_launcher_transport'] = result
        backup = backup_path.read_bytes()
        report['installed_launcher_sha256'] = hashlib.sha256(backup).hexdigest()
        if (result['returncode'] or result['timed_out'] or result['overlong']
                or result['stderr_overlong'] or result['reader_errors']
                or not result.get('encoding_valid') or result.get('remote_returncode') != 0
                or result['bytes'] != size or len(backup) != size
                or report['installed_launcher_sha256'] != INSTALLED):
            raise ValueError('installed launcher backup failed validation')
        controls = [('nonexecuting', b'printf "MUST_NOT_EXECUTE\\n"; exit 37\n', 0),
                    ('invalid', b'if then\n', 2), ('launcher', source, 0)]
        for label, data, status in controls:
            script = full_script if label == 'launcher' else syntax_script(data, nonce)
            raw = probe(label, script)
            report[label] = parse_syntax(raw, nonce, hashlib.sha256(data).hexdigest(), len(data), status)
            report[label]['command_bytes'] = len(transport.argv(script)[-1].encode('utf-8'))
        raw = probe('runtime', runtime_script(nonce)).decode('ascii')
        pattern = rf'@@runtime_{nonce}@@\s+wait=37 failed_open=([1-9]\d*) fd_control=0 outer=continued\s*'
        match = re.search(pattern, raw)
        if not match or match.end() != len(raw):
            raise ValueError('shell runtime primitive controls failed')
        report['runtime'] = dict(wait_status=37, failed_open_status=int(match[1]), fd_control=0)
    except Exception as exc:
        report['errors'].append(str(exc))
    finally:
        try:
            after = stock_snapshot(probe('after', compat.state_script(pid, nonce)), pid, nonce)
            report['after'] = after
            report['stock_state_preserved'] = before is not None and after == before
            if not report['stock_state_preserved']:
                report['errors'].append('stock/source identity changed or unavailable')
        except Exception as exc:
            report['errors'].append('after: ' + str(exc))
    report['readonly_preflight_passed'] = not report['errors'] and report.get('stock_state_preserved', False)
    report['limits'] = [
        'Full source syntax and selected primitives only; launcher was not installed or executed.',
        'Access/mount/space observations do not prove future writes, launch or recovery behavior.',
        'No firmware, flag, device output file, signal, reboot or automatic retry.',
        'Output growth, memory headroom and prior MOVE reboot cause remain unproven.',
    ]
    (output / 'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', required=True)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--launcher', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = run_check(args.adb, args.serial, args.pid, args.launcher, args.output)
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report['readonly_preflight_passed'] else 1)


if __name__ == '__main__':
    main()
