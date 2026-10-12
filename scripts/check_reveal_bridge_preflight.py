#!/usr/bin/env python3
"""Read-only preparation for the bridge: no install, arm, signal or launch.

Verify the local ELF first; preserve fresh stock identity and an exact backup
of the currently installed launcher. Check the new launcher's complete source
with sh -n only. Evidence is written exclusively into a new host directory.
"""

import argparse
import hashlib
import json
import re
import secrets
from pathlib import Path

import capture_move_checkpoint as base
from capture_move_legacy_checkpoint import card_mount, file_identity, sections
from check_move_launcher_preflight import parse_syntax, runtime_script, syntax_script, valid_nonce
from legacy_adb_transport import LegacyAdb
from verify_reveal_bridge_diag import verify


CANDIDATE = '7cc98a67a32dabce3b4d22b50b8dc847f5462d99d70d0ee04254a0ec272439a9'
CANDIDATE_SIZE = 7146848
LAUNCHER = '850691851dbf5cabbd244bae222e958e70885386e35ac6d425bd35f35342e32b'
INSTALLED = '1cdfed5423da735895993ae18755526cf0395b2c88ad82c138d29ba803f24f6e'
OLD_CANDIDATE = '15cf4457e829692a52482c0b64a8b478f426f014b7cb31099ed6325a496c3f07'
STOCK = '0fedb30f91937eafb5baaf3c75422cdbde04a62fe8bac8eca3c7a88bb761da0e'
STOCK_WRAPPER = 'fa5a7a3f10f858a6c4909e4424d0b3cec356986edaccab7d1e2ef5b7eb76cbc8'
PATCH = '/data/hiby_player_reveal_bridge_7cc98a67'
FLAG = '/mnt/sd_0/RS2_REVEAL_BRIDGE_ONCE'
LOG_BASE = '/mnt/sd_0/rs2_reveal_bridge_evidence'
COMMANDS = ('sh', 'awk', 'df', 'date', 'cat', 'ps', 'sha256sum', 'readlink',
            'od', 'ls', 'uudecode', 'gzip', 'rm', 'mkdir', 'sync', 'reboot',
            'sleep', 'wc', 'kill', 'test', 'pidof')


def validate(pid, nonce):
    valid_nonce(nonce)
    if type(pid) is not int or not 1 <= pid <= 4194304:
        raise ValueError('invalid player PID')


def script_sections(commands, nonce):
    valid_nonce(nonce)
    parts = ['RC=0']
    for name, command in commands.items():
        parts += [f'printf "\\n@@{name}@@\\n"', f'{{ {command}; }} || RC=1']
    parts += [f'printf "\\n@@done_{nonce}@@\\n%s\\n" "$RC"']
    script = '; '.join(parts)
    LegacyAdb('unused', 'unused', nonce).argv(script)
    return script


def state_script(pid, nonce):
    validate(pid, nonce)
    absent = lambda path: f'if test -e {path} || test -L {path}; then echo present; else echo absent; fi'
    return script_sections({
        'boot': 'cat /proc/sys/kernel/random/boot_id',
        'stat_before': f'cat /proc/{pid}/stat',
        'exe': f'sha256sum /proc/{pid}/exe',
        'players': 'pidof hiby_player',
        'old_flag': absent('/mnt/sd_0/RS2_SORTFIX_TEST'),
        'flag': absent(FLAG), 'target': absent(PATCH),
        'installed': 'sha256sum /ui_data/player /data/hiby_player_sortfix /usr/bin/hiby_player /usr/bin/hiby_player.sh',
        'launcher_stat': 'LC_ALL=C ls -Lndi --color=never /ui_data/player',
        'meminfo': 'cat /proc/meminfo', 'status': f'cat /proc/{pid}/status',
        'stat_after': f'cat /proc/{pid}/stat',
    }, nonce)


def checked_sections(data, names, nonce):
    valid_nonce(nonce)
    parsed = sections(data)
    done = 'done_' + nonce
    if set(parsed) != set(names) | {done} or parsed[done] != '0':
        raise ValueError('incomplete, unexpected or failed evidence')
    return parsed


def stock_snapshot(data, pid, nonce):
    validate(pid, nonce)
    s = checked_sections(data, ('boot', 'stat_before', 'exe', 'players', 'old_flag',
                                'flag', 'target', 'installed', 'launcher_stat',
                                'meminfo', 'status', 'stat_after'), nonce)
    if not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', s['boot']):
        raise ValueError('invalid boot identity')
    start = base.process_identity(s['stat_before'], pid)
    if base.process_identity(s['stat_after'], pid) != start:
        raise ValueError('stock process changed within snapshot')
    parents = [s[key].rsplit(') ', 1)[1].split()[1] for key in ('stat_before', 'stat_after')]
    if not all(value.isdigit() for value in parents) or parents[0] != parents[1]:
        raise ValueError('stock parent identity changed within snapshot')
    if s['exe'].split() != [STOCK, f'/proc/{pid}/exe'] or s['players'] != str(pid):
        raise ValueError('requires exactly the selected original stock player')
    if any(s[key] != 'absent' for key in ('old_flag', 'flag', 'target')):
        raise ValueError('requires both flags and the new candidate target absent')
    hashes = [INSTALLED, '/ui_data/player', OLD_CANDIDATE, '/data/hiby_player_sortfix',
              STOCK, '/usr/bin/hiby_player', STOCK_WRAPPER, '/usr/bin/hiby_player.sh']
    if s['installed'].split() != hashes:
        raise ValueError('installed launcher, old candidate or stock files changed')
    inode, size = file_identity(s['launcher_stat'], '/ui_data/player')
    if not 0 < size <= 65536:
        raise ValueError('installed launcher outside backup budget')
    if (not re.search(r'^MemTotal:\s+[1-9]\d* kB$', s['meminfo'], re.M)
            or not re.search(rf'^Pid:\s+{pid}$', s['status'], re.M)):
        raise ValueError('missing memory/process evidence')
    return dict(boot=s['boot'], pid=pid, start_ticks=start, parent_pid=int(parents[0]), exe=STOCK,
                installed=INSTALLED, old_candidate=OLD_CANDIDATE,
                stock_wrapper=STOCK_WRAPPER, old_flag='absent', flag='absent',
                target='absent', launcher_inode=inode, launcher_size=size)


def prereq_script(pid, nonce):
    validate(pid, nonce)
    return script_sections({
        'commands': '; '.join(f'command -v {name} || RC=1' for name in COMMANDS),
        'mounts': 'cat /proc/self/mountinfo', 'player_mounts': f'cat /proc/{pid}/mountinfo',
        'card_df': 'df -Pk /mnt/sd_0', 'data_df': 'df -Pk /data',
        'access': 'test -d /mnt/sd_0 && test -w /mnt/sd_0 && test -x /mnt/sd_0 '
                  '&& test -d /data && test -w /data && test -x /data '
                  '&& test -w /ui_data && test -x /usr/bin/hiby_player.sh '
                  '&& if test -e ' + LOG_BASE + '; then '
                  'test -d ' + LOG_BASE + ' && test -w ' + LOG_BASE + '; else :; fi && echo ok',
        'syntax': 'sh -n /usr/bin/hiby_player.sh && sh -n /ui_data/player && echo ok',
        'stock_wrapper': 'cat /usr/bin/hiby_player.sh',
        'stack': 'ulimit -s', 'stamp': 'date +%Y%m%dT%H%M%S',
        'same_exe': f'test /proc/{pid}/exe -ef /usr/bin/hiby_player && echo same',
        'processes': 'ps', 'uptime': 'cat /proc/uptime',
    }, nonce)


def _rw_mount(text, mount_id):
    matches = [line for line in text.splitlines() if line.split()[0] == str(mount_id)]
    if len(matches) != 1:
        raise ValueError('ambiguous mount ID')
    left, _, right = matches[0].partition(' - ')
    if 'rw' not in left.split()[5].split(',') or 'rw' not in right.split()[2].split(','):
        raise ValueError('read-only mount')


def _data_mount(text):
    rows = []
    for line in text.splitlines():
        left, _, right = line.partition(' - ')
        fields, tail = left.split(), right.split()
        if len(fields) >= 6 and fields[4] == '/data':
            if fields[3] != '/' or len(tail) != 3 or tail[0] != 'ubifs' or not fields[0].isdigit():
                raise ValueError('unexpected data mount')
            _rw_mount(text, int(fields[0]))
            rows.append((int(fields[0]), fields[2], tail[1]))
    if len(rows) != 1:
        raise ValueError('missing/ambiguous data mount')
    return rows[0]


def _available(raw, source, path, minimum):
    lines = raw.splitlines()
    fields = lines[1].split() if len(lines) == 2 else []
    if (len(fields) != 6 or fields[0] != source or fields[-1] != path
            or not fields[3].isdigit() or int(fields[3]) < minimum):
        raise ValueError('missing, inconsistent or insufficient free space: ' + path)
    return int(fields[3])


def parse_prereqs(data, pid, nonce):
    validate(pid, nonce)
    s = checked_sections(data, ('commands', 'mounts', 'player_mounts', 'card_df', 'data_df',
                                'access', 'syntax', 'stock_wrapper', 'stack', 'stamp',
                                'same_exe', 'processes', 'uptime'), nonce)
    commands = s['commands'].splitlines()
    if len(commands) != len(COMMANDS) or any(Path(p).name != name for p, name in zip(commands, COMMANDS)):
        raise ValueError('required command missing')
    log = LOG_BASE + '/run_unknown_1_0/bridge.bin'
    mount = card_mount(s['mounts'], log)
    if card_mount(s['player_mounts'], log) != mount:
        raise ValueError('card namespace mismatch')
    for key in ('mounts', 'player_mounts'):
        _rw_mount(s[key], mount['mount_id'])
    data_mount = _data_mount(s['mounts'])
    if _data_mount(s['player_mounts']) != data_mount:
        raise ValueError('data namespace mismatch')
    card_free = _available(s['card_df'], mount['source'], '/mnt/sd_0', 65536)
    data_free = _available(s['data_df'], data_mount[2], '/data', 16384)
    if s['access'] != 'ok' or s['syntax'] != 'ok' or s['same_exe'] != 'same':
        raise ValueError('access, syntax or executable identity primitive failed')
    if (not s['stack'].isdigit() or int(s['stack']) < 1024
            or not re.fullmatch(r'\d{8}T\d{6}', s['stamp'])
            or not re.fullmatch(r'\d+(?:\.\d+)? \d+(?:\.\d+)?', s['uptime'])
            or not s['stock_wrapper'].startswith('#!')
            or not re.search(rf'^\s*{pid}\s', s['processes'], re.M)):
        raise ValueError('missing shell/process prerequisites')
    return dict(card_mount=mount, data_mount=data_mount, card_available_kib=card_free,
                data_available_kib=data_free, stack_kib=int(s['stack']),
                command_paths=commands, permission_checks_only=True)


def transport_ok(result):
    return not any(result[key] for key in ('returncode', 'timed_out', 'overlong',
                                          'stderr_overlong', 'reader_errors'))


def identity_script(payload, pid, nonce):
    """Exercise only the exact pinned read-only stat helpers, not the launcher."""
    validate(pid, nonce)
    if hashlib.sha256(payload).hexdigest() != LAUNCHER:
        raise ValueError('unreviewed helper source')
    text = payload.decode('ascii')
    if text.count('\nfield() {') != 1 or text.count('\ndigest() {') != 1:
        raise ValueError('unexpected helper boundaries')
    helper = 'field() {' + text.split('\nfield() {', 1)[1].split('\ndigest() {', 1)[0]
    commands = script_sections({'start': f'start {pid}', 'parent': f'FIELD=parent field {pid}'}, nonce)
    script = 'PROC=/proc\n' + helper + '\n' + commands
    LegacyAdb('unused', 'unused', nonce).argv(script)
    return script


def run_check(adb, serial, pid, launcher, source, candidate, output):
    nonce = secrets.token_hex(16)
    validate(pid, nonce)
    if not isinstance(serial, str) or not base.SERIAL_RE.fullmatch(serial):
        raise ValueError('invalid serial')
    payload = Path(launcher).read_bytes()
    if hashlib.sha256(payload).hexdigest() != LAUNCHER:
        raise ValueError('launcher differs from pinned reviewed source')
    binary = Path(candidate).read_bytes()
    if len(binary) != CANDIDATE_SIZE or hashlib.sha256(binary).hexdigest() != CANDIDATE:
        raise ValueError('candidate differs from pinned bridge')
    verified = verify(Path(source).read_bytes(), binary)
    full_syntax = syntax_script(payload, nonce)  # Enforce legacy limit before device access.
    stat_helpers = identity_script(payload, pid, nonce)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    transport = LegacyAdb(adb, serial, nonce)
    report = dict(readonly_preflight_passed=False, launcher_executed=False,
                  device_files_written=False, hardware_validated=False,
                  errors=[], nonce=nonce, local_verification=verified)

    def probe(label, script):
        path = output / (label + '.txt')
        result = transport.probe(script, path, 30)
        report[label + '_transport'] = result
        if not transport_ok(result):
            raise ValueError(label + ' transport failed')
        return path.read_bytes()

    before = None
    try:
        before = stock_snapshot(probe('before', state_script(pid, nonce)), pid, nonce)
        report['before'] = before
        report['prerequisites'] = parse_prereqs(probe('prerequisites', prereq_script(pid, nonce)), pid, nonce)
        size = before['launcher_size']
        backup_script = (f'printf "@@{nonce}:BEGIN@@\\n"; '
                         'if exec 8</ui_data/player; then '
                         f'od -An -v -tx1 -N {size} <&8; R=$?; else R=98; fi; '
                         f'printf "\\n@@{nonce}:END:%s@@\\n" "$R"')
        backup = output / 'installed_launcher.bin'
        result = transport.stream(backup_script, backup, size, 30)
        report['backup_transport'] = result
        digest = hashlib.sha256(backup.read_bytes()).hexdigest()
        report['backup_sha256'] = digest
        if (not transport_ok(result) or not result.get('encoding_valid')
                or result.get('remote_returncode') != 0 or result['bytes'] != size
                or backup.stat().st_size != size or digest != INSTALLED):
            raise ValueError('installed launcher backup failed')
        controls = [('nonexecuting', b'printf "MUST_NOT_EXECUTE\\n"; exit 37\n', 0),
                    ('invalid', b'if then\n', 2), ('launcher', payload, 0)]
        for label, data, status in controls:
            script = full_syntax if label == 'launcher' else syntax_script(data, nonce)
            raw = probe(label, script)
            report[label] = parse_syntax(raw, nonce, hashlib.sha256(data).hexdigest(), len(data), status)
            report[label]['command_bytes'] = len(transport.argv(script)[-1].encode('utf-8'))
        raw = probe('runtime', runtime_script(nonce)).decode('ascii')
        match = re.search(rf'@@runtime_{nonce}@@\s+wait=37 failed_open=([1-9]\d*) fd_control=0 outer=continued\s*', raw)
        if not match or match.end() != len(raw):
            raise ValueError('shell runtime controls failed')
        report['runtime'] = dict(wait_status=37, failed_open_status=int(match[1]), fd_control=0)
        values = checked_sections(probe('identity_helpers', stat_helpers), ('start', 'parent'), nonce)
        if values != {'start': str(before['start_ticks']), 'parent': str(before['parent_pid']),
                      'done_' + nonce: '0'}:
            raise ValueError('launcher process identity helpers disagree with stock evidence')
        report['identity_helpers'] = dict(start_ticks=int(values['start']), parent_pid=int(values['parent']))
    except Exception as error:
        report['errors'].append(str(error))
    finally:
        try:
            after = stock_snapshot(probe('after', state_script(pid, nonce)), pid, nonce)
            report['after'] = after
            report['stock_state_preserved'] = before is not None and after == before
            if not report['stock_state_preserved']:
                report['errors'].append('stock/source state changed or unconfirmed')
        except Exception as error:
            report['errors'].append('after: ' + str(error))
    report['readonly_preflight_passed'] = not report['errors'] and report.get('stock_state_preserved', False)
    report['limits'] = [
        'Syntax and read-only prerequisites only; no launcher execution or firmware load.',
        'No device output file, installation, one-shot flag, signal, sync, reboot or retry.',
        'Filesystem access and space observations do not prove later writes or recovery.',
        'Memory figures are observations, not measured launch headroom; watchdog is not hard real time.',
    ]
    (output / 'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--adb', required=True)
    p.add_argument('--serial', required=True)
    p.add_argument('--pid', type=int, required=True)
    for name in ('launcher', 'source', 'candidate', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    args = p.parse_args()
    report = run_check(args.adb, args.serial, args.pid, args.launcher,
                       args.source, args.candidate, args.output)
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report['readonly_preflight_passed'] else 1)


if __name__ == '__main__':
    main()
