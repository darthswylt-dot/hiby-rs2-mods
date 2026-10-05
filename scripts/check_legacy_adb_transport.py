#!/usr/bin/env python3
"""Read-only stock-RS2 compatibility checks, not a live MOVE checkpoint.

Reads a fixed 64-KiB prefix of the known closed September MOVE log. Writes
only a fresh host evidence directory; never creates a device file.
"""
import argparse
import hashlib
import json
import re
import secrets
from pathlib import Path

import capture_move_checkpoint as base
from capture_move_legacy_checkpoint import sections, file_identity
from legacy_adb_transport import LegacyAdb

STOCK = '0fedb30f91937eafb5baaf3c75422cdbde04a62fe8bac8eca3c7a88bb761da0e'
REFERENCE = 'e181b61124075c46c6b9be3cc6ebe6ad2c48d8639014991de4545fd632a63222'
CLOSED_LOG = '/mnt/sd_0/rs2_folderfollow_move_diag.bin'


def state_script(pid, nonce):
    commands = {
        'boot': 'cat /proc/sys/kernel/random/boot_id',
        'stat': f'cat /proc/{pid}/stat',
        'exe': f'sha256sum /proc/{pid}/exe',
        'flag': 'if test -e /mnt/sd_0/RS2_SORTFIX_TEST; then echo present; else echo absent; fi',
        'installed': 'sha256sum /ui_data/player /data/hiby_player_sortfix',
        'closed_log': f'sha256sum {CLOSED_LOG}',
        'log_identity': f'LC_ALL=C ls -Lndi --color=never {CLOSED_LOG}',
        'meminfo': 'cat /proc/meminfo',
        'status': f'cat /proc/{pid}/status',
    }
    parts = ['RC=0']
    for name, command in commands.items():
        parts += [f'printf "\\n@@{name}@@\\n"', f'{{ {command}; }} || RC=1']
    parts += [f'printf "\\n@@done_{nonce}@@\\n%s\\n" "$RC"']
    return '; '.join(parts)


def check(adb, serial, pid, reference, output):
    base.validate(serial, pid, '/mnt/sd_0/rs2_move_evidence/run_unknown_1_0', 65536, 30)
    ref = Path(reference).read_bytes()
    if hashlib.sha256(ref).hexdigest() != REFERENCE:
        raise ValueError('wrong local reference; do not contact device')
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    report = dict(compatibility_passed=False, live_move_validated=False, errors=[])
    nonce = secrets.token_hex(16)
    transport = LegacyAdb(adb, serial, nonce)
    state_command = state_script(pid, nonce)

    def state(label):
        path = output / (label + '.txt')
        result = transport.probe(state_command, path, 30)
        report[label + '_transport'] = result
        if result['returncode'] or result['timed_out'] or result['overlong'] or result['stderr_overlong'] or result['reader_errors']:
            raise ValueError(label + ' transport failed')
        parsed = sections(path.read_bytes())
        expected_sections = {'boot', 'stat', 'exe', 'flag', 'installed', 'closed_log',
                             'log_identity', 'meminfo', 'status', 'done_' + nonce}
        if set(parsed) != expected_sections or parsed.get('done_' + nonce) != '0':
            raise ValueError(label + ' state failed/incomplete')
        if not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', parsed['boot']):
            raise ValueError('invalid stock boot ID')
        installed = [line.split() for line in parsed['installed'].splitlines()]
        if (len(installed) != 2
                or any(len(row) != 2 or not re.fullmatch(r'[0-9a-f]{64}', row[0]) for row in installed)
                or [row[1] for row in installed] != ['/ui_data/player', '/data/hiby_player_sortfix']):
            raise ValueError('invalid installed-file evidence')
        if (not re.search(r'^MemTotal:\s+\d+ kB$', parsed['meminfo'], re.M)
                or not re.search(rf'^Pid:\s+{pid}$', parsed['status'], re.M)):
            raise ValueError('stock memory/process evidence unavailable')
        if parsed['exe'].split() != [STOCK, f'/proc/{pid}/exe'] or parsed['flag'] != 'absent':
            raise ValueError('compatibility check requires unarmed original stock')
        if parsed['closed_log'].split() != [REFERENCE, CLOSED_LOG]:
            raise ValueError('closed log changed or unavailable')
        parsed['start_ticks'] = base.process_identity(parsed['stat'], pid)
        return parsed

    def stream(label, body, expected, success=True):
        script = (f'printf "@@{nonce}:BEGIN@@\\n"; {body}; '
                  f'printf "\\n@@{nonce}:END:%s@@\\n" "$RC"')
        path = output / (label + '.bin')
        result = transport.stream(script, path, len(expected), 30)
        report[label] = result
        data = path.read_bytes()
        report[label + '_sha256'] = hashlib.sha256(data).hexdigest()
        if (result['timed_out'] or result['overlong'] or result['stderr_overlong']
                or result['reader_errors'] or not result.get('encoding_valid')
                or result['bytes'] != len(expected) or data != expected):
            raise ValueError(label + ' bounded transport or byte control failed')
        if success:
            if result['returncode'] or result.get('remote_returncode') != 0:
                raise ValueError(label + ' binary control failed')
        elif (result['returncode'] != 37 or result.get('remote_returncode') != 37
              or result.get('host_returncode') != 0):
            raise ValueError('nonzero remote status was not retained')

    before = None
    try:
        before = state('before')
        # Every byte value, including NUL, CR, LF and non-ASCII, in one bounded
        # stdout control. printf is a shell builtin; no device file is made.
        payload = bytes(range(256)) + b'\0\r\n\xffA\nB\r\nZ'
        octal = ''.join('\\%03o' % byte for byte in payload)
        stream('all_bytes', f"printf '{octal}' | od -An -v -tx1 -N {len(payload)}; RC=$?", payload)
        stream('remote_failure', 'RC=37', b'', success=False)
        inode, size = file_identity(before['log_identity'], CLOSED_LOG)
        if size != len(ref):
            raise ValueError('closed log size mismatch')
        expected = ref[:65536]
        # Pin this closed file for the primitive check. It intentionally does
        # not masquerade as a live player FD9 or a supervised MOVE run.
        body = (
            f'exec 8<{CLOSED_LOG}; '
            f'if [ {CLOSED_LOG} -ef /proc/$$/fd/8 ]; then '
            'I=$(LC_ALL=C ls -Lndi --color=never /proc/$$/fd/8); set -- $I; '
            f'if [ "$1" = {inode} ] && [ "$6" = {size} ]; then '
            f'od -An -v -tx1 -N {len(expected)} <&8; RC=$?; '
            f'[ {CLOSED_LOG} -ef /proc/$$/fd/8 ] || RC=91; '
            'else RC=90; fi; else RC=89; fi'
        )
        stream('closed_prefix', body, expected)
    except Exception as exc:
        report['errors'].append(str(exc))
    finally:
        try:
            after = state('after')
            if before is not None:
                stable_keys = ('boot', 'start_ticks', 'exe', 'flag', 'installed', 'closed_log', 'log_identity')
                report['stock_state_preserved'] = all(before[key] == after[key] for key in stable_keys)
                if not report['stock_state_preserved']:
                    report['errors'].append('stock/source state changed during check')
            else:
                report['stock_state_preserved'] = False
        except Exception as exc:
            report['errors'].append('after state: ' + str(exc))
    report['compatibility_passed'] = not report['errors'] and report.get('stock_state_preserved', False)
    report['limits'] = ['Closed-file/primitive transport check only, not a live MOVE source or crash-capture validation.',
                        'No firmware, launcher, flag or device file writes; reads have CPU/cache/I/O cost.']
    (output / 'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', required=True)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = check(args.adb, args.serial, args.pid, args.reference, args.output)
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report['compatibility_passed'] else 1)


if __name__ == '__main__':
    main()
