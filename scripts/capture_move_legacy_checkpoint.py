#!/usr/bin/env python3
"""Bounded, read-only MOVE collection over the RS2's legacy PTY ADB transport.

No player launch, file copy, signal, reboot, device write or automatic retry.
Requires the exact live MOVE build and an evidence-launcher run directory.
"""
import argparse
import json
import re
import secrets
import shlex
from pathlib import Path

import capture_move_checkpoint as base


CARD = '/mnt/sd_0'


def sections(data):
    if len(data) > base.MAX_METADATA:
        raise ValueError('metadata budget exceeded')
    result, name = {}, None
    for line in data.decode('ascii', errors='strict').splitlines():
        marker = re.fullmatch(r'@@([a-z_0-9]+)@@', line)
        if marker:
            name = marker[1]
            if name in result:
                raise ValueError('duplicate metadata section')
            result[name] = []
        elif line.strip():
            if name is None:
                raise ValueError('unexpected metadata prelude')
            result[name].append(line)
    return {name: '\n'.join(lines).strip() for name, lines in result.items()}


def file_identity(text, path):
    # ls -Lndi --color=never, LC_ALL=C: inode, mode, nlink, uid, gid, size,
    # month, day, time/year, name. Requested paths contain no spaces.
    fields = text.split()
    if len(fields) != 10 or fields[-1] != path:
        raise ValueError('invalid ls identity or unexpected filename')
    if not re.fullmatch(r'-[rwxstST-]{9}', fields[1]):
        raise ValueError('source is not a regular file')
    if not all(fields[i].isdigit() for i in (0, 2, 3, 4, 5)):
        raise ValueError('invalid inode/owner/size')
    if int(fields[0]) == 0 or int(fields[2]) == 0:
        raise ValueError('invalid inode/link count')
    return int(fields[0]), int(fields[5])


def card_mount(text, log):
    candidates = []
    for line in text.splitlines():
        left, sep, right = line.partition(' - ')
        fields, tail = left.split(), right.split()
        if not sep or len(fields) < 6 or len(tail) != 3:
            raise ValueError('malformed mountinfo')
        mountpoint = fields[4]
        if mountpoint == '/' or log == mountpoint or log.startswith(mountpoint + '/'):
            candidates.append((len(mountpoint), fields, tail))
    if not candidates:
        raise ValueError('no mount for log')
    longest = max(item[0] for item in candidates)
    matches = [item for item in candidates if item[0] == longest]
    if len(matches) != 1:
        raise ValueError('ambiguous log mount')
    _, fields, tail = matches[0]
    # vfat cannot contain symlinks. Reject bind/submount paths rather than
    # attributing an arbitrary pathname or FD to the card's device number.
    if fields[4] != CARD or fields[3] != '/' or tail[0] != 'vfat':
        raise ValueError('log is not on the expected direct vfat card mount')
    if not fields[0].isdigit() or not fields[1].isdigit() or not re.fullmatch(r'\d+:\d+', fields[2]):
        raise ValueError('invalid mount identity')
    return dict(mount_id=int(fields[0]), parent_id=int(fields[1]), device=fields[2],
                root=fields[3], mountpoint=fields[4], filesystem=tail[0], source=tail[1])


class LegacyProtocol:
    disk_multiplier = 6  # Encoded wire + decoded bytes + complete prefix/tail.
    limits = [
        'Hex and framing are ASCII; only their CR/LF transport changes are normalized.',
        'Identity uses test -ef (device+inode), numeric ls and the direct vfat card mount.',
        'Kernel fdinfo lacks mnt_id; matching shell/player mount tables are required.',
        'A pinned read FD is compared with pathname and live player FD9 around od.',
        'Pre/post checks do not make contents atomic or exclude an in-place rewrite.',
        'Read-only capture still consumes device CPU, I/O and page-cache memory.',
        'Primitive compatibility is checked; a live supervised MOVE run is not yet validated.',
    ]

    def __init__(self, nonce=None):
        self.nonce = secrets.token_hex(16) if nonce is None else nonce
        if not re.fullmatch(r'[0-9a-f]{32}', self.nonce):
            raise ValueError('invalid framing nonce')

    def probe_script(self, pid, log):
        qlog = shlex.quote(log)
        fd = f'/proc/{pid}/fd/9'
        same = f'if [ {qlog} -ef {fd} ]; then echo same; else echo different; RC=1; fi'
        commands = {
            'boot': 'cat /proc/sys/kernel/random/boot_id',
            'uptime': 'cat /proc/uptime',
            'stat_before': f'cat /proc/{pid}/stat',
            'exe': f'sha256sum /proc/{pid}/exe',
            'fd9': f'readlink {fd}',
            'mounts': 'cat /proc/self/mountinfo',
            'player_mounts': f'cat /proc/{pid}/mountinfo',
            'same_before': same,
            'log_stat': f'LC_ALL=C ls -Lndi --color=never {qlog}',
            'fd_stat': f'LC_ALL=C ls -Lndi --color=never {fd}',
            'same_after': same,
            'meminfo': 'cat /proc/meminfo',
            'status': f'cat /proc/{pid}/status',
            'stat_after': f'cat /proc/{pid}/stat',
        }
        parts = ['RC=0']
        for name, command in commands.items():
            parts += [f"printf '\\n@@{name}@@\\n'", f'{{ {command}; }} || RC=1']
        parts += [f"printf '\\n@@done_{self.nonce}@@\\n'", 'printf "%s\\n" "$RC"']
        return '; '.join(parts)

    def parse_probe(self, data, pid, log):
        s = sections(data)
        expected = {'boot', 'uptime', 'stat_before', 'exe', 'fd9', 'mounts', 'player_mounts',
                    'same_before', 'log_stat', 'fd_stat', 'same_after', 'meminfo', 'status',
                    'stat_after', 'done_' + self.nonce}
        if set(s) != expected or s['done_' + self.nonce] != '0':
            raise ValueError('metadata incomplete, failed, or wrong nonce')
        if not re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', s['boot']):
            raise ValueError('invalid boot ID')
        uptime = s['uptime'].split()
        if len(uptime) != 2 or not all(re.fullmatch(r'\d+(?:\.\d+)?', item) for item in uptime):
            raise ValueError('invalid uptime')
        start = base.process_identity(s['stat_before'], pid)
        if base.process_identity(s['stat_after'], pid) != start:
            raise ValueError('process changed within probe')
        if s['exe'].split() != [base.EXPECTED, f'/proc/{pid}/exe']:
            raise ValueError('not the expected live MOVE executable')
        if s['fd9'] != log or s['same_before'] != 'same' or s['same_after'] != 'same':
            raise ValueError('pathname and live FD9 do not identify the same file')
        mount = card_mount(s['mounts'], log)
        if card_mount(s['player_mounts'], log) != mount:
            raise ValueError('player and shell mount identities disagree')
        inode, size = file_identity(s['log_stat'], log)
        fd_inode, fd_size = file_identity(s['fd_stat'], f'/proc/{pid}/fd/9')
        if inode != fd_inode or fd_size < size:
            raise ValueError('inode or size changed within probe')
        if not re.search(r'^MemTotal:\s+\d+ kB$', s['meminfo'], re.M):
            raise ValueError('memory evidence unavailable')
        if not re.search(rf'^Pid:\s+{pid}$', s['status'], re.M):
            raise ValueError('player status unavailable')
        return dict(boot=s['boot'].lower(), pid=pid, start_ticks=start, exe_sha256=base.EXPECTED,
                    fd9=log, file_device=mount['device'], file_inode=inode, mount=mount,
                    size=size, fd_size=fd_size, uptime=float(uptime[0]))

    @staticmethod
    def coherent(before, after):
        return base.coherent(before, after) and before['mount'] == after['mount']

    def stream_script(self, pid, log, size, before):
        # Arguments and before metadata were validated by capture/parse_probe.
        # Pin a new read descriptor. Never seek/read through the player's own
        # file-description offset, never copy the log to device storage.
        qlog = shlex.quote(log)
        fd = f'/proc/{pid}/fd/9'
        inode = before['file_inode']
        start = before['start_ticks']
        boot = before['boot']
        mount = before['mount']
        mount_awk = (
            '$5=="/mnt/sd_0" {if($1==m && $3==d && $4=="/") ok++} '
            '$5!="/" && $5!="/mnt/sd_0" && (p==$5 || index(p,$5"/")==1) {bad=1} '
            'END {exit(ok!=1 || bad)}'
        )
        mount_function = (
            f'mountok() {{ awk -v m={mount["mount_id"]} -v d={mount["device"]} '
            f'-v p={qlog} {shlex.quote(mount_awk)} "$1"; }}'
        )
        # /proc/stat comm may contain spaces/parentheses: strip through last
        # ') ' before splitting fields. Starttime is then the twentieth word.
        identity = (
            f'[ "$(cat /proc/sys/kernel/random/boot_id)" = {boot} ] && '
            f'S=$(cat /proc/{pid}/stat) && S=${{S##*) }} && set -- $S && '
            f'[ "${{20}}" = {start} ] && '
            f'mountok /proc/self/mountinfo && mountok /proc/{pid}/mountinfo && '
            f'[ "$(readlink {fd})" = {qlog} ] && '
            f'[ {qlog} -ef /proc/$$/fd/8 ] && [ {fd} -ef /proc/$$/fd/8 ] && '
            'I=$(LC_ALL=C ls -Lndi --color=never /proc/$$/fd/8) && set -- $I && '
            f'[ "$1" = {inode} ] && [ "$6" -ge {size} ]'
        )
        return (
            f'{mount_function}; check() {{ {identity}; }}; '
            f'printf "@@{self.nonce}:BEGIN@@\\n"; '
            f'if exec 8<{qlog}; then '
            'if check; then '
            f'od -An -v -tx1 -N {size} <&8; RC=$?; '
            'check || RC=91; '
            'else RC=90; fi; '
            'else RC=89; fi; '
            f'printf "\\n@@{self.nonce}:END:%s@@\\n" "$RC"'
        )


def main():
    from legacy_adb_transport import LegacyAdb
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', type=Path, required=True)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--run', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--max-bytes', type=int, default=32 * 1024 * 1024)
    parser.add_argument('--timeout', type=int, default=30)
    args = parser.parse_args()
    protocol = LegacyProtocol()
    report = base.capture(LegacyAdb(args.adb, args.serial, protocol.nonce), args.serial,
                          args.pid, args.run, args.output, args.max_bytes, args.timeout,
                          protocol=protocol)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    raise SystemExit(0 if report['capture_accepted'] else 1)


if __name__ == '__main__':
    main()
