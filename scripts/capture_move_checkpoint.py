#!/usr/bin/env python3
"""Read-only bounded ADB -> host MOVE checkpoint; no device-side copies.

Local draft, no device validation. A new output directory is mandatory.
Partial/corrupt data are retained but never silently promoted to success.
"""
import argparse
import hashlib
import json
import re
import shlex
import shutil
import struct
import subprocess
import threading
from pathlib import Path

import build_folderfollow_move_diag as fmt
from decode_folderfollow_move_diag import decode, summary


EXPECTED = '15cf4457e829692a52482c0b64a8b478f426f014b7cb31099ed6325a496c3f07'
RUN_RE = re.compile(r'/mnt/sd_0/rs2_move_evidence/run_(?:\d{8}T\d{6}|unknown)_\d{1,10}_[0-7]', re.ASCII)
SERIAL_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9 _.:+\-]{0,127}')
RECORD_SIZES = {b'MOVE': fmt.RECORD, b'MSNP': fmt.snap.SIZE, b'MSTS': 32}
MAX_METADATA = 256 * 1024


def validate(serial, pid, run, max_bytes, timeout):
    if not SERIAL_RE.fullmatch(serial):
        raise ValueError('invalid device serial')
    if not 1 <= pid <= 4194304:
        raise ValueError('invalid player PID')
    if not RUN_RE.fullmatch(run):
        raise ValueError('run must be one exact evidence-launcher directory')
    if not 1 <= max_bytes <= 128 * 1024 * 1024:
        raise ValueError('host byte budget must be 1..128 MiB')
    if not 1 <= timeout <= 60:
        raise ValueError('per-command timeout must be 1..60 seconds')


def probe_script(pid, log):
    # Values reach this function only after allowlist/integer validation.
    commands = {
        'boot': 'cat /proc/sys/kernel/random/boot_id',
        'uptime': 'cat /proc/uptime',
        'stat_before': f'cat /proc/{pid}/stat',
        'exe': f'sha256sum /proc/{pid}/exe',
        'fd9': f'readlink /proc/{pid}/fd/9',
        'log_stat': f"stat -c '%d %i %s' {shlex.quote(log)}",
        'fd_stat': f"stat -L -c '%d %i %s' /proc/{pid}/fd/9",
        'meminfo': 'cat /proc/meminfo',
        'status': f'cat /proc/{pid}/status',
        'stat_after': f'cat /proc/{pid}/stat',
    }
    parts = ['RC=0']
    for name, command in commands.items():
        parts.extend([f"printf '\\n@@{name}@@\\n'", f'{command} || RC=1'])
    parts.extend(["printf '\\n@@done@@\\n'", 'printf "%s\\n" "$RC"', 'exit "$RC"'])
    return '; '.join(parts)


def process_identity(raw, pid):
    line = raw.strip()
    split = line.rfind(') ')
    if split < 0 or not line.startswith(f'{pid} ('):
        raise ValueError('invalid process stat')
    fields = line[split + 2:].split()  # Starts at field 3 (state).
    if len(fields) < 20 or not fields[19].isdigit():
        raise ValueError('missing process starttime')
    return int(fields[19])


def parse_probe(data, pid, log):
    if len(data) > MAX_METADATA:
        raise ValueError('metadata budget exceeded')
    text = data.decode('utf-8', errors='strict')
    sections = {}
    current = None
    for line in text.splitlines():
        marker = re.fullmatch(r'@@([a-z_0-9]+)@@', line)
        if marker:
            current = marker[1]
            if current in sections:
                raise ValueError('duplicate metadata section')
            sections[current] = []
        elif current:
            sections[current].append(line)
        elif line.strip():
            raise ValueError('unexpected metadata prelude')
    sections = {k: '\n'.join(v).strip() for k, v in sections.items()}
    if sections.get('done') != '0':
        raise ValueError('metadata probe incomplete or failed')
    boot = sections.get('boot', '')
    if not re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', boot):
        raise ValueError('boot ID unavailable or malformed')
    uptime = sections.get('uptime', '').split()
    if len(uptime) != 2 or not all(re.fullmatch(r'\d+(?:\.\d+)?', n) for n in uptime):
        raise ValueError('invalid uptime')
    before = process_identity(sections.get('stat_before', ''), pid)
    after = process_identity(sections.get('stat_after', ''), pid)
    if before != after:
        raise ValueError('process changed within probe')
    exe = sections.get('exe', '').split()
    if len(exe) != 2 or exe != [EXPECTED, f'/proc/{pid}/exe']:
        raise ValueError('not the expected live MOVE executable')
    if sections.get('fd9') != log:
        raise ValueError('FD9 is not the requested log')
    def stat(name):
        values = sections.get(name, '').split()
        if len(values) != 3 or any(not n.isdigit() for n in values):
            raise ValueError(f'invalid {name}')
        return tuple(map(int, values))
    file_stat, fd_stat = stat('log_stat'), stat('fd_stat')
    if file_stat[:2] != fd_stat[:2] or fd_stat[2] < file_stat[2]:
        raise ValueError('pathname and FD9 file identities disagree')
    if not re.search(r'^MemTotal:\s+\d+ kB$', sections.get('meminfo', ''), re.M):
        raise ValueError('memory evidence unavailable')
    if not re.search(rf'^Pid:\s+{pid}$', sections.get('status', ''), re.M):
        raise ValueError('player status unavailable or changed')
    return dict(boot=boot.lower(), pid=pid, start_ticks=before, exe_sha256=EXPECTED,
                fd9=log, file_device=file_stat[0], file_inode=file_stat[1],
                size=file_stat[2], fd_size=fd_stat[2], uptime=float(uptime[0]))


def coherent(before, after):
    keys = ('boot', 'pid', 'start_ticks', 'exe_sha256', 'fd9', 'file_device', 'file_inode')
    return (all(before[k] == after[k] for k in keys)
            and after['uptime'] >= before['uptime']
            and after['size'] >= before['fd_size'])


def framing(data):
    """Only remove an incomplete final record, never valid unsettled records."""
    offset = 0
    rows = []
    while offset < len(data):
        remaining = len(data) - offset
        if remaining < 4:
            # A short magic must still be a prefix of a known record magic.
            if not any(magic.startswith(data[offset:]) for magic in RECORD_SIZES):
                raise ValueError(f'invalid partial magic at {offset:#x}')
            break
        magic = data[offset:offset + 4]
        size = RECORD_SIZES.get(magic)
        if size is None:
            raise ValueError(f'unknown record magic at {offset:#x}')
        if remaining < size:
            # Validate fields that are already present even in an incomplete
            # header, rather than disguising an invalid version as truncation.
            if remaining >= 8 and struct.unpack_from('<I', data, offset + 4)[0] != 2:
                raise ValueError('invalid partial-record version')
            if magic == b'MSNP' and remaining >= 12 and struct.unpack_from('<I', data, offset + 8)[0] != size:
                raise ValueError('invalid partial snapshot size')
            break
        rows.extend(decode(data[offset:offset + size]))
        offset += size
    return offset, summary(rows)


class Adb:
    def __init__(self, executable, serial):
        self.executable = str(executable)
        self.serial = serial

    def argv(self, script):
        # No local shell/PowerShell text pipeline; exec-out has no PTY.
        return [self.executable, '-s', self.serial, 'exec-out',
                'sh -c ' + shlex.quote(script)]

    def probe(self, script, output, timeout):
        return self._transfer(script, output, MAX_METADATA, timeout)

    def stream(self, script, output, size, timeout):
        return self._transfer(script, output, size, timeout)

    def _transfer(self, script, output, size, timeout):
        # Bound host raw output too. One extra byte detects an overlong stream.
        # Both channels go to host files, never unbounded communicate() buffers.
        with output.open('xb') as target, output.with_suffix('.stderr').open('xb') as errors:
            proc = subprocess.Popen(self.argv(script), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            read_errors = []
            written = [0, 0]
            overlong = [False, False]
            def pump(channel, stream, sink, limit):
                try:
                    while written[channel] <= limit:
                        chunk = stream.read(min(65536, limit + 1 - written[channel]))
                        if not chunk:
                            break
                        sink.write(chunk)
                        written[channel] += len(chunk)
                        if written[channel] > limit:
                            overlong[channel] = True
                            proc.kill()  # Own ADB client only, never player PID.
                            break
                except Exception as exc:
                    read_errors.append(str(exc))
                    proc.kill()
            readers = [threading.Thread(target=pump, args=args, daemon=True) for args in
                       ((0, proc.stdout, target, size), (1, proc.stderr, errors, MAX_METADATA))]
            for reader in readers:
                reader.start()
            timed_out = False
            try:
                rc = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                proc.kill()
                rc = proc.wait(timeout=5)
            for reader in readers:
                reader.join(timeout=5)
            if any(reader.is_alive() for reader in readers):
                raise RuntimeError('ADB pipe reader did not stop; evidence is incomplete')
            proc.stdout.close()
            proc.stderr.close()
            target.flush()
        return dict(returncode=rc, timed_out=timed_out, bytes=written[0],
                    overlong=overlong[0], stderr_bytes=written[1],
                    stderr_overlong=overlong[1], reader_errors=read_errors)


class NativeProtocol:
    """Original raw exec-out/stat protocol; retained for compatible devices."""
    disk_multiplier = 2

    probe_script = staticmethod(probe_script)
    parse_probe = staticmethod(parse_probe)
    coherent = staticmethod(coherent)

    @staticmethod
    def stream_script(pid, log, size, before):
        return f'exec head -c {size} {shlex.quote(log)} 2>/dev/null'

    limits = [
        'Pre/post identities do not make append-stream capture or object snapshots atomic.',
        'Host SHA-256 is not a separate device hash verification of the streamed prefix.',
        'Raw/partial evidence remains saved on failed captures; no retry or device mutation.',
        'Reads still incur device I/O, page cache and small ADB/head/probe process costs.',
        'Remote BusyBox/head/stat/exec-out support has not been device-validated.',
    ]


def capture(transport, serial, pid, run, output, max_bytes=32 * 1024 * 1024, timeout=30,
            protocol=None):
    validate(serial, pid, run, max_bytes, timeout)
    protocol = NativeProtocol() if protocol is None else protocol
    output = Path(output)
    # Refuse any existing output before asking the device anything.
    output.mkdir(parents=True, exist_ok=False)
    log = run + '/move.bin'
    report = dict(capture_accepted=False, source_coherent=False, errors=[],
                  remote_log=log, byte_budget=max_bytes, per_command_timeout=timeout)
    try:
        if shutil.disk_usage(output).free < protocol.disk_multiplier * max_bytes + 4 * 1024 * 1024:
            raise ValueError('insufficient host free space for raw+prefix evidence')
        script = protocol.probe_script(pid, log)
        result = transport.probe(script, output / 'before.txt', timeout)
        report['before_transport'] = result
        if (result['returncode'] != 0 or result['timed_out'] or result.get('overlong')
                or result.get('stderr_overlong') or result.get('reader_errors')):
            raise ValueError('before probe failed')
        before = protocol.parse_probe((output / 'before.txt').read_bytes(), pid, log)
        report['before'] = before
        size = before['size']
        if not 0 < size <= max_bytes:
            raise ValueError('remote size empty or exceeds host byte budget')
        # The selected bounded read must be supported by the device. Failure
        # or short stdout is not a reason to retry or change the device.
        stream_script = protocol.stream_script(pid, log, size, before)
        stream_ok = False
        try:
            result = transport.stream(stream_script, output / 'raw.bin', size, timeout)
            report['stream_transport'] = result
            stream_ok = (result['returncode'] == 0 and not result['timed_out']
                         and not result['overlong'] and not result.get('stderr_overlong')
                         and result.get('encoding_valid', True)
                         and not result['reader_errors'] and result['bytes'] == size)
        except Exception as exc:
            report['errors'].append('transfer exception: ' + str(exc))
        # Post-evidence and retained-byte analysis are independent of transfer
        # exceptions and metadata parse failure. Neither silently loses raw.
        try:
            post_result = transport.probe(script, output / 'after.txt', timeout)
            report['after_transport'] = post_result
            if (post_result['returncode'] == 0 and not post_result['timed_out']
                    and not post_result.get('overlong') and not post_result.get('stderr_overlong')
                    and not post_result.get('reader_errors')):
                after = protocol.parse_probe((output / 'after.txt').read_bytes(), pid, log)
                report['after'] = after
                report['source_coherent'] = protocol.coherent(before, after)
        except Exception as exc:
            report['errors'].append('after evidence: ' + str(exc))
        if not (output / 'raw.bin').exists():
            raise ValueError('no raw bytes file; transfer did not start')
        raw = (output / 'raw.bin').read_bytes()
        report['raw_bytes'] = len(raw)
        report['raw_sha256'] = hashlib.sha256(raw).hexdigest()
        stream_ok = stream_ok and len(raw) == size
        if not stream_ok:
            report['errors'].append('short/overlong/failed/timed-out stream')
        if not report['source_coherent']:
            report['errors'].append('source identity/after evidence unverified or changed')
        boundary, decoded = framing(raw)
        report['complete_record_bytes'] = boundary
        report['incomplete_tail_bytes'] = len(raw) - boundary
        report['decoded_complete_prefix'] = decoded
        (output / 'complete_prefix.bin').write_bytes(raw[:boundary])
        if boundary < len(raw):
            (output / 'incomplete_tail.bin').write_bytes(raw[boundary:])
            report['errors'].append('incomplete final record retained separately')
        if not decoded['accepted_prefix']:
            report['errors'].append('complete prefix unsettled or reports loss')
        report['capture_accepted'] = not report['errors']
    except Exception as exc:
        report['errors'].append(str(exc))
    report['limits'] = protocol.limits
    (output / 'report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', type=Path, required=True)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--run', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--max-bytes', type=int, default=32 * 1024 * 1024)
    parser.add_argument('--timeout', type=int, default=30)
    args = parser.parse_args()
    report = capture(Adb(args.adb, args.serial), args.serial, args.pid, args.run,
                     args.output, args.max_bytes, args.timeout)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    raise SystemExit(0 if report['capture_accepted'] else 1)


if __name__ == '__main__':
    main()
