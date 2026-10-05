"""Bounded ASCII transport for legacy ADB shells that always allocate a PTY.

Only the ASCII envelope is parsed; binary output is reconstructed from hex.
Original wire bytes and every safely decoded byte remain available on failure.
This module never builds or executes a device capture script on its own.
"""
import re
import shlex
from pathlib import Path

from capture_move_checkpoint import Adb


MAX_COMMAND_BYTES = 4000
MAX_HEX_LINE = 4096
WIRE_OVERHEAD = 16384
ASCII_SPACE = b' \t\r\n'
HEX_TOKEN = re.compile(rb'[0-9a-fA-F]{2}')
HEX_LINE = re.compile(
    rb'[ \t\r\n]*(?:[0-9a-fA-F]{2}[ \t\r\n]+)*'
    rb'[0-9a-fA-F]{2}[ \t\r\n]*')


def _decode_wire(path, target, size, nonce):
    """Decode a bounded line at a time, stopping at the first invalid token."""
    begin = f'@@{nonce}:BEGIN@@'.encode('ascii')
    end = re.compile(rb'@@' + nonce.encode('ascii') + rb':END:([0-9]{1,3})@@')
    state = 'before'
    count = 0
    remote_rc = None
    errors = []
    overlong = False

    def write_prefix(data):
        nonlocal count, overlong
        # Keep one extra decoded byte as evidence, matching the base transport.
        available = size + 1 - count
        kept = data[:available]
        target.write(kept)
        count += len(kept)
        if count > size or len(kept) != len(data):
            overlong = True
            errors.append('decoded output exceeds frozen byte count')

    with path.open('rb') as source:
        while True:
            line = source.readline(MAX_HEX_LINE + 1)
            if not line:
                break
            if len(line) > MAX_HEX_LINE:
                errors.append('encoded line exceeds line budget')
                break
            # PTY CR/CR/LF expansion is harmless for ASCII lines. Do not apply
            # any newline rewriting to the reconstructed binary bytes.
            marker = line.rstrip(b'\r\n')
            if state == 'before':
                if marker == begin:
                    state = 'payload'
                elif line.strip(ASCII_SPACE):
                    errors.append('unexpected content before begin marker')
                    break
                continue
            if state == 'after':
                if line.strip(ASCII_SPACE):
                    errors.append('unexpected content after end marker')
                    break
                continue
            match = end.fullmatch(marker)
            if match:
                remote_rc = int(match[1])
                if remote_rc > 255:
                    errors.append('remote status is outside shell status range')
                    break
                state = 'after'
                continue
            if not line.strip(ASCII_SPACE):
                continue
            if HEX_LINE.fullmatch(line):
                write_prefix(bytes.fromhex(line.decode('ascii')))
            else:
                # A truncated token must not discard preceding complete tokens
                # on the same line. Never search ahead for another valid frame.
                valid = []
                for token in re.split(rb'[ \t\r\n]+', line.strip(ASCII_SPACE)):
                    if not HEX_TOKEN.fullmatch(token):
                        break
                    valid.append(token)
                if valid:
                    write_prefix(bytes.fromhex(b' '.join(valid).decode('ascii')))
                errors.append('malformed hex token or unexpected payload marker')
                break
            if overlong:
                break
    if state == 'before':
        errors.append('begin marker missing')
    if state != 'after':
        errors.append('end marker missing or invalid')
    if count != size:
        errors.append('decoded byte count differs from frozen byte count')
    return dict(bytes=count, encoding_valid=not errors, remote_returncode=remote_rc,
                encoding_errors=errors, decoded_overlong=overlong)


class LegacyAdb(Adb):
    """Use nonce-framed ASCII hex, retaining base time and output bounds.

    The caller supplies the script and must bind its completion status to the
    encoder and source checks. A successful ADB client status alone is not a
    successful capture on a legacy device.
    """

    def __init__(self, executable, serial, nonce):
        if not isinstance(nonce, str) or not re.fullmatch(r'[0-9a-f]{32}', nonce):
            raise ValueError('nonce must be exactly 32 lowercase hex characters')
        super().__init__(executable, serial)
        self.nonce = nonce

    def argv(self, script):
        command = 'sh -c ' + shlex.quote(script)
        if '\x00' in command or len(command.encode('utf-8')) > MAX_COMMAND_BYTES:
            raise ValueError('legacy remote command contains NUL or exceeds 4000 bytes')
        return [self.executable, '-s', self.serial, 'shell', command]

    def stream(self, script, output, size, timeout):
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ValueError('frozen byte count must be a nonnegative integer')
        output = Path(output)
        wire = output.with_suffix('.hex')
        stderr = wire.with_suffix('.stderr')
        paths = (output, wire, stderr)
        if len(set(paths)) != len(paths):
            raise ValueError('decoded, encoded and stderr paths must be distinct')
        for path in paths:
            if path.exists() or path.is_symlink():
                raise FileExistsError(f'refusing existing evidence file: {path}')
        self.argv(script)  # Reject oversized commands before opening artifacts.
        result = dict(returncode=1, timed_out=False, bytes=0, overlong=False,
                      stderr_bytes=0, stderr_overlong=False, reader_errors=[])
        decoded = dict(bytes=0, encoding_valid=False, remote_returncode=None,
                       encoding_errors=[], decoded_overlong=False)
        # Reserve the decoded output before any remote call; every artifact is
        # exclusively created, including those created by the base transport.
        with output.open('xb') as target:
            try:
                result = super()._transfer(
                    script, wire, 4 * size + WIRE_OVERHEAD, timeout)
                result['host_returncode'] = result['returncode']
            except Exception as exc:
                result['reader_errors'].append('transfer exception: ' + str(exc))
                result['host_returncode'] = None
            result['encoded_bytes'] = wire.stat().st_size if wire.exists() else 0
            result['encoded_overlong'] = result['overlong']
            try:
                if wire.exists():
                    decoded = _decode_wire(wire, target, size, self.nonce)
                else:
                    decoded['encoding_errors'].append('encoded evidence unavailable')
            except Exception as exc:
                decoded['encoding_errors'].append('decoding exception: ' + str(exc))
                decoded['encoding_valid'] = False
        result.update(decoded)
        result['bytes'] = output.stat().st_size
        result['overlong'] = result['encoded_overlong'] or result['decoded_overlong']
        if result['returncode'] == 0:
            if result['remote_returncode'] not in (None, 0):
                result['returncode'] = result['remote_returncode']
            elif not result['encoding_valid']:
                result['returncode'] = 1
        return result
