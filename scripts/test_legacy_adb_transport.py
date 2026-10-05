"""Host subprocess tests only; never invoke ADB or access a player."""
import shlex
import sys
import tempfile
import unittest
from pathlib import Path

import capture_move_checkpoint as base
import legacy_adb_transport as legacy


NONCE = '0123456789abcdef0123456789abcdef'
BEGIN = f'@@{NONCE}:BEGIN@@'.encode()
END = f'@@{NONCE}:END:0@@'.encode()


def envelope(data, rc=0, newline=b'\r\r\n'):
    lines = [BEGIN]
    lines.extend(b' ' + chunk.hex(' ').encode() for chunk in
                 (data[offset:offset + 16] for offset in range(0, len(data), 16)))
    lines.append(f'@@{NONCE}:END:{rc}@@'.encode())
    return newline.join(lines) + newline


class LocalTransport(legacy.LegacyAdb):
    def __init__(self, wire=b'', code=None):
        super().__init__('unused-adb.exe', 'HiBy RS2', NONCE)
        self.code = code if code is not None else (
            f'import sys;sys.stdout.buffer.write({wire!r});'
            'sys.stderr.buffer.write(b"diagnostic")')

    def argv(self, script):
        return [sys.executable, '-c', self.code]


class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='legacy-transport-test-')
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def stream(self, wire, size, name='raw.bin', **kwargs):
        output = self.root / name
        result = LocalTransport(wire, **kwargs).stream('unused', output, size, 3)
        self.assertEqual(result['bytes'], output.stat().st_size)
        return result, output

    def test_all_bytes_preserved_across_pty_newline_expansion(self):
        data = bytes(range(256)) * 3 + b'\r\n\x00\xff'
        wire = envelope(data)
        result, output = self.stream(wire, len(data))
        self.assertEqual(result['returncode'], 0)
        self.assertEqual(result['host_returncode'], 0)
        self.assertEqual(result['remote_returncode'], 0)
        self.assertTrue(result['encoding_valid'])
        self.assertEqual(output.read_bytes(), data)
        self.assertEqual(output.with_suffix('.hex').read_bytes(), wire)
        self.assertEqual(output.with_suffix('.stderr').read_bytes(), b'diagnostic')
        self.assertEqual(result['encoded_bytes'], len(wire))

    def test_ascii_whitespace_and_uppercase_hex(self):
        wire = b' \t\r\n' + BEGIN + b'\n\t00 FF\t0D 0A\r\r\n' + END + b'\n\t\r\n'
        result, output = self.stream(wire, 4)
        self.assertTrue(result['encoding_valid'])
        self.assertEqual(output.read_bytes(), b'\x00\xff\r\n')

    def test_missing_duplicate_and_wrong_nonce_markers(self):
        cases = (
            (b'00\n' + END + b'\n', b''),
            (BEGIN + b'\n00\n', b'\0'),
            (BEGIN + b'\n' + BEGIN + b'\n00\n' + END + b'\n', b''),
            (envelope(b'\0') + END + b'\n', b'\0'),
            (envelope(b'\0').replace(NONCE.encode(), b'f' * 32, 1), b''),
            (envelope(b'\0').replace(END, END.replace(NONCE.encode(), b'f' * 32)), b'\0'),
            (envelope(b'\0') + BEGIN + b'\n', b'\0'),
        )
        for index, (wire, prefix) in enumerate(cases):
            with self.subTest(index=index):
                result, output = self.stream(wire, 1, f'bad{index}.bin')
                self.assertFalse(result['encoding_valid'])
                self.assertNotEqual(result['returncode'], 0)
                self.assertEqual(output.read_bytes(), prefix)
                self.assertEqual(output.with_suffix('.hex').read_bytes(), wire)

    def test_malformed_hex_retains_complete_tokens_on_same_line(self):
        for index, bad in enumerate((b'f', b'fg', b'0001', b'GG', b'02\v03', b'\xff')):
            with self.subTest(bad=bad):
                wire = BEGIN + b'\n00 01 ' + bad + b'\n' + END + b'\n'
                result, output = self.stream(wire, 4, f'hex{index}.bin')
                self.assertFalse(result['encoding_valid'])
                self.assertEqual(output.read_bytes(), b'\x00\x01')

    def test_partial_last_hex_token_retains_decoded_prefix(self):
        result, output = self.stream(BEGIN + b'\n00 01 a', 3)
        self.assertFalse(result['encoding_valid'])
        self.assertIsNone(result['remote_returncode'])
        self.assertEqual(output.read_bytes(), b'\x00\x01')

    def test_junk_before_after_or_inside_payload_rejected(self):
        cases = (b'banner\n' + envelope(b'\0'), envelope(b'\0') + b'junk\n',
                 envelope(b'\0').replace(b' 00', b' 00 error: closed'))
        for index, wire in enumerate(cases):
            result, _ = self.stream(wire, 1, f'junk{index}.bin')
            self.assertFalse(result['encoding_valid'])
            self.assertNotEqual(result['returncode'], 0)

    def test_remote_nonzero_overrides_successful_host_status(self):
        result, output = self.stream(envelope(b'ab', rc=37), 2)
        self.assertTrue(result['encoding_valid'])
        self.assertEqual(result['host_returncode'], 0)
        self.assertEqual(result['remote_returncode'], 37)
        self.assertEqual(result['returncode'], 37)
        self.assertEqual(output.read_bytes(), b'ab')

    def test_invalid_remote_status(self):
        for index, rc in enumerate(('-1', 'x', '256', '0000', '0 junk')):
            result, _ = self.stream(envelope(b'a', rc=rc), 1, f'rc{index}.bin')
            self.assertFalse(result['encoding_valid'])
            self.assertNotEqual(result['returncode'], 0)

    def test_short_and_overlong_decoded_streams(self):
        result, output = self.stream(envelope(b'ab'), 3)
        self.assertFalse(result['encoding_valid'])
        self.assertFalse(result['overlong'])
        self.assertEqual(output.read_bytes(), b'ab')
        result, output = self.stream(envelope(b'abcdef'), 3, 'long.bin')
        self.assertFalse(result['encoding_valid'])
        self.assertTrue(result['overlong'])
        self.assertEqual(output.read_bytes(), b'abcd')

    def test_bounded_payload_line(self):
        wire = BEGIN + b'\n00\n' + b' ' * (legacy.MAX_HEX_LINE + 1) + b'\n' + END + b'\n'
        result, output = self.stream(wire, 2)
        self.assertFalse(result['encoding_valid'])
        self.assertEqual(output.read_bytes(), b'\0')
        self.assertIn('encoded line exceeds line budget', result['encoding_errors'])

    def test_wire_stdout_is_bounded(self):
        output = self.root / 'raw.bin'
        size = 3
        limit = 4 * size + legacy.WIRE_OVERHEAD
        code = 'import sys;sys.stdout.buffer.write(b"X"*100000)'
        result = LocalTransport(code=code).stream('unused', output, size, 3)
        self.assertTrue(result['overlong'])
        self.assertTrue(result['encoded_overlong'])
        self.assertEqual(result['encoded_bytes'], limit + 1)
        self.assertEqual(output.with_suffix('.hex').stat().st_size, limit + 1)

    def test_wire_stderr_is_bounded(self):
        output = self.root / 'raw.bin'
        code = (f'import sys;sys.stdout.buffer.write({envelope(b"ab")!r});'
                'sys.stdout.buffer.flush();sys.stderr.buffer.write(b"X"*400000)')
        result = LocalTransport(code=code).stream('unused', output, 2, 3)
        self.assertTrue(result['stderr_overlong'])
        self.assertEqual(output.with_suffix('.stderr').stat().st_size, base.MAX_METADATA + 1)

    def test_timeout_retains_wire_and_decoded_prefix(self):
        output = self.root / 'raw.bin'
        wire = BEGIN + b'\r\r\n00 01 a'
        code = (f'import sys,time;sys.stdout.buffer.write({wire!r});'
                'sys.stdout.buffer.flush();time.sleep(5)')
        result = LocalTransport(code=code).stream('unused', output, 3, 1)
        self.assertTrue(result['timed_out'])
        self.assertFalse(result['encoding_valid'])
        self.assertEqual(output.with_suffix('.hex').read_bytes(), wire)
        self.assertEqual(output.read_bytes(), b'\x00\x01')

    def test_host_nonzero_remains_failure_with_valid_envelope(self):
        code = f'import sys;sys.stdout.buffer.write({envelope(b"ab")!r});sys.exit(7)'
        result, _ = self.stream(b'', 2, code=code)
        self.assertTrue(result['encoding_valid'])
        self.assertEqual(result['host_returncode'], 7)
        self.assertEqual(result['returncode'], 7)

    def test_metadata_uses_inherited_bounds_without_hex_decode(self):
        for channel in ('stdout', 'stderr'):
            with self.subTest(channel=channel):
                output = self.root / (channel + '.txt')
                code = f'import sys;sys.{channel}.buffer.write(b"X"*400000)'
                result = LocalTransport(code=code).probe('unused', output, 3)
                key = 'overlong' if channel == 'stdout' else 'stderr_overlong'
                path = output if channel == 'stdout' else output.with_suffix('.stderr')
                self.assertTrue(result[key])
                self.assertEqual(path.stat().st_size, base.MAX_METADATA + 1)
                self.assertFalse(output.with_suffix('.hex').exists())

    def test_existing_artifact_never_overwritten(self):
        for index, suffix in enumerate(('.bin', '.hex', '.stderr')):
            with self.subTest(suffix=suffix):
                output = self.root / f'existing{index}.bin'
                existing = output.with_suffix(suffix)
                existing.write_bytes(b'KEEP')
                with self.assertRaises(FileExistsError):
                    LocalTransport(envelope(b'ab')).stream('unused', output, 2, 3)
                self.assertEqual(existing.read_bytes(), b'KEEP')
                self.assertEqual(list(self.root.glob(f'existing{index}.*')), [existing])

    def test_artifact_path_collision_rejected(self):
        for suffix in ('.hex', '.stderr'):
            with self.assertRaises(ValueError):
                LocalTransport().stream('unused', self.root / ('raw' + suffix), 1, 3)

    def test_failed_process_launch_retains_empty_artifacts_and_failure(self):
        transport = legacy.LegacyAdb(self.root / 'missing-adb.exe', 'HiBy RS2', NONCE)
        output = self.root / 'raw.bin'
        result = transport.stream('true', output, 1, 3)
        self.assertNotEqual(result['returncode'], 0)
        self.assertIsNone(result['host_returncode'])
        self.assertFalse(result['encoding_valid'])
        self.assertTrue(result['reader_errors'])
        self.assertEqual(output.read_bytes(), b'')
        self.assertEqual(output.with_suffix('.hex').read_bytes(), b'')

    def test_nonce_and_frozen_size_validation(self):
        for nonce in ('', NONCE[:-1], NONCE.upper(), NONCE + '0', 'x' * 32, None):
            with self.assertRaises(ValueError):
                legacy.LegacyAdb('adb.exe', 'HiBy RS2', nonce)
        for size in (-1, 1.5, True):
            with self.assertRaises(ValueError):
                LocalTransport().stream('unused', self.root / 'raw.bin', size, 3)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_argv_is_quoted_legacy_shell_and_command_byte_limit(self):
        transport = legacy.LegacyAdb('C:/ADB tools/adb.exe', 'HiBy RS2', NONCE)
        script = "printf '%s\\n' 'a; b'"
        argv = transport.argv(script)
        self.assertEqual(argv, ['C:/ADB tools/adb.exe', '-s', 'HiBy RS2',
                                'shell', 'sh -c ' + shlex.quote(script)])
        # Unquoted safe ASCII leaves six bytes for the sh -c prefix.
        self.assertEqual(len(transport.argv('a' * 3994)[-1].encode()), 4000)
        for script in ('a' * 3995, '\u00e9' * 2000, 'true\0false'):
            with self.assertRaises(ValueError):
                transport.argv(script)


if __name__ == '__main__':
    unittest.main()
