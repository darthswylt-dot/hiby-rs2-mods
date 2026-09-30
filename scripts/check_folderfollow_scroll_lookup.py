#!/usr/bin/env python3
"""Read-only checks of explorer configuration and saved cue-list positions.

This does not execute the firmware helper or establish live database identity.
"""
import argparse
import hashlib
import sqlite3
from pathlib import Path

from mips_static_trace import Elf32


def snapshot_position(connection, folder, path, cue_id):
    """Offline rowid-order experiment; None means missing, never row zero.

    Live ctime/mtime sorting and live cache consistency are not modeled.
    """
    managers = connection.execute(
        'SELECT id FROM MANAGER_TABLE WHERE path = ?', (folder,)).fetchall()
    if not managers:
        return None
    if len(managers) != 1 or type(managers[0][0]) is not int or managers[0][0] < 0:
        raise ValueError('ambiguous or invalid manager ID')
    table = f'list_tb_{managers[0][0]}'  # Only a validated integer is interpolated.
    matches = connection.execute(
        f'SELECT rowid FROM {table} WHERE path = ? AND cue_id = ?',
        (path, cue_id)).fetchall()
    if not matches:
        return None
    if len(matches) != 1:
        raise ValueError('ambiguous path/cue match')
    return connection.execute(
        f'SELECT count(*) FROM {table} WHERE rowid < ?', matches[0]).fetchone()[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('database', type=Path)
    args = parser.parse_args()
    elf = Elf32(args.elf)

    def string(address):
        offset = elf.va_to_off(address)
        return elf.data[offset:offset + 512].split(b'\0', 1)[0].decode('ascii')

    # Constructor copies 102 records, stride 0x34, from 0x942410.
    # Name/type/lookup-key are at record +0x28/+0x2C/+0x30.
    records = []
    for index in range(102):
        name_field = 0x942438 + index * 0x34
        if elf.word(name_field) == 0x922704:
            records.append((name_field, elf.word(name_field + 4),
                            string(elf.word(name_field + 8))))
    if records != [(0x942674, 2, '')]:
        raise SystemExit(f'unexpected explorer configuration: {records!r}')
    print('explorer_type=2; constructor_lookup_key=empty')
    stock_query = string(0x99CB28)
    if stock_query != ('SELECT count(id) FROM %s WHERE rowid < '
                       '(SELECT rowid FROM %s WHERE path like ? and cue_id = %d)'):
        raise SystemExit('unexpected stock SQL template')
    print('database_sha256=' + hashlib.sha256(args.database.read_bytes()).hexdigest())
    connection = sqlite3.connect(args.database.resolve().as_uri() + '?mode=ro', uri=True)
    try:
        for table in ('list_tb_5', 'list_tb_6'):
            manager_id = int(table.removeprefix('list_tb_'))
            manager = connection.execute(
                'SELECT path, count FROM MANAGER_TABLE WHERE id = ?',
                (manager_id,)).fetchall()
            if len(manager) != 1:
                raise SystemExit(f'expected one manager mapping for {table}')
            folder, declared_count = manager[0]
            # Fixed identifiers, never interpolate user input as SQL names.
            rows = connection.execute(
                f'SELECT rowid, path, cue_id FROM {table} ORDER BY rowid').fetchall()
            if not rows:
                raise SystemExit(f'{table} is empty in this snapshot')
            if declared_count != len(rows):
                raise SystemExit(f'{table} count differs from manager metadata')
            print(f'manager_id={manager_id}; table={table}; entries={len(rows)}')
            query = stock_query.replace('%s', table).replace('%d', '?')
            for position, (_, path, cue_id) in enumerate(rows):
                result = connection.execute(query, (path, cue_id)).fetchone()[0]
                if result != position:
                    raise SystemExit(f'{table} position mismatch: {position}, {result}')
                if snapshot_position(connection, folder, path, cue_id) != position:
                    raise SystemExit('explicit-match position mismatch')
            missing = connection.execute(query, ('__RS2_ABSENT_PATH__', -999)).fetchone()[0]
            if missing != 0:
                raise SystemExit('unexpected absent-path count')
            for target_folder, target_path, target_cue in (
                (folder, '__RS2_ABSENT_PATH__', -999),
                (folder, rows[0][1], -999),
                ('__RS2_ABSENT_FOLDER__', rows[0][1], rows[0][2]),
            ):
                if snapshot_position(connection, target_folder, target_path, target_cue) is not None:
                    raise SystemExit('explicit-match lookup accepted a missing target')
            print(f'{table}: {len(rows)} positions verified; absent_path_also_returns_zero')
            if table == 'list_tb_5':
                if len({path for _, path, _ in rows}) != 1 or len({cue for _, _, cue in rows}) != len(rows):
                    raise SystemExit('expected one file with distinct cue IDs for Slayer')
            if table == 'list_tb_6':
                cue_zero = [index for index, (_, _, cue) in enumerate(rows) if cue == 0]
                print(f'sleep_cue_zero_positions={cue_zero}')
    finally:
        connection.close()
    print('scope=static_configuration_and_saved_database_only; no_device_access')


if __name__ == '__main__':
    main()
