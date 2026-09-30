#!/usr/bin/env python3
"""Read-only checks of scroll telemetry and the corresponding stock code anchors."""
import argparse
from pathlib import Path
from decode_folderfollow_scroll_diag import decode
from mips_static_trace import Elf32


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('elf', type=Path)
    p.add_argument('log', type=Path)
    args = p.parse_args()
    elf = Elf32(args.elf)
    anchors = {
        0x490F08: 0x8C653B68,  # P = view+3B68
        0x490F14: 0x8CA501B8,  # Q = P+1B8
        0x490F18: 0x8C830010,  # viewport height
        0x490F1C: 0x8CA5009C,  # actual extent used for bottom adjustment
        0x48FA8C: 0x8C6501B8,  # saved-position restoration uses same chain
        0x48FA98: 0x8CA5009C,
        0x6F8B38: 0x8E22D7B0,  # branch delay slot loads database context
        0x6F8D94: 0x8C420538,  # raw sort selector, not an inferred replacement
        0x8B4550: 0x10A00034,  # bounds depend on object flags
        0x8B455C: 0x1080000F,
        0x456CCC: 0x244257E0,  # constructor installs raw getter
        0x456CD0: 0xAE02002C,
        0x456CE4: 0x24425DC0,  # constructor installs count getter
        0x456CE8: 0xAE020030,
        0x455DDC: 0xAFBF001C,
        0x455DCC: 0x8C82000C,  # non-null count path is a plain read
        0x49126C: 0x0C115BA0,  # destroy primary list
        0x491280: 0x0C115BA0,  # destroy additional list
        0x499D08: 0x0C296F18,  # row-local memset before stock lookup
        0x499D0C: 0x24060A88,
        0x499D18: 0x02579821,  # s3 = visible slot + starting row
        0x499D44: 0x0C10C9F0,  # stock row getter
        0x499D48: 0x27A60018,  # descriptor is caller stack +0x18
        0x499D4C: 0x8E020040,  # first instruction after return
        0x499ED4: 0x26520001,  # visible-slot iteration
        0x499EE0: 0x24020008,  # eight-slot cap
        0x496CE0: 0x8FA40DB8,  # draw callback's fifth argument
        0x497050: 0x0C125878,  # normal playing predicate
        0x497F0C: 0x0C125878,
        0x6ED5EC: 0xAFA60AD8,  # preserve query offset
        0x6ED69C: 0x0C168B40,  # bind offset to parameter 2
        0x6ED6A0: 0x24050002,
        0x6ED6A8: 0x00008821,  # row ordinal starts at zero
        0x6ED6D8: 0x0C1BA360,  # populate local descriptor
        0x6ED6E0: 0x8ED90018,  # next step is append to supplied list
        0x6ED6EC: 0x27A50020,
        0x6ED6F0: 0x26310001,  # increment even if append failed
        0x6F8BEC: 0x0C1BB570,
        0x455DA4: 0x081156F0,  # append tail calls insertion
        0x455DA8: 0x8C85000C,  # insertion index = old count
        0x455CF8: 0xAEC2000C,  # commit new count after copy
        0x455D00: 0x02A01021,  # return insertion index, not Boolean
        0x455D98: 0x2415FFFF,  # failure value -1
        0x4557C8: 0xAC80000C,  # clear count without replacing address
        0x495144: 0xAE820000,  # publish list before filling it
        0x49519C: 0x0C1BDF28,  # subsequent fill
        0x4951A4: 0x8E23000C,  # observe actual count after fill
        0x493FA8: 0x0C115BA0,  # additional-list destruction
        0x493FBC: 0x0C115BA0,  # primary-list destruction
        0x493FD8: 0xAE003B68,
        0x48D120: 0x0320F809,  # additional list cleared in-place
        0x48D168: 0x8E2401BC,  # primary list reused
        0x48D170: 0x0320F809,  # clear
        0x48D1B8: 0x0C1BDF28,  # refill existing list
        0x48D1C0: 0x8E390404,  # metadata callback only after refill
        0x48D5C0: 0x0320F809,  # another primary clear
        0x48D608: 0x0C1BDF28,
        0x48D610: 0x8E390404,
        0x6ED6C0: 0x14520010,  # initial non-row result reaches common exit
        0x6ED6FC: 0x1052FFF2,  # subsequent step result: row or exit
        0x6ED704: 0x0C170C70,  # clobbers terminal step result
        0x6ED70C: 0x1040002F,
        0x6ED714: 0x1043002D,
        0x6ED730: 0x10000027,  # logging error still returns row counter
        0x6ED7D0: 0x02201021,
        0x6F8BFC: 0x00008021,  # outer folder branch forces return to zero
        0x6F7F6C: 0x02001021,
    }
    for pc, expected in anchors.items():
        if elf.word(pc) != expected:
            raise SystemExit(f'code anchor mismatch at {pc:#x}')
    # Getter is a leaf: no direct or indirect call, no LL/SC or SYNC.
    # This says nothing about external locks held by its callers.
    for pc in range(0x4557E0, 0x455844, 4):
        word = elf.word(pc)
        op, fn = word >> 26, word & 63
        if op in (3, 0x30, 0x38) or (op == 0 and fn in (9, 15)):
            raise SystemExit(f'getter implementation changed at {pc:#x}')
    rows = list(decode(args.log.read_bytes()))
    slayer = [r for r in rows if r['explorer_valid'] and
              '1987 USA Discovery Systems' in r['folder'] and
              'Slayer - Show No Mercy' in r['playback']]
    if not slayer: raise SystemExit('no matching deep Slayer samples')
    for cue in sorted({r['cue_before'] for r in slayer}):
        offsets = sorted({r['scroll_y'] for r in slayer if r['cue_before'] == cue})
        print(f'cue={cue}: scroll_y={offsets}')
    print('pitch/viewport_height:', sorted({(r['pitch'], r['height']) for r in slayer}))
    print('raw_C_plus_20:', sorted({r['content_height'] for r in slayer}))
    print('raw_db_plus_538:', [hex(x) for x in sorted({r['sort'] & 0xffffffff for r in rows})])
    print('lookup_keys:', sorted({r['lookup_key'] for r in slayer}))
    print('cue_copy_mismatches:', sum(r['cue_changed_during_copy'] for r in rows))
    print(f'validated {len(anchors)} code anchors and {len(rows)} complete records; no device access')


if __name__ == '__main__': main()
