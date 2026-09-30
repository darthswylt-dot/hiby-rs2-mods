#!/usr/bin/env python3
"""Read-only UI dispatch anchors and actual-instruction refresh callback cases.

Executes 49A1A0, 49A160 and 490B40. Current-view resolution, row refresh and
timer registry operations are mocked. This is not a scheduler/lifetime test.
"""
import argparse
import hashlib
from pathlib import Path

from mips_static_trace import Elf32, sx16
from check_folderfollow_scroll_route import SetterMachine, signed
from build_folderfollow_safe_pointer_diag import GOLDEN_SHA256, RECOVERED_02FD_SHA256


ANCHORS = {
    0x43C9A4: 0x0C115080,  # UI loop -> queued-event dispatcher
    0x43C9E4: 0x0C11CD58,  # same loop -> timer pump
    0x43CA9C: 0x0C11CD58,  # alternate loop also pumps timers
    0x45424C: 0x0C114180,  # dequeue 20-byte message
    0x454250: 0x24060014,
    0x45425C: 0x24846B94,
    0x454260: 0x8FA6001C,  # message+4 event code
    0x454294: 0x8C990004,
    0x4542A0: 0x0320F809,
    0x926BDC: 0x00001001,
    0x926BE0: 0x00451CA0,
    0x451CB8: 0x0C22C508,
    0x47361C: 0x8E190008,  # record+14 callback
    0x473628: 0x8E04FFF4,  # record+00 timer ID
    0x47362C: 0x0320F809,
    0x473630: 0x8E050004,  # record+10 callback data
    0xA98B80: 0x0049B460,  # explorer table name+4C
    0x49B078: 0x0C126858,  # input path cancels ID 20
    0x49B07C: 0x24040014,
    0x49B580: 0x24040064,  # delayed refresh: interval 100, not ID
    0x49B584: 0x0C126490,
    0x49B588: 0x02002821,
    0x49924C: 0x24040014,  # ID 20, NOT interval 20
    0x499258: 0x0C11CDA8,
    0x49926C: 0x3C06004A,
    0x499274: 0x0C11CE28,
    0x499278: 0x24C6A1A0,
    0x499290: 0x0C11CDE8,  # existing timer: reset interval/elapsed
    0x473924: 0xAC450004,
    0x47392C: 0xAC470010,
    0x473938: 0xAC460014,
    0x47386C: 0xAC450004,
    0x473874: 0xAC400008,
    0x49A1B0: 0x0C10F480,  # global controller, ignores callback data
    0x49A1BC: 0x0C1395A0,  # resolve current view at firing time
    0x49A1D0: 0x0C1242D0,
    0x49A1F8: 0x0C126708,
    0x49A1FC: 0x8C8500CC,
    0x49A17C: 0x0C11CE80,  # remove timer after callback
    0x4926D8: 0xAE02008C,  # positively identified constructor writer
    0x490900: 0xAE00008C,
    0x49092C: 0xAE00008C,
}


class RefreshMachine(SetterMachine):
    RANGES = ((0x49A160, 0x49A218), (0x490B40, 0x490B68))

    def __init__(self, elf, *, view=True, flags=1, timer=True, refill_result=0):
        self.elf, self.regions = elf, {}
        self.controller, self.view, self.render = 0x1100000, 0x1200000, 0x1300000
        self.map(self.view, 0x100)
        self.map(0x2000000, 0x4000)
        self.put(self.view+0x70, flags, 4)
        self.put(self.view+0xCC, self.render, 4)
        # +78 and +8C stay zero; only the +70 gate applies in this callback.
        self.current = self.view if view else 0
        self.timer, self.refill_result = timer, refill_result
        self.calls = []

    def plain(self, w):
        rs, rt, rd, fn = (w>>21)&31, (w>>16)&31, (w>>11)&31, w&63
        if w>>26 == 0 and fn in (4, 7):
            if fn == 4:
                self.r[rd] = (self.r[rt] << (self.r[rs]&31)) & 0xFFFFFFFF
            else:
                self.r[rd] = (signed(self.r[rt]) >> (self.r[rs]&31)) & 0xFFFFFFFF
            self.r[0] = 0
        else:
            super().plain(w)

    def mock(self, target):
        a0, a1 = self.r[4:6]
        self.calls.append(target)
        result = 0
        if target == 0x43D200:
            result = self.controller
        elif target == 0x4E5680:
            assert a0 == self.controller
            self.put(a1, self.current, 4)
        elif target == 0x499C20:
            assert (a0, a1) == (self.view, self.render)
            result = self.refill_result
        elif target == 0x4736A0:
            assert a0 == 20
            result = int(self.timer)
        elif target == 0x473A00:
            assert a0 == 20 and self.timer
            self.timer = False
        else:
            raise AssertionError(f'unexpected mock {target:#x}')
        for r in [1, *range(2,16), 24, 25]:
            self.r[r] = 0xBAD00000+r
        self.r[2] = result & 0xFFFFFFFF

    def execute(self):
        self.r = [0]*32
        # Unmapped/stale callback data must not be read by original code.
        self.r[4:6] = [20, 0xDEAD0100]
        self.r[16:24] = range(0xCA110000, 0xCA110008)
        self.r[29], self.r[31] = 0x2003000, 0xDEAD0000
        saved = self.r[16:24].copy()
        pc = 0x49A1A0
        for _ in range(256):
            if pc == 0xDEAD0000:
                break
            assert any(a <= pc < b for a,b in self.RANGES), hex(pc)
            w = self.elf.word(pc)
            op, rs, rt = w>>26, (w>>21)&31, (w>>16)&31
            if op in (4,5):
                taken = (self.r[rs] == self.r[rt]) == (op == 4)
                self.plain(self.elf.word(pc+4))
                pc = pc+4+sx16(w&65535)*4 if taken else pc+8
            elif op == 3:
                target = (w&0x3FFFFFF)<<2
                self.r[31] = pc+8
                self.plain(self.elf.word(pc+4))
                if target in (0x490B40, 0x49A160):
                    pc = target
                else:
                    self.mock(target)
                    pc = self.r[31]
            elif op == 0 and w&63 == 8:
                target = self.r[rs]
                self.plain(self.elf.word(pc+4))
                pc = target
            else:
                self.plain(w)
                pc += 4
        else:
            raise AssertionError('instruction limit')
        assert self.r[16:24] == saved and self.r[29] == 0x2003000
        assert self.get(self.view+0x8C,4) == 0
        return self.calls.count(0x499C20), self.calls.count(0x473A00)


def check(elf):
    if hashlib.sha256(elf.data).hexdigest() not in (GOLDEN_SHA256, RECOVERED_02FD_SHA256):
        raise ValueError('unknown source hash')
    for pc, word in ANCHORS.items():
        assert elf.word(pc) == word, f'anchor mismatch {pc:#x}'
    cases = [
        ('current view, initialization flag clear', {}, (1,1)),
        ('no current view', {'view':False}, (0,1)),
        ('mode disabled', {'flags':0}, (0,1)),
        ('different mode bit', {'flags':2}, (0,1)),
        ('enabled among other bits', {'flags':0x401}, (1,1)),
        ('timer already absent', {'timer':False}, (1,0)),
        ('no view or timer', {'view':False, 'timer':False}, (0,0)),
        ('refill failure still cancels', {'refill_result':-1}, (1,1)),
    ]
    for name, kwargs, expected in cases:
        actual = RefreshMachine(elf, **kwargs).execute()
        assert actual == expected, (name, actual, expected)
    return len(cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    args = parser.parse_args()
    count = check(Elf32(args.elf))
    print(f'PASS: {len(ANCHORS)} anchors, {count} actual-instruction refresh callback cases')
    print('View resolver, row refill and timer registry mocked; no runtime/thread/lifetime proof')


if __name__ == '__main__':
    main()
