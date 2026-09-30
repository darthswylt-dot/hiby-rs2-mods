#!/usr/bin/env python3
"""Read-only stock scroll-route anchors and instruction-level setter checks.

Executes only the content-offset branch of 0x8B43C0 in a small memory model.
The downstream parent invalidation call is mocked, not a simulated UI.
No device connection, firmware output or claim of runtime callback coverage.
"""
import argparse
import hashlib
from pathlib import Path

from mips_static_trace import Elf32, sx16
from test_folderfollow_active_view_rebuild import Machine
from build_folderfollow_safe_pointer_diag import GOLDEN_SHA256, RECOVERED_02FD_SHA256


ANCHORS = {
    0xA98B74: 0x0049B000,  # explorer table's callback at name+0x40
    0x49B110: 0x24020002,  # gesture state 2
    0x49B114: 0x10620018,
    0x49B178: 0x8FA70020,  # computed vertical delta
    0x49B184: 0x0C125A50,  # -> 496940
    0x496974: 0x0C1164D0,  # resolve owner
    0x496988: 0x0C125648,  # validation helper, not bypassed here
    0x4969CC: 0x8E0241E0,
    0x4969D8: 0x8E07007C,
    0x4969DC: 0xAE020080,  # movement state, not +8C refill flag
    0x4969E8: 0x0C12E940,  # -> 4BA500
    0x496A0C: 0x0C12F8F8,  # scrollbar companion
    0x496B2C: 0x0C12E9A8,  # alternate object-position route
    0x4BA51C: 0x8C840050,
    0x4BA528: 0xAC8200F0,
    0x4BA544: 0x0C12E6E8,  # layout limits -> 4B9BA0
    0x4BA574: 0x8E020018,  # current content y
    0x4BA5F4: 0x0C22D0F0,
    0x4BA664: 0x3C070003,
    0x4BA674: 0x0C22D0F0,
    0x4BA678: 0x24E70002,  # 0x30002 relative content y
    0x4BA704: 0x3C070001,
    0x4BA71C: 0x0C22D0F0,
    0x4BA718: 0x24E70002,  # alternate 0x10002 = object position, not content
    0x8B43CC: 0x8C900040,  # parent gate
    0x8B43DC: 0x1460004D,  # content branch
    0x8B4524: 0x8C880018,
    0x8B4550: 0x10A00034,  # flags & 4
    0x8B455C: 0x1080000F,  # flags & 8 clamp
    0x8B4564: 0x8C4A0020,
    0x8B4568: 0x8C470010,
    0x8B45AC: 0xAC430018,
    0x8B45B8: 0x0C22C1B8,  # parent invalidation, not row lookup
    0x8B460C: 0x01031821,  # relative addition
    0x8B462C: 0xAC430018,  # alternate vertical-enabled store
    0x490D3C: 0x8C850018,  # redraw reads current offset
    0x490DB0: 0x0C116610,
    0x490DD4: 0x0C126708,  # explicit visible row refill
    0x499CBC: 0x8E370018,
    0x499CE8: 0x0000B812,  # quotient becomes first row
    0x499D18: 0x02579821,  # first row + visible slot
    0x499D44: 0x0C10C9F0,
    # Resource -> constructor descriptor -> render-object flags/callbacks.
    0x492918: 0x0C10EB40,
    0x492924: 0xAE0200CC,
    0x43AD54: 0x0C1218A8,
    0x43AD58: 0x24A508B4,  # "viewgroup" at 0x9208B4
    0x43AE40: 0x8E42000C,
    0x43AE4C: 0xAFA20030,  # descriptor+18 = resource+0C
    0x43AE50: 0x3C020044,
    0x43AE54: 0x24429EC0,
    0x43AE58: 0xAFA20044,  # descriptor+2C = 439EC0
    0x43AE64: 0x0C22D048,
    0x8B4184: 0x8E220018,
    0x8B4188: 0xAE02003C,
    0x8B418C: 0x8E22002C,
    0x8B4190: 0xAE020048,
    0x8B41DC: 0x10400006,  # extent copied only with bit 4
    0x8B41F0: 0xAE020020,
    # Redraw high bit preserves the low scrolling-mode bits.
    0x8B4390: 0x3C064000,
    0x8B4394: 0x00E63025,
    0x8B4398: 0xAE06003C,
    0x8B46B8: 0x3C07BFFF,
    0x8B46C0: 0x34E7FFFF,
    0x8B46C8: 0x00473824,
    0x8B46E8: 0xAEA7003C,
    # Conditional render dispatch; anchors are not runtime coverage.
    0x8B1514: 0x0C22D198,
    0x8B4958: 0x8EB90048,
    0x8B4990: 0x0320F809,
    0x8B40D0: 0x8ED90048,
    0x8B40E4: 0x0320F809,
    0x439F90: 0x0C10E080,
    0x4382F4: 0x8FD90154,
    0x438300: 0x0320F809,
    0x459528: 0xAC850154,
    0x4928C0: 0x0C116548,
    0x4928C4: 0x24A508A0,
    0x4908E8: 0x8E02008C,
    0x4908F4: 0x8E220078,
    0x490920: 0x0C126708,
    0x49092C: 0xAE00008C,
    0x926BDC: 0x00001001,
    0x926BE0: 0x00451CA0,
    0x451CB8: 0x0C22C508,
}


def signed(value):
    return value - 0x100000000 if value & 0x80000000 else value


class SetterMachine(Machine):
    def __init__(self, elf, *, flags=4, y=0, height=260, extent=1040, parent=True):
        # Reuse only the mock's memory helpers and basic integer instructions.
        self.regions = {}
        self.elf = elf
        self.obj, self.pair, self.parent = 0x1000000, 0x1100000, 0x1200000
        self.map(self.obj, 0x80); self.map(self.pair, 8); self.map(0x2000000, 0x4000)
        for offset, value in {0xC:240,0x10:height,0x14:0,0x18:y,0x1C:240,
                              0x20:extent,0x3C:flags,0x40:self.parent if parent else 0}.items():
            self.put(self.obj+offset,value,4)
        self.calls=[]

    def plain(self,w):
        op,rs,rt,rd=w>>26,(w>>21)&31,(w>>16)&31,(w>>11)&31
        fn=w&63
        if op==12:self.r[rt]=self.r[rs] & (w&65535)
        elif op==10:self.r[rt]=int(signed(self.r[rs]) < sx16(w&65535))
        elif op==0 and fn==0x24:self.r[rd]=self.r[rs] & self.r[rt]
        elif op==0 and fn==0x23:self.r[rd]=(self.r[rs]-self.r[rt])&0xffffffff
        elif op==0 and fn==0x2A:self.r[rd]=int(signed(self.r[rs]) < signed(self.r[rt]))
        elif op==0 and fn in (10,11):
            if (self.r[rt]==0)==(fn==10):self.r[rd]=self.r[rs]
        else:return super().plain(w)
        self.r[0]=0

    def execute(self,value,mode=0x20002):
        if mode not in (0x20002,0x30002):raise ValueError('content-y modes only')
        original_flags=self.get(self.obj+0x3C,4)
        self.put(self.pair+4,value,4)
        self.r=[0]*32;self.r[4:8]=[self.obj,self.pair,0,mode]
        self.r[16:24]=range(0xCA110000,0xCA110008)
        self.r[29]=0x2003000;self.r[31]=0xDEAD0000
        saved=self.r[16:24].copy();pc=0x8B43C0
        for _ in range(256):
            if pc==0xDEAD0000:break
            if not 0x8B43C0<=pc<0x8B4654:raise AssertionError(hex(pc))
            w=self.elf.word(pc);op=w>>26;rs=(w>>21)&31;rt=(w>>16)&31
            if op in (4,5):
                taken=(self.r[rs]==self.r[rt])==(op==4)
                self.plain(self.elf.word(pc+4));pc=pc+4+sx16(w&65535)*4 if taken else pc+8
            elif op==3:
                target=(w&0x3ffffff)<<2;self.r[31]=pc+8
                self.plain(self.elf.word(pc+4))
                if target!=0x8B06E0:raise AssertionError(f'unexpected call {target:#x}')
                assert self.r[4:6]==[self.parent,self.obj+4]
                self.calls.append(target)
                for r in [1,*range(2,16),24,25]:self.r[r]=0xBAD00000+r
                self.r[2]=0;pc=self.r[31]
            elif op==0 and w&63==8:
                target=self.r[rs];self.plain(self.elf.word(pc+4));pc=target
            else:self.plain(w);pc+=4
        else:raise AssertionError('instruction limit')
        assert self.r[16:24]==saved and self.r[29]==0x2003000
        assert self.get(self.obj+0x3C,4)==original_flags
        return signed(self.get(self.obj+0x18,4)),signed(self.r[2]),len(self.calls)


def check(elf):
    if hashlib.sha256(elf.data).hexdigest() not in (GOLDEN_SHA256,RECOVERED_02FD_SHA256):
        raise ValueError('unknown source hash')
    for pc,w in ANCHORS.items():
        if elf.word(pc)!=w:raise AssertionError(f'anchor mismatch {pc:#x}')
    name=b'vg_listview_explorer\0';off=elf.va_to_off(0xA98B34)
    assert elf.data[off:off+len(name)]==name
    resource_name=b'viewgroup\0';off=elf.va_to_off(0x9208B4)
    assert elf.data[off:off+len(resource_name)]==resource_name
    # Expected (new y, return, parent invalidations). These are synthetic
    # flags/extents, not runtime observations of the player's current view.
    cases=[
        ('absolute',dict(flags=4),330,0x20002,(330,0,1)),
        ('relative',dict(flags=4,y=100),33,0x30002,(133,0,1)),
        ('unchanged',dict(flags=4,y=100),100,0x20002,(100,0,0)),
        ('no clamp',dict(flags=4),-25,0x20002,(-25,0,1)),
        ('no upper clamp',dict(flags=4),2000,0x20002,(2000,0,1)),
        ('lower clamp',dict(flags=12,y=100),-25,0x20002,(0,0,1)),
        ('upper clamp',dict(flags=12),2000,0x20002,(780,0,1)),
        ('short extent negative',dict(flags=12,extent=0),100,0x20002,(-260,0,1)),
        ('vertical flag',dict(flags=2),330,0x20002,(330,0,1)),
        ('no vertical flag',dict(flags=0),330,0x20002,(0,0,1)),
        ('horizontal only',dict(flags=1),330,0x20002,(0,0,1)),
        ('no parent',dict(parent=False),330,0x20002,(0,-1,0)),
        ('redraw bit vertical',dict(flags=0x40000002),330,0x20002,(330,0,1)),
        ('redraw bit unclamped',dict(flags=0x40000004),2000,0x20002,(2000,0,1)),
        ('redraw bit clamped',dict(flags=0x4000000C),2000,0x20002,(780,0,1)),
    ]
    for name,kwargs,value,mode,expected in cases:
        actual=SetterMachine(elf,**kwargs).execute(value,mode)
        if actual!=expected:raise AssertionError((name,actual,expected))
    return len(cases)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('elf',type=Path)
    args=p.parse_args();count=check(Elf32(args.elf))
    print(f'PASS: {len(ANCHORS)} anchors, explorer/resource names, {count} actual-instruction setter cases')
    print('Parent invalidation mocked; no runtime callback/lifetime/locking proof; no device access')


if __name__=='__main__':main()
