#!/usr/bin/env python3
"""Emitted instructions + original setter with mocked external calls; no device."""
import struct
import unittest
from pathlib import Path
import build_folderfollow_move_diag as d
from decode_folderfollow_move_diag import decode, summary
from test_folderfollow_scroll_diag import Probe as SnapshotProbe
from mips_static_trace import Elf32, sx16
from verify_folderfollow_move_diag import verify

ROOT=Path(__file__).resolve().parents[1]
# Keep the original workstation layout usable, and find the hash-verified
# reference in its preserved import location on the current workstation.
SOURCES=(ROOT/'artifacts/import-20261001/hiby_player_02fd.bin',
         ROOT.parent/'hiby_player_02fd.bin')
SOURCE=next((path for path in SOURCES if path.is_file()), SOURCES[0])
BUFFER=0xBD4000


def signed(x):return x-(1<<32) if x&0x80000000 else x


class Probe(SnapshotProbe):
    def __init__(self, name='vg_listview_explorer'):
        super().__init__(name)
        self.map(BUFFER,d.HEADER+d.RECORD*d.CAPACITY)
        self.obj,self.pair=0x1400000,0x1500000
        self.map(self.obj,0x54);self.map(self.pair,16)
        self.put(self.obj+0x40,0x1600000,4)
        self.put(self.obj+0x3C,4,4);self.put(self.obj+0x10,260,4);self.put(self.obj+0x20,1040,4)
        self.put(self.view+0xCC,self.obj,4);self.put(self.view+0x4C,80,4)
        self.put(self.view+0x70,1,4);self.put(self.view+0x8C,1,4)
        self.code,self.labels=d.assemble(BUFFER)
        self.words=struct.unpack('<%dI'%(len(self.code)//4),self.code)
        self.sc_failures=0;self.outputs=[];self.write_results=[];self.invalidation_calls=[]
        self.union_calls=[]
        self.stock=Elf32(SOURCE) if SOURCE.exists() else None
        self.patched=True;self.hilo=(0x12345678,0x87654321)

    def plain(self,w):
        op,rs,rt,rd=w>>26,(w>>21)&31,(w>>16)&31,(w>>11)&31
        fn=w&63;address=(self.r[rs]+sx16(w&65535))&0xFFFFFFFF
        if w==15:return
        if op==0 and fn==0:self.r[rd]=(self.r[rt]<<((w>>6)&31))&0xFFFFFFFF
        elif op==12:self.r[rt]=self.r[rs]&(w&65535)
        elif op==10:self.r[rt]=int(signed(self.r[rs])<sx16(w&65535))
        elif op==11:self.r[rt]=int(self.r[rs]<(sx16(w&65535)&0xFFFFFFFF))
        elif op==0 and fn==0x24:self.r[rd]=self.r[rs]&self.r[rt]
        elif op==0 and fn==0x23:self.r[rd]=(self.r[rs]-self.r[rt])&0xFFFFFFFF
        elif op==0 and fn==0x2A:self.r[rd]=int(signed(self.r[rs])<signed(self.r[rt]))
        elif op==0 and fn in (10,11):
            if (self.r[rt]==0)==(fn==10):self.r[rd]=self.r[rs]
        elif op==0x30:self.r[rt]=self.get(address,4)
        elif op==0x38:
            if self.sc_failures:self.sc_failures-=1;self.r[rt]=0
            else:self.put(address,self.r[rt],4);self.r[rt]=1
        else:return super().plain(w)
        self.r[0]=0

    def word(self,pc):
        if d.CODE<=pc<d.CODE+len(self.code):return self.words[(pc-d.CODE)//4]
        if self.patched and pc in (0x8B43C0,0x8B43C4):
            return (0x08000000|(self.labels['setter']>>2)) if pc==0x8B43C0 else 0
        assert self.stock is not None
        return self.stock.word(pc)

    def external(self,target):
        if target==0x8B06E0:
            assert self.r[4]==0x1600000
            rectangle=self.r[5]
            self.invalidation_calls.append(tuple(self.get(rectangle+i,4) for i in (0,4,8,12)));result=0
        elif target==0x8B3140:
            assert self.r[4]==self.r[5] and self.r[6]==self.obj+4
            self.union_calls.append(tuple(self.get(self.r[4]+i,4) for i in (0,4,8,12)))
            result=0  # Identical deterministic union stub for both executions.
        elif target==d.b.WRITE_PLT:
            assert self.r[4]==9
            data,off=self.region(self.r[5],self.r[6]);raw=bytes(data[off:off+self.r[6]])
            result=self.write_results.pop(0) if self.write_results else len(raw)
            # Model actual bytes exported, including a short write.
            self.outputs.append(raw[:max(0,result)])
        else:
            super().call(target);return
        for r in [1,*range(2,16),24,25]:self.r[r]=0xBAD00000+r
        self.r[2]=result&0xFFFFFFFF

    def registers(self):
        self.r=[0]+[0xCA110000+i for i in range(1,32)]
        self.r[29],self.r[31]=0x2003000,0xDEAD0000

    def run_at(self,pc,stop=0xDEAD0000):
        for _ in range(20000):
            if pc==stop:return
            w=self.word(pc);op=w>>26;rs=(w>>21)&31;rt=(w>>16)&31
            if op in (4,5):
                yes=(self.r[rs]==self.r[rt])==(op==4)
                self.plain(self.word(pc+4));pc=pc+4+sx16(w&65535)*4 if yes else pc+8
            elif op in (2,3) or (op==0 and w&63 in (8,9)):
                target=(w&0x3FFFFFF)<<2 if op in (2,3) else self.r[rs]
                link=op==3 or (op==0 and w&63==9)
                if link:self.r[31]=pc+8
                self.plain(self.word(pc+4))
                if link and not (d.CODE<=target<d.CODE+len(self.code) or 0x8B43C0<=target<0x8B4654):
                    self.external(target);pc=self.r[31]
                else:pc=target
            else:self.plain(w);pc+=4
        raise AssertionError('instruction limit')

    def setter(self,value=330,mode=0x20002):
        self.registers();self.put(self.pair+4,value,4)
        self.r[4:8]=[self.obj,self.pair,0,mode]
        self.run_at(0x8B43C0)
        assert self.hilo==(0x12345678,0x87654321)

    def refresh(self):
        self.registers();self.r[16:18]=[self.view,self.obj]
        self.r[29]=0x2001000;self.put(self.r[29]+0xED4,0x49A200,4)
        before=self.r.copy()
        self.run_at(self.labels['refresh'],0x499CBC)
        before[22]=260;before[2]=80
        assert self.r==before

    def timer(self):
        self.registers();self.r[4:6]=[10,self.context];before=self.r.copy()
        self.run_at(self.labels['timer'])
        assert self.r[2]==0x13579 and self.r[16:24]==before[16:24] and self.r[29]==before[29]

    def events(self):
        count=self.get(BUFFER,4)
        return list(decode(bytes(self.regions[BUFFER][d.HEADER:d.HEADER+count*d.RECORD])))


class Tests(unittest.TestCase):
    @unittest.skipUnless(SOURCE.exists(),'reference ELF not available')
    def test_original_setter_equivalence(self):
        for flags,y,value,mode in [(4,0,330,0x20002),(4,100,33,0x30002),
                (4,100,100,0x20002),(12,0,2000,0x20002),(2,0,330,0x20002),
                (0,0,330,0x20002),(0x40000004,0,-25,0x20002),(4,0,30,0x20003)]:
            with self.subTest(flags=flags,mode=mode):
                baseline,probe=Probe(),Probe();baseline.patched=False
                for m in (baseline,probe):
                    m.put(m.obj+0x3C,flags,4);m.put(m.obj+0x18,y,4);m.setter(value,mode)
                self.assertEqual(probe.r,baseline.r)
                self.assertEqual(probe.regions[probe.obj],baseline.regions[baseline.obj])
                self.assertEqual(probe.invalidation_calls,baseline.invalidation_calls)
                r=probe.events()[0]
                self.assertEqual((r['old_y'],r['new_y'],r['requested_y']),(y,signed(probe.get(probe.obj+0x18,4)),value))
                self.assertEqual(r['result'],signed(baseline.r[2]))
                self.assertEqual(r['flags'],flags)

    @unittest.skipUnless(SOURCE.exists(),'reference ELF not available')
    def test_no_parent_does_not_read_invalid_request(self):
        m=Probe();m.put(m.obj+0x40,0,4);m.registers();m.r[4:8]=[m.obj,0xDEAD0400,0,0x20002]
        m.run_at(0x8B43C0);self.assertEqual(m.r[2],0xFFFFFFFF);self.assertEqual(m.events(),[])

    @unittest.skipUnless(SOURCE.exists(),'reference ELF not available')
    def test_non_content_mode_filtered(self):
        m=Probe();m.put(m.obj+0x40,0,4);m.setter(mode=0x10002)
        self.assertEqual(m.events(),[])

    @unittest.skipUnless(SOURCE.exists(),'reference ELF not available')
    def test_other_geometry_modes_preserve_original_execution(self):
        for mode in (0x10002,0x00002,0x1000F,0x0000F):
            with self.subTest(mode=mode):
                baseline,probe=Probe(),Probe();baseline.patched=False
                for m in (baseline,probe):m.setter(33,mode)
                self.assertEqual(probe.r,baseline.r)
                self.assertEqual(probe.regions[probe.obj],baseline.regions[baseline.obj])
                self.assertEqual(probe.invalidation_calls,baseline.invalidation_calls)
                self.assertEqual(probe.union_calls,baseline.union_calls)
                self.assertEqual(probe.events(),[])

    def test_refresh_context_and_registers(self):
        m=Probe();m.refresh();r=m.events()[0]
        self.assertEqual((r['kind'],r['caller'],r['view'],r['object']),('refresh',0x49A200,m.view,m.obj))
        self.assertEqual((r['pitch'],r['view_flags'],r['view_8c'],r['cue_before']),(80,1,1,7))
        self.assertIsNone(r['new_y'])

    def test_hot_refresh_has_no_calls_or_object_writes(self):
        m=Probe();before={k:bytes(v) for k,v in m.regions.items() if k not in (BUFFER,0x2000000)}
        m.refresh();self.assertEqual(m.calls,[])
        self.assertEqual(before,{k:bytes(v) for k,v in m.regions.items() if k not in (BUFFER,0x2000000)})

    def test_buffer_last_slot_and_retry(self):
        m=Probe();m.put(BUFFER,d.CAPACITY-1,4);m.sc_failures=7;m.refresh()
        self.assertEqual(m.get(BUFFER,4),d.CAPACITY);self.assertEqual(m.get(BUFFER+12,4),0)
        m.refresh();self.assertEqual(m.get(BUFFER+8,4),1)

    def test_retry_limit_and_loss(self):
        m=Probe();m.sc_failures=8;m.refresh()
        self.assertEqual(m.get(BUFFER,4),0);self.assertEqual(m.get(BUFFER+12,4),1)

    @unittest.skipUnless(SOURCE.exists(),'reference ELF not available')
    def test_setter_survives_logging_loss(self):
        for full in (True,False):
            a,m=Probe(),Probe();a.patched=False
            if full:m.put(BUFFER,d.CAPACITY,4)
            else:m.sc_failures=8
            a.setter();m.setter();self.assertEqual(a.r,m.r)
            self.assertEqual(a.regions[a.obj],m.regions[m.obj])

    def test_snapshot_and_eight_event_drain_limit(self):
        m=Probe()
        for _ in range(10):m.refresh()
        m.timer();self.assertEqual(m.get(BUFFER+4,4),8)
        m.timer();self.assertEqual(m.get(BUFFER+4,4),10)
        m.timer();rows=list(decode(b''.join(m.outputs)))
        self.assertTrue(summary(rows)['accepted_prefix'])
        self.assertEqual(summary(rows)['counts'],{'setter':0,'refresh':10,'snapshot':3})
        snaps=[r for r in rows if r['kind']=='snapshot']
        self.assertEqual([r['tick'] for r in snaps],[1,2,3])
        self.assertTrue(all(r['name']=='vg_listview_explorer' for r in snaps))
        self.assertEqual(snaps[0]['viewport'],m.obj)

    def test_unpublished_head_blocks_drain(self):
        m=Probe();m.put(BUFFER,1,4);m.timer()
        self.assertEqual(m.get(BUFFER+4,4),0)
        self.assertFalse(summary(decode(b''.join(m.outputs)))['accepted_prefix'])

    def test_write_failure_freezes_drain(self):
        for results in ([-1],[7],[d.snap.SIZE,-1],[d.snap.SIZE,32,-1]):
            m=Probe();m.refresh();m.write_results=list(results);m.timer()
            exported=len(m.outputs);m.timer()
            self.assertEqual(m.get(BUFFER+16,4),1);self.assertEqual(len(m.outputs),exported)
            self.assertEqual(m.get(BUFFER+4,4),0)

    def test_non_explorer_snapshot_and_null_context(self):
        for absent in (False,True):
            m=Probe('playing_plane');m.map(m.view,64);m.bytes(m.view,b'playing_plane\0')
            if absent:m.context=0
            m.timer();rows=list(decode(b''.join(m.outputs)))
            self.assertEqual(rows[0]['explorer_valid'],0)

    def test_cue_race_and_clock_failure(self):
        m=Probe();m.change_cue=True;m.clock_result=-1;m.timer()
        row=list(decode(b''.join(m.outputs)))[0]
        self.assertTrue(row['cue_changed_during_copy']);self.assertEqual(row['time'],(0,0))

    def test_decoder_corruption_and_mixed_runs(self):
        m=Probe();m.refresh();m.timer();m.timer();data=b''.join(m.outputs)
        for damaged in (data[:-1],b'BAD!'+data[4:],data[:4]+struct.pack('<I',1)+data[8:]):
            with self.assertRaises(ValueError):list(decode(damaged))
        self.assertFalse(summary(decode(data+data))['accepted_prefix'])
        self.assertFalse(summary([])['accepted_prefix'])

    def test_reported_loss_rejects_prefix(self):
        m=Probe();m.put(BUFFER+12,1,4);m.timer()
        self.assertFalse(summary(decode(b''.join(m.outputs)))['accepted_prefix'])

    @unittest.skipUnless(SOURCE.exists(),'reference ELF not available')
    def test_build_scope_and_reproducibility(self):
        source=SOURCE.read_bytes();out,meta=d.build(source);result=verify(source,out)
        self.assertLessEqual(meta['code_bytes'],d.b.CAVE_CAPACITY)
        self.assertEqual(result['size'],len(source))
        corrupted=bytearray(out);corrupted[0x100]^=1
        with self.assertRaises(ValueError):verify(source,bytes(corrupted))
        with self.assertRaises((ValueError,SystemExit)):d.build(bytes(corrupted))


if __name__=='__main__':unittest.main()
