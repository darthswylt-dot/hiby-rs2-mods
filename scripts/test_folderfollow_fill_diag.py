#!/usr/bin/env python3
"""Execute emitted MIPS with mocked stock calls; no device access."""
import struct
import unittest
from pathlib import Path
import build_folderfollow_fill_diag as d
from test_folderfollow_active_view_rebuild import Machine
from decode_folderfollow_fill_diag import decode, sessions

BUFFER=0xBD4000


class Probe(Machine):
    def __init__(self):
        super().__init__()
        self.map(BUFFER,d.HEADER+d.RECORD*d.CAPACITY)
        self.listptr=0x1800000;self.map(self.listptr,0x40)
        self.folder=0x1900000;self.map(self.folder,0x208);self.wide(self.folder,'a:\\Slayer\\*')
        self.code,self.labels=d.assemble(BUFFER)
        self.words=struct.unpack('<%dI'%(len(self.code)//4),self.code)
        self.calls=[];self.writes=[];self.sc_failures=0;self.write_result=None;self.append_result=None
        self.mode=0;self.write_results=[]
        self.frame=0x2001000
        self.put(self.frame+0xACC,0x6F8BF4,4);self.put(self.frame+0xAD8,0,4)
        self.put(self.frame+0xAE4,self.folder,4)
        self.wide(self.frame+0x24,'a:\\Slayer\\song.flac');self.put(self.frame+0x444,5,4)
        self.put(self.frame+0xAC8,0xF00D0030,4);self.put(self.frame+0xAC4,0xF00D0023,4)

    def registers(self,kind,ordinal=0,result=0):
        self.r=[0]+[0x11000000+i for i in range(1,32)]
        self.r[29]=self.frame;self.r[16]=0x1700000;self.r[22]=self.listptr;self.r[23]=self.mode
        self.r[17]=ordinal;self.r[2]=result
        if kind=='row': self.r[4:6]=[self.listptr,self.frame+0x20];self.r[25]=0x455DA0;self.r[31]=0x6ED6F0
        if kind=='terminal':self.r[4]=self.r[16];self.r[31]=0x6ED70C
        self.before=self.r.copy()

    def plain(self,w):
        op,rs,rt,rd=w>>26,(w>>21)&31,(w>>16)&31,(w>>11)&31
        imm=w&65535; signed=imm-65536 if imm&32768 else imm
        if w==15:return  # SYNC, ordering tested structurally, not simulated CPU
        if op==0 and w&63==0:
            self.r[rd]=(self.r[rt]<<((w>>6)&31))&0xffffffff
        elif op==11:self.r[rt]=int(self.r[rs]<(signed&0xffffffff))
        elif op==0x30:self.r[rt]=self.get((self.r[rs]+signed)&0xffffffff,4)
        elif op==0x38:
            if self.sc_failures:self.sc_failures-=1;self.r[rt]=0
            else:self.put((self.r[rs]+signed)&0xffffffff,self.r[rt],4);self.r[rt]=1
        else:return super().plain(w)
        self.r[0]=0

    def external(self,target):
        self.calls.append(target)
        if target==0x455DA0:
            assert self.r[4:6]==[self.listptr,self.frame+0x20]
            count=self.get(self.listptr+12,4)
            result=count if self.append_result is None else self.append_result
            if result>=0:self.put(self.listptr+12,count+1,4)
        elif target==d.b.ORIGINAL_CALLBACK:result=0x13579
        elif target==d.b.WRITE_PLT:
            assert self.r[4]==9
            raw,off=self.region(self.r[5],self.r[6]);self.writes.append(bytes(raw[off:off+self.r[6]]))
            result=self.r[6] if self.write_result is None else self.write_result
            if self.write_results:result=self.write_results.pop(0)
        else:raise AssertionError(hex(target))
        for r in d.VOLATILE:
            if r!=31:self.r[r]=0xBAD00000+r
        self.r[2]=result&0xffffffff
        self.after_call=self.r.copy()

    def execute(self,kind,ordinal=0,result=0):
        self.registers(kind,ordinal,result)
        if kind=='timer':self.r[31]=0xDEAD0000;self.before=self.r.copy()
        pc=self.labels[kind]
        stops={'begin':0x6ED62C,'row':0x6ED6F0,'terminal':0x5C31C0,'end':0x6ED7DC,'timer':0xDEAD0000}
        for _ in range(30000):
            if pc==stops[kind]:break
            assert d.CODE<=pc<d.CODE+len(self.code),hex(pc)
            i=(pc-d.CODE)//4;w=self.words[i];op=w>>26;rs=(w>>21)&31;rt=(w>>16)&31
            if op in (4,5):
                yes=(self.r[rs]==self.r[rt])==(op==4)
                rel=w&65535;rel=rel-65536 if rel&32768 else rel
                self.plain(self.words[i+1]);pc=pc+4+rel*4 if yes else pc+8
            elif op in (2,3) or (op==0 and w&63 in (8,9)):
                target=(w&0x3ffffff)<<2 if op in (2,3) else self.r[rs]
                link=op==3 or (op==0 and w&63==9)
                if link:self.r[31]=pc+8
                self.plain(self.words[i+1])
                if link and not d.CODE<=target<d.CODE+len(self.code):
                    self.external(target);pc=self.r[31]
                else:pc=target
            else:self.plain(w);pc+=4
        else:raise AssertionError('instruction limit')
        assert self.r[29]==self.frame
        if kind=='timer':
            assert self.r[2]==0x13579 and self.r[16:24]==self.before[16:24]
        else:
            expected=self.after_call.copy() if kind=='row' else self.before.copy()
            if kind=='row': expected[29]=self.frame;expected[31]=0x6ED6F0
            if kind=='begin':
                expected[18]=(expected[18]-19672)&0xffffffff;expected[20]=(expected[20]-15040)&0xffffffff
            if kind=='end':expected[30]=0xF00D0030;expected[23]=0xF00D0023
            assert self.r==expected,[(i,hex(x),hex(y)) for i,(x,y) in enumerate(zip(self.r,expected)) if x!=y]

    def records(self):
        n=self.get(BUFFER,4)
        return list(decode(bytes(self.regions[BUFFER][d.HEADER:d.HEADER+n*d.RECORD])))


class Tests(unittest.TestCase):
    def test_complete_session_and_timer(self):
        m=Probe();m.execute('begin',1);m.execute('row');m.execute('terminal',1,101);m.execute('end',1,1)
        self.assertEqual([r['kind'] for r in m.records()],['begin','row','terminal','end'])
        self.assertEqual(m.records()[1]['cue'],5)
        for _ in range(6):m.execute('timer')
        decoded=list(decode(b''.join(m.writes))); report=list(sessions(decoded))
        self.assertTrue(report[0]['accepted_snapshot'],report)
        self.assertEqual(report[0]['mapping'][0]['index'],0)

    def test_append_failure_and_terminal_error(self):
        m=Probe();m.execute('begin',1);m.append_result=-1;m.execute('row');m.execute('terminal',1,5);m.execute('end',1,1)
        for _ in range(6):m.execute('timer')
        report=list(sessions(decode(b''.join(m.writes))))
        self.assertFalse(report[0]['accepted_snapshot'])

    def test_scope_filter(self):
        m=Probe();m.put(m.frame+0xACC,0x123456,4);m.execute('begin',10)
        self.assertEqual(m.get(BUFFER,4),0)

    def test_mode_filter_and_date_caller(self):
        m=Probe();m.mode=1;m.execute('begin',10)
        self.assertEqual(m.get(BUFFER,4),0)
        m.mode=0;m.put(m.frame+0xACC,0x6F8E0C,4);m.execute('begin',10)
        self.assertEqual(m.records()[0]['caller'],0x6F8E0C)

    def test_last_slot_and_retry_success(self):
        m=Probe();m.put(BUFFER,d.CAPACITY-1,4);m.sc_failures=7;m.execute('begin',1)
        self.assertEqual(m.get(BUFFER,4),d.CAPACITY)
        self.assertEqual(m.get(BUFFER+12,4),0)
        start=d.HEADER+(d.CAPACITY-1)*d.RECORD
        row=list(decode(bytes(m.regions[BUFFER][start:start+d.RECORD])))[0]
        self.assertEqual(row['seq'],d.CAPACITY-1)

    def test_contention_and_capacity(self):
        m=Probe();m.sc_failures=8;m.execute('begin',1)
        self.assertEqual(m.get(BUFFER,4),0);self.assertEqual(m.get(BUFFER+12,4),1)
        m.put(BUFFER,d.CAPACITY,4);m.execute('begin',1)
        self.assertEqual(m.get(BUFFER+8,4),1);self.assertEqual(m.get(BUFFER,4),d.CAPACITY)

    def test_unpublished_slot_not_read(self):
        m=Probe();m.put(BUFFER,1,4);m.execute('timer')
        self.assertEqual(len(m.writes),1);self.assertEqual(m.get(BUFFER+4,4),0)

    def test_io_error_disables_drain(self):
        for result in (-1,0,7):
            m=Probe();m.execute('begin',1);m.write_result=result;m.execute('timer');m.execute('timer')
            self.assertEqual(m.get(BUFFER+16,4),1);self.assertEqual(len(m.writes),1)

    def test_record_write_failure_does_not_advance(self):
        m=Probe();m.execute('begin',1);m.write_results=[32,-1];m.execute('timer');m.execute('timer')
        self.assertEqual(m.get(BUFFER+4,4),0)
        self.assertEqual(m.get(BUFFER+16,4),1);self.assertEqual(len(m.writes),2)

    def test_decoder_rejects_unsettled_or_lossy(self):
        m=Probe();m.execute('begin',1);m.execute('row');m.execute('terminal',1,101);m.execute('end',1,1)
        for _ in range(4):m.execute('timer')
        rows=list(decode(b''.join(m.writes)))
        self.assertFalse(list(sessions(rows))[0]['accepted_snapshot'])
        m.execute('timer');rows=list(decode(b''.join(m.writes)))
        self.assertTrue(list(sessions(rows))[0]['accepted_snapshot'])
        rows[-1]['overflow']=1
        self.assertFalse(list(sessions(rows))[0]['accepted_snapshot'])

    def test_decoder_rejects_duplicate_and_scope(self):
        m=Probe();m.execute('begin',2);m.execute('row');m.execute('row',1)
        m.execute('terminal',2,101);m.execute('end',2,2)
        for _ in range(6):m.execute('timer')
        rows=list(decode(b''.join(m.writes)))
        report=list(sessions(rows))[0]
        self.assertIn('duplicate path/cue',report['errors'])
        next(r for r in rows if r['kind']=='begin')['mode']=9
        self.assertIn('invalid begin',list(sessions(rows))[0]['errors'])

    def test_nonzero_offset_mapping(self):
        m=Probe();m.put(m.frame+0xAD8,24,4);m.execute('begin',1);m.execute('row')
        m.execute('terminal',1,101);m.execute('end',1,1)
        for _ in range(5):m.execute('timer')
        report=list(sessions(decode(b''.join(m.writes))))[0]
        self.assertTrue(report['accepted_snapshot']);self.assertEqual(report['mapping'][0]['index'],24)

    def test_empty_completed_query(self):
        m=Probe();m.execute('begin',10);m.execute('terminal',0,101);m.execute('end',0,0)
        for _ in range(4):m.execute('timer')
        report=list(sessions(decode(b''.join(m.writes))))[0]
        self.assertTrue(report['accepted_snapshot']);self.assertEqual(report['mapping'],[])

    def test_bind_failure_without_terminal_is_not_empty_success(self):
        m=Probe();m.execute('begin',10);m.execute('end',0,0)
        for _ in range(3):m.execute('timer')
        report=list(sessions(decode(b''.join(m.writes))))[0]
        self.assertFalse(report['accepted_snapshot'])
        self.assertIn('query completion not confirmed',report['errors'])

    def test_clear_same_address_is_new_snapshot(self):
        m=Probe()
        for cue in (5,6):
            m.put(m.listptr+12,0,4);m.put(m.frame+0x444,cue,4)
            m.execute('begin',1);m.execute('row');m.execute('terminal',1,101);m.execute('end',1,1)
        for _ in range(9):m.execute('timer')
        report=list(sessions(decode(b''.join(m.writes))))
        self.assertEqual(len(report),2);self.assertTrue(all(r['accepted_snapshot'] for r in report))
        self.assertEqual([r['mapping'][0]['cue'] for r in report],[5,6])

    def test_unknown_source_rejected(self):
        with self.assertRaises(SystemExit):d.build(b'not the known ELF')

    def test_long_path_is_marked(self):
        m=Probe();m.bytes(m.folder,('Ж'*260).encode('utf-16le'));m.execute('begin',1)
        r=m.records()[0];self.assertEqual(r['truncated'],1);self.assertEqual(len(r['path']),259)

    def test_decoder_rejects_partial(self):
        m=Probe();m.execute('begin',1)
        raw=bytes(m.regions[BUFFER][d.HEADER:d.HEADER+d.RECORD])
        with self.assertRaises(ValueError):list(decode(raw[:-1]))


if __name__=='__main__':unittest.main()
