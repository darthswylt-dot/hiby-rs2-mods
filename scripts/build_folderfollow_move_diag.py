#!/usr/bin/env python3
"""MOVE v2: passive content-y transactions, row refresh and MSNP snapshots.

No deployment. Hot probes make no extra external call or object write.
Uses the previously tested SCRL snapshot wrapper, with a fail-closed writer.
"""
import argparse
import hashlib
import struct
from pathlib import Path
import build_folderfollow_scroll_diag as snap
from build_folderfollow_fill_diag import Asm, shift

b = snap.b
BASE, CODE = 0x400000, b.CAVE_VADDR
RECORD, HEADER, CAPACITY = 0x60, 0x40, 1024
FRAME = 0x50
REGS = [2,4,8,9,10,11,12,13,14,31]
SAVE = {r:0x20+i*4 for i,r in enumerate(REGS)}
HOOKS = {'setter':(0x8B43C0,[0x27BDFFD0,0xAFBF002C]),
         'refresh':(0x499CB4,[0x8E360010,0x8E02004C])}
EVENT_MAGIC, STATUS_MAGIC, SNAP_MAGIC = 0x45564F4D, 0x5354534D, 0x504E534D


def layout(source):
    phoff=struct.unpack_from('<I',source,0x1C)[0]
    stride,count=struct.unpack_from('<HH',source,0x2A)
    loads=[]
    for i in range(count):
        off=phoff+i*stride;p=struct.unpack_from('<8I',source,off)
        if p[0]==1:loads.append((off,p))
    off,p=max(loads,key=lambda item:item[1][2]+item[1][5])
    if p[6]!=6:raise ValueError('last ELF load must be RW')
    buffer=(p[2]+p[5]+4095)&~4095
    return off+20,buffer+HEADER+RECORD*CAPACITY-p[2],buffer


def assemble(buffer):
    a=Asm();a.label('timer')
    prefix=snap.build_wrapper()
    a.w=list(struct.unpack('<%dI'%(len(prefix)//4),prefix))
    writes=[i for i,w in enumerate(a.w) if w==b.jal(b.WRITE_PLT)]
    if len(writes)!=1:raise ValueError('snapshot write call changed')
    a.fix.append((writes[0],'jump','drain',3,0,0))
    def save():
        a.e(b.addiu(29,29,-FRAME))
        for r,off in SAVE.items():a.e(b.sw(r,off,29))
    def restore(pop=True):
        for r,off in SAVE.items():a.e(b.lw(r,off,29))
        if pop:a.e(b.addiu(29,29,FRAME))
    def field(src,off,dst):a.e(b.lw(9,off,src),b.sw(9,dst,2))
    def cue(dst):a.abs(8,0xADD88C);field(8,0,dst)
    def common():
        # C is r8; no pointer is retained outside its original invocation.
        a.e(b.sw(8,20,2))
        for src,dst in [(0x18,36),(0x3C,44),(0x40,48),(0x10,52),(0x20,56)]:field(8,src,dst)
        a.abs(8,buffer);field(8,20,84)
        cue(76)
    def publish():
        a.e(15);a.abs(9,EVENT_MAGIC);a.e(b.sw(9,0,2))

    a.label('setter');save()
    a.e(b.sw(0,0x18,29))
    # All content-y requests, including combined x/y modes; no name filter.
    a.abs(8,0x20002);a.e(b.r_type(7,8,9,0x24))
    a.branch(5,9,8,'setter_original');a.branch(4,4,0,'setter_original')
    a.branch(4,5,0,'setter_original')
    # Stock returns before reading the request when parent is absent.
    a.e(b.lw(8,0x40,4));a.branch(4,8,0,'setter_original')
    a.e(b.addiu(4,0,1));a.jump('reserve',True)
    a.branch(4,2,0,'setter_original')
    a.e(b.sw(2,0x18,29),b.lw(8,SAVE[31],29),b.sw(8,16,2),
        b.sw(7,28,2));field(5,4,32)
    a.e(b.lw(8,SAVE[4],29));common()
    a.label('setter_original');restore(False)
    a.jump('original_setter',True)
    # Preserve all scratch registers/result AFTER the original call too.
    save();a.e(b.lw(2,FRAME+0x18,29))
    a.branch(4,2,0,'setter_return')
    a.e(b.lw(8,20,2));field(8,0x18,40)
    a.e(b.lw(9,SAVE[2],29),b.sw(9,60,2));cue(80);publish()
    a.label('setter_return');restore()
    a.e(b.lw(31,SAVE[31],29),b.addiu(29,29,FRAME),b.r_type(31,0,0,8),0)
    a.label('original_setter');a.e(*HOOKS['setter'][1]);a.jump(0x8B43C8)

    a.label('refresh');save()
    a.e(b.addiu(4,0,2));a.jump('reserve',True)
    a.branch(4,2,0,'refresh_return')
    a.e(b.lw(8,FRAME+0xED4,29),b.sw(8,16,2),b.sw(16,24,2),b.move(8,17))
    common()
    for src,dst in [(0x4C,64),(0x70,68),(0x8C,72)]:field(16,src,dst)
    publish()
    a.label('refresh_return');restore();a.e(*HOOKS['refresh'][1]);a.jump(0x499CBC)

    a.label('reserve');a.abs(10,buffer);a.e(b.addiu(11,0,8))
    a.label('retry')
    a.e(b.i_type(0x30,10,12,0),b.i_type(11,12,13,CAPACITY))
    a.branch(4,13,0,'overflow')
    a.e(b.addiu(13,12,1),b.i_type(0x38,10,13,0))
    a.branch(5,13,0,'reserved')
    a.e(b.addiu(11,11,-1));a.branch(5,11,0,'retry')
    a.e(b.addiu(13,0,1),b.sw(13,12,10));a.jump('reserve_fail')
    a.label('overflow');a.e(b.addiu(13,0,1),b.sw(13,8,10))
    a.label('reserve_fail');a.e(b.move(2,0),b.r_type(31,0,0,8),0)
    a.label('reserved')
    a.e(shift(13,12,6),shift(14,12,5),b.r_type(13,14,13,0x21),
        b.r_type(10,13,2,0x21),b.addiu(2,2,HEADER),b.addiu(9,0,2),
        b.sw(9,4,2),b.sw(4,8,2),b.sw(12,12,2),b.r_type(31,0,0,8),0)

    # Called in place of SCRL's WRITE. Preserve its S registers/return contract.
    # First MSNP, then status, then up to 8 already-published MOVE records.
    a.label('drain')
    a.e(b.addiu(29,29,-0x50),b.sw(31,0x4C,29),b.sw(16,0x48,29),
        b.sw(17,0x44,29),b.sw(18,0x40,29));a.abs(16,buffer)
    a.e(b.lw(8,16,16));a.branch(5,8,0,'drain_done')
    a.e(b.lw(8,20,16),b.addiu(8,8,1),b.sw(8,20,16),b.sw(8,0x70,5))
    a.abs(8,SNAP_MAGIC);a.e(b.sw(8,0,5),b.addiu(8,0,2),b.sw(8,4,5))
    a.jump(b.WRITE_PLT,True);a.e(b.addiu(8,0,snap.SIZE));a.branch(5,2,8,'io_error')
    a.abs(8,STATUS_MAGIC);a.e(b.sw(8,0x20,29),b.addiu(8,0,2),b.sw(8,0x24,29))
    for src,dst in [(0,0x28),(4,0x2C),(8,0x30),(12,0x34),(16,0x38)]:
        a.e(b.lw(8,src,16),b.sw(8,dst,29))
    a.e(b.addiu(8,0,CAPACITY),b.sw(8,0x3C,29),b.addiu(4,0,9),
        b.addiu(5,29,0x20),b.addiu(6,0,32));a.jump(b.WRITE_PLT,True)
    a.e(b.addiu(8,0,32));a.branch(5,2,8,'io_error')
    a.e(b.addiu(18,0,8))
    a.label('drain_next');a.e(b.lw(17,4,16),b.lw(8,0,16));a.branch(4,17,8,'drain_done')
    a.e(shift(8,17,6),shift(9,17,5),b.r_type(8,9,8,0x21),b.r_type(16,8,5,0x21),
        b.addiu(5,5,HEADER),b.lw(8,0,5));a.abs(9,EVENT_MAGIC)
    a.branch(5,8,9,'drain_done');a.e(15,b.addiu(4,0,9),b.addiu(6,0,RECORD))
    a.jump(b.WRITE_PLT,True);a.e(b.addiu(8,0,RECORD));a.branch(5,2,8,'io_error')
    a.e(b.addiu(17,17,1),b.sw(17,4,16),b.addiu(18,18,-1))
    a.branch(5,18,0,'drain_next');a.jump('drain_done')
    a.label('io_error');a.e(b.addiu(8,0,1),b.sw(8,16,16))
    a.label('drain_done')
    a.e(b.lw(18,0x40,29),b.lw(17,0x44,29),b.lw(16,0x48,29),
        b.lw(31,0x4C,29),b.r_type(31,0,0,8),b.addiu(29,29,0x50))
    code=a.finish()
    if len(code)>b.CAVE_CAPACITY:raise ValueError(f'cave overflow {len(code):#x}')
    return code,a.labels


def build(source):
    golden,_=b.normalize_source(source)
    sizeoff,memsize,buffer=layout(golden);code,labels=assemble(buffer)
    out=bytearray(golden)
    if any(out[b.CAVE_OFFSET:b.CAVE_OFFSET+b.CAVE_CAPACITY]):raise ValueError('occupied cave')
    struct.pack_into('<I',out,sizeoff,memsize)
    for kind,(pc,expected) in HOOKS.items():
        if list(struct.unpack_from('<2I',out,pc-BASE))!=expected:raise ValueError(f'bad hook {kind}')
        struct.pack_into('<2I',out,pc-BASE,0x08000000|(labels[kind]>>2),0)
    target=labels['timer']
    struct.pack_into('<I',out,b.CALLBACK_HI_OFFSET,b.lui(6,(target+0x8000)>>16))
    struct.pack_into('<I',out,b.CALLBACK_LO_OFFSET,b.addiu(6,6,target&65535))
    out[b.CAVE_OFFSET:b.CAVE_OFFSET+len(code)]=code
    return bytes(out),dict(buffer=buffer,memory_bytes=HEADER+RECORD*CAPACITY,
                          code_bytes=len(code),labels=labels,memsize_offset=sizeoff)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('source',type=Path);p.add_argument('output',type=Path)
    args=p.parse_args();out,meta=build(args.source.read_bytes())
    if args.output.exists():raise ValueError('refuse to overwrite an existing artifact')
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_bytes(out)
    print('sha256='+hashlib.sha256(out).hexdigest());print(meta)
    print('hardware=UNTESTED; no deployment; no autoscroll added')


if __name__=='__main__':main()
