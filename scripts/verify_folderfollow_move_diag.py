#!/usr/bin/env python3
"""Read-only reproducibility, scope, BSS and control-transfer audit for MOVE."""
import argparse
import hashlib
import struct
from pathlib import Path
import build_folderfollow_move_diag as d
from mips_static_trace import sx16


def verify(source,candidate):
    golden,_=d.b.normalize_source(source);expected,meta=d.build(source)
    if candidate!=expected:raise ValueError('not the reproducible candidate')
    if len(candidate)!=len(golden):raise ValueError('file size changed')
    spans=[(meta['memsize_offset'],4),(d.b.CALLBACK_HI_OFFSET,4),(d.b.CALLBACK_LO_OFFSET,4),
           (d.b.CAVE_OFFSET,meta['code_bytes'])]+[(pc-d.BASE,8) for pc,_ in d.HOOKS.values()]
    changes=[i for i,(a,b) in enumerate(zip(golden,candidate)) if a!=b]
    if any(not any(start<=i<start+size for start,size in spans) for i in changes):raise ValueError('unexpected patch range')
    phoff=struct.unpack_from('<I',candidate,0x1C)[0];stride,count=struct.unpack_from('<HH',candidate,0x2A)
    loads=[struct.unpack_from('<8I',candidate,phoff+i*stride) for i in range(count)]
    loads=[p for p in loads if p[0]==1];rw=max(loads,key=lambda p:p[2]+p[5])
    if rw[6]!=6 or rw[2]+rw[4]>meta['buffer'] or rw[2]+rw[5]!=meta['buffer']+meta['memory_bytes']:
        raise ValueError('invalid appended BSS')
    if any(p!=rw and max(p[2],rw[2])<min(p[2]+p[5],rw[2]+rw[5]) for p in loads):raise ValueError('overlapping loads')
    for kind,(pc,orig) in d.HOOKS.items():
        word,delay=struct.unpack_from('<2I',candidate,pc-d.BASE)
        if word>>26!=2 or (word&0x3FFFFFF)<<2!=meta['labels'][kind] or delay:raise ValueError('bad hook')
        # Direct control transfers must not enter the overwritten second word.
        for p in loads:
            if not p[6]&1:continue
            for off in range(p[1],p[1]+p[4]-4,4):
                w=struct.unpack_from('<I',golden,off)[0];at=p[2]+off-p[1];op=w>>26
                dest=None
                if op in (2,3):dest=((at+4)&0xF0000000)|((w&0x3FFFFFF)<<2)
                elif op in (1,4,5,6,7):dest=at+4+sx16(w&65535)*4
                if dest==pc+4:raise ValueError('direct entry into hook delay slot')
    code,labels=d.assemble(meta['buffer'])
    # No hot-probe external call. They never touch HI/LO or floating registers.
    words=struct.unpack('<%dI'%(len(code)//4),code)
    for i in range((labels['setter']-d.CODE)//4,(labels['drain']-d.CODE)//4):
        w=words[i];op=w>>26
        if op==3 and not d.CODE<=((w&0x3FFFFFF)<<2)<d.CODE+len(code):raise ValueError('external hot-probe call')
        if op in (0x10,0x11,0x12,0x13,0x31,0x35,0x39,0x3D) or (op==0 and w&63 in range(0x10,0x1C)):
            raise ValueError('unexpected special-register instruction')
    return dict(size=len(candidate),changed_bytes=len(changes),sha256=hashlib.sha256(candidate).hexdigest(),**meta)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('source',type=Path);p.add_argument('candidate',type=Path)
    args=p.parse_args();print(verify(args.source.read_bytes(),args.candidate.read_bytes()))
    print('offline checks only; hardware UNTESTED; no deployment')


if __name__=='__main__':main()
