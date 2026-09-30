#!/usr/bin/env python3
"""Check reproducibility, exact patch scope, ELF memory range and hook targets."""
import argparse
import hashlib
import struct
from pathlib import Path
import build_folderfollow_fill_diag as d


def verify(source, candidate):
    golden, _ = d.b.normalize_source(source)
    expected, meta = d.build(source)
    if candidate != expected: raise ValueError('candidate differs from reproducible build')
    if len(candidate)!=len(golden): raise ValueError('file length changed')
    spans=[(meta['memsize_offset'],4),(d.b.CALLBACK_HI_OFFSET,4),
           (d.b.CALLBACK_LO_OFFSET,4),(d.b.CAVE_OFFSET,meta['code_bytes'])]
    spans += [(pc-d.BASE,8) for pc,_ in d.HOOKS.values()]
    changes=[i for i,(a,b) in enumerate(zip(golden,candidate)) if a!=b]
    if any(not any(start<=i<start+size for start,size in spans) for i in changes):
        raise ValueError('change outside declared spans')
    phoff=struct.unpack_from('<I',candidate,0x1C)[0]
    stride,count=struct.unpack_from('<HH',candidate,0x2A)
    loads=[]
    for i in range(count):
        p=struct.unpack_from('<8I',candidate,phoff+i*stride)
        if p[0]==1:loads.append(p)
    rw=[p for p in loads if p[6]==6][-1]
    if not (rw[2]+rw[4]<=meta['buffer'] and
            rw[2]+rw[5]==meta['buffer']+meta['memory_bytes']):
        raise ValueError('buffer is not wholly in appended BSS')
    for p in loads:
        if p!=rw and max(p[2],rw[2])<min(p[2]+p[5],rw[2]+rw[5]):
            raise ValueError('overlapping ELF loads')
    for kind,(pc,original) in d.HOOKS.items():
        w,delay=struct.unpack_from('<2I',candidate,pc-d.BASE)
        if (w&0x3ffffff)<<2 != meta['labels'][kind]:raise ValueError('hook target mismatch')
        if delay!=(original[1] if kind in ('row','terminal') else 0):raise ValueError('delay mismatch')
    hi=struct.unpack_from('<I',candidate,d.b.CALLBACK_HI_OFFSET)[0]&65535
    lo=struct.unpack_from('<I',candidate,d.b.CALLBACK_LO_OFFSET)[0]&65535
    if (hi<<16)+(lo-65536 if lo&32768 else lo)!=meta['labels']['timer']:
        raise ValueError('callback pointer mismatch')
    return {'size':len(candidate),'changed_bytes':len(changes),
            'sha256':hashlib.sha256(candidate).hexdigest(),**meta}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('source',type=Path);p.add_argument('candidate',type=Path)
    args=p.parse_args();print(verify(args.source.read_bytes(),args.candidate.read_bytes()))
    print('offline verification only; see notes for hardware results; no deployment by this verifier')


if __name__=='__main__':main()
