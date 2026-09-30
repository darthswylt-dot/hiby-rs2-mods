#!/usr/bin/env python3
"""Strict mixed MOVE/MSNP/MSTS v2 decoder. No event-time/lifetime inference."""
import argparse
import json
import struct
from pathlib import Path
import build_folderfollow_move_diag as d
from decode_folderfollow_scroll_diag import decode as decode_snapshot

FIELDS = ('magic','version','event','seq','caller','object','view','mode',
          'requested_y','old_y','new_y','flags','parent','height','raw_extent',
          'result','pitch','view_flags','view_8c','cue_before','cue_after','tick',
          'reserved0','reserved1')
SIGNED = ('requested_y','old_y','new_y','height','raw_extent','result','pitch','cue_before','cue_after')


def decode(data):
    pos=0
    while pos<len(data):
        magic=data[pos:pos+4]
        size={b'MOVE':d.RECORD,b'MSNP':d.snap.SIZE,b'MSTS':32}.get(magic)
        if size is None or pos+size>len(data):raise ValueError(f'bad/truncated record at {pos:#x}')
        raw=data[pos:pos+size]
        if struct.unpack_from('<I',raw,4)[0]!=2:raise ValueError('unsupported version')
        if magic==b'MOVE':
            row=dict(zip(FIELDS,struct.unpack('<24I',raw)))
            if row['event'] not in (1,2) or row['seq']>=d.CAPACITY or row['reserved0'] or row['reserved1']:
                raise ValueError('invalid event metadata')
            if not row['object']:raise ValueError('missing event object')
            if row['event']==1:
                if row['mode']&0x20002!=0x20002 or not row['parent'] or any(row[k] for k in ('view','pitch','view_flags','view_8c')):
                    raise ValueError('invalid setter scope')
            elif not row['view'] or any(row[k] for k in ('mode','requested_y','new_y','result','cue_after')):
                raise ValueError('invalid refresh scope')
            for k in SIGNED:
                if row[k]&0x80000000:row[k]-=1<<32
            row['kind']='setter' if row['event']==1 else 'refresh'
            if row['event']==2:
                for k in ('mode','requested_y','new_y','result','cue_after'):row[k]=None
            else:row['cue_changed_during_call']=row['cue_before']!=row['cue_after']
            del row['magic']
        elif magic==b'MSTS':
            row=dict(zip(('magic','version','reserved','drained','overflow','contention_loss','io_error','capacity'),struct.unpack('<8I',raw)))
            if row['capacity']!=d.CAPACITY or not 0<=row['drained']<=row['reserved']<=d.CAPACITY:
                raise ValueError('invalid counters')
            if any(row[k] not in (0,1) for k in ('overflow','contention_loss','io_error')):raise ValueError('invalid loss flags')
            row['kind']='status';del row['magic']
        else:
            if struct.unpack_from('<I',raw,8)[0]!=d.snap.SIZE:raise ValueError('invalid snapshot length')
            tick=struct.unpack_from('<I',raw,0x70)[0]
            converted=bytearray(raw);converted[:4]=b'SCRL';struct.pack_into('<I',converted,4,1)
            row=next(decode_snapshot(bytes(converted)));row.update(kind='snapshot',tick=tick)
        yield row
        pos+=size


def summary(rows):
    rows=list(rows);expected=0;last=None;errors=[];ticks=[];counts={'setter':0,'refresh':0,'snapshot':0}
    for r in rows:
        if r['kind']=='status':
            if last and (r['reserved']<last['reserved'] or r['drained']<last['drained']):errors.append('counter reversal/mixed runs')
            if r['drained']!=expected:errors.append('drain/export mismatch')
            if any(r[k] for k in ('overflow','contention_loss','io_error')):errors.append('reported loss')
            last=r
        elif r['kind']=='snapshot':
            counts['snapshot']+=1;ticks.append(r['tick'])
        else:
            counts[r['kind']]+=1
            if r['seq']!=expected:errors.append('sequence gap/mixed runs')
            expected=r['seq']+1
    if not ticks or ticks[0]!=1 or any(b!=a+1 for a,b in zip(ticks,ticks[1:])):errors.append('snapshot tick gap/mixed runs')
    if not last or last['reserved']!=last['drained'] or last['drained']!=expected:errors.append('unsettled/unconfirmed tail')
    if not rows or rows[-1]['kind']!='status':errors.append('no final status')
    return dict(accepted_prefix=not errors,errors=sorted(set(errors)),events=expected,counts=counts,
                limitations='exported prefix only; no proof of later I/O success, atomic snapshots, event timestamps or object lifetime')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('log',type=Path);p.add_argument('--events',action='store_true')
    args=p.parse_args();rows=list(decode(args.log.read_bytes()))
    if args.events:
        for r in rows:print(json.dumps(r,ensure_ascii=False))
    else:print(json.dumps(summary(rows),ensure_ascii=False,indent=2))


if __name__=='__main__':main()
