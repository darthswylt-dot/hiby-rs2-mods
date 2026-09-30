#!/usr/bin/env python3
"""Decode mixed FSTS/FILL stream and report conservatively complete sessions."""
import argparse
import json
import struct
from pathlib import Path
from build_folderfollow_fill_diag import RECORD, CAPACITY


def signed(n): return n - 0x100000000 if n & 0x80000000 else n


def decode(data):
    pos = 0
    while pos < len(data):
        magic = data[pos:pos+4]
        size = 32 if magic == b'FSTS' else RECORD if magic == b'FILL' else 0
        if not size or pos+size > len(data): raise ValueError(f'bad/truncated record at {pos:#x}')
        words = struct.unpack_from('<%dI' % (8 if magic == b'FSTS' else 16),data,pos)
        if words[1] != 1: raise ValueError('unsupported version')
        if magic == b'FSTS':
            row = dict(zip(('magic','version','reserved','drained','overflow','contention_loss','io_error','capacity'),words))
            row['kind'] = 'status'
            if row['capacity'] != CAPACITY or not 0 <= row['drained'] <= row['reserved'] <= CAPACITY:
                raise ValueError('invalid buffer counters')
            if any(row[k] not in (0,1) for k in ('overflow','contention_loss','io_error')):
                raise ValueError('invalid loss flags')
        else:
            row = dict(zip(('magic','version','event','seq','frame','statement','list','mode','offset','ordinal','result','caller','cue','truncated','list_count','reserved'),words))
            if row['event'] not in (1,2,3,4): raise ValueError('invalid event')
            if row['seq'] >= CAPACITY or row['truncated'] not in (0,1) or row['reserved']:
                raise ValueError('invalid event metadata')
            row['kind'] = ('begin','row','terminal','end')[row['event']-1]
            for key in ('offset','ordinal','result','cue','list_count'): row[key] = signed(row[key])
            raw = data[pos+0x40:pos+0x248]
            units = [raw[i:i+2] for i in range(0,len(raw),2)]
            if b'\0\0' not in units: raise ValueError('unterminated path')
            row['path'] = b''.join(units[:units.index(b'\0\0')]).decode('utf-16le',errors='strict')
        del row['magic']
        yield row
        pos += size


def sessions(records):
    active, finished = {}, []
    expected, loss, last_status = 0, False, None
    for r in records:
        if r['kind']=='status':
            if last_status and (r['reserved']<last_status['reserved'] or r['drained']<last_status['drained']):
                loss=True  # mixed runs or corrupted counters
            last_status=r
            loss |= bool(r['overflow'] or r['contention_loss'] or r['io_error'])
            continue
        if r['seq'] != expected: loss=True
        expected=r['seq']+1
        key=(r['frame'],r['statement'],r['list'])
        if r['kind']=='begin':
            if key in active:
                old=active.pop(key); old['errors'].append('reentered/reused before end'); finished.append(old)
            active[key]={'begin':r,'rows':[],'terminal':None,'end':None,'errors':[]}
            continue
        if key not in active:
            loss=True; continue
        s=active[key]
        if r['offset']!=s['begin']['offset'] or r['mode']!=0 or r['caller']!=s['begin']['caller']:
            s['errors'].append('scope changed')
        if r['kind']=='row':
            n=len(s['rows'])
            if s['terminal'] is not None or r['ordinal']!=n or r['result']!=n or r['list_count']!=n+1 or r['truncated'] or not r['path']:
                s['errors'].append('row/append mismatch')
            s['rows'].append(r)
        elif r['kind']=='terminal':
            if s['terminal'] is not None: s['errors'].append('duplicate terminal')
            s['terminal']=r
        elif r['kind']=='end':
            s['end']=r; finished.append(active.pop(key))
    for s in active.values(): s['errors'].append('missing end'); finished.append(s)
    # A later status must confirm every exported reservation was drained. This
    # does not claim the producer will never run again after the snapshot.
    settled = bool(last_status and last_status['reserved']==last_status['drained']==expected)
    for s in finished:
        n=len(s['rows']); begin=s['begin']; term=s['terminal']; end=s['end']
        if loss or not settled: s['errors'].append('loss or undrained/unconfirmed snapshot')
        if (begin['mode']!=0 or begin['caller'] not in (0x6F8BF4,0x6F8E0C)
                or not begin['list'] or not begin['statement'] or begin['ordinal']!=0
                or begin['list_count']!=0 or begin['offset']<0 or begin['result']<0
                or begin['truncated'] or not begin['path']):
            s['errors'].append('invalid begin')
        if term is None or term['result']!=101 or term['ordinal']!=n or term['list_count']!=n:
            s['errors'].append('query completion not confirmed')
        if end is None or end['ordinal']!=n or end['result']!=n or end['list_count']!=n or n>begin['result']:
            s['errors'].append('incomplete fill/count mismatch')
        identities=[(r['path'],r['cue']) for r in s['rows']]
        if len(set(identities))!=n: s['errors'].append('duplicate path/cue')
        yield {'folder':begin['path'],'offset':begin['offset'],'rows':n,'begin_seq':begin['seq'],
               'accepted_snapshot':not s['errors'],'errors':sorted(set(s['errors'])),
               'mapping':[] if s['errors'] else [{'index':begin['offset']+i,'path':r['path'],'cue':r['cue']} for i,r in enumerate(s['rows'])]}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('log',type=Path);p.add_argument('--events',action='store_true')
    args=p.parse_args(); rows=list(decode(args.log.read_bytes()))
    report=rows if args.events else list(sessions(rows))
    if not report: print(json.dumps({'accepted_snapshot':False,'errors':['no captured sessions/events']}))
    for row in report: print(json.dumps(row,ensure_ascii=False))


if __name__=='__main__':main()
