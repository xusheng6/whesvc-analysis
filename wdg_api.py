"""Extract the native `wdg.*` API surface referenced by every Lua module."""
import glob, os, sys, collections
from luac54 import load, OPNAMES

calls = collections.defaultdict(set)   # wdg func -> set of modules


def scan(f, module):
    # track registers currently holding the `wdg` table
    for proto in [f] + list(iter_protos(f)):
        wdgregs = set()
        for ins in proto.code:
            op = ins & 0x7f
            nm = OPNAMES[op] if op < len(OPNAMES) else '?'
            A = (ins >> 7) & 0xff
            B = (ins >> 16) & 0xff
            C = (ins >> 24) & 0xff
            if nm == 'GETTABUP':
                kv = proto.k[C] if C < len(proto.k) else None
                (wdgregs.add if kv == 'wdg' else wdgregs.discard)(A)
            elif nm == 'GETFIELD':
                if B in wdgregs:
                    kv = proto.k[C] if C < len(proto.k) else None
                    if kv: calls[kv].add(module)
                wdgregs.discard(A)
            elif nm == 'SELF':
                if B in wdgregs:
                    kv = proto.k[C] if C < len(proto.k) else None
                    if kv: calls[kv].add(module)
                wdgregs.discard(A)
            else:
                wdgregs.discard(A)


def iter_protos(f):
    for p in f.protos:
        yield p
        for q in iter_protos(p):
            yield q


for path in sorted(glob.glob('unpacked/*.luac')):
    mod = os.path.basename(path)[:-5]
    mod = mod.split('__', 1)[1] if '__' in mod else mod
    try:
        scan(load(open(path, 'rb').read()), mod)
    except Exception as e:
        print('[!] %s: %s' % (mod, e), file=sys.stderr)

print('=== native wdg.* API surface: %d functions ===\n' % len(calls))
for fn in sorted(calls):
    mods = sorted(calls[fn])
    shown = ', '.join(mods[:4]) + (' +%d more' % (len(mods) - 4) if len(mods) > 4 else '')
    print('%-34s [%2d] %s' % (fn, len(mods), shown))
