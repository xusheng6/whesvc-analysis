"""Dump all string constants of a Lua module (recursively through protos)."""
import sys, glob, os
from luac54 import load


def strings(f, seen):
    for v in f.k:
        if isinstance(v, str):
            seen.append(v)
    for p in f.protos:
        strings(p, seen)


if len(sys.argv) > 1 and not os.path.isdir(sys.argv[1]):
    for path in sys.argv[1:]:
        f = load(open(path, 'rb').read())
        seen = []
        strings(f, seen)
        print('\n===== %s (%d string constants) =====' % (os.path.basename(path), len(seen)))
        out, s = [], set()
        for v in seen:
            if v not in s:
                s.add(v); out.append(v)
        for v in out:
            print('  %s' % v.replace('\n', '\\n'))
else:
    # search mode: print modules whose constants match a substring
    pat = sys.argv[1].lower() if len(sys.argv) > 1 else ''
    for path in sorted(glob.glob('unpacked/*.luac')):
        f = load(open(path, 'rb').read())
        seen = []
        strings(f, seen)
        hits = sorted(set(v for v in seen if pat in v.lower()))
        if hits:
            print('%s:' % os.path.basename(path)[:-5])
            for h in hits:
                print('    %s' % h.replace('\n', '\\n'))
