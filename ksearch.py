"""Search string constants across all unpacked Lua modules. Usage: ksearch.py <regex>"""
import sys, glob, os, re
from luac54 import load

pat = re.compile(sys.argv[1], re.I)


def strings(f, out):
    for v in f.k:
        if isinstance(v, str):
            out.append(v)
    for p in f.protos:
        strings(p, out)


for path in sorted(glob.glob('unpacked/*.luac')):
    f = load(open(path, 'rb').read())
    seen = []
    strings(f, seen)
    hits = sorted(set(v for v in seen if pat.search(v)))
    if hits:
        print('%s:' % os.path.basename(path)[:-5].split('__', 1)[-1])
        for h in hits:
            print('    %s' % h.replace('\n', '\\n'))
