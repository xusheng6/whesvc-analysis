"""Dump HLIL of functions whose (demangled) name matches any given substring.
Usage: bn_funcs.py <binary> <substr> [<substr> ...]"""
import sys
import binaryninja as bn

path = sys.argv[1]
pats = [p.lower() for p in sys.argv[2:]]
bv = bn.load(path, update_analysis=True)
print('[*] %s: %d functions\n' % (path, len(bv.functions)))

for fn in bv.functions:
    name = fn.name
    if not any(p in name.lower() for p in pats):
        continue
    print('=' * 78)
    print('%s @ %#x' % (name, fn.start))
    print('=' * 78)
    try:
        for line in fn.hlil.root.lines:
            print('   %s' % line)
    except Exception as e:
        print('   [hlil failed: %s]' % e)
    print()
