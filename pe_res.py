import struct, sys, os

d = open(sys.argv[1], 'rb').read()
pe = struct.unpack_from('<I', d, 0x3c)[0]
assert d[pe:pe+4] == b'PE\0\0'
nsec  = struct.unpack_from('<H', d, pe+6)[0]
optsz = struct.unpack_from('<H', d, pe+20)[0]
magic = struct.unpack_from('<H', d, pe+24)[0]
ddoff = pe + 24 + (112 if magic == 0x20b else 96)
rva, size = struct.unpack_from('<II', d, ddoff + 2*8)   # dir entry 2 = resources

secs = []
secoff = pe + 24 + optsz
for i in range(nsec):
    o = secoff + 40*i
    nm = d[o:o+8].rstrip(b'\0').decode(errors='replace')
    vs, va, rs, pr = struct.unpack_from('<IIII', d, o+8)
    secs.append((nm, va, vs, pr, rs))

def r2o(r):
    for nm, va, vs, pr, rs in secs:
        if va <= r < va + max(vs, rs):
            return pr + (r - va)
    return None

base = r2o(rva)

def rstr(off):
    ln = struct.unpack_from('<H', d, off)[0]
    return d[off+2 : off+2+ln*2].decode('utf-16-le')

def walk(off, path):
    n_named, n_id = struct.unpack_from('<HH', d, off+12)
    out = []
    for i in range(n_named + n_id):
        e = off + 16 + 8*i
        nameval, offval = struct.unpack_from('<II', d, e)
        nm = rstr(base + (nameval & 0x7fffffff)) if nameval & 0x80000000 else '#%d' % nameval
        if offval & 0x80000000:
            out += walk(base + (offval & 0x7fffffff), path + [nm])
        else:
            drva, dsz = struct.unpack_from('<II', d, base + offval)
            out.append((path + [nm], r2o(drva), dsz))
    return out

outdir = sys.argv[2] if len(sys.argv) > 2 else 'resources'
os.makedirs(outdir, exist_ok=True)
BS = chr(92)
tot = 0
cur = None
for path, off, sz in walk(base, []):
    t, nm = path[0], path[1]
    if t != cur:
        print('\n== TYPE %s ==' % t)
        cur = t
    data = d[off:off+sz]
    tot += sz
    safe = ('%s__%s' % (t, nm)).replace('/', '_').replace(BS, '_').replace('#', 'id')
    open(os.path.join(outdir, safe + '.bin'), 'wb').write(data)
    print('  %-46s %8d  %s' % (nm, sz, data[:16].hex()))
print('\nTOTAL %d bytes' % tot)
