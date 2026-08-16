"""Read each PE's CodeView debug record and fetch the matching PDB from the
Microsoft symbol server into the same folder."""
import struct, os, sys, urllib.request, urllib.error

SYMSRV = 'https://msdl.microsoft.com/download/symbols'
UA = 'Microsoft-Symbol-Server/10.0.10036.206'


def pdb_info(path):
    """Return (pdb_name, guid_age_key) from the PE debug directory."""
    d = open(path, 'rb').read()
    pe = struct.unpack_from('<I', d, 0x3c)[0]
    nsec = struct.unpack_from('<H', d, pe + 6)[0]
    optsz = struct.unpack_from('<H', d, pe + 20)[0]
    magic = struct.unpack_from('<H', d, pe + 24)[0]
    ddoff = pe + 24 + (112 if magic == 0x20b else 96)
    rva, size = struct.unpack_from('<II', d, ddoff + 6 * 8)      # entry 6 = debug
    if not rva:
        raise RuntimeError('no debug directory')

    secs = []
    secoff = pe + 24 + optsz
    for i in range(nsec):
        o = secoff + 40 * i
        vs, va, rs, pr = struct.unpack_from('<IIII', d, o + 8)
        secs.append((va, vs, pr, rs))

    def r2o(r):
        for va, vs, pr, rs in secs:
            if va <= r < va + max(vs, rs):
                return pr + (r - va)
        return None

    off = r2o(rva)
    for i in range(size // 28):
        e = off + 28 * i
        typ = struct.unpack_from('<I', d, e + 12)[0]
        dsz, draw = struct.unpack_from('<II', d, e + 16)
        if typ != 2:                                             # IMAGE_DEBUG_TYPE_CODEVIEW
            continue
        cv = d[draw:draw + dsz]
        if cv[:4] != b'RSDS':
            continue
        d1, d2, d3 = struct.unpack_from('<IHH', cv, 4)
        d4 = cv[12:20]
        age = struct.unpack_from('<I', cv, 20)[0]
        name = cv[24:].split(b'\0')[0].decode()
        guid = '%08X%04X%04X%s' % (d1, d2, d3, d4.hex().upper())
        return os.path.basename(name), '%s%X' % (guid, age)
    raise RuntimeError('no RSDS record')


outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
for f in sys.argv[2:]:
    path = os.path.join(outdir, f)
    try:
        name, key = pdb_info(path)
    except Exception as e:
        print('[!] %-22s %s' % (f, e))
        continue
    url = '%s/%s/%s/%s' % (SYMSRV, name, key, name)
    dest = os.path.join(outdir, name)
    print('%-22s -> %s  %s' % (f, name, key))
    try:
        req = urllib.request.Request(url, headers={'User-Agent': UA})
        with urllib.request.urlopen(req, timeout=120) as r:
            data = r.read()
        open(dest, 'wb').write(data)
        print('    OK  %d bytes  <- %s' % (len(data), url))
    except urllib.error.HTTPError as e:
        print('    HTTP %s  %s' % (e.code, url))
    except Exception as e:
        print('    FAILED  %s' % e)
