"""Unpack whesvc_assets.dll resource blobs.

Container layout (little-endian):
  0x00  u32  magic 0xc0e5510a  (bytes 0a 51 e5 c0)
  0x04  u16  header size (0x18)
  0x06  u16  flags / type tag
  0x08  u64  uncompressed size
  0x10  u64  uncompressed size (duplicate)
  0x18  u32  compressed payload size
  0x1c  ...  MSZIP block: 'CK' + raw DEFLATE
"""
import struct, zlib, os, sys, glob

srcdir = sys.argv[1] if len(sys.argv) > 1 else 'resources'
outdir = sys.argv[2] if len(sys.argv) > 2 else 'unpacked'
os.makedirs(outdir, exist_ok=True)

ok = bad = 0
for path in sorted(glob.glob(os.path.join(srcdir, '*.bin'))):
    d = open(path, 'rb').read()
    name = os.path.basename(path)[:-4]
    if d[:4] != bytes.fromhex('0a51e5c0'):
        # PROFILE resources are plain XML
        open(os.path.join(outdir, name + '.xml'), 'wb').write(d)
        print('%-52s raw (not compressed) %8d' % (name, len(d)))
        ok += 1
        continue
    hdrsz, tag = struct.unpack_from('<HH', d, 4)
    usize, usize2 = struct.unpack_from('<QQ', d, 8)
    csize, = struct.unpack_from('<I', d, hdrsz)
    payload = d[hdrsz+4 : hdrsz+4+csize]
    if payload[:2] != b'CK':
        print('%-52s [!] no CK magic: %s' % (name, payload[:4].hex()))
        bad += 1
        continue
    try:
        out = zlib.decompress(payload[2:], -15)
    except Exception as e:
        print('%-52s [!] inflate failed: %s' % (name, e))
        bad += 1
        continue
    status = 'OK ' if len(out) == usize else '(size %d != %d)' % (len(out), usize)
    ext = '.luac' if out[:4] == b'\x1bLua' else '.bin'
    open(os.path.join(outdir, name + ext), 'wb').write(out)
    print('%-52s tag=%#06x %7d -> %7d  %s  %s' % (name, tag, csize, len(out), status, out[:6].hex()))
    ok += 1

print('\nunpacked %d, failed %d' % (ok, bad))
