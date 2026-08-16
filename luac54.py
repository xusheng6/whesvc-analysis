"""Minimal Lua 5.4 bytecode parser + disassembler."""
import struct, sys

OPNAMES = """MOVE LOADI LOADF LOADK LOADKX LOADFALSE LFALSESKIP LOADTRUE LOADNIL
GETUPVAL SETUPVAL GETTABUP GETTABLE GETI GETFIELD
SETTABUP SETTABLE SETI SETFIELD NEWTABLE SELF
ADDI ADDK SUBK MULK MODK POWK DIVK IDIVK BANDK BORK BXORK SHRI SHLI
ADD SUB MUL MOD POW DIV IDIV BAND BOR BXOR SHL SHR
MMBIN MMBINI MMBINK UNM BNOT NOT LEN CONCAT CLOSE TBC JMP
EQ LT LE EQK EQI LTI LEI GTI GEI
TEST TESTSET CALL TAILCALL RETURN RETURN0 RETURN1
FORLOOP FORPREP TFORPREP TFORCALL TFORLOOP SETLIST CLOSURE VARARG VARARGPREP EXTRAARG""".split()

# opcode -> operand mode
iABC, iABx, iAsBx, iAx, isJ = 0, 1, 2, 3, 4
MODES = {}
for n in OPNAMES: MODES[n] = iABC
for n in "LOADK CLOSURE".split(): MODES[n] = iABx
for n in "LOADI LOADF".split(): MODES[n] = iAsBx
for n in ["EXTRAARG"]: MODES[n] = iAx
for n in "JMP FORLOOP FORPREP TFORPREP TFORLOOP".split(): MODES[n] = isJ

OFFSET_sBx = (1 << 17) - 1 >> 1      # MAXARG_Bx=2^17-1, sBx offset = MAXARG_Bx>>1
OFFSET_sJ = ((1 << 25) - 1) >> 1


class Reader:
    def __init__(self, d): self.d, self.p = d, 0
    def byte(self):
        b = self.d[self.p]; self.p += 1; return b
    def raw(self, n):
        s = self.d[self.p:self.p+n]; self.p += n; return s
    def uvarint(self):
        # Lua 5.4 loadUnsigned: 7 bits/byte, terminator has high bit SET
        x = 0
        while True:
            b = self.byte()
            x = (x << 7) | (b & 0x7f)
            if b & 0x80: return x
    def integer(self): return struct.unpack('<q', self.raw(8))[0]
    def number(self):  return struct.unpack('<d', self.raw(8))[0]
    def string(self):
        n = self.uvarint()
        if n == 0: return None
        return self.raw(n - 1).decode('utf-8', 'replace')


class Proto:
    pass


def load_proto(r, psource):
    f = Proto()
    f.source = r.string() or psource
    f.linedefined = r.uvarint()
    f.lastlinedefined = r.uvarint()
    f.numparams = r.byte()
    f.is_vararg = r.byte()
    f.maxstacksize = r.byte()
    n = r.uvarint()
    f.code = [struct.unpack('<I', r.raw(4))[0] for _ in range(n)]
    n = r.uvarint()
    f.k = []
    for _ in range(n):
        t = r.byte()
        if t == 0x00: f.k.append(None)                       # nil
        elif t == 0x01: f.k.append(False)
        elif t == 0x11: f.k.append(True)
        elif t == 0x03: f.k.append(r.integer())
        elif t == 0x13: f.k.append(r.number())
        elif t in (0x04, 0x14): f.k.append(r.string())
        else: raise ValueError('const type %#x' % t)
    n = r.uvarint()
    f.upvals = [(r.byte(), r.byte(), r.byte()) for _ in range(n)]   # instack, idx, kind
    n = r.uvarint()
    f.protos = [load_proto(r, f.source) for _ in range(n)]
    # debug
    n = r.uvarint()
    f.lineinfo = [struct.unpack('<b', r.raw(1))[0] for _ in range(n)]
    n = r.uvarint()
    f.abslineinfo = [(r.uvarint(), r.uvarint()) for _ in range(n)]
    n = r.uvarint()
    f.locvars = [(r.string(), r.uvarint(), r.uvarint()) for _ in range(n)]
    n = r.uvarint()
    f.upvalnames = [r.string() for _ in range(n)]
    return f


def load(data):
    r = Reader(data)
    assert r.raw(4) == b'\x1bLua', 'not luac'
    ver, fmt = r.byte(), r.byte()
    assert ver == 0x54, 'not Lua 5.4 (ver=%#x)' % ver
    r.raw(6)                    # LUAC_DATA
    r.raw(3)                    # sizes of Instruction/lua_Integer/lua_Number
    r.integer(); r.number()     # LUAC_INT / LUAC_NUM
    r.byte()                    # sizeupvalues of main
    return load_proto(r, None)


def kstr(f, i):
    if i >= len(f.k): return 'K%d?' % i
    v = f.k[i]
    return '"%s"' % v if isinstance(v, str) else repr(v)


def upname(f, i):
    if i < len(f.upvalnames) and f.upvalnames[i]: return f.upvalnames[i]
    return 'U%d' % i


def lineof(f, pc):
    line = f.linedefined
    base = 0
    for apc, aline in f.abslineinfo:
        if apc <= pc: base, line = apc, aline
    for i in range(base, min(pc + 1, len(f.lineinfo))):
        d = f.lineinfo[i]
        if d != -0x80: line += d
    return line


def disasm(f, out, name='main', depth=0):
    ind = '  ' * depth
    out.append('%s-- %s  (%s:%d-%d)  params=%d vararg=%d stack=%d' % (
        ind, name, f.source, f.linedefined, f.lastlinedefined,
        f.numparams, f.is_vararg, f.maxstacksize))
    if f.upvalnames:
        out.append('%s   upvals: %s' % (ind, ', '.join(n or '?' for n in f.upvalnames)))
    locs = [v[0] for v in f.locvars[:f.numparams]]
    if locs: out.append('%s   args: %s' % (ind, ', '.join(locs)))

    for pc, ins in enumerate(f.code):
        op = ins & 0x7f
        nm = OPNAMES[op] if op < len(OPNAMES) else 'OP%d' % op
        A = (ins >> 7) & 0xff
        k = (ins >> 15) & 1
        B = (ins >> 16) & 0xff
        C = (ins >> 24) & 0xff
        Bx = (ins >> 15) & 0x1ffff
        Ax = (ins >> 7) & 0x1ffffff
        sJ = Ax - OFFSET_sJ
        mode = MODES.get(nm, iABC)

        if mode == iABx:   args, cmt = 'A=%d Bx=%d' % (A, Bx), ''
        elif mode == iAsBx: args, cmt = 'A=%d sBx=%d' % (A, Bx - OFFSET_sBx), ''
        elif mode == iAx:  args, cmt = 'Ax=%d' % Ax, ''
        elif mode == isJ:  args, cmt = 'sJ=%d' % sJ, '-> %d' % (pc + 1 + sJ)
        else:              args, cmt = 'A=%d B=%d C=%d k=%d' % (A, B, C, k), ''

        # helpful comments
        if nm == 'LOADK':      cmt = kstr(f, Bx)
        elif nm == 'GETTABUP': cmt = '%s[%s]' % (upname(f, B), kstr(f, C))
        elif nm == 'SETTABUP': cmt = '%s[%s] := %s' % (upname(f, A), kstr(f, B), kstr(f, C) if k else 'R%d' % C)
        elif nm == 'GETFIELD': cmt = 'R%d.%s' % (B, f.k[C] if C < len(f.k) else '?')
        elif nm == 'SETFIELD': cmt = 'R%d.%s := %s' % (A, f.k[B] if B < len(f.k) else '?', kstr(f, C) if k else 'R%d' % C)
        elif nm == 'SELF':     cmt = 'R%d:%s' % (B, f.k[C] if k and C < len(f.k) else 'R%d' % C)
        elif nm in ('GETUPVAL', 'SETUPVAL'): cmt = upname(f, B)
        elif nm == 'CLOSURE':  cmt = 'proto[%d]' % Bx
        elif nm in ('ADDK','SUBK','MULK','MODK','POWK','DIVK','IDIVK','BANDK','BORK','BXORK','EQK'):
            cmt = kstr(f, C)
        elif nm == 'CALL':     cmt = 'R%d(%s) -> %s' % (A, 'B-1 args' if B else 'all', 'all' if C == 0 else '%d ret' % (C - 1))
        elif nm == 'SETLIST':  cmt = '%d elems' % B

        out.append('%s  [%3d] %-4d %-11s %-26s %s' % (ind, pc, lineof(f, pc), nm, args, cmt))

    for i, p in enumerate(f.protos):
        out.append('')
        disasm(p, out, 'proto[%d]' % i, depth + 1)


if __name__ == '__main__':
    f = load(open(sys.argv[1], 'rb').read())
    out = []
    disasm(f, out)
    print('\n'.join(out))
