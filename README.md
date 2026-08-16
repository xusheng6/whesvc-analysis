# whesvc-analysis

Tooling and notes from reverse engineering **Windows Health and Optimized Experiences**
(`whesvc`) — the Windows 11 service that went viral in August 2026 over claims it was
spying on gaming PCs.

It isn't. It is a sandboxed **Lua 5.4 interpreter running as SYSTEM**, with 84 compiled
Lua scripts shipped in a resource-only DLL, and a native API surface considerably wider
than a performance optimizer needs.

Blog post: **[Windows' Performance Optimizer Is More Capable Than It Needs to Be](https://jeffli678.github.io/posts/reversing/whesvc/)**
Full writeup: [`docs/ANALYSIS.md`](docs/ANALYSIS.md)

## What's here

This repo contains **tools, not Microsoft binaries**. The DLLs and the extracted scripts
are Microsoft's copyrighted material, so rather than redistribute them, the tooling below
lets you unpack the copies already on your own machine. Everything reproduces in about a
minute.

| File | Purpose |
|---|---|
| `pe_res.py` | PE resource extractor. Needed because resource-directory name strings are length-prefixed and *not* null-terminated, so the Win32 `EnumResource*` APIs return mangled names. |
| `unpack.py` | Decompresses the custom container (magic `0xC0E5510A`, MSZIP payload). |
| `luac54.py` | Lua 5.4 bytecode parser and disassembler. Resolves constants, upvalue names, local variable names and line numbers. |
| `kdump.py` | Dumps all string constants of one module. |
| `ksearch.py` | Regex search across the string constants of every module. |
| `wdg_api.py` | Recovers the native `wdg.*` API surface by tracking which registers hold the native table. |
| `get_pdbs.py` | Reads each PE's CodeView record and fetches the matching PDB from the Microsoft symbol server. |
| `bn_whesvc.py`, `bn_funcs.py` | Binary Ninja headless scripts for the native side. |

## Reproducing

Requires Python 3 and an elevated shell for the initial copy.

```powershell
mkdir binary
copy C:\Windows\System32\whesvc.dll        binary\
copy C:\Windows\System32\whesvc_assets.dll binary\
copy C:\Windows\System32\windiag.dll       binary\
```

```bash
# 1. extract the resources
python pe_res.py binary/whesvc_assets.dll resources
python pe_res.py binary/windiag.dll       resources

# 2. decompress the container -> Lua 5.4 bytecode
python unpack.py resources unpacked

# 3. read a module
python luac54.py unpacked/LUAMOD__SCENARIO_INIT.luac
python kdump.py  unpacked/LUAMOD__SCENARIO_NOISY_FAN.luac

# 4. survey
python wdg_api.py                    # the 79-function native surface
python ksearch.py 'AllowTelemetry'   # search every module's constants
```

Optionally, symbols for the native side (both are public):

```bash
python get_pdbs.py binary whesvc.dll windiag.dll
```

`whesvc_assets.dll` has no PDB — it has no `.text` section at all.

## Container format

Each Lua resource is wrapped in this header, then MSZIP (`'CK'` + raw DEFLATE):

```
0x00  u32  magic 0xC0E5510A   (bytes 0A 51 E5 C0)
0x04  u16  header size (0x18)
0x06  u16  tag / flags
0x08  u64  uncompressed size
0x10  u64  uncompressed size (duplicate)
0x18  u32  compressed size
0x1C  ...  'CK' + raw DEFLATE
```

No hash, no MAC, no encryption.

## Notes on the bytecode

The scripts are stock `luac` output with **nothing stripped** — 6,069 named local
variables, 2,149 named upvalues, 47,688 line-number entries, and 86 original source
paths (`@lualib\core\net.lua`, `@luamod\scenario\ecp.lua`, …) survive across 105 chunks.
The header sentinels are unmodified (`LUAC_INT = 0x5678`, `LUAC_NUM = 370.5`) and the
opcode table is upstream ordering, so a stock disassembler decodes it correctly.

If you want real source rather than disassembly, [unluac](https://sourceforge.net/projects/unluac/)
handles Lua 5.4 and the retained debug info makes its output close to the original.

## Findings, briefly

- **79 native functions** — 60 exposed through 12 `core/*` libraries, and 19 more injected
  as ambient globals by `core/global.lua`. Between them: full registry write, unrestricted
  file I/O, `CreateProcess`, WMI *method* invocation, and a general FFI (`native.invoke`).
- The sandbox removes `load`/`loadfile`/`dofile`/`require`/`package`, so scripts cannot
  load new code — but `io` was never blocked, `io.popen` is re-exported as `io_popen`,
  and the module loader restores every stripped global around each library load.
- No Authenticode verification of the asset DLL at load time. Mitigated in practice by
  the file being `TrustedInstaller:(F)` with everyone else at `(RX)`.
- The "every 15 minutes" claim traces to `WINDIAG_SYSTEM_SUMMARY_FLUSH_SEC = 900`, which
  writes a local JSON summary and emits one small telemetry event.
- No scenario module makes an HTTP request. `windiag.dll` imports three WinINet functions
  and zero socket functions.
- Heavy tracing requires `AllowTelemetry == 3` and fails closed; auto-escalation is off by
  default in all ten automatic scenarios.
- [CVE-2025-59241](https://www.tenable.com/cve/CVE-2025-59241) (local EoP, CVSS 7.8) came
  from this service writing artifacts into a user-writable `ProgramData` tree.

See [`docs/ANALYSIS.md`](docs/ANALYSIS.md) for the full detail, including confidence
levels on what is verified versus inferred.

## License

Tools are MIT (see `LICENSE`). The analysis notes are my own observations about Microsoft
binaries; no Microsoft code is redistributed here.
