# whesvc — "Windows Health and Optimized Experiences"

A reverse-engineering writeup of the Windows 11 service at the centre of the
August 2026 "Microsoft is spying on your gaming PC" claim.

**Analysed:** Windows 11 Pro 26200, service binaries `10.0.26100.8972`
**Tools:** Binary Ninja 5.4 (headless), custom Lua 5.4 parser/disassembler, PE resource extractor

---

## TL;DR

- The service is a **sandboxed Lua 5.4.7 scripting host** running as LocalSystem. 84 compiled
  Lua modules ship inside a resource-only DLL.
- The viral "every 15 minutes" claim is **numerically right, semantically wrong**. There is a
  900-second flush; it writes a local JSON summary and emits one small telemetry event.
- **No scenario module uses HTTP.** The only URL in the entire corpus is Microsoft's public
  symbol server, behind a dev-only env var. The live process holds zero sockets.
- Heavy trace capture is gated on **Optional telemetry (`AllowTelemetry == 3`)** and fails closed.
- An **auto-escalation upload path exists** and is disabled by default in all ten automatic
  scenarios — enabled only in the user-initiated hotkey scenario.
- The design has real sharp edges: unrestricted filesystem access, a sandbox that is not a
  security boundary, and no signature check on the script DLL. It already produced
  **CVE-2025-59241** (CVSS 7.8 local EoP).

---

## 1. Subject

| Property | Value |
|---|---|
| Service name | `whesvc` |
| Display name | Windows Health and Optimized Experiences |
| Description | "Monitors the device for a better user experience" |
| Host | `svchost.exe -k whesvc -p` |
| Account | LocalSystem |
| Start | Automatic (`DelayedAutoStart = 1`) |
| Depends on | `RpcSs` |
| ServiceDll | `C:\Windows\System32\whesvc.dll`, entry `ServiceMain` |

### Binaries

| File | Size | SHA-256 |
|---|---|---|
| `whesvc.dll` | 229,376 | `CD1CE81779945BE03180EBCB8E8C05873F72AF9549590E00564D075DE06DF203` |
| `whesvc_assets.dll` | 372,736 | `B56ACEF2BECD3B2A586A5CE29D2D17458018240FA03EF39F1B2D2693B3D09098` |
| `windiag.dll` | 946,176 | `A6662185BE667B1FB90C8AF5481E4AC3F318EBC6D9B3BE360F6684CFCAF0B735` |

All Microsoft-signed (`CN=Microsoft Windows`). Symbols available from the public symbol server:
`whesvc.pdb` (`DEF5510423CE9771207BFF22DD440E941`), `windiag.pdb` (`B4291087D019BFC91823EC2122250C611`).
`whesvc_assets.dll` has **no PDB and no `.text` section** — its sections are `.rdata` and `.rsrc` only.

Internal source paths (from `wil` error records): `pcshell\base\whesvc\lib\{healthandoptimizersvc,orchestrator,modulehandler,assetloader}.cpp`.
Internal codename: **Aegis**. Scenario IDs use the prefix **FunExp** (Fundamentals Experience).

---

## 2. Architecture

`whesvc.dll` is a thin host. `windiag.dll` is the engine — an embedded
**Lua 5.4.7 (PUC-Rio)** interpreter plus 79 native bindings. `whesvc_assets.dll` is a pure
resource container holding the compiled scripts.

```
HealthAndOptimizerService::StartWHEService()
  ├─ RegGetValue(...\whesvc, "WaitForDebugger")
  ├─ SetProcessMitigationPolicy(ProcessRedirectionTrustPolicy, 1)
  ├─ InitializeAssetLoader()      → LoadLibraryW(%systemroot%\system32\whesvc_assets.dll)
  ├─ WinDiag::Initialize()        → GetSystemDirectoryW + \windiag.dll
  │                                 exports: WinDiagnosticsRequest / Resume / Free
  ├─ OrchestratorSingleton::Initialize()
  ├─ OrchestratorSingleton::RegisterOneSettingsConfigChangeWNF()
  └─ StartWindiagModuleWithUri("builtin://scenario/init")
```

**URI schemes.** `builtin://` resolves a module from DLL resources. `callback://` calls back into
native code (`/invoke/module`, `/load/library`, `/plugin/action`, `/trace/profile`, `/wnf/register`,
`/onesettings/module_config`, `/feature/enabled`, `/queue/heavymodule`, `/host/id`).
`action://` performs a system change, dispatched through a **hardcoded `ActionToDllMapping`**
limited to two targets: `SettingsHandlers_OneCore_BatterySaver.dll` and `SettingsHandlers_BatteryUsage.dll`.

---

## 3. Asset format

Resources in `whesvc_assets.dll`: **61 `LUALIBM`** (libraries), **23 `LUAMOD`** (scenarios),
**5 `PROFILE`** (WPRP trace-profile XML). `windiag.dll` adds 20 `LUALIB` (identical copies of the
core libs), `CORE/GLOBAL`, and `SANDBOX/DEFAULT` (`LUASB`).

Each Lua resource is wrapped in a custom container:

```
0x00  u32  magic 0xC0E5510A   (bytes 0A 51 E5 C0)
0x04  u16  header size (0x18)
0x06  u16  tag / flags
0x08  u64  uncompressed size
0x10  u64  uncompressed size (duplicate)
0x18  u32  compressed size
0x1C  ...  MSZIP block: 'CK' + raw DEFLATE
```

No hash, no MAC, no encryption — compression only.

### Not obfuscated

The payload is stock `luac` output with **nothing stripped**. Header sentinels are unmodified
(`format = 0`, `LUAC_INT = 0x5678`, `LUAC_NUM = 370.5`) and the opcode table is the unmodified
upstream Lua 5.4 ordering — a stock disassembler decodes it correctly on the first pass.

| Retained debug info | Count |
|---|---|
| Modules carrying debug info | 105 / 105 |
| Function prototypes | 1,145 |
| Named local variables | 6,069 |
| Named upvalues | 2,149 |
| Line-number entries | 47,688 |
| Distinct source paths | 86 (`@lualib\core\net.lua`, `@luamod\scenario\ecp.lua`, …) |

Debug info is almost certainly retained deliberately: the engine formats errors as
`file(line)!addr` and `wil` telemetry logs failures with call context. The sandbox script also
carries `lua_debugger_enabled` / `vscode_debugger_enabled` hooks.

---

## 4. Capability surface

**79** native `wdg.*` functions. Sixty are exposed through 12 core libraries;
the remaining nineteen are injected directly into every script's environment by
`core/global.lua` (`getpid`, `getcmd`, `getcwd`, `process_info`, `system_info`,
`system_times`, `sessionid`, `thread_name`, `create_guid`, `sleep`, `event_write`,
and timing primitives).

| Library | Capability |
|---|---|
| `core/reg` | Full registry read/write, all hives: `create_key`, `delete_key`, `delete_value`, `set_*`, `get_*`, `enum_*` |
| `core/file` | `read_data`, `write_data`, `append_data`, `copy`, `move`, `remove`, `mkdir`, `rmdir`, `enum`, `attribute`, `is_reparse_point`, **`grep_init`/`grep_next`** (content search) |
| `core/security` | `create_process`, `impersonate_process`, `revert_impersonation`, `token_info`, `code_integrity`, `process_protection`, `local_admin` |
| `core/etw` | `wpr_start_trace`, `wpr_stop_trace`, `etw_trace_summary`, realtime sessions, provider/keyword/level control |
| `core/wmi` | `wmi_query` **and `wmi_method`** — `Win32_Process`, `Win32_Service`, `Win32_NTLogEvent`, `MSFT_MpComputerStatus`, `MSFT_MpPreference` |
| `core/wnf` | Create/update/query/delete WNF state names (machine/user/session/process scope) |
| `core/native` | **`invoke`** — general FFI with typed buffers and DLL/file/registry/kernel/SCM handles |
| `core/power` | Battery, power schemes, thermal + fan sensors, EMI, processor info |
| `core/net` | `http_req` — the entire network API |
| `core/sym` | Symbol download, `sym_decode_stack` |
| `core/ai` | Local language model (`Summarize`, `Rewrite`, `TextToTable`) |
| `core/utc`, `core/oset`, `core/cabinet` | DiagTrack scenario state; OneSettings config; `.cab` creation |

**`windiag.dll` import profile:** 3 WinINet functions (`InternetOpenA`, `HttpOpenRequestA`,
`HttpSendRequestA`), **0 sockets, 0 crypto**, 7 ETW, 11 registry, 6 WNF,
`CreateProcessW`/`CreateProcessAsUserW`, `AdjustTokenPrivileges`/`OpenProcessToken`.
No audio/microphone APIs anywhere.

### Filesystem access is unrestricted

```lua
-- core/file.lua:9-12
function write_data(path, data)
    assert(io.open(path, "wb")):write(data)     -- no validation of any kind
end
```

No path check exists at any layer: not in the Lua wrapper, not in a native binding (read/write
bypass `wdg` entirely), and `io` is confirmed **stock PUC-Rio `liolib`** — `windiag.pdb` exports
`luaopen_io`, `luaopen_os`, `luaopen_package`, `luaopen_debug` unmodified. There is no
Microsoft code in the read/write path that *could* enforce a restriction.

`ProcessRedirectionTrustPolicy` is not a path sandbox — it blocks following junctions and
symlinks created by untrusted principals, nothing more.

---

## 5. The sandbox

`SANDBOX/DEFAULT` + `core/global.lua` nil out globals before scenario modules run:

| Mode | Blocked globals |
|---|---|
| `normal_mode` (retail) | `debug`, `require`, `os`, `package`, `loadfile`, `dofile`, `load`, `getmetatable`, `setmetatable`, `collectgarbage` |
| `debug_mode` | `require`, `os`, `package`, `loadfile`, `dofile`, `collectgarbage` |

**What it achieves:** scenario modules cannot load new code. Modules resolve only from resources
of one fixed signed DLL. The one filesystem-loading path, `WINDIAG_LUALIB_PATH`, is gated on
`host_id == 'windiag.exe'` — unreachable from the service.

**What it does not achieve — it is not a security boundary:**

1. **`io` was never blocked**, and `io.popen` is deliberately re-exported as the global
   `io_popen` (`core/global.lua:331`). `core/etw.lua:815` uses it to shell out.
2. **Capture-before-strip.** `core/file.remove` closes over `os.remove` captured at load time.
   `core/global` keeps an upvalue literally named `sandbox_stripped_refs`.
3. **The loader reverses the sandbox.** `core/global.lua:693-701` restores *every* stripped
   global into `_ENV` around each `callback://system/load/library` call, then re-strips them.

Net: namespace hygiene, not confinement.

---

## 6. Execution model

`scenario/init` is the only entry point. **21 of 23 modules launch by default.**

**`init` starts 6:**

| Module | Gate |
|---|---|
| `housekeeper`, `rtsmon`, `devicehot`, `noisy_fan` | always |
| `ecp` | feature `ECP` + battery present |
| `memory_handle_leak` | feature `MemoryLeakDetection` |

**`rtsmon` opens the realtime ETW session `WinDiag-Realtime-Session` and starts 14:**

| Module | Gate |
|---|---|
| `hang_trace`, `hotkey_trace`, `input_delays`, `perftrack_monitor`, `svc_start_stop`, `sleep_offenders`, `slow_app_launch`, `system_summary`, `tracing` | always |
| `excessive_power_drain` | battery present |
| `device_health` | feature `DeviceHealth` |
| `memory_monitor` | feature `MemoryLeakDetection` |
| `fast_battery_drain_improvement` | feature `HighPowerDrainFMax` + battery |
| `output_delays` | feature `OutputDelays` |

Totals: **13 unconditional, 6 feature-gated, 1 battery-gated.**
`analysis/sys_perf` is not a scenario — it is queued as a *heavy module* by five scenarios.
`scenario/boot` has **no launcher anywhere** and is dormant.

Feature gating in the service resolves via `callback://whesvc/feature/enabled` →
`ModuleHandler::FeatureEnabled` → Windows feature staging, i.e. **Microsoft controls those six
flags server-side**. Roughly 60 `WINDIAG_*` environment variables tune thresholds.

Most modules are resident but idle, waking on ETW events. Only `system_summary` (900 s),
`housekeeper`, `devicehot`, `noisy_fan`, `memory_monitor` and `ecp` are timer-driven — which is
why the process sits near-zero CPU with 21 modules loaded.

### Module reference

**Orchestration** — `init` (bootstrap, emits `FeatureStates`) · `rtsmon` (owns the realtime ETW
session, starts 14 scenarios) · `housekeeper` (coroutine loop; deletes aged Feedback Hub artifacts).

**Responsiveness** — `hang_trace` (waits on `WerHangTraceSignal`) · `input_delays`
(`InputProcessDelay` clustering) · `output_delays` (display glitches > `min_glitch_duration_ms`) ·
`slow_app_launch` (PerfTrack launch thresholds) · `svc_start_stop` (services stuck pending) ·
`perftrack_monitor` (scenario duration percentiles → registry + JSON) · `tracing` (generic
coalescing trace trigger) · `hotkey_trace` (**user-initiated** full trace on a hotkey).

**Power/thermal** — `ecp` (decides `LowerPower`/`NoChange`/`HigherPower`, applies via `action://`) ·
`excessive_power_drain` (drain > `excessive_threshold_mw`, bad background apps) ·
`fast_battery_drain_improvement` (state machine engaging **QoS separation and CPU frequency
throttling**) · `sleep_offenders` (modern-standby analysis; runs `powercfg /sleepstudy`) ·
`noisy_fan` · `devicehot` (temperature + processor MSR thermal readouts vs `threshold_c`).

**Memory** — `memory_monitor` (heap snapshot traces; can configure Driver Verifier) ·
`memory_handle_leak` (leak detection by consecutive-increase count and linear-regression slope).

**Aggregation** — `system_summary` (the 900 s flush) · `device_health` (central `signal_problem`
sink with thresholds/cooldowns, raises the Feedback Hub toast) · `analysis/sys_perf` (parses a
captured ETL into `sys_perf.json`).

**Dormant** — `boot` (parses `WdiContextLog` / boot ETL for markers like `<<<DESKTOP_READY>>>`).

### How `noisy_fan` works

No microphone — there are no audio APIs in the stack. `fan_impact_info` returns a fan RPM
descriptor bucketed into `FanNoiseZoneLow/Medium/MediumHigh/High`, each with a
`noise_zone_max_rpm` and accumulated `seconds_in_zone`. Those thresholds come from the OEM
thermal stack (MPTF). The module polls, then:

```lua
if time_per_impact[FanNoiseZoneHigh].seconds_in_zone > high_impact_sec_threshold then
    device_health.signal_problem{ problem_area = Power, source = "NoisyFan" }
end
```

"Noisy" means *sustained above an OEM-declared RPM*, a proxy rather than a measurement. On
machines without fan telemetry it exits with `"Fan sensors not supported on device"`.

---

## 7. What it collects, and where it goes

### Local artifacts

| Path | Contents |
|---|---|
| `C:\ProgramData\Whesvc\<type>\` | JSON summaries: `app_crashes_summary`, `perftrack_summary`, `pool_tags_summary`, `sleep_study_top_offenders_summary`, `sys_perf_summary` |
| `%TEMP%\DiagOutputDir\Whesvc` | Feedback Hub staging |
| `%TEMP%\Whesvc`, `%TEMP%\whesvc_trace.etl` | Working traces |

Retention is enforced by `MaxFileCountExceeded` and `OlderThanExpirationPeriod`.

Sample record (real, from the test machine):

```json
{"app_name":"binaryninja.exe","mod_name":"TTDReplay.dll","exception_code":"0xC0000005",
 "exception_offset":"0x994EA","app_version":"5.4.10219.0","count":1}
```

### The 15-minute flush

`WINDIAG_SYSTEM_SUMMARY_FLUSH_SEC` defaults to **900**. On-disk artifacts confirm it
(`"elapsed_time":"00:15:40.203030"`). Each flush does two things: writes the local JSON above,
and emits one ETW telemetry event —

| Field | Value |
|---|---|
| Event | `Microsoft.Windows.Fundamentals.HealthAndExperience` |
| Provider | `617d1814-4002-5af5-e1a8-8caeb2d6c449`, group `MicrosoftTelemetry` |
| Keyword | `MICROSOFT_KEYWORD_MEASURES` |
| `PartA_PrivTags` | `DeviceConnectivityAndConfiguration`, `ProductAndServicePerformance`, `ProductAndServiceUsage` |

### Trace contents

The `DATA/GTP` profile enables **86 event providers** plus a kernel `SystemProvider` with
`CSwitch`, `DPC`, `Interrupt`, `Loader`, `ProcessThread`, `SampledProfile` and stack caching —
call stacks, image loads, context switches and CPU samples system-wide. This data stays local.

### Every egress path

| Path | Trigger | Default |
|---|---|---|
| UTC telemetry event | 900 s flush | On (subject to telemetry level) |
| **UTC scenario escalation** | Scenario decides | **Off in 10/11 scenarios** |
| WER sync (`MISC/WER_SYNC`) | Observes `WerReportUploaded` | Attaches to a user-consented WER report |
| Feedback Hub | User submits feedback | User-initiated |
| `symweb.azurefd.net` | `core/sym` | Requires `WINDIAG_SYM_CLOUD_TOKEN` (dev-only) |

The live service process holds **zero TCP and zero UDP endpoints**. Two processes are spawned,
both in-box with fixed arguments — via **two different mechanisms**:

| Mechanism | Path | Caller |
|---|---|---|
| `security.create_process` | native → `CreateProcessW` / `CreateProcessAsUserW` | `misc/sleep_study` → `powercfg.exe /sleepstudy [/json] /output "<path>"` |
| `io_popen` | stock Lua `io.popen` → shell | `core/etw` → `wpr.exe -merge` |

`core/security.create_process` is a direct re-export of the native binding with no Lua-side
wrapper: it takes an arbitrary `cmd_line` string with no allowlist or validation. As with file
I/O, the constraint is which scripts ship, not the binding. Auditing the `wdg` surface alone
would miss the `io_popen` path entirely.

---

## 8. Privacy controls

### Optional-telemetry gate

`luamod\scenario\unified_tracing.lua:292-331`:

```lua
if not feature_enabled("WhesvcConfigurableTracing") then
    return true, "feature_disabled"          -- gate not deployed → PERMISSIVE
end
local lvl = get_telemetry_level()
if lvl == nil then return false, "telemetry_unknown" end   -- fails CLOSED
if lvl == 3   then return true,  "telemetry_full"  end
return false, "telemetry_" .. tostring(lvl)
```

`get_telemetry_level()` reads `AllowTelemetry` from
`SOFTWARE\Microsoft\PolicyManager\current\device\System`, falling back to
`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection`. The comparison is
`EQI A=4 B=130`; Lua 5.4 encodes sB as excess-127, so the required value is **3** (Optional/Full).

Caveats: the gate is itself behind a feature flag that defaults permissive when absent, and
12 of the scenarios route through `unified_tracing` — `hotkey_trace`, `output_delays`,
`fast_battery_drain_improvement`, `device_health`, `boot` and `system_summary` reach trace APIs
by other paths.

### Auto-escalation

`lualib\misc\auto_escalate.lua:19-41` is the one path that can push data off-box without
Feedback Hub:

```lua
function escalate_scenario(workflow_instance_id, sc_id, local_only)
    local opts
    if local_only then
        opts = { zip_output = true,
                 output_dir = env.expand("%windir%\\temp"),
                 upload_action = 0 }          -- 0 = do not upload
    end
    local ok, err, reportId = pcall(utc.scenario_escalation, sc_id, opts or {})
```

**All six call sites pass only two arguments** — `local_only` is nil everywhere, so escalation
always uses UTC defaults. What saves it is the per-scenario gate:

| Scenario | `WINDIAG_ESCALATION_ENABLED` default |
|---|---|
| devicehot, excessive_power_drain, hang_trace, input_delays, memory_monitor, noisy_fan, perftrack_monitor, sleep_offenders, slow_app_launch, svc_start_stop | **False** |
| **hotkey_trace** | **True** |

Escalation is off by default in every automatic scenario and on only in the one the user
explicitly triggers. *Not verified: what DiagTrack does with an escalation once handed off —
`diagtrack.dll` was not reversed.*

Separately, `perftrack_monitor` conditions collection on `utc.scenario_active()` for
`4e1bc75e-aacb-41d2-9bfa-fda09e9b87dc` (perf) and `00b775fc-c3f4-49b5-970e-4f581220d489` (power)
— **server-activated** UTC scenarios.

---

## 9. What it changes

- **Power settings** via `action://`: `batterysaver/toggleenergysaver`, `batterysaver/setpowermode`,
  `batterysaver/overrideppmpolicy` (processor Fmax), `ecp/toggleadaptive`,
  `batteryusage/setesbrightnesstoggle`. Restricted to two allowlisted DLLs.
- **Registry**, confined to its own `whesvc\scenarios` state keys — *except*
  `MISC/DRIVER_INFO`, which writes `VerifyDrivers`, `VerifyDriverLevel`, `VerifyMode` and
  `VerifierOptions` under `Session Manager\Memory Management`. That is **Driver Verifier**
  configuration, called from `memory_monitor`, gated by `WINDIAG_DRIVER_TELEMETRY_ENABLED`.
  The most invasive change found.
- **Files** under the three artifact directories; **ETW sessions**; **WNF publishes** that raise toasts.

`ECP_WhatIf = 0` on the test machine — ECP's dry-run mode is off, so it applies changes for real.

---

## 10. Security analysis

### CVE-2025-59241 — local elevation of privilege

CWE-59 link following, CVSS 7.8, fixed in **26100.6899 / 26200.6899** (October 2025).
Microsoft published one sentence; the following reconstructs the class from code and live ACLs.

**Preconditions, all verified:**

```
icacls C:\ProgramData\Whesvc
    BUILTIN\Users:(I)(CI)(WD,AD,WEA,WA)      ← create files + subdirectories
    CREATOR OWNER:(I)(OI)(CI)(IO)(F)         ← creator owns it outright
```

Every ACE is `(I)` — **inherited**. The service never sets an explicit DACL. Meanwhile
`artifact_manager.lua:354` does `file.mkdir(programdata.."/Whesvc/"..artifact_type)` followed by
an unvalidated `io.open(..., "wb")`, with `artifact_type` drawn from a fixed, predictable set, on
a 15-minute timer. The retention logic supplies a matching *delete* primitive.

Pre-create a known artifact directory as a junction, wait for the flush, and SYSTEM's write or
delete resolves through it. *Which specific path Microsoft saw exploited is not published, and no
pre-6899 binary exists on the test machine to diff.*

**The fix**, as present in current binaries:

1. `SetProcessMitigationPolicy(ProcessRedirectionTrustPolicy, 1)` at the top of `StartWHEService`
   — the kernel refuses to follow junctions/symlinks created by less-trusted principals. Also set
   declaratively: the `whesvc` svchost group key carries `RedirectionTrustPolicy : 1`.
2. `core/file.lua:92` — the recursive walker refuses to descend into reparse points. This is the
   **only** call site of `is_reparse_point` in all 84 modules.
3. Nothing at the ACL layer — the artifact root still inherits ProgramData's permissive DACL.

### The script DLL signature is never checked

| Check | Result |
|---|---|
| `WinVerifyTrust` / `CryptCATAdmin` in either binary | **Absent** |
| `SetProcessMitigationPolicy` calls | Exactly one — `RedirectionTrustPolicy`. No `ProcessSignaturePolicy`. |
| svchost group config | COM settings + `RedirectionTrustPolicy` only; no signature level |
| User-mode Code Integrity | `UsermodeCodeIntegrityPolicyEnforcementStatus = 0` |

The Authenticode signature on `whesvc_assets.dll` exists and is never consulted at load. Nor is
there any integrity field in the container, and the Lua binary-chunk loader validates nothing.

Worse, `InitializeAssetLoader` uses plain **`LoadLibraryW`** on a resource-only DLL rather than
`LOAD_LIBRARY_AS_DATAFILE`, so a replaced file's `DllMain` would execute as SYSTEM without any
Lua involvement. Note also a path-derivation inconsistency: the asset DLL path comes from
`ExpandEnvironmentStringsW("%systemroot%\...")` while the engine uses `GetSystemDirectoryW()`.

**This is not a low-privilege attack.** The file is `TrustedInstaller:(F)` with everyone else —
including SYSTEM and Administrators — at `(RX)`. A standard user cannot write it. It is a
**persistence and defense-evasion** weakness: an attacker who already has admin can replace one
resource DLL for SYSTEM code execution at every boot, while the binaries an EDR would scrutinise
(`whesvc.dll`, `windiag.dll`) stay authentically Microsoft-signed.

The script set is therefore held closed by a **filesystem ACL and the servicing pipeline**, not by
code signing. One-line hardening: `ProcessSignaturePolicy` / `MicrosoftSignedOnly`, plus
`AS_DATAFILE`. The service only ever loads Microsoft DLLs, so neither would break anything.

### Residual risk, ranked

1. **Link-following / confused deputy.** Recurs whenever a new artifact path is added.
2. **Parser surface.** `windiag.dll` parses ETL, JSON, WPRP XML and PDBs as SYSTEM, and realtime
   ETW payloads are partly shaped by unprivileged processes. Unexplored publicly.
3. **The Lua binary-chunk loader**, unhardened by upstream design — currently safe only because
   chunks come from a signed DLL.

### Is it a "trojan"?

No. Untrusted input cannot become code: modules resolve only from a signed DLL,
`load`/`loadfile`/`dofile`/`require`/`package` are stripped, the filesystem-loading path is gated
to `windiag.exe`, and OneSettings ships config values rather than code. The Lua layer grants no
authority the process did not already hold — Microsoft already has SYSTEM via Windows Update, so
there is no new trust relationship. The valid criticism is attack surface, and that criticism was
already vindicated by CVE-2025-59241.

---

## 11. Dead and unused capability

Five capabilities are fully implemented and called by **nothing**:

| Item | Notes |
|---|---|
| `core/ai` | Local language model binding. Zero callers. |
| Defender introspection in `core/wmi` | `MSFT_MpComputerStatus`, `MSFT_MpPreference`, `\\.\root\Microsoft\Windows\Defender`, ATP registry key, an `exclusions` helper. Zero callers. |
| `file.grep_init` / `grep_next` | Content search across files. Zero callers. |
| `security.impersonate_process` / `revert_impersonation` | Zero callers. Same for `code_integrity`, `process_protection` and the `process_protected_signer` enum (`Antimalware`, `Lsa`, `WinTcb`, `WinSystem`, …). Note `create_process` **is** used — once, by `misc/sleep_study`. |
| `device_id()` | `core/global.lua:653` — reads `LID` from `HKU\.DEFAULT\...\IdentityCRL\ExtendedProperties`, returns `"g:<decimal>"` (Microsoft Account CID format). Referenced once, at its own definition. |
| `scenario/boot` | No launcher in the Lua corpus or in `whesvc.dll` strings. |

None is a smoking gun. Collectively they show an engine built to a much larger spec than the
shipped scenarios exercise — and they are worth re-checking on future builds.

**Probable bug:** `memory_monitor` escalates under the scenario ID `"FunExpSvcStartStopTrace"`
while every other module uses its own (`FunExpHangTrace`, `FunExpInputDelayTrace`,
`FunExpPerfMonitorTrace`, …). Reads like copy-paste; would misattribute escalations server-side.
`noisy_fan` also shares `FunExpDeviceHotTrace` with `devicehot`, which may be intentional.

**Opaque flags:** real user-visible behaviour hangs off velocity flags named `BugFixes4D`,
`BugFixes5D`, `BugFixes7D`, alongside `WhesvcConfigurableTracing` and `LowerMemoryFootprint`.

---

## 12. Verdict on the viral claims

| Claim | Verdict |
|---|---|
| "New service added to Windows 11" | **False.** Present since a May 2025 Canary build. |
| "Sends data to Microsoft every 15 minutes" | **Partly true.** A 900-second flush writes a local JSON summary and emits one small telemetry event through the standard pipeline. Not trace upload. |
| "Secretly screen recording / uploading traces" | **False.** No scenario uses HTTP; 3 WinINet imports total; zero sockets on the live process; traces stay in local directories with retention. |
| "Does nothing useful" | **False.** It actively tunes power settings, and can engage CPU frequency throttling and Driver Verifier. |

Public prior art is thin: [Albacore flagged the Lua runtime in May 2025](https://www.windowslatest.com/2025/05/28/leak-hints-at-windows-11s-new-feature-that-optimizes-performance-tied-to-copilot-branding/)
and later coverage restates it. Two errors are worth correcting: there is **no `windialog.exe`**
(the service loads `windiag.dll` in-process; `windiag.exe` exists only as a host *identity* used
by the `is_windiag_host_id()` gate), and the shipped module is `luamod\scenario\ecp.lua`, one of
20 scenarios, not `ecp.v2.lua` driving the whole service.

---

## 13. Methodology and reproduction

```bash
# 1. extract PE resources (custom parser — resource-dir strings are not null-terminated)
python pe_res.py binary/whesvc_assets.dll
python pe_res.py binary/windiag.dll

# 2. decompress the custom container (header + MSZIP)
python unpack.py resources unpacked

# 3. disassemble Lua 5.4 bytecode
python luac54.py unpacked/LUAMOD__SCENARIO_INIT.luac

# 4. survey
python wdg_api.py                       # native API surface
python ksearch.py 'AllowTelemetry'      # search string constants
python kdump.py unpacked/<module>.luac  # dump one module's constants

# 5. native analysis
python bn_whesvc.py binary/whesvc.dll
python bn_funcs.py binary/whesvc.dll StartWindiagModuleWithUri InitializeAssetLoader

# 6. symbols
python get_pdbs.py binary whesvc.dll windiag.dll
```

**Layout**

```
binary/          the 3 DLLs + whesvc.pdb + windiag.pdb
resources/       raw extracted PE resources
unpacked/        decompressed Lua bytecode (.luac) and WPRP profiles (.xml)
disasm/          annotated disassembly of all 105 modules
*.py             tooling (see above)
```

### Confidence

**Verified from binaries or the live system:** container format; Lua version and debug-info
retention; the 79-function native surface; sandbox contents and its three bypasses; the boot
chain and module graph; the `AllowTelemetry == 3` comparison; escalation call sites and defaults;
all ACLs, mitigation policies and the absence of signature checking; import profiles; live socket
and artifact state.

**Inferred, flagged in text:** the specific path exploited by CVE-2025-59241; what DiagTrack does
with an escalation after hand-off; behaviour of native `wdg` file bindings that were not
decompiled (moot for the arbitrary-read/write conclusion, since stock `io.open` already provides it).
