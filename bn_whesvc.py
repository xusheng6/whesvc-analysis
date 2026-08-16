"""Binary Ninja headless: map whesvc.dll's callback:// dispatch and action handlers."""
import sys
import binaryninja as bn

path = sys.argv[1] if len(sys.argv) > 1 else 'whesvc.dll'
print('[*] loading %s ...' % path)
bv = bn.load(path, update_analysis=True)
print('[*] analysis done: %d functions, arch=%s' % (len(bv.functions), bv.arch.name))

TARGETS = ['/invoke/module', '/load/library', '/plugin/action', '/trace/profile',
           '/wnf/register', '/wnf/unregister', '/onesettings/module_config',
           '/onesettings/extra_config', '/queue/heavymodule', '/feature/enabled',
           '/host/id', '/module/heap', '/resume/delay',
           'action://batterysaver/overrideppmpolicy', 'action://batterysaver/setpowermode',
           'action://batterysaver/toggleenergysaver', 'action://ecp/toggleadaptive',
           'action://batteryusage/setesbrightnesstoggle',
           'whesvc_assets.dll', 'windiag.dll', 'WHESVC_MOD', 'WHESVC_EXT',
           'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\whesvc']

# map string -> address
strs = {}
for s in bv.strings:
    strs.setdefault(s.value, []).append(s.start)

funcs_of_interest = {}
for t in TARGETS:
    addrs = strs.get(t, [])
    if not addrs:
        # substring match fallback
        addrs = [a for v, aa in strs.items() if t in v for a in aa]
    if not addrs:
        print('  [!] string not found: %r' % t)
        continue
    for a in addrs:
        for ref in bv.get_code_refs(a):
            fn = ref.function
            if fn:
                funcs_of_interest.setdefault(fn.start, set()).add(t)

print('\n[*] %d functions reference the target strings\n' % len(funcs_of_interest))
for addr in sorted(funcs_of_interest):
    fn = bv.get_function_at(addr)
    print('=' * 78)
    print('%s @ %#x   refs: %s' % (fn.name, addr, ', '.join(sorted(funcs_of_interest[addr]))))
    print('=' * 78)
    try:
        for line in fn.hlil.root.lines:
            print('   %s' % line)
    except Exception as e:
        print('   [hlil failed: %s]' % e)
    print()
