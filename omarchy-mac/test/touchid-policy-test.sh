#!/bin/bash
set -euo pipefail
source "$(dirname "$0")/base-test.sh"
python3 -B - "$ROOT/lib/touchid-policy" <<'PY'
from pathlib import Path
import importlib.machinery, importlib.util, json, sys, tempfile
loader=importlib.machinery.SourceFileLoader('policy',sys.argv[1]);spec=importlib.util.spec_from_loader(loader.name,loader);p=importlib.util.module_from_spec(spec);loader.exec_module(p)
with tempfile.TemporaryDirectory() as tmp:
 root=Path(tmp);options=root/'options.conf';driver=root/'apple_sep';diag=driver/'28.sep/diag';diag.mkdir(parents=True)
 parameters=root/'module/parameters';parameters.mkdir(parents=True);(parameters/'sensor_spi_mode').write_text('0\n')
 options.write_text('options apple_sep '+' '.join(k+'='+v for k,v in p.EXPECTED.items())+'\n')
 values={**p.EXPECTED,'refkey_v2':'0','identity_override':'0','identity_source':'dt'}
 (diag/'policy').write_text(' '.join(k+'='+v for k,v in values.items())+'\n')
 result=p.report(options,driver,'',True)
 assert result['status']=='verified' and result['active']==values,result
 # Tracing is optional diagnostic output, not an admission requirement.
 for trace in ('0', '1'):
  (diag/'policy').write_text(' '.join(k+'='+v for k,v in {**values,'xarm_trace':trace}.items())+'\n')
  assert p.report(options,driver,'',True)['status']=='verified'
 # linux#2591 removed provision_keybag: diag/policy always reads 1 and the loader ignores our 0.
 post={**values,'provision_keybag':'1','xarm_trace':'0'};(diag/'policy').write_text(' '.join(k+'='+v for k,v in post.items())+'\n')
 removed="apple_sep: unknown parameter 'xart_writes' ignored\napple_sep: unknown parameter 'provision_keybag' ignored\n"
 result=p.report(options,driver,removed,True)
 assert result['status']=='verified' and not result['mismatches'],result
 assert p.report(options,driver,'',True)['status']=='mismatch','an older kernel reporting 1 ignored the configured 0'
 assert p.report(options,driver,removed.splitlines()[0],True)['status']=='mismatch','only the provision_keybag parameter is exempt'
 created=removed+'apple_sep 28.sep: sks: identity keybag provisioned\n'
 assert p.report(options,driver,created,True)['status']=='mismatch','a new identity is never adopted'
 (diag/'policy').write_text(' '.join(k+'='+v for k,v in {**post,'xart_writes':'0'}.items())+'\n')
 assert p.report(options,driver,removed,True)['status']=='mismatch','other fields are still checked'
 (diag/'policy').write_text(' '.join(k+'='+v for k,v in post.items())+'\n')
 kept=options.read_text();options.write_text('options apple_sep xart_writes=1 xart_guard=1 trusted_keys=0 filevault_api=0\n')
 assert p.report(options,driver,removed,True)['status']=='mismatch','the configured 0 stays required for older kernels'
 options.write_text('options apple_sep xart_writes=1 provision_keybag=1\n')
 assert p.report(options,driver,removed)['status']=='observed','the normal profile is unchanged on newer kernels'
 options.write_text(kept)
 # The log can rotate away the loader's line; the installed module still answers.
 assert p.report(options,driver,'',True,'removed')['status']=='verified','a wrapped log is not a mismatch'
 assert p.report(options,driver,removed,True,'present')['status']=='mismatch','a module with the parameter beats the log'
 assert p.report(options,driver,'',True,'removed')['active']['provision_keybag_parameter']=='removed'
 assert p.report(options,driver,created,True,'removed')['status']=='mismatch','a new identity is refused either way'
 module=root/'sys/module/apple_sep';module.mkdir(parents=True);modinfo=root/'modinfo'
 def stub(parms,version='ABC'):
  modinfo.write_text('#!/bin/sh\nif [ "$1" = -p ]; then printf "'+''.join(n+':desc (u8)\\n' for n in parms)+'"; else echo '+version+'; fi\n');modinfo.chmod(0o755)
 stub(['trusted_keys','xart_guard','xart_start_sector'])
 assert p.installed_parameter(module,str(modinfo))=='removed'
 stub(['xart_writes','provision_keybag','xart_guard'])
 assert p.installed_parameter(module,str(modinfo))=='present'
 stub(['unrelated'])
 assert p.installed_parameter(module,str(modinfo)) is None,'another driver named apple_sep says nothing'
 stub(['xart_guard']);(module/'srcversion').write_text('OLD\n')
 assert p.installed_parameter(module,str(modinfo)) is None,'a module rebuilt since the load says nothing'
 (module/'srcversion').write_text('ABC\n')
 assert p.installed_parameter(module,str(modinfo))=='removed'
 (module/'parameters').mkdir();(module/'parameters/provision_keybag').write_text('0\n')
 assert p.installed_parameter(module,str(modinfo))=='present','a published parameter wins'
 assert p.installed_parameter(root/'none',str(root/'missing-modinfo')) is None
 (diag/'policy').unlink();(diag/'xart').write_text('enabled\n');(diag/'xart_guard').write_text('1\n')
 log='apple_sep: xART guard level 1\napple_sep: writes ENABLED\napple_sep: xART: using /chosen/apfs-preboot-uuid\n'
 result=p.report(options,driver,log,True)
 assert result['status']=='partially-observed' and not result['mismatches'] and result['active']['identity_source']=='dt',result
 (diag/'xart').write_text('disabled\n')
 assert p.report(options,driver,log,True)['status']=='mismatch','cached contradictory evidence must beat old logs'
 (diag/'xart').unlink();(diag/'xart_guard').unlink()
 result=p.report(options,driver,'',True)
 assert result['status']=='partially-observed' and not result['mismatches'],'absence is not contradiction'
 result=p.report(options,driver,'apple_sep: using explicit OS UUID DO-NOT-OUTPUT',True)
 assert result['status']=='mismatch' and 'DO-NOT-OUTPUT' not in json.dumps(result)
 options.write_text(options.read_text()+'options apple_sep os_uuid_hi=0x123456789 os_uuid_lo=0 refkey_v2=1\n')
 result=p.report(options,driver,'',True)
 assert result['status']=='mismatch' and '123456789' not in json.dumps(result)
 options.write_text('options apple_sep xart_writes=1 provision_keybag=1\n')
 assert p.report(options,driver,'')['status']=='observed','normal first-time profile stays unchanged'
print('ok - cached policy, post-#2591 provision_keybag=1 (module or log), old-ABI diagnostics/logs and missing parameter files stay distinct; no identity values leaked')
PY
