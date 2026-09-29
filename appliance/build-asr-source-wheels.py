#!/usr/bin/env python3
"""Build four retained pure-Python sdists offline in an isolated filesystem."""
from pathlib import Path
import subprocess,json,hashlib,datetime,zipfile,shutil
from acquisition_common import arguments
ROOT,E=arguments()
BASE=E
src=ROOT/'serving-inputs/asr-sources';out=ROOT/'serving-inputs/asr-built-wheels'
out.mkdir(exist_ok=False)
builder=ROOT/'asr-wheel-builder';uv=Path(shutil.which('uv')).resolve()
subprocess.run([str(uv),'venv','--python','/usr/bin/python3.12',str(builder)],check=True)
subprocess.run([str(uv),'pip','install','--python',str(builder/'bin/python'),'--no-index','--find-links',str(src),'setuptools==83.0.0'],check=True)
names=['antlr4-python3-runtime-4.9.3.tar.gz','kaldi-python-io-1.2.2.tar.gz','sox-1.5.0.tar.gz','wget-3.2.zip']
r={'date_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'query':'Build exactly four source-only payloads from retained ASR source inventory; require pure wheel tags and record actual output identity','uv_sha256':hashlib.sha256(uv.read_bytes()).hexdigest(),'builder':'asr-wheel-builder.json; pinned setuptools 83.0.0; host Python 3.12 for pure wheels','results':[]}
rp=E/'asr-source-wheel-build.json'
for name in names:
 p=src/name;assert p.is_file()
 argv=['bwrap','--unshare-all','--die-with-parent','--new-session','--ro-bind','/usr','/usr','--ro-bind','/lib','/lib','--ro-bind','/lib64','/lib64','--proc','/proc','--dev','/dev','--tmpfs','/tmp','--ro-bind',str(builder),str(builder),'--ro-bind',str(src),'/sources','--bind',str(out),'/output','--ro-bind',str(uv),'/uv','--clearenv','--setenv','PATH','/usr/bin:/bin','--setenv','HOME','/tmp','--setenv','SOURCE_DATE_EPOCH','1788652800','--chdir','/tmp','/uv','build','--wheel','--no-build-isolation','--offline','--no-index','--no-config','--no-cache','--no-python-downloads','--python',str(builder/'bin/python'),'--out-dir','/output','/sources/'+name]
 result=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
 log=E/('wheel-build-'+name+'.log');log.write_bytes(result.stdout)
 r['results'].append({'source':name,'source_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'argv':argv,'exit_code':result.returncode,'log':str(log.relative_to(BASE))})
 rp.write_text(json.dumps(r,indent=2)+'\n')
 if result.returncode:raise SystemExit(result.returncode)
r['wheels']=[]
for p in sorted(out.glob('*.whl')):
 with zipfile.ZipFile(p) as z:
  meta=[n for n in z.namelist() if n.endswith('.dist-info/WHEEL')];assert len(meta)==1
  text=z.read(meta[0]).decode();assert 'Root-Is-Purelib: true' in text
  tags=[x[5:] for x in text.splitlines() if x.startswith('Tag: ')];assert tags and all(x.endswith('-none-any') for x in tags)
 r['wheels'].append({'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size,'tags':tags})
assert len(r['wheels'])==4
r['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat();rp.write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'built_wheels':len(r['wheels']),'receipt':str(rp)}))
