#!/usr/bin/env python3
"""Stage pinned CPython 3.10 ASR wheels without execution or network access."""
from pathlib import Path
import subprocess,json,hashlib,datetime
from acquisition_common import arguments
ROOT,E=arguments();BASE=E
src=ROOT/'serving-inputs/asr-sources';built=ROOT/'serving-inputs/asr-built-wheels';target=ROOT/'serving-inputs/asr-site-packages'
assert not target.exists()
files=sorted(src.glob('*.whl'))+sorted(built.glob('*.whl'));assert len(files)==190
req=ROOT/'serving-inputs/asr-install-requirements.txt'
rows=[]
for p in files:
 h=hashlib.sha256()
 with p.open('rb') as f:
  for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
 rows.append(p.as_uri()+' --hash=sha256:'+h.hexdigest())
req.write_text('\n'.join(rows)+'\n')
argv=['uv','pip','install','--target',str(target),'--python-version','3.10','--python-platform','x86_64-manylinux_2_35','--no-python-downloads','--offline','--no-index','--no-config','--no-build','--require-hashes','--link-mode','copy','--cache-dir',str(ROOT/'asr-install-cache'),'--strict','--requirements',str(req)]
r={'started':datetime.datetime.now(datetime.timezone.utc).isoformat(),'query':'Install every wheel from retained 186-wheel payload plus four locally built pure wheels, with full dependency resolution, pinned hashes and CPython 3.10/glibc 2.35 target','argv':argv,'requirements_sha256':hashlib.sha256(req.read_bytes()).hexdigest(),'requirements':rows}
p=E/'asr-package-install.json';p.write_text(json.dumps(r,indent=2)+'\n')
log=E/'asr-package-install.log'
with log.open('wb') as f:q=subprocess.run(argv,stdout=f,stderr=subprocess.STDOUT)
r.update({'finished':datetime.datetime.now(datetime.timezone.utc).isoformat(),'exit_code':q.returncode,'log':str(log.relative_to(BASE))});p.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'exit_code':q.returncode,'log':str(log)}))
if q.returncode: raise SystemExit(q.returncode)
from normalize_wheels import normalize
normalize(target)
