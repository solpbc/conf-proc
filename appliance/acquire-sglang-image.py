#!/usr/bin/env python3
"""Acquire the independently identified OCI image without running its content."""
from pathlib import Path
import json,subprocess,hashlib,datetime,os
from acquisition_common import arguments
R,E=arguments()
W=R/'serving-tools';W.mkdir(parents=True,exist_ok=True)
O=R/'serving-inputs/sglang-oci';O.parent.mkdir(exist_ok=True);assert not O.exists()
(W/'auth.json').write_text('{"auths":{}}\n');(W/'tmp').mkdir(exist_ok=True)
a=['skopeo','--insecure-policy','copy','--src-authfile',str(W/'auth.json'),'--preserve-digests','docker://lmsysorg/sglang@sha256:9611bd4c5624b0e9e17829506188a12f17205f2083de0dd44d6c521733553a50','dir:'+str(O)]
r={'started':datetime.datetime.now(datetime.timezone.utc).isoformat(),'argv':a,'scope':'Content-addressed public image input; signature policy permits acquisition, every blob independently verified; no container executed'}
p=E/'sglang-acquisition.json';p.write_text(json.dumps(r,indent=2)+'\n')
with (E/'sglang-copy.log').open('wb') as f:q=subprocess.run(a,stdout=f,stderr=subprocess.STDOUT,env={**os.environ,'TMPDIR':str(W/'tmp')})
r['copy_returncode']=q.returncode;p.write_text(json.dumps(r,indent=2)+'\n');assert q.returncode==0,'see preserved copy log'
b=(O/'manifest.json').read_bytes();assert hashlib.sha256(b).hexdigest()=='9611bd4c5624b0e9e17829506188a12f17205f2083de0dd44d6c521733553a50';m=json.loads(b)
verified=[]
for row in [m['config'],*m['layers']]:
 f=O/row['digest'].split(':',1)[1];assert f.stat().st_size==row['size'];h=hashlib.sha256()
 with f.open('rb') as stream:
  for chunk in iter(lambda:stream.read(1024*1024),b''):h.update(chunk)
 assert 'sha256:'+h.hexdigest()==row['digest'];verified.append({'digest':row['digest'],'bytes':f.stat().st_size})
r.update({'finished':datetime.datetime.now(datetime.timezone.utc).isoformat(),'verified_blobs':verified});p.write_text(json.dumps(r,indent=2)+'\n');print('Exact SGLang manifest/config/layer bytes acquired and independently verified.')

subprocess.run(['skopeo','--insecure-policy','copy','--preserve-digests','dir:'+str(O),'oci:'+str(O.parent/'sglang-layout')+':runtime'],check=True)
subprocess.run(['umoci','unpack','--rootless','--image',str(O.parent/'sglang-layout')+':runtime',str(O.parent/'sglang-bundle')],check=True)
