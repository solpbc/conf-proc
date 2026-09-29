#!/usr/bin/env python3
"""Acquire fixed model payloads inside this run's owned root and verify each byte."""
from pathlib import Path
import json,hashlib,subprocess,shutil,datetime
from acquisition_common import arguments, DATA
ROOT,E=arguments()
R=ROOT/'serving-inputs';R.mkdir(mode=0o700,exist_ok=True)
rows=[]
for label,repo,rev in [('qwen','Qwen/Qwen3.5-4B','851bf6e806efd8d0a36b00ddf55e13ccb7b8cd0a'),('asr','nvidia/parakeet-tdt-0.6b-v3','7c35754d166cca382ad1e53e68b01e7c575f3a1d')]:
 tree=json.loads((DATA/(label+'-tree.json')).read_text())
 for x in tree:
  if x['type']!='file':continue
  name=x['path']
  if label=='qwen' and name not in {'.gitattributes','README.md'}:
   rows.append((label,repo,rev,x))
  if label=='asr' and name=='parakeet-tdt-0.6b-v3.nemo':rows.append((label,repo,rev,x))
assert all(Path(x['path']).name==x['path'] for _,_,_,x in rows)
assert shutil.disk_usage(R).free > sum(x['size'] for _,_,_,x in rows)
receipt={'started':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'Pinned public payload acquisition only; not executed or qualified','rows':[]}
def save(): (E/'model-acquisition.json').write_text(json.dumps(receipt,indent=2)+'\n')
save()
for label,repo,rev,x in rows:
 dest=R/label/x['path'];dest.parent.mkdir(exist_ok=True);assert not dest.exists();part=dest.with_name(dest.name+'.part');assert not part.exists()
 url=f"https://huggingface.co/{repo}/resolve/{rev}/{x['path']}?download=true"
 a=['curl','--fail','--location','--silent','--show-error','--retry','2','--connect-timeout','30','--max-time','3600','--output',str(part),url]
 q=subprocess.run(a,capture_output=True,text=True)
 row={'path':str(dest),'url':url,'curl_returncode':q.returncode,'stderr':q.stderr,'expected_size':x['size']};receipt['rows'].append(row);save()
 if q.returncode:raise RuntimeError('download failed: '+x['path'])
 sha=hashlib.sha256();git=hashlib.sha1();size=part.stat().st_size;git.update(b'blob '+str(size).encode()+b'\0')
 with part.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):sha.update(b);git.update(b)
 row.update({'bytes':size,'sha256':sha.hexdigest(),'git_blob_sha1':git.hexdigest()})
 assert size==x['size']
 if 'lfs' in x:assert sha.hexdigest()==x['lfs']['oid']
 else:assert git.hexdigest()==x['oid']
 if x['path']=='parakeet-tdt-0.6b-v3.nemo':assert sha.hexdigest()=='3cbdc85877e668ca7b82d0d56770eb1fac76691f55d6b97545e8d61ca588d10d'
 if x['path']=='model.safetensors.index.json':assert sha.hexdigest()=='cf3f798ee02ba45f9622aa8892a47369ab667d0afbf154ee7c2212de42e6302d'
 part.rename(dest);row['verified']=True;save();print('verified',label,x['path'],flush=True)
receipt['finished']=datetime.datetime.now(datetime.timezone.utc).isoformat();save()
