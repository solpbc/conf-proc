#!/usr/bin/env python3
"""Reacquire the retained ASR source/wheel payloads by exact published hashes."""
from pathlib import Path
import concurrent.futures,urllib.request,json,hashlib,subprocess,datetime,shutil
from acquisition_common import arguments, DATA
ROOT,E=arguments()
R=ROOT/'serving-inputs/asr-sources';R.mkdir(mode=0o700,parents=True)
M=DATA/'asr-sources.json'
pins=json.loads(M.read_text())
rows=[(x['sha256'],x['filename']) for x in pins]
receipt={'manifest_sha256':hashlib.sha256(M.read_bytes()).hexdigest(),'metadata':[],'results':[]}
p=E/'asr-source-acquisition.json'
def save():p.write_text(json.dumps(receipt,indent=2)+'\n')
def metadata(item):
 expected,name=item
 if name.endswith('.whl'):project,version=name.split('-')[:2]
 else:project,version=name.removesuffix('.tar.gz').removesuffix('.zip').rsplit('-',1)
 url=f'https://pypi.org/pypi/{project}/{version}/json'
 with urllib.request.urlopen(url,timeout=60) as q:b=q.read(8*1024*1024+1)
 assert len(b)<=8*1024*1024
 matches=[x for x in json.loads(b)['urls'] if x['filename']==name and x['digests']['sha256']==expected];assert len(matches)==1,name
 x=matches[0];assert x['url'].startswith('https://files.pythonhosted.org/')
 return {'filename':name,'sha256':expected,'url':x['url'],'bytes':x['size'],'metadata_url':url,'metadata_sha256':hashlib.sha256(b).hexdigest()}
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
 for row in pool.map(metadata,rows):receipt['metadata'].append(row);save()
assert shutil.disk_usage(R).free>sum(x['bytes'] for x in receipt['metadata'])
print('All retained source identities resolved against public release metadata.',flush=True)
def acquire(x):
 part=R/(x['filename']+'.part');dest=R/x['filename'];assert not part.exists() and not dest.exists()
 a=['curl','--fail','--location','--silent','--show-error','--retry','2','--connect-timeout','30','--max-time','3600','--output',str(part),x['url']];q=subprocess.run(a,capture_output=True,text=True)
 result={'filename':x['filename'],'returncode':q.returncode,'stderr':q.stderr,'verified':False}
 if q.returncode:return result
 h=hashlib.sha256()
 with part.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 result.update({'actual_sha256':h.hexdigest(),'actual_bytes':part.stat().st_size})
 if result['actual_sha256']!=x['sha256'] or result['actual_bytes']!=x['bytes']:return result
 part.rename(dest);result['verified']=True;return result
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
 for result in pool.map(acquire,receipt['metadata']):receipt['results'].append(result);save()
receipt['finished']=datetime.datetime.now(datetime.timezone.utc).isoformat();save();assert all(x['verified'] for x in receipt['results'])
print('All retained ASR source/wheel payloads downloaded and hash verified.')
