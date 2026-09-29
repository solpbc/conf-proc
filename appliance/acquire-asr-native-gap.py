#!/usr/bin/env python3
"""Recover libmpdec3 from authenticated fixed Jammy snapshot metadata."""
from pathlib import Path
import urllib.request,hashlib,json,subprocess,lzma,datetime
from acquisition_common import arguments
R,E=arguments()
W=R/'serving-inputs/asr-native-gap';W.mkdir(parents=True,exist_ok=False)
base='https://snapshot.ubuntu.com/ubuntu/20260615T120000Z/'
r={'started':datetime.datetime.now(datetime.timezone.utc).isoformat(),'snapshot':base,'requests':[]};rp=E/'asr-native-gap.json'
def save():rp.write_text(json.dumps(r,indent=2)+'\n')
def get(rel,dest,limit):
 with urllib.request.urlopen(base+rel,timeout=120) as q:data=q.read(limit+1)
 assert len(data)<=limit;dest.write_bytes(data);r['requests'].append({'url':base+rel,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()});save();return data
release=get('dists/jammy/InRelease',W/'InRelease',1024*1024)
a=['gpgv','--keyring','/usr/share/keyrings/ubuntu-archive-keyring.gpg',str(W/'InRelease')];q=subprocess.run(a,capture_output=True,text=True);r['signature_verification']={'argv':a,'exit_code':q.returncode,'stdout':q.stdout,'stderr':q.stderr};save();assert q.returncode==0
section=release.decode().split('SHA256:\n',1)[1].split('\nSHA512:',1)[0]
rows=[x.split() for x in section.splitlines() if len(x.split())==3];matches=[x for x in rows if x[2]=='main/binary-amd64/Packages.xz'];assert len(matches)==1
sha,size,rel=matches[0];data=get('dists/jammy/'+rel,W/'Packages.xz',int(size));assert len(data)==int(size) and hashlib.sha256(data).hexdigest()==sha
matches=[]
for stanza in lzma.decompress(data).decode().split('\n\n'):
 fields={line.split(': ',1)[0]:line.split(': ',1)[1] for line in stanza.splitlines() if ': ' in line and not line.startswith(' ')}
 if fields.get('Package')=='libmpdec3' and fields.get('Architecture')=='amd64':matches.append(fields)
assert len(matches)==1;item=matches[0];r['package_metadata']=item;save();p=W/'libmpdec3.deb';data=get(item['Filename'],p,int(item['Size']));assert len(data)==int(item['Size']) and hashlib.sha256(data).hexdigest()==item['SHA256']
r['finished']=datetime.datetime.now(datetime.timezone.utc).isoformat();save();print(json.dumps({'package':item['Package'],'version':item['Version'],'sha256':item['SHA256'],'signature_verified':True,'acquired':True}))
