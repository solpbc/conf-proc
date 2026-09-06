#!/usr/bin/env python3
"""Native kernel subscription and same-descriptor cross-exec checks."""
from pathlib import Path
import importlib.util,json,os,socket,subprocess,sys
ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'conf_proc_spp_candidate_device.py'
if not sys.argv[1:]:
 results=[]
 for case in ('positive','wrong-binding','occupied-slot','events','wrong-descriptor'):
  args=['bwrap','--unshare-all','--as-pid-1','--die-with-parent','--uid','0','--gid','0','--cap-add','ALL','--ro-bind','/','/','--proc','/proc','--dev','/dev','--',sys.executable,str(Path(__file__).resolve()),'--inside',case]
  result=subprocess.run(args,capture_output=True,timeout=20)
  assert result.returncode==0,(case,result.returncode,result.stderr.decode())
  report=json.loads(result.stdout);assert report['passed'] is True
  results.append(report)
 print(json.dumps(results));raise SystemExit(0)
spec=importlib.util.spec_from_file_location('device',SOURCE);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
case=sys.argv[2]
assert os.getpid()==1
if sys.argv[1]=='--inside':
 monitor=m.DeviceMonitor()
 if case=='events':
  from unittest.mock import patch
  import struct
  original=monitor.socket
  class Leaf:
   def __init__(self,result):self.result=result
   def __getattr__(self,name):return getattr(original,name)
   def recvmsg(self,*args):return self.result
  rootcred=(socket.SOL_SOCKET,socket.SCM_CREDENTIALS,struct.pack('3i',0,0,0))
  cases=[(b'add@/devices/test\0',[rootcred],0,(0,1)),
         (b'add@/devices/test\0',[rootcred],socket.MSG_TRUNC,(0,1)),
         (b'add@/devices/test\0',[rootcred],0,(123,1)),
         (b'add@/devices/test\0',[],0,(0,1)),
         (b'add@/devices/test\0',[rootcred,(socket.SOL_SOCKET,m.SO_RXQ_OVFL,struct.pack('I',1))],0,(0,1))]
  for event in cases:
   monitor.socket=Leaf(event)
   try:monitor.check()
   except RuntimeError:pass
   else:raise AssertionError('post-seal device event accepted')
  monitor.socket=original
  with patch.object(m,'device_census',return_value=monitor.census[1:]):
   try:monitor.check()
   except RuntimeError:pass
   else:raise AssertionError('changed physical census accepted')
  monitor.close();print(json.dumps({'case':case,'passed':True}));raise SystemExit(0)
 if case=='occupied-slot':
  assert monitor.socket.fileno()!=4
  fd=os.open('/dev/null',os.O_RDONLY)
  if fd!=4:os.dup2(fd,4);os.close(fd)
  before=os.fstat(4)
  try:monitor.move_to_handoff()
  except RuntimeError:pass
  else:raise AssertionError('occupied handoff slot overwritten')
  assert os.fstat(4)==before
  print(json.dumps({'case':case,'passed':True}));raise SystemExit(0)
 binding=monitor.move_to_handoff();assert monitor.socket.fileno()==4
 if case=='wrong-binding':binding=bytes([binding[0]^1])+binding[1:]
 if case=='wrong-descriptor':
  monitor.close();fd=os.open('/dev/null',os.O_RDONLY)
  if fd!=4:os.dup2(fd,4);os.close(fd)
 os.set_inheritable(4,True)
 os.execve(sys.executable,[sys.executable,str(Path(__file__).resolve()),'--resumed',case,binding.hex()],{'LANG':'C','LC_ALL':'C'})
assert sys.argv[1]=='--resumed' and os.get_inheritable(4)
os.set_inheritable(4,False)
try:monitor=m.DeviceMonitor.resume(bytes.fromhex(sys.argv[3]))
except (RuntimeError,OSError):
 assert case in ('wrong-binding','wrong-descriptor')
 try:os.fstat(4)
 except OSError:pass
 else:raise AssertionError('failed resume leaked device monitor')
else:
 assert case=='positive'
 monitor.check();assert not os.get_inheritable(4);monitor.close()
print(json.dumps({'case':case,'passed':True}))
