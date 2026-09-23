#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
#
# Behavioural check of the prod egress ruleset, loaded by the image's own nft into a throwaway
# network namespace (bwrap; no root needed where bwrap may create user namespaces). The calling
# process stands in for each slice in turn, and packets leaving a dummy interface are counted:
#   content slice: loopback works; nothing leaves, not even :443
#   gateway slice: loopback works; :443 leaves; anything else does not
# Usage: check_egress_ruleset.sh NFT_PACKAGE_ROOT
set -euo pipefail
NR=$(realpath "$1"); HERE=$(dirname "$(realpath "$0")")
RULES=$(mktemp); trap 'rm -f "$RULES" "$RULES".*' EXIT
python3 -c "import sys;sys.path.insert(0,'$HERE');import spp_appliance as a;open('$RULES','w').write(a.NFT_RULESET)"
MYSLICE=$(awk -F/ 'NR==1{print $2}' <(cut -d: -f3 /proc/self/cgroup))
OTHER=system.slice; [ "$MYSLICE" = system.slice ] && OTHER=init.scope
bwrap --unshare-user --uid 0 --gid 0 --unshare-net --bind / / --dev /dev --proc /proc \
  --cap-add CAP_NET_ADMIN -- env NR="$NR" RULES="$RULES" MYSLICE="$MYSLICE" OTHER="$OTHER" \
  LD_LIBRARY_PATH="$NR/usr/lib/x86_64-linux-gnu" bash -euo pipefail -c '
NFT=$NR/usr/sbin/nft
ip link set lo up; ip link add d0 type dummy; ip addr add 10.99.0.2/24 dev d0; ip link set d0 up
python3 -c "import socket,time;s=socket.socket();s.bind((\"127.0.0.1\",8000));s.listen();time.sleep(60)" & sleep 0.5
tx(){ ip -s -j link show d0 | python3 -c "import json,sys;print(json.load(sys.stdin)[0][\"stats64\"][\"tx\"][\"packets\"])"; }
out(){ b=$(tx); python3 -c "
import socket;s=socket.socket();s.settimeout(0.5)
try: s.connect((\"$1\",$2))
except Exception: pass" ; echo $(( $(tx) - b )); }
lo(){ python3 -c "import socket;socket.create_connection((\"127.0.0.1\",8000),1)" && echo ok || echo FAIL; }
fail=0; want(){ [ "$2" = "$3" ] && echo "  ok    $1" || { echo "  FAIL  $1 (got $3, want $2)"; fail=1; }; }
[ "$(out 10.99.0.9 80)" = 1 ] || { echo "control failed: no packet left with no ruleset"; exit 2; }
sed "s/\"sppcontent.slice\"/\"$MYSLICE\"/; s/\"sppgateway.slice\"/\"$OTHER\"/" "$RULES" > "$RULES.c"; $NFT -f "$RULES.c"
echo "as content slice:"; want loopback ok "$(lo)"; want ":443 leaves" 0 "$(out 10.99.0.9 443)"; want ":80 leaves" 0 "$(out 10.99.0.9 80)"
$NFT flush ruleset
sed "s/\"sppcontent.slice\"/\"$OTHER\"/; s/\"sppgateway.slice\"/\"$MYSLICE\"/" "$RULES" > "$RULES.g"; $NFT -f "$RULES.g"
echo "as gateway slice:"; want loopback ok "$(lo)"; want ":443 leaves" 1 "$(out 10.99.0.9 443)"; want ":80 leaves" 0 "$(out 10.99.0.9 80)"
exit $fail'
