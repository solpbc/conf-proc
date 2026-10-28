#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Exercise the final firewall with live controls in isolated namespaces."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading

from spp_appliance import NFT_RULESET


def run(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, timeout=10, **kwargs)


def connect(host, port):
    try:
        with socket.create_connection((host, port), timeout=0.4):
            return True
    except OSError:
        return False


def serve(port):
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", port))
    listener.listen(32)
    def echo(connection):
        with connection:
            connection.settimeout(10)
            try:
                while chunk := connection.recv(32):
                    connection.sendall(chunk)
            except OSError:
                pass
    def accept():
        while True:
            connection, _ = listener.accept()
            threading.Thread(target=echo, args=(connection,), daemon=True).start()
    threading.Thread(target=accept, daemon=True).start()


def inside(package):
    nft = str(package / "usr/sbin/nft")
    env = dict(os.environ, LD_LIBRARY_PATH=str(package / "usr/lib/x86_64-linux-gnu"))
    my_slice = Path("/proc/self/cgroup").read_text().split(":", 2)[2].strip().split("/")[1]
    other = "system.slice" if my_slice != "system.slice" else "init.scope"
    assert my_slice and '"' not in my_slice
    run(["ip", "link", "set", "lo", "up"])
    run(["ip", "link", "add", "d0", "type", "dummy"])
    run(["ip", "addr", "add", "10.99.0.2/24", "dev", "d0"])
    run(["ip", "link", "set", "d0", "up"])
    peer = subprocess.Popen(["unshare", "--net", sys.executable, "-u", "-c",
                             "import sys; print('ready'); sys.stdin.read()"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    held = None
    try:
        assert peer.stdout.readline() == b"ready\n", "peer namespace failed to start"
        run(["ip", "link", "add", "v0", "type", "veth", "peer", "name", "v1"])
        run(["ip", "link", "set", "v1", "netns", str(peer.pid)])
        run(["ip", "addr", "add", "10.98.0.1/24", "dev", "v0"])
        run(["ip", "link", "set", "v0", "up"])
        prefix = ["nsenter", "-t", str(peer.pid), "-n"]
        run([*prefix, "ip", "addr", "add", "10.98.0.2/24", "dev", "v1"])
        run([*prefix, "ip", "link", "set", "v1", "up"])
        for port in (8000, 8001, 9100, 9443):
            serve(port)

        def incoming(port):
            code = ("import socket,sys\ntry:\n s=socket.create_connection(('10.98.0.1'," + str(port) +
                    "),.4); s.close(); sys.exit(0)\nexcept OSError: sys.exit(1)")
            result = subprocess.run([*prefix, sys.executable, "-c", code], capture_output=True, timeout=3)
            assert result.returncode in (0, 1), result.stderr
            return result.returncode == 0

        def tx():
            value = run(["ip", "-s", "-j", "link", "show", "d0"])
            return json.loads(value.stdout)[0]["stats64"]["tx"]["packets"]

        def outgoing(port):
            before = tx()
            connect("10.99.0.9", port)
            return tx() - before

        def rules(content):
            run([nft, "flush", "ruleset"], env=env)
            text = NFT_RULESET.replace('"sppcontent.slice"', '"' + (my_slice if content else other) + '"')
            text = text.replace('"sppgateway.slice"', '"' + (other if content else my_slice) + '"')
            run([nft, "-f", "-"], input=text.encode(), env=env)

        assert all(connect("127.0.0.1", port) for port in (8000, 9100, 9443)), "loopback listener controls"
        assert incoming(8001) and incoming(9443), "incoming listener controls"
        assert outgoing(80) > 0, "outbound packet control"
        held = subprocess.Popen([*prefix, sys.executable, "-u", "-c",
            "import socket,sys\ns=socket.create_connection(('10.98.0.1',8001),1)\n"
            "s.sendall(b'a'); assert s.recv(1)==b'a'; print('ready')\n"
            "sys.stdin.readline(); s.settimeout(.5); s.sendall(b'b')\n"
            "try:\n data=s.recv(1); sys.exit(1 if data else 0)\n"
            "except socket.timeout: sys.exit(0)"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert held.stdout.readline() == b"ready\n", "established connection control"
        rules(content=True)
        held.communicate(input=b"\n", timeout=3)
        assert held.returncode == 0, "established content socket still transmits"
        assert connect("127.0.0.1", 8000), "content-to-content loopback"
        assert not connect("127.0.0.1", 9100), "content reaches gateway metrics"
        assert not connect("127.0.0.1", 9443), "content reaches gateway admission"
        assert outgoing(443) == 0 and outgoing(80) == 0, "content non-loopback egress"
        rules(content=False)
        assert connect("127.0.0.1", 8000) and connect("127.0.0.1", 9443), "gateway loopback"
        assert outgoing(443) > 0 and outgoing(80) == 0, "gateway egress restriction"
        assert incoming(9443), "gateway incoming positive"
        assert not incoming(8001), "extra listener incoming denial"
        print("PASS: listener controls, content isolation, established denial, gateway egress and inbound firewall")
    finally:
        for process in (held, peer):
            if process is not None and process.poll() is None:
                process.terminate()
                process.wait(timeout=3)


if __name__ == "__main__":
    if sys.argv[1] == "--inside":
        inside(Path(sys.argv[2]))
    else:
        package = Path(sys.argv[1]).resolve()
        args = ["bwrap", "--unshare-user", "--uid", "0", "--gid", "0", "--unshare-net",
                "--bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
                "--cap-add", "CAP_NET_ADMIN", "--cap-add", "CAP_SYS_ADMIN", "--",
                sys.executable, str(Path(__file__).resolve()), "--inside", str(package)]
        raise SystemExit(subprocess.run(args).returncode)
