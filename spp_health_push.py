# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Fixed-schema advisory health push, independent of admission and content."""
from __future__ import annotations

import http.client
import io
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import ssl
import subprocess
import threading
import time
import wave

CONTRACT = json.loads(Path(__file__).with_name("health-push-contract.json").read_text())
REPORT = CONTRACT["messages"]["report"]
FIELDS = REPORT["fields"]
SNAPSHOT_PATH = Path("/run/spp-health/snapshot.json")
BUILD_PATH = Path("/etc/spp/build-id")
HOST = "spp-health.solpbc.org"
LIMIT = 8192
SNAPSHOT_MAX_AGE_NS = 30_000_000_000
UNITS = tuple(FIELDS["units"]["fields"])
MODEL_IDS = {"text": "Qwen/Qwen3.5-4B", "asr": "nvidia/parakeet-tdt-0.6b-v3"}


def validate(value, spec) -> None:
    if "$ref" in spec:
        spec = CONTRACT["definitions"][spec["$ref"]]
    kind = spec["type"]
    good = False
    if kind == "object":
        good = type(value) is dict and value.keys() == spec["fields"].keys()
        if good:
            for key, child in spec["fields"].items():
                validate(value[key], child)
    elif kind == "array":
        good = type(value) is list and len(value) <= spec.get("max_len", spec.get("len", 0))
        good = good and ("len" not in spec or len(value) == spec["len"])
        if good:
            for item in value:
                validate(item, spec["items"])
    elif kind == "int":
        good = type(value) is int and spec["min"] <= value <= spec["max"]
    elif kind == "bool":
        good = type(value) is bool
    elif kind == "enum":
        good = type(value) is str and value in spec["values"]
    elif kind == "hex":
        good = type(value) is str and re.fullmatch("[0-9a-f]{%d}" % (2 * spec["bytes"]), value) is not None
    if not good:
        raise ValueError("invalid health field")


def encode(report: dict) -> bytes:
    validate(report, REPORT)
    body = json.dumps(report, separators=(",", ":"), sort_keys=True).encode("ascii")
    if len(body) > LIMIT:
        raise ValueError("health report too large")
    return body


def fallback_snapshot(category: str) -> dict:
    return {
        "accounting_boot": "0" * 32,
        "counters": {key: 0 for key in FIELDS["counters"]["fields"]},
        "histogram": {"month": 0, "released": False, "bands": [0, 0, 0], "counted_days": 0},
        "collector": {"snapshot": category, "state": "unavailable", "operation": "none", "active_ms": 0,
                      "last_result": "none", "queue_timeouts": 0, "execution_timeouts": 0, "available": False},
    }


def read_snapshot(path: Path = SNAPSHOT_PATH, now_ns=None) -> dict:
    try:
        with path.open("rb") as stream:
            raw = stream.read(LIMIT + 1)
        if len(raw) > LIMIT:
            raise ValueError("snapshot too large")
        value = json.loads(raw)
        if type(value) is not dict or value.keys() != {"written_monotonic_ns", "accounting_boot", "counters", "histogram", "collector"}:
            raise ValueError("snapshot shape")
        written = value.pop("written_monotonic_ns")
        if type(written) is not int or written < 0:
            raise ValueError("snapshot time")
        for key in value:
            validate(value[key], FIELDS[key])
        now = time.monotonic_ns() if now_ns is None else now_ns
        if not 0 <= now - written <= SNAPSHOT_MAX_AGE_NS:
            return fallback_snapshot("stale")
        return value
    except FileNotFoundError:
        return fallback_snapshot("missing")
    except (OSError, ValueError, TypeError, RecursionError):
        return fallback_snapshot("invalid")


class SnapshotWriter:
    def __init__(self, collector, fleet, path: Path = SNAPSHOT_PATH):
        self.collector, self.fleet, self.path = collector, fleet, path
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True, name="health-snapshot")

    def write(self):
        # Timestamp BEFORE any locks; a blocked writer cannot freshen old state.
        started = time.monotonic_ns()
        diagnostic = self.collector.snapshot()
        collector = {key: diagnostic[key] for key in
                     ("state", "operation", "last_result", "queue_timeouts", "execution_timeouts", "available")}
        collector.update(snapshot="current", active_ms=min(86_400_000, int(diagnostic["active_seconds"] * 1000)))
        value = {**self.fleet.snapshot(), "collector": collector}
        for key in value:
            validate(value[key], FIELDS[key])
        value["written_monotonic_ns"] = started
        raw = json.dumps(value, separators=(",", ":")).encode("ascii")
        if len(raw) > LIMIT:
            raise ValueError("snapshot too large")
        temporary = self.path.with_suffix(".new")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o644)
            stream.write(raw)
        temporary.replace(self.path)

    def run(self):
        while not self.stop_event.is_set():
            try:
                self.write()
            except (OSError, ValueError, TypeError):
                pass  # Age of the last successful write exposes failure; no exception text.
            self.stop_event.wait(5)

    def start(self):
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        self.thread.join(timeout=1)


def command(argv: list[str], timeout=5.0) -> str:
    """Bound time AND bytes, including a child that never closes its output."""
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               start_new_session=True, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    deadline = time.monotonic() + timeout
    data = bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                left = deadline - time.monotonic()
                if left <= 0 or not selector.select(left):
                    raise TimeoutError("probe timeout")
                block = os.read(process.stdout.fileno(), LIMIT + 1 - len(data))
                if not block:
                    break
                data.extend(block)
                if len(data) > LIMIT:
                    raise ValueError("probe too large")
        if process.wait(timeout=max(0.001, deadline - time.monotonic())):
            raise ValueError("probe failed")
        return data.decode("ascii")
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.stdout.close()
        process.wait(timeout=1)


def unit_state(name: str, runner=command) -> dict:
    result = {"state": "unknown", "restarts": 0, "last_exit": "unknown"}
    try:
        raw = runner(["systemctl", "show", name + ".service", "--property=ActiveState,NRestarts,Result,ExecMainCode,ExecMainStatus"])
        props = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
        state = props.get("ActiveState")
        allowed = CONTRACT["definitions"]["unit"]["fields"]["state"]["values"]
        result["state"] = state if state in allowed else "unknown"
        restarts = props.get("NRestarts", "0")
        result["restarts"] = min(1_000_000, int(restarts)) if restarts.isdecimal() else 0
        reason = props.get("Result", "")
        if reason in ("oom-kill", "timeout"):
            result["last_exit"] = {"oom-kill": "oom", "timeout": "timeout"}[reason]
        elif props.get("ExecMainCode") in ("2", "3"):
            result["last_exit"] = "signal"
        elif reason == "success" and props.get("ExecMainStatus") == "0":
            result["last_exit"] = "none" if props.get("ExecMainCode") == "0" else "clean"
        elif reason in ("exit-code", "signal", "core-dump", "watchdog", "start-limit-hit", "resources", "protocol"):
            result["last_exit"] = "error"
    except (OSError, ValueError, TimeoutError, subprocess.SubprocessError):
        pass
    return result


def gpu_state(runner=command):
    cc = {"mode": "unknown", "environment": "unknown"}
    gpu = {"present": 0, "cc_ready": 0}
    for flag, label, key, mapping in (
        ("-f", "CC status", "mode", {"ON": "on", "OFF": "off"}),
        ("-e", "CC Environment", "environment", {"PRODUCTION": "production", "DEVTOOLS": "development", "DEVELOPMENT": "development"}),
    ):
        try:
            props = dict((k.strip(), v.strip()) for k, sep, v in
                         (line.partition(":") for line in runner(["nvidia-smi", "conf-compute", flag]).splitlines()) if sep)
            cc[key] = mapping.get(props.get(label), "unknown")
        except (OSError, ValueError, TimeoutError, subprocess.SubprocessError):
            pass
    try:
        names = runner(["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"]).strip().splitlines()
        # A wrong device is not counted as an expected device.
        gpu["present"] = min(16, len(names)) if all(n.strip() == "NVIDIA H100 NVL" for n in names) else 0
        if cc == {"mode": "on", "environment": "production"}:
            gpu["cc_ready"] = gpu["present"]
    except (OSError, ValueError, TimeoutError, subprocess.SubprocessError):
        pass
    return cc, gpu


def local_request(port: int, path: str, body: bytes | None = None, content_type=None, timeout=10.0):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    deadline = time.monotonic() + timeout
    timer = None
    try:
        connection.connect()
        wire = connection.sock
        def interrupt():
            try:
                wire.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        # Socket timeouts alone restart after every byte of a slow HTTP header.
        timer = threading.Timer(max(0.001, deadline - time.monotonic()), interrupt)
        timer.daemon = True
        timer.start()
        connection.request("GET" if body is None else "POST", path, body=body,
                           headers={"Content-Type": content_type} if content_type else {})
        response = connection.getresponse()
        data = bytearray()
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("local probe timeout")
            if connection.sock is not None:
                connection.sock.settimeout(left)
            block = response.read1(LIMIT + 1 - len(data))
            if not block:
                return response.status, bytes(data)
            data.extend(block)
            if len(data) > LIMIT:
                raise ValueError("local response too large")
    finally:
        if timer is not None:
            timer.cancel()
        connection.close()


def silence_request() -> bytes:
    stream = io.BytesIO()
    with wave.open(stream, "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(16000)
        wav.writeframes(b"\0" * 32000)
    return (b'--spp-health-fixed\r\nContent-Disposition: form-data; name="file"; filename="health.wav"\r\n'
            b'Content-Type: audio/wav\r\n\r\n' + stream.getvalue() + b'\r\n--spp-health-fixed--\r\n')


def model_state(slot: str, requester=local_request) -> dict:
    result = {"identity": "unknown", "ready": "unknown"}
    port, models, health = (8000, "/v1/models", "/health_generate") if slot == "text" else (8100, "/v1/audio/models", "/v1/audio/health")
    try:
        status, data = requester(port, models)
        if status == 200:
            value = json.loads(data)
            ids = [item.get("id") for item in value.get("data", [])]
            result["identity"] = "match" if ids == [MODEL_IDS[slot]] else "mismatch"
        status, _ = requester(port, health)
        if status == 200 and slot == "asr":
            status, _ = requester(port, "/v1/audio/transcriptions", silence_request(),
                                  "multipart/form-data; boundary=spp-health-fixed")
        result["ready"] = "ready" if status == 200 else "failed"
    except (OSError, ValueError, TypeError, AttributeError, TimeoutError, http.client.HTTPException):
        result["ready"] = "failed"
    return result


def sample(build: str, boot: str, seq: int, started: float) -> dict:
    units = {name: unit_state(name) for name in UNITS}
    cc, gpu = gpu_state()
    errors = []
    for name in ("spp-gateway", "sglang", "spp-asr"):
        exit_state = units[name]["last_exit"]
        if exit_state in ("signal", "error", "oom", "timeout"):
            errors.append({"component": name, "code": {"signal": "crash", "error": "unknown"}.get(exit_state, exit_state), "count": 1})
    models = {slot: model_state(slot) for slot in MODEL_IDS}
    # Read after probes so an old snapshot cannot look current after a slow probe.
    return {"v": 1, "kind": "report", "build": build, "boot": boot, "seq": seq,
            "uptime_s": min(1_000_000_000, max(0, int(time.monotonic() - started))),
            "cc": cc, "gpu": gpu, "units": units, "models": models, "errors": errors, **read_snapshot()}


def post(body: bytes) -> int:
    """Read only the bounded HTTP status line; no response headers or body."""
    context = ssl.create_default_context()
    with socket.create_connection((HOST, 443), timeout=10) as plain:
        with context.wrap_socket(plain, server_hostname=HOST) as connection:
            deadline = time.monotonic() + 10
            connection.sendall((f"POST /v1/report HTTP/1.1\r\nHost: {HOST}\r\nContent-Type: application/json\r\n"
                                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode("ascii") + body)
            line = bytearray()
            while len(line) < 128:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise TimeoutError("push timeout")
                connection.settimeout(left)
                char = connection.recv(1)
                if not char:
                    break
                line.extend(char)
                if line.endswith(b"\r\n"):
                    match = re.fullmatch(rb"HTTP/1\.[01] ([1-5][0-9]{2}) [^\r\n]*\r\n", line)
                    return int(match[1]) if match else 0
            return 0


def main() -> int:
    build = BUILD_PATH.read_text().strip()
    validate(build, FIELDS["build"])
    boot, started, seq = os.urandom(16).hex(), time.monotonic(), 0
    while True:
        tick = time.monotonic()
        seq += 1
        try:
            post(encode(sample(build, boot, seq, started)))
        except (OSError, ValueError, TimeoutError, subprocess.SubprocessError):
            pass
        time.sleep(max(1, 60 - (time.monotonic() - tick)))


if __name__ == "__main__":
    raise SystemExit(main())
