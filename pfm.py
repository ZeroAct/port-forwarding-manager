"""Port Forwarding Manager — local web UI for managing ssh -L tunnels per host.

    python pfm.py [--port 8765] [--ssh-config ~/.ssh/config] [--no-browser]
"""
from __future__ import annotations

import argparse
import atexit
import collections
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote

import core
import fileapi
from remotefs import REMOTE_CMD, AgentPool, RemoteError

HERE = Path(__file__).resolve().parent
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


# --------------------------------------------------------------------------
# profile storage
# --------------------------------------------------------------------------

class Store:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        self.data = {"profiles": {}}
        if path.exists():
            try:
                self.data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as e:
                backup = path.with_suffix(".broken.json")
                shutil.copy(path, backup)
                print(f"[pfm] profiles 파일을 읽지 못해 {backup} 로 백업함: {e}")
        self.data.setdefault("profiles", {})
        self.data.setdefault("ui", {})
        self.data.setdefault("settings", {})

    def os_settings(self, os_key: str) -> dict:
        return dict(self.data["settings"].get(os_key) or {})

    def save_os_settings(self, os_key: str, values: dict):
        """Paths are kept per OS so one profiles.json can be shared between machines."""
        with self.lock:
            cur = {k: v for k, v in values.items() if v}
            if cur:
                self.data["settings"][os_key] = cur
            else:
                self.data["settings"].pop(os_key, None)
            self._write()

    def profile(self, alias: str) -> dict | None:
        return self.data["profiles"].get(alias)

    def save_profile(self, alias: str, profile: dict):
        with self.lock:
            self.data["profiles"][alias] = profile
            self._write()

    def save_ui(self, prefs: dict):
        """Browser UI prefs (last host, tab, sort...). Kept server-side because the
        browser's localStorage is per origin and the port can change between runs."""
        with self.lock:
            ui = self.data["ui"]
            for k, v in prefs.items():
                if not isinstance(k, str) or len(k) > 200:
                    continue
                if v is None:
                    ui.pop(k, None)
                elif len(json.dumps(v)) <= 2000:
                    ui[k] = v
            while len(ui) > 500:  # e.g. one remembered path per host; drop oldest
                ui.pop(next(iter(ui)))
            self._write()

    def _write(self):  # caller holds self.lock
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, self.path)


def clean_profile(body: dict) -> dict:
    rules = []
    for r in body.get("rules", []):
        rules.append({
            "local": str(r.get("local", "")).strip(),
            "remoteHost": str(r.get("remoteHost", "")).strip(),
            "remote": str(r.get("remote", "")).strip(),
            "enabled": bool(r.get("enabled", True)),
            "note": str(r.get("note", ""))[:200],
        })
    rules = [core.normalize_rule(r) for r in rules]
    return {"rules": rules, "autoReconnect": bool(body.get("autoReconnect", True)),
            "autoStart": bool(body.get("autoStart", True))}


# --------------------------------------------------------------------------
# tunnels
# --------------------------------------------------------------------------

def port_in_use(port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", port))
        return False
    except OSError:
        return True
    finally:
        s.close()


# Win32-OpenSSH caps a process at ~256 handles (each forward = 2 sockets, v4+v6)
# and Windows caps command lines at 32K chars, so big port sets are split across
# several ssh processes that are managed as one tunnel.
CHUNK_SIZE = 100


class Tunnel:
    def __init__(self, mgr: "TunnelManager", alias: str):
        self.mgr, self.alias = mgr, alias
        self.procs: list[subprocess.Popen] = []
        self.authed: set[int] = set()
        self.gen = 0  # bumps on every spawn/stop so stale watcher threads are ignored
        self.state = "stopped"  # stopped|starting|running|reconnecting|error
        self.message = ""
        self.log: collections.deque[str] = collections.deque(maxlen=500)
        self.forwards: list[tuple[int, str, int]] = []
        self.desired = False
        self.auto_reconnect = True
        self.retries = 0
        self.started_at = 0.0
        self.lock = threading.RLock()

    def status(self) -> dict:
        return {"state": self.state, "message": self.message, "ports": len(self.forwards),
                "pids": [p.pid for p in self.procs], "since": self.started_at,
                "retries": self.retries}

    def _log(self, line: str):
        self.log.append(time.strftime("%H:%M:%S ") + line.rstrip())

    def start(self, forwards, auto_reconnect: bool) -> str | None:
        with self.lock:
            self.stop(quiet=True)
            if not forwards:
                return "활성화된 포트 규칙이 없습니다."
            busy = [lp for lp, _, _ in forwards if port_in_use(lp)]
            if busy:
                msg = "로컬 포트가 이미 사용 중: " + core._fmt_ports(busy)
                self.state, self.message = "error", msg
                self._log(msg)
                return msg
            self.forwards, self.auto_reconnect = forwards, auto_reconnect
            self.desired, self.retries = True, 0
            self._spawn()
            return None

    def _spawn(self):
        self.gen += 1
        gen = self.gen
        chunks = [self.forwards[i:i + CHUNK_SIZE] for i in range(0, len(self.forwards), CHUNK_SIZE)]
        self.procs, self.authed = [], set()
        self.state, self.message = "starting", "연결 중..."
        self.started_at = time.time()
        extra = f", ssh {len(chunks)}개로 분할" if len(chunks) > 1 else ""
        self._log(f"$ ssh ... {self.alias}  ({len(self.forwards)}개 포트{extra})")
        for chunk in chunks:
            cmd = self.mgr.build_command(self.alias, chunk)
            try:
                proc = subprocess.Popen(
                    cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace",
                    creationflags=NO_WINDOW)
            except OSError as e:
                self._kill_all()
                self.state, self.message, self.desired = "error", f"ssh 실행 실패: {e}", False
                self._log(self.message)
                return
            self.procs.append(proc)
            threading.Thread(target=self._watch, args=(proc, gen, chunk), daemon=True).start()

    def _watch(self, proc: subprocess.Popen, gen: int, chunk):
        label = f"[{chunk[0][0]}-{chunk[-1][0]}] " if len(self.procs) > 1 or len(self.forwards) > CHUNK_SIZE else ""
        for line in proc.stderr:
            line = line.strip()
            if not line:
                continue
            self._log(label + line)
            if gen != self.gen:
                continue
            if "Authenticated to" in line:
                with self.lock:
                    self.authed.add(proc.pid)
                    if gen == self.gen and len(self.authed) == len(self.procs):
                        self.state, self.message, self.retries = "running", "", 0
            elif self.state != "running" and any(k in line for k in (
                    "Permission denied", "Could not resolve", "Connection refused",
                    "timed out", "cannot listen", "Could not request")):
                self.message = line
        code = proc.wait()
        with self.lock:
            if gen != self.gen:
                return
            # one ssh of the group died: take the whole group down and handle it once
            self.gen += 1
            self._kill_all()
            if not self.desired:
                self.state, self.message = "stopped", ""
                return
            self._log(f"{label}ssh 종료 (exit {code})")
            if self.auto_reconnect and self.retries < 50:
                self.retries += 1
                delay = min(60, 2 ** min(self.retries, 6))
                self.state = "reconnecting"
                self.message = f"{delay}초 후 재연결 ({self.retries}회차) — {self.message or f'exit {code}'}"
                threading.Timer(delay, self._retry, args=(self.gen,)).start()
            else:
                self.desired = False
                self.state = "error"
                self.message = self.message or f"ssh 종료 (exit {code})"

    def _retry(self, gen: int):
        with self.lock:
            if self.desired and gen == self.gen and not self.procs:
                self._spawn()

    def _kill_all(self):
        procs, self.procs = self.procs, []
        for p in procs:
            if p.poll() is None:
                p.terminate()
        for p in procs:
            try:
                p.wait(3)
            except subprocess.TimeoutExpired:
                p.kill()
        return procs

    def stop(self, quiet=False):
        with self.lock:
            self.desired = False
            self.gen += 1
            procs = self._kill_all()
            if procs and not quiet:
                self._log("중지됨")
            self.state, self.message = "stopped", ""


class TunnelManager:
    def __init__(self, ssh_bin: str, ssh_config: Path, run_dir: Path):
        self.ssh_bin, self.ssh_config, self.run_dir = ssh_bin, ssh_config, run_dir
        self.tunnels: dict[str, Tunnel] = {}
        self.lock = threading.Lock()

    def get(self, alias: str) -> Tunnel:
        with self.lock:
            if alias not in self.tunnels:
                self.tunnels[alias] = Tunnel(self, alias)
            return self.tunnels[alias]

    def build_command(self, alias: str, forwards) -> list[str]:
        cmd = [self.ssh_bin, "-N", "-T",
               "-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes",
               "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3",
               "-o", "ConnectTimeout=15", "-o", "LogLevel=VERBOSE"]
        clean_cfg = self._config_without_forwards(alias)
        if clean_cfg:
            cmd += ["-F", str(clean_cfg)]
        elif self.ssh_config:
            cmd += ["-F", str(self.ssh_config)]
        for lp, rhost, rp in forwards:
            target = f"[{rhost}]" if ":" in rhost else rhost
            cmd += ["-L", f"{lp}:{target}:{rp}"]
        cmd.append(alias)
        return cmd

    def _config_without_forwards(self, alias: str) -> Path | None:
        """If the ssh config already defines forwards for this host they would be
        opened too (and clash), so feed ssh a resolved copy of the host's config
        (`ssh -G`) with all forwarding directives removed."""
        hosts = {h["alias"]: h for h in core.parse_ssh_config(self.ssh_config)}
        if not hosts.get(alias, {}).get("forwards"):
            return None
        try:
            out = subprocess.run([self.ssh_bin, "-F", str(self.ssh_config), "-G", alias],
                                 capture_output=True, text=True, timeout=10,
                                 stdin=subprocess.DEVNULL, creationflags=NO_WINDOW).stdout
        except (OSError, subprocess.TimeoutExpired):
            return None
        skip = ("localforward ", "remoteforward ", "dynamicforward ")
        lines = [l for l in out.splitlines() if not l.lower().startswith(skip)]
        if not any(l.lower().startswith("hostname ") for l in lines):
            return None
        self.run_dir.mkdir(parents=True, exist_ok=True)
        path = self.run_dir / f"{alias}.conf"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def stop_all(self):
        for t in list(self.tunnels.values()):
            t.stop(quiet=True)


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

def os_key() -> str:
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


OS_LABEL = {"windows": "Windows", "macos": "macOS", "linux": "Linux"}
DEFAULT_SSH_CONFIG = "~/.ssh/config"


def detect_ssh() -> str:
    found = shutil.which("ssh")
    if found:
        return found
    if os_key() == "windows":  # built-in OpenSSH, in case PATH was trimmed
        p = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "OpenSSH" / "ssh.exe"
        if p.exists():
            return str(p)
    return "ssh"


def resolve_ssh_bin(value: str) -> str | None:
    """A name on PATH or a path to an executable -> absolute path, or None."""
    v = os.path.expanduser(value.strip().strip('"'))
    found = shutil.which(v)
    if found:
        return found
    return v if os.path.isfile(v) else None


class App:
    def __init__(self, args):
        self.os = os_key()
        self.cli = {"sshBin": args.ssh or "", "sshConfig": args.ssh_config or ""}
        data_dir = Path(os.path.expanduser(args.data_dir))
        self.store = Store(data_dir / "profiles.json")
        self.mgr = TunnelManager("ssh", Path(), data_dir / "run")
        self.files = AgentPool(self.agent_command, NO_WINDOW)
        self.port = args.port
        self.apply_paths()

    def path_settings(self) -> dict:
        """Effective ssh paths and where each came from: cli > saved (this OS) > auto."""
        saved = self.store.os_settings(self.os)
        auto = {"sshBin": detect_ssh(), "sshConfig": DEFAULT_SSH_CONFIG}
        out = {}
        for k in ("sshBin", "sshConfig"):
            if self.cli[k]:
                value, source = self.cli[k], "cli"
            elif saved.get(k):
                value, source = saved[k], "saved"
            else:
                value, source = auto[k], "auto"
            out[k] = {"value": value, "source": source, "auto": auto[k], "saved": saved.get(k, "")}
        return out

    def apply_paths(self):
        ps = self.path_settings()
        bin_value = ps["sshBin"]["value"]
        self.mgr.ssh_bin = resolve_ssh_bin(bin_value) or bin_value
        self.ssh_config = Path(os.path.expanduser(ps["sshConfig"]["value"]))
        self.mgr.ssh_config = self.ssh_config

    def settings_view(self) -> dict:
        ps = self.path_settings()
        ps["sshBin"]["resolved"] = self.mgr.ssh_bin
        ps["sshBin"]["ok"] = resolve_ssh_bin(ps["sshBin"]["value"]) is not None
        ps["sshConfig"]["resolved"] = str(self.ssh_config)
        ps["sshConfig"]["ok"] = self.ssh_config.is_file()
        return {"os": self.os, "osLabel": OS_LABEL[self.os], "paths": ps}

    def save_settings(self, body: dict) -> dict:
        values = {}
        for k in ("sshBin", "sshConfig"):
            v = str(body.get(k, "")).strip().strip('"')
            if len(v) > 1000:
                raise ValueError("경로가 너무 깁니다")
            values[k] = v
        if values["sshBin"] and not resolve_ssh_bin(values["sshBin"]):
            raise ValueError(f"ssh 실행 파일을 찾을 수 없습니다: {values['sshBin']}")
        if values["sshConfig"]:
            p = Path(os.path.expanduser(values["sshConfig"]))
            if p.exists() and not p.is_file():
                raise ValueError(f"파일이 아니라 폴더입니다: {values['sshConfig']}")
        self.store.save_os_settings(self.os, values)
        self.apply_paths()
        self.files.retire_all()  # new connections use the new binary/config
        return self.settings_view()

    def agent_command(self, alias: str) -> list[str]:
        # ClearAllForwardings: the browser connection must not open the config's LocalForwards
        return [self.mgr.ssh_bin, "-T", "-F", str(self.ssh_config),
                "-o", "BatchMode=yes", "-o", "ClearAllForwardings=yes",
                "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=30",
                "-o", "LogLevel=ERROR", alias, REMOTE_CMD]

    def hosts(self) -> list[dict]:
        hosts = core.parse_ssh_config(self.ssh_config) if self.ssh_config.exists() else []
        for h in hosts:
            h["importRules"] = core.forwards_to_rules(h.pop("forwards"))
        return hosts

    def profile_view(self, alias: str, profile: dict) -> dict:
        profile = {**profile, "rules": [core.normalize_rule(r) for r in profile.get("rules", [])]}
        forwards, errors = core.validate_rules(profile["rules"])
        return {**profile, "errors": errors, "portCount": len(forwards)}

    def state(self) -> dict:
        hosts = self.hosts()
        profiles = {}
        for h in hosts:
            p = self.store.profile(h["alias"])
            if p is None:  # first time: seed from ssh config LocalForward lines
                p = {"rules": h["importRules"], "autoReconnect": True, "autoStart": True}
            profiles[h["alias"]] = self.profile_view(h["alias"], p)
        return {
            "hosts": hosts, "profiles": profiles,
            "tunnels": {a: t.status() for a, t in self.mgr.tunnels.items()},
            "sshConfig": str(self.ssh_config), "sshBin": self.mgr.ssh_bin,
            "settings": self.settings_view(),
            "dataFile": str(self.store.path), "ui": self.store.data["ui"],
        }

    def save(self, alias: str, body: dict) -> dict:
        profile = clean_profile(body)
        self.store.save_profile(alias, profile)
        return self.profile_view(alias, profile)

    def start(self, alias: str) -> dict:
        p = self.store.profile(alias)
        if p is None:
            h = next((h for h in self.hosts() if h["alias"] == alias), None)
            p = {"rules": h["importRules"] if h else [], "autoReconnect": True}
        forwards, errors = core.validate_rules(p["rules"])
        bad = [f"행 {i + 1}: {e}" for i, e in enumerate(errors) if e]
        if bad:
            return {"ok": False, "error": "규칙 오류를 먼저 고치세요 — " + "; ".join(bad)}
        err = self.mgr.get(alias).start(forwards, p.get("autoReconnect", True))
        return {"ok": err is None, "error": err}

    def autostart(self):
        """Start every saved profile that has enabled rules and autoStart on."""
        known = {h["alias"] for h in self.hosts()}
        for alias, p in list(self.store.data["profiles"].items()):
            if not p.get("autoStart", True) or not any(r.get("enabled", True) for r in p.get("rules", [])):
                continue
            if alias not in known:
                print(f"[pfm] 자동 실행 건너뜀: {alias} (ssh config에 없음)")
                continue
            res = self.start(alias)
            if res["ok"]:
                print(f"[pfm] 자동 실행: {alias}")
            else:
                print(f"[pfm] 자동 실행 실패: {alias} — {res['error']}")
                t = self.mgr.get(alias)
                t._log("자동 실행 실패: " + str(res["error"]))
                if t.state == "stopped":
                    t.state, t.message = "error", "자동 실행 실패 — " + str(res["error"])


def make_handler(app: App):
    allowed_hosts = {f"127.0.0.1:{app.port}", f"localhost:{app.port}"}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="application/json; charset=utf-8"):
            data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _guard(self) -> bool:
            # block DNS-rebinding and cross-site requests
            if self.headers.get("Host") not in allowed_hosts:
                self._send(403, {"error": "forbidden host"})
                return False
            origin = self.headers.get("Origin")
            if origin and origin.split("://", 1)[-1] not in allowed_hosts:
                self._send(403, {"error": "forbidden origin"})
                return False
            return True

        def _parts(self):
            return [unquote(p) for p in self.path.split("?")[0].strip("/").split("/")]

        def _query(self) -> dict:
            q = parse_qs(self.path.partition("?")[2], keep_blank_values=True)
            return {k: v[0] for k, v in q.items()}

        def _files(self, method: str, alias: str, op: str) -> bool:
            """Handle /api/fs/<alias>/<op>. Returns False if the route is unknown."""
            q = self._query()
            path = q.get("path", "")
            self.pfm_streaming = False  # set by fileapi once a streamed response has begun
            try:
                if method == "GET" and op == "list":
                    self._send(200, fileapi.list_dir(app.files, alias, path))
                elif method == "GET" and op == "preview":
                    self._send(200, fileapi.preview(app.files, alias, path))
                elif method == "GET" and op == "raw":
                    fileapi.send_raw(self, app.files, alias, path, q.get("dl") == "1")
                elif method == "GET" and op == "archive":
                    fileapi.send_archive(self, app.files, alias, path)
                elif method == "PUT" and op == "upload":
                    if "application/octet-stream" not in (self.headers.get("Content-Type") or ""):
                        self._send(400, {"error": "octet-stream required"})
                    else:
                        self._send(200, fileapi.receive_upload(
                            self, app.files, alias, path, q.get("overwrite") == "1"))
                elif method == "POST" and op == "mkdir":
                    self._send(200, fileapi.mkdir(app.files, alias, self._body().get("path", "")))
                else:
                    return False
            except RemoteError as e:
                status = {"notfound": 404, "denied": 403, "perm": 403, "exists": 409}.get(e.code, 502)
                if self.pfm_streaming:
                    self.close_connection = True  # response already streaming; just drop it
                else:
                    try:
                        self._send(status, {"error": str(e), "code": e.code})
                    except OSError:
                        pass
            except (ConnectionError, OSError):
                self.close_connection = True
            return True

        def do_GET(self):
            if not self._guard():
                return
            parts = self._parts()
            if parts == [""]:
                return self._send(200, (HERE / "index.html").read_bytes(), "text/html; charset=utf-8")
            if parts == ["api", "state"]:
                return self._send(200, app.state())
            if len(parts) == 4 and parts[:2] == ["api", "fs"] and self._files("GET", parts[2], parts[3]):
                return
            if len(parts) == 4 and parts[:2] == ["api", "tunnels"] and parts[3] == "log":
                return self._send(200, {"log": list(app.mgr.get(parts[2]).log)})
            self._send(404, {"error": "not found"})

        def _body(self):
            if "application/json" not in (self.headers.get("Content-Type") or ""):
                raise ValueError("JSON required")
            n = int(self.headers.get("Content-Length") or 0)
            return json.loads(self.rfile.read(n) or b"{}")

        def do_PUT(self):
            if not self._guard():
                return
            parts = self._parts()
            if len(parts) == 4 and parts[:2] == ["api", "fs"] and self._files("PUT", parts[2], parts[3]):
                return
            try:
                body = self._body()
            except ValueError as e:
                return self._send(400, {"error": str(e)})
            if parts == ["api", "settings"] and isinstance(body, dict):
                try:
                    return self._send(200, app.save_settings(body))
                except ValueError as e:
                    return self._send(400, {"error": str(e)})
            if parts == ["api", "ui"] and isinstance(body, dict):
                app.store.save_ui(body)
                return self._send(200, {"ok": True})
            if len(parts) == 3 and parts[:2] == ["api", "profiles"]:
                return self._send(200, app.save(parts[2], body))
            self._send(404, {"error": "not found"})

        def do_POST(self):
            if not self._guard():
                return
            parts = self._parts()
            if len(parts) == 4 and parts[:2] == ["api", "fs"]:
                try:
                    if self._files("POST", parts[2], parts[3]):
                        return
                except ValueError as e:
                    return self._send(400, {"error": str(e)})
            try:
                self._body()
            except ValueError as e:
                return self._send(400, {"error": str(e)})
            if len(parts) == 4 and parts[:2] == ["api", "tunnels"]:
                alias, action = parts[2], parts[3]
                if action == "start":
                    return self._send(200, app.start(alias))
                if action == "stop":
                    app.mgr.get(alias).stop()
                    return self._send(200, {"ok": True})
            if parts == ["api", "tunnels", "stop-all"]:
                app.mgr.stop_all()
                return self._send(200, {"ok": True})
            self._send(404, {"error": "not found"})

    return Handler


def main():
    ap = argparse.ArgumentParser(description="SSH port forwarding manager")
    ap.add_argument("--port", type=int, default=8765, help="web UI port (default 8765)")
    ap.add_argument("--ssh-config", default="",
                    help="ssh config file (default: path set in the UI, else ~/.ssh/config)")
    ap.add_argument("--ssh", default="", help="ssh executable (default: path set in the UI, else ssh on PATH)")
    ap.add_argument("--data-dir", default="~/.pfm", help="where profiles.json is stored")
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--no-autostart", action="store_true", help="do not start saved tunnels on launch")
    args = ap.parse_args()

    app = App(args)
    atexit.register(app.mgr.stop_all)
    atexit.register(app.files.close_all)
    server = None
    # Windows (WSL/Hyper-V) can silently hold ports -> WinError 10013/10048; try the next ones
    for port in range(args.port, args.port + 50):
        app.port = port
        try:
            server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(app))
            break
        except OSError as e:
            print(f"[pfm] 포트 {port} 사용 불가 ({e.strerror or e}), 다음 포트 시도")
    if server is None:
        print(f"[pfm] {args.port}~{args.port + 49} 포트를 모두 쓸 수 없습니다. --port 로 다른 포트를 지정하세요.")
        return 1
    url = f"http://127.0.0.1:{app.port}/"
    print(f"[pfm] {url}  (ssh: {app.mgr.ssh_bin}, config: {app.ssh_config})")
    print("[pfm] Ctrl+C 로 종료하면 모든 터널도 함께 종료됩니다.")
    if not args.no_autostart:
        threading.Thread(target=app.autostart, daemon=True).start()
    if not args.no_browser:
        threading.Timer(0.5, webbrowser.open, args=(url,)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        app.mgr.stop_all()
        server.server_close()


if __name__ == "__main__":
    sys.exit(main())
