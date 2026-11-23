"""Remote file access over ssh for the file browser.

A small Python agent is started on the server through ssh
(`python3 -c <bootstrap> <base64 source>`) and speaks a framed protocol over
stdin/stdout:

    request : one JSON line {"op": ..., "n": <payload bytes>, ...} + payload
    response: one JSON line {"ok": bool, "n": <payload bytes>, ...} + payload

All path handling, including the "only inside $HOME" rule, is enforced by the
agent on the server with realpath(), so symlinks cannot escape.
"""
from __future__ import annotations

import base64
import collections
import json
import subprocess
import threading
import time

CHUNK = 1024 * 1024
IDLE_TIMEOUT = 300   # seconds an idle agent is kept alive
MAX_AGENTS = 4       # per host: 1 for browsing + parallel transfers

AGENT_SRC = r'''
import sys, os, json, stat, tarfile, shutil
inp, out = sys.stdin.buffer, sys.stdout.buffer
HOME = os.path.realpath(os.path.expanduser("~"))
MAX_LIST = 5000

class Denied(Exception):
    pass

def send(obj, data=b""):
    obj["n"] = len(data)
    out.write((json.dumps(obj) + "\n").encode())
    if data:
        out.write(data)
    out.flush()

def inside(p):
    return HOME == "/" or p == HOME or p.startswith(HOME + os.sep)

def resolve(path):
    path = path or ""
    if path == "~" or path.startswith("~/"):
        path = path[1:].lstrip("/")
    if path.startswith("/"):
        p = os.path.realpath(path)
    else:
        p = os.path.realpath(os.path.join(HOME, path))
    if not inside(p):
        raise Denied("홈 디렉터리 밖에는 접근할 수 없습니다")
    return p

def rel(p):
    r = os.path.relpath(p, HOME)
    return "" if r == "." else r

def entry(dirpath, name):
    full = os.path.join(dirpath, name)
    st = os.lstat(full)
    link = stat.S_ISLNK(st.st_mode)
    kind = "other"
    target_ok = True
    if link:
        try:
            tst = os.stat(full)
            target_ok = inside(os.path.realpath(full))
        except OSError:
            tst, target_ok = None, False
    else:
        tst = st
    if tst is not None:
        if stat.S_ISDIR(tst.st_mode):
            kind = "dir"
        elif stat.S_ISREG(tst.st_mode):
            kind = "file"
    return {"name": name, "type": kind, "link": link, "outside": link and not target_ok,
            "size": tst.st_size if tst is not None and kind == "file" else None,
            "mtime": int(st.st_mtime), "mode": stat.filemode(st.st_mode)}

handles = {}
counter = __import__("itertools").count(1)

def op_hello(r, d):
    send({"ok": True, "home": HOME, "user": os.environ.get("USER", ""),
          "python": sys.version.split()[0]})

def op_list(r, d):
    p = resolve(r.get("path"))
    if not os.path.exists(p):
        raise FileNotFoundError(p)
    if not os.path.isdir(p):
        raise NotADirectoryError("폴더가 아닙니다: " + rel(p))
    names = os.listdir(p)
    entries = []
    for name in names[:MAX_LIST]:
        try:
            entries.append(entry(p, name))
        except OSError:
            pass
    send({"ok": True, "path": rel(p), "entries": entries,
          "truncated": len(names) > MAX_LIST, "total": len(names),
          "writable": os.access(p, os.W_OK)})

def op_stat(r, d):
    p = resolve(r.get("path"))
    e = entry(os.path.dirname(p), os.path.basename(p))
    e["path"] = rel(p)
    send({"ok": True, "entry": e})

def op_read(r, d):
    p = resolve(r.get("path"))
    size = os.path.getsize(p)
    with open(p, "rb") as f:
        f.seek(int(r.get("offset", 0)))
        data = f.read(min(int(r.get("length", 1 << 20)), 4 << 20))
    send({"ok": True, "size": size}, data)

def op_mkdir(r, d):
    p = resolve(r.get("path"))
    os.mkdir(p)
    send({"ok": True, "path": rel(p)})

def op_open_write(r, d):
    p = resolve(r.get("path"))
    if os.path.isdir(p):
        raise IsADirectoryError("같은 이름의 폴더가 있습니다")
    if os.path.exists(p) and not r.get("overwrite"):
        send({"ok": False, "error": "이미 존재하는 파일", "code": "exists"})
        return
    tmp = os.path.join(os.path.dirname(p), "." + os.path.basename(p) + ".pfm-part")
    hid = str(next(counter))
    handles[hid] = (open(tmp, "wb"), tmp, p)
    send({"ok": True, "handle": hid})

def op_write(r, d):
    handles[r["handle"]][0].write(d)
    send({"ok": True})

def op_close_write(r, d):
    f, tmp, p = handles.pop(r["handle"])
    f.close()
    if r.get("abort"):
        os.unlink(tmp)
        send({"ok": True})
        return
    if os.path.exists(p):
        try:
            shutil.copymode(p, tmp)
        except OSError:
            pass
    os.replace(tmp, p)
    send({"ok": True, "path": rel(p)})

class FrameWriter(object):
    def __init__(self):
        self.buf = bytearray()
    def write(self, b):
        self.buf += b
        if len(self.buf) >= (256 << 10):
            self.flush()
        return len(b)
    def flush(self):
        if self.buf:
            send({"ok": True, "more": True}, bytes(self.buf))
            self.buf = bytearray()

def op_tar(r, d):
    p = resolve(r.get("path"))
    w = FrameWriter()
    # symlinks are stored as links (not followed), so nothing outside $HOME is read
    with tarfile.open(fileobj=w, mode="w|gz") as tf:
        tf.add(p, arcname=os.path.basename(p) or "home")
    w.flush()
    send({"ok": True, "more": False})

OPS = {k[3:]: v for k, v in globals().items() if k.startswith("op_")}

while True:
    line = inp.readline()
    if not line:
        break
    req = json.loads(line.decode())
    n = req.get("n", 0)
    data = inp.read(n) if n else b""
    try:
        OPS[req["op"]](req, data)
    except Denied as e:
        send({"ok": False, "error": str(e), "code": "denied"})
    except FileNotFoundError:
        send({"ok": False, "error": "파일이나 폴더가 없습니다", "code": "notfound"})
    except PermissionError:
        send({"ok": False, "error": "권한이 없습니다", "code": "perm"})
    except FileExistsError:
        send({"ok": False, "error": "이미 존재합니다", "code": "exists"})
    except Exception as e:
        send({"ok": False, "error": "%s: %s" % (type(e).__name__, e), "code": "error"})
'''

_B64 = base64.b64encode(AGENT_SRC.encode()).decode()
REMOTE_CMD = ("python3 -c 'import sys,base64;exec(base64.b64decode(sys.argv[1]))' " + _B64)


class RemoteError(Exception):
    def __init__(self, msg: str, code: str = "error"):
        super().__init__(msg)
        self.code = code


class Agent:
    def __init__(self, cmd: list[str], creationflags: int = 0):
        self.stderr = collections.deque(maxlen=30)
        self.busy = False
        self.last_used = time.time()
        self.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, creationflags=creationflags)
        threading.Thread(target=self._drain, daemon=True).start()
        try:
            self.info = self.call("hello")[0]
        except RemoteError:
            self.close()
            raise

    def _drain(self):
        for line in self.proc.stderr:
            self.stderr.append(line.decode("utf-8", "replace").strip())

    def alive(self) -> bool:
        return self.proc.poll() is None

    def _fail(self):
        self.close()
        time.sleep(0.2)  # let stderr drain
        err = [l for l in self.stderr if l and "Pseudo-terminal" not in l]
        text = " / ".join(err[-3:]) or "ssh 연결이 끊겼습니다"
        if "python3" in text and ("not found" in text or "No such file" in text):
            text = "원격 서버에 python3가 필요합니다 (" + text + ")"
        raise RemoteError(text, "conn")

    def _read_frame(self) -> tuple[dict, bytes]:
        line = self.proc.stdout.readline()
        if not line:
            self._fail()
        try:
            resp = json.loads(line)
        except ValueError:
            self.close()
            raise RemoteError("원격 응답을 해석할 수 없습니다: " + line[:200].decode("utf-8", "replace"))
        n = resp.get("n", 0)
        data = b""
        while len(data) < n:
            chunk = self.proc.stdout.read(n - len(data))
            if not chunk:
                self._fail()
            data += chunk
        return resp, data

    def _send(self, op: str, data: bytes, args: dict):
        req = dict(args, op=op, n=len(data))
        try:
            self.proc.stdin.write((json.dumps(req) + "\n").encode())
            if data:
                self.proc.stdin.write(data)
            self.proc.stdin.flush()
        except OSError:
            self._fail()

    def call(self, op: str, data: bytes = b"", **args) -> tuple[dict, bytes]:
        self._send(op, data, args)
        resp, payload = self._read_frame()
        if not resp.get("ok"):
            raise RemoteError(resp.get("error", "error"), resp.get("code", "error"))
        return resp, payload

    def stream(self, op: str, **args):
        """Yield payloads of a multi-frame response (frames with more=True)."""
        self._send(op, b"", args)
        while True:
            resp, payload = self._read_frame()
            if not resp.get("ok"):
                raise RemoteError(resp.get("error", "error"), resp.get("code", "error"))
            if payload:
                yield payload
            if not resp.get("more"):
                return

    def close(self):
        if self.proc.poll() is None:
            self.proc.kill()


class AgentPool:
    """Per-host pool of agents. `with pool.acquire(alias) as agent:`"""

    def __init__(self, build_cmd, creationflags: int = 0):
        self.build_cmd = build_cmd
        self.creationflags = creationflags
        self.agents: dict[str, list[Agent]] = {}
        self.cond = threading.Condition()
        self.spawning: dict[str, int] = {}
        threading.Thread(target=self._reaper, daemon=True).start()

    def acquire(self, alias: str):
        pool = self

        class _Lease:
            def __enter__(self):
                self.agent = pool._get(alias)
                return self.agent

            def __exit__(self, exc_type, exc, tb):
                pool._release(alias, self.agent, broken=exc_type is not None
                              and not isinstance(exc, RemoteError))
                return False

        return _Lease()

    def _get(self, alias: str) -> Agent:
        deadline = time.time() + 60
        with self.cond:
            while True:
                lst = self.agents.setdefault(alias, [])
                lst[:] = [a for a in lst if a.alive()]
                for a in lst:
                    if not a.busy:
                        a.busy = True
                        return a
                if len(lst) + self.spawning.get(alias, 0) < MAX_AGENTS:
                    self.spawning[alias] = self.spawning.get(alias, 0) + 1
                    break
                if not self.cond.wait(timeout=max(0.1, deadline - time.time())) and time.time() > deadline:
                    raise RemoteError("작업이 너무 많습니다. 잠시 후 다시 시도하세요.")
        try:
            agent = Agent(self.build_cmd(alias), self.creationflags)
        finally:
            with self.cond:
                self.spawning[alias] -= 1
                self.cond.notify_all()
        agent.busy = True
        with self.cond:
            self.agents.setdefault(alias, []).append(agent)
        return agent

    def _release(self, alias: str, agent: Agent, broken: bool):
        # an interrupted stream leaves unread frames in the pipe -> agent unusable
        if broken or getattr(agent, "retired", False):
            agent.close()
        with self.cond:
            agent.busy = False
            agent.last_used = time.time()
            self.cond.notify_all()

    def _reaper(self):
        while True:
            time.sleep(30)
            with self.cond:
                for lst in self.agents.values():
                    for a in lst:
                        if not a.busy and time.time() - a.last_used > IDLE_TIMEOUT:
                            a.close()

    def retire_all(self):
        """Settings changed (ssh binary / config): idle agents close now, busy ones
        finish their transfer and close on release."""
        with self.cond:
            for lst in self.agents.values():
                for a in lst:
                    a.retired = True
                    if not a.busy:
                        a.close()

    def close_all(self):
        with self.cond:
            for lst in self.agents.values():
                for a in lst:
                    a.close()
