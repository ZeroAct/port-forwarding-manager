"""SSH key setup: find or create a key pair and register it on a server.

The one password prompt happens in a real terminal window that pfm opens, so pfm
never sees the password. That window runs this module (`python sshkey.py ...`),
which runs ssh and writes the outcome to a status file pfm polls.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
NEW_CONSOLE = getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
DEFAULT_KEY = "~/.ssh/id_ed25519"
# what ssh tries when the config names no IdentityFile (OpenSSH 9/10)
DEFAULT_IDENTITIES = {f"~/.ssh/{n}" for n in ("id_rsa", "id_ecdsa", "id_ecdsa_sk", "id_ed25519",
                                             "id_ed25519_sk", "id_xmss", "id_dsa")}
OK_MARK = "PFM_KEY_OK"
PUBKEY_RE = re.compile(r"^((?:ssh|ecdsa|sk)-[A-Za-z0-9@.-]+) ([A-Za-z0-9+/]+={0,3})(?:\s+(.*))?$")


def keygen_bin(ssh_bin: str) -> str | None:
    """ssh-keygen next to the ssh in use (same OpenSSH build), else from PATH."""
    p = Path(ssh_bin)
    sib = p.with_name("ssh-keygen" + p.suffix)
    if p.is_absolute() and sib.is_file():
        return str(sib)
    return shutil.which("ssh-keygen")


def _expand(path: str) -> Path:
    return Path(os.path.expanduser(path))


def identity_files(ssh_bin: str, config: Path, alias: str) -> list[str]:
    """IdentityFile values ssh would use for this host (`ssh -G`), unexpanded."""
    try:
        out = subprocess.run([ssh_bin, "-F", str(config), "-G", alias], capture_output=True,
                             text=True, timeout=10, stdin=subprocess.DEVNULL,
                             creationflags=NO_WINDOW).stdout
    except (OSError, subprocess.TimeoutExpired):
        return []
    return [l.split(None, 1)[1].strip() for l in out.splitlines()
            if l.lower().startswith("identityfile ") and len(l.split(None, 1)) == 2]


def read_pubkey(path: Path) -> str | None:
    try:
        line = path.with_name(path.name + ".pub").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    line = line.strip().splitlines()[0] if line.strip() else ""
    return line if PUBKEY_RE.match(line) else None


def pick_key(ssh_bin: str, config: Path, alias: str) -> dict:
    """The key to register for `alias`:
    an existing key pair ssh already tries for this host, else the host's own
    IdentityFile (to be created), else ~/.ssh/id_ed25519 (to be created; ssh tries it
    by default, so the config needs no change)."""
    files = identity_files(ssh_bin, config, alias)
    for f in files:
        p = _expand(f)
        if p.is_file() and read_pubkey(p):
            return {"path": str(p), "exists": True, "pub": read_pubkey(p)}
    explicit = [f for f in files if f not in DEFAULT_IDENTITIES and "%" not in f]
    path = _expand(explicit[0] if explicit else DEFAULT_KEY)
    # a private key without .pub (e.g. a .pem from a cloud console) is not ours to touch
    blocked = path.exists()
    return {"path": str(path), "exists": False, "pub": None, "blocked": blocked}


def generate(ssh_bin: str, path: str) -> str:
    kg = keygen_bin(ssh_bin)
    if not kg:
        raise RuntimeError("ssh-keygen을 찾을 수 없습니다")
    p = Path(path)
    if p.exists() or p.with_name(p.name + ".pub").exists():
        raise RuntimeError(f"이미 파일이 있습니다: {p}")
    p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    comment = re.sub(r"[^\w@.-]", "", f"pfm@{socket.gethostname()}")
    # -N "" : no passphrase, so tunnels (BatchMode=yes) work without ssh-agent
    r = subprocess.run([kg, "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(p)],
                       capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL,
                       creationflags=NO_WINDOW)
    pub = read_pubkey(p)
    if r.returncode != 0 or not pub:
        raise RuntimeError((r.stderr or r.stdout or f"ssh-keygen exit {r.returncode}").strip()[-1000:])
    return pub


def remote_script(pub: str) -> str:
    """POSIX sh run on the server: append the key once, fix permissions."""
    m = PUBKEY_RE.match(pub)
    if not m:
        raise ValueError("공개 키 형식이 아닙니다")
    kind, blob, comment = m.group(1), m.group(2), re.sub(r"[^\w@.-]", "", m.group(3) or "")
    key = f"{kind} {blob}"
    line = f"{key} {comment}".strip()
    # only [\w@.+/=-] and spaces inside "..." -> safe in sh double quotes and in the outer '...'
    return ('umask 077; mkdir -p ~/.ssh && chmod 700 ~/.ssh && f=~/.ssh/authorized_keys'
            ' && touch "$f" && chmod 600 "$f" && {'
            f' grep -qF "{key}" "$f" ||'
            ' { if [ -s "$f" ] && [ -n "$(tail -c1 "$f")" ]; then echo >> "$f"; fi;'
            f' echo "{line}" >> "$f"; }}; }}'
            f' && echo {OK_MARK}')


def install_command(ssh_bin: str, config: Path, alias: str, pub: str) -> list[str]:
    # `sh -c '...'` so it also works when the login shell is fish/csh
    return [ssh_bin, "-F", str(config), "-T", "-o", "ClearAllForwardings=yes",
            "-o", "ConnectTimeout=15", alias, "sh -c '" + remote_script(pub) + "'"]


def manual_command(alias: str, key_path: str) -> str:
    """A short command a user can paste into a terminal instead."""
    pub = key_path + ".pub"
    if sys.platform.startswith("win"):  # PowerShell; no inner double quotes (PS 5.1 mangles them)
        return (f'type "{pub}" | ssh {alias} '
                '"umask 077; mkdir -p ~/.ssh; cat >> ~/.ssh/authorized_keys"')
    return f"ssh-copy-id -i {shlex.quote(pub)} {shlex.quote(alias)}"


def test_login(ssh_bin: str, config: Path, alias: str) -> dict:
    """Can we log in without a password (what tunnels and the file browser need)?"""
    cmd = [ssh_bin, "-F", str(config), "-T", "-o", "BatchMode=yes", "-o", "ClearAllForwardings=yes",
           "-o", "ConnectTimeout=10", "-o", "LogLevel=ERROR", alias, "echo " + OK_MARK]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=25, stdin=subprocess.DEVNULL, creationflags=NO_WINDOW)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "시간 초과"}
    except OSError as e:
        return {"ok": False, "error": str(e)}
    if OK_MARK in r.stdout:
        return {"ok": True}
    err = (r.stderr or "").strip()
    out = {"ok": False, "error": err[-800:] or f"exit {r.returncode}"}
    if "host key verification failed" in err.lower():
        out["hostKey"] = True  # never connected before: the install window asks yes/no
    return out


# ---------------------------------------------------------------- terminal window

def _terminal_argv(argv: list[str]) -> list[str] | None:
    """Wrap argv so it runs in a new, visible terminal window (macOS/Linux)."""
    line = shlex.join(argv)
    if sys.platform == "darwin":
        script = line.replace("\\", "\\\\").replace('"', '\\"')
        return ["osascript", "-e", f'tell application "Terminal" to do script "{script}"',
                "-e", 'tell application "Terminal" to activate']
    for term, flag in (("x-terminal-emulator", "-e"), ("gnome-terminal", "--"), ("konsole", "-e"),
                       ("xfce4-terminal", "-x"), ("kitty", None), ("alacritty", "-e"), ("xterm", "-e")):
        if shutil.which(term):
            return [term] + ([flag] if flag else []) + argv
    return None


def open_install_window(ssh_bin: str, config: Path, alias: str, pub: str, status: Path) -> str | None:
    """Start the install in a terminal window; returns an error message or None."""
    status.parent.mkdir(parents=True, exist_ok=True)
    status.write_text(json.dumps({"state": "waiting", "t": time.time()}), encoding="utf-8")
    argv = [sys.executable, str(Path(__file__).resolve()), str(status), alias] + \
        install_command(ssh_bin, config, alias, pub)
    try:
        if sys.platform.startswith("win"):
            subprocess.Popen(argv, creationflags=NEW_CONSOLE, stdin=None, stdout=None, stderr=None)
            return None
        wrapped = _terminal_argv(argv)
        if not wrapped or (not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY")
                           and sys.platform != "darwin"):
            status.unlink(missing_ok=True)
            return "터미널 창을 열 수 없습니다. 아래 명령을 터미널에서 직접 실행하세요."
        subprocess.Popen(wrapped, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
        return None
    except OSError as e:
        status.unlink(missing_ok=True)
        return f"터미널 창을 열 수 없습니다: {e}"


def read_status(status: Path) -> dict | None:
    try:
        return json.loads(status.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _window_main(status_path: str, alias: str, cmd: list[str]) -> int:
    """Runs inside the terminal window."""
    status = Path(status_path)
    print(f"[pfm] {alias} 서버에 공개 키를 등록합니다.")
    print("[pfm] 처음 접속하는 서버라면 호스트 키 확인(yes/no)에 yes, 이어서 비밀번호를 입력하세요.\n")
    status.write_text(json.dumps({"state": "running", "t": time.time()}), encoding="utf-8")
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
        out, code = r.stdout or "", r.returncode
    except (OSError, KeyboardInterrupt) as e:
        out, code = "", -1
        print(f"\n[pfm] 실행 실패: {e}")
    ok = OK_MARK in out
    rest = out.replace(OK_MARK, "").strip()
    if rest:
        print(rest)
    status.write_text(json.dumps({"state": "done" if ok else "failed", "code": code, "t": time.time()}),
                      encoding="utf-8")
    if ok:
        print("\n[pfm] 등록 완료. 이 창은 곧 닫힙니다.")
        time.sleep(2.5)
        return 0
    print(f"\n[pfm] 등록하지 못했습니다 (exit {code}). 위 메시지를 확인하세요.")
    try:
        input("Enter를 누르면 창이 닫힙니다...")
    except (EOFError, KeyboardInterrupt):
        pass
    return 1


if __name__ == "__main__":
    sys.exit(_window_main(sys.argv[1], sys.argv[2], sys.argv[3:]))
