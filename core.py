"""SSH config parsing and port-rule handling for the port forwarding manager.

Pure functions only (no processes, no I/O except reading config files) so they
are easy to test.
"""
from __future__ import annotations

import fnmatch
import glob
import os
import re
from pathlib import Path

MAX_PORTS_PER_RULE = 1000

# --------------------------------------------------------------------------
# ssh config
# --------------------------------------------------------------------------

_LINE_RE = re.compile(r"^\s*([A-Za-z]+)\s*(?:=\s*|\s+)(.*?)\s*$")
_TOKEN_RE = re.compile(r'"([^"]*)"|(\S+)')


def _tokens(rest: str) -> list[str]:
    return [a if a else b for a, b in _TOKEN_RE.findall(rest)]


def _is_pattern(alias: str) -> bool:
    return any(c in alias for c in "*?!")


def _iter_lines(path: Path, ssh_dir: Path, depth: int = 0):
    """Yield (keyword_lower, args) from a config file, following Include."""
    if depth > 8:
        return
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _LINE_RE.match(line)
        if not m:
            continue
        key, args = m.group(1).lower(), _tokens(m.group(2))
        if key == "include":
            for pattern in args:
                p = os.path.expanduser(pattern)
                if not os.path.isabs(p):
                    p = str(ssh_dir / p)
                for inc in sorted(glob.glob(p)):
                    yield from _iter_lines(Path(inc), ssh_dir, depth + 1)
            continue
        yield key, args


def parse_forward(args: list[str]) -> dict | None:
    """Parse LocalForward args: ``[bind:]port host:hostport``."""
    if len(args) < 2:
        return None
    listen, target = args[0], args[1]
    bind = ""
    if ":" in listen:
        bind, _, listen = listen.rpartition(":")
        bind = bind.strip("[]")
    m = re.match(r"^\[?([^\]]*?)\]?:(\d+)$", target)
    if not (listen.isdigit() and m):
        return None  # unix sockets etc. are not supported
    return {"bind": bind, "lport": int(listen), "rhost": m.group(1), "rport": int(m.group(2))}


def parse_ssh_config(path: str | os.PathLike) -> list[dict]:
    """Return concrete (non-wildcard) hosts in file order.

    Scalar options follow ssh's first-match-wins rule; LocalForward
    accumulates. Match blocks are ignored.
    """
    path = Path(path)
    blocks: list[tuple[list[str] | None, list]] = [(["*"], [])]  # options before any Host apply to all
    aliases: list[str] = []
    for key, args in _iter_lines(path, path.parent):
        if key == "host":
            blocks.append((args, []))
            for a in args:
                if not _is_pattern(a) and a not in aliases:
                    aliases.append(a)
        elif key == "match":
            blocks.append((None, []))
        else:
            blocks[-1][1].append((key, args))

    hosts = []
    for alias in aliases:
        h = {"alias": alias, "hostname": "", "user": "", "port": "",
             "identityFile": "", "forwards": []}
        for patterns, options in blocks:
            if patterns is not None and _host_matches(alias, patterns):
                _apply(h, options)
        hosts.append(h)
    return hosts


def _host_matches(alias: str, patterns: list[str]) -> bool:
    hit = False
    for p in patterns:
        neg = p.startswith("!")
        if fnmatch.fnmatchcase(alias, p[1:] if neg else p):
            if neg:
                return False
            hit = True
    return hit


def _apply(h: dict, options: list):
    for key, args in options:
        if key == "localforward":
            fw = parse_forward(args)
            if fw:
                h["forwards"].append(fw)
        elif key in ("hostname", "user", "port", "identityfile") and args:
            field = "identityFile" if key == "identityfile" else key
            if not h[field]:
                h[field] = args[0]


# --------------------------------------------------------------------------
# port rules
# --------------------------------------------------------------------------
# A rule is {"local": "9720-9739", "remoteHost": "localhost",
#            "remote": "" (same as local) | "80" | "8000-8019",
#            "enabled": bool, "note": str}


def parse_port_spec(spec: str) -> tuple[int, int]:
    """'8080' -> (8080, 8080); '9720-9739' -> (9720, 9739). Raises ValueError."""
    s = (spec or "").strip().replace(" ", "")
    m = re.fullmatch(r"(\d+)(?:-(\d+))?", s)
    if not m:
        raise ValueError(f"잘못된 포트 형식: '{spec}' (예: 8080 또는 9720-9739)")
    a = int(m.group(1))
    b = int(m.group(2)) if m.group(2) else a
    for p in (a, b):
        if not 1 <= p <= 65535:
            raise ValueError(f"포트 범위 초과: {p} (1-65535)")
    if b < a:
        raise ValueError(f"구간 끝이 시작보다 작음: {spec}")
    if b - a + 1 > MAX_PORTS_PER_RULE:
        raise ValueError(f"구간이 너무 큼: {b - a + 1}개 (최대 {MAX_PORTS_PER_RULE})")
    return a, b


def expand_rule(rule: dict) -> list[tuple[int, str, int]]:
    """Expand a rule into [(local_port, remote_host, remote_port), ...].

    Either side may be left empty to mean "same number as the other side".
    """
    local = (rule.get("local") or "").strip()
    remote = (rule.get("remote") or "").strip()
    if not local and not remote:
        raise ValueError("포트를 입력하세요")
    ra, rb = parse_port_spec(remote) if remote else parse_port_spec(local)
    la, lb = parse_port_spec(local) if local else (ra, rb)
    if rb - ra != lb - la:
        raise ValueError(f"로컬({lb - la + 1}개)과 원격({rb - ra + 1}개) 포트 수가 다름")
    rhost = (rule.get("remoteHost") or "").strip() or "localhost"
    if re.search(r"\s", rhost):
        raise ValueError(f"잘못된 원격 호스트: '{rhost}'")
    return [(la + i, rhost, ra + i) for i in range(lb - la + 1)]


def validate_rules(rules: list[dict]) -> tuple[list[tuple[int, str, int]], list[str | None]]:
    """Return (forwards from enabled valid rules, per-rule error or None)."""
    errors: list[str | None] = [None] * len(rules)
    owner: dict[int, int] = {}
    forwards: list[tuple[int, str, int]] = []
    for i, rule in enumerate(rules):
        if not rule.get("enabled", True):
            continue
        try:
            fws = expand_rule(rule)
        except ValueError as e:
            errors[i] = str(e)
            continue
        dup = sorted({lp for lp, _, _ in fws if lp in owner})
        if dup:
            others = sorted({owner[p] + 1 for p in dup})
            errors[i] = f"로컬 포트 중복: {_fmt_ports(dup)} (행 {', '.join(map(str, others))})"
            continue
        for lp, _, _ in fws:
            owner[lp] = i
        forwards.extend(fws)
    return forwards, errors


def _fmt_ports(ports: list[int]) -> str:
    out = []
    for r in compress_ints(ports):
        out.append(str(r[0]) if r[0] == r[1] else f"{r[0]}-{r[1]}")
    return ", ".join(out)


def compress_ints(nums: list[int]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for n in sorted(set(nums)):
        if out and n == out[-1][1] + 1:
            out[-1] = (out[-1][0], n)
        else:
            out.append((n, n))
    return out


def normalize_rule(rule: dict) -> dict:
    """Canonical form is remote-first: the remote port is always filled in and an
    empty local port means "same number". Older rules stored only the local port."""
    r = dict(rule)
    local, remote = (r.get("local") or "").strip(), (r.get("remote") or "").strip()
    if local and not remote:
        r["remote"], r["local"] = local, ""
    elif local and local == remote:
        r["local"] = ""
    return r


def forwards_to_rules(forwards: list[dict]) -> list[dict]:
    """Collapse config LocalForward entries into range rules.

    Consecutive local ports with the same remote host and a constant
    local->remote offset become one rule.
    """
    groups: list[dict] = []
    for fw in sorted(forwards, key=lambda f: (f["rhost"], f["rport"] - f["lport"], f["lport"])):
        g = groups[-1] if groups else None
        if (g and g["rhost"] == fw["rhost"] and g["off"] == fw["rport"] - fw["lport"]
                and fw["lport"] == g["lb"] + 1):
            g["lb"] = fw["lport"]
        else:
            groups.append({"rhost": fw["rhost"], "off": fw["rport"] - fw["lport"],
                           "la": fw["lport"], "lb": fw["lport"]})
    groups.sort(key=lambda g: g["la"])
    rules = []
    for g in groups:
        local = str(g["la"]) if g["la"] == g["lb"] else f"{g['la']}-{g['lb']}"
        if g["off"] == 0:
            remote = ""
        else:
            ra, rb = g["la"] + g["off"], g["lb"] + g["off"]
            remote = str(ra) if ra == rb else f"{ra}-{rb}"
        rules.append(normalize_rule({"local": local, "remoteHost": g["rhost"], "remote": remote,
                                     "enabled": True, "note": "ssh config"}))
    return rules
