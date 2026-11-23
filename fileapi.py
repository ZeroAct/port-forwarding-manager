"""HTTP side of the remote file browser (list / preview / raw / archive / upload / mkdir)."""
from __future__ import annotations

import os
import re
from urllib.parse import quote

from remotefs import CHUNK, AgentPool, RemoteError

TEXT_PREVIEW = 256 * 1024
IMAGE_MAX = 30 * 1024 * 1024
PDF_MAX = 80 * 1024 * 1024

IMAGE = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "gif": "image/gif",
         "webp": "image/webp", "bmp": "image/bmp", "ico": "image/x-icon", "avif": "image/avif",
         "svg": "image/svg+xml"}
VIDEO = {"mp4": "video/mp4", "m4v": "video/mp4", "webm": "video/webm", "mov": "video/quicktime",
         "ogv": "video/ogg"}
AUDIO = {"mp3": "audio/mpeg", "wav": "audio/wav", "ogg": "audio/ogg", "oga": "audio/ogg",
         "m4a": "audio/mp4", "aac": "audio/aac", "flac": "audio/flac", "opus": "audio/opus"}
INLINE_TYPES = {**IMAGE, **VIDEO, **AUDIO, "pdf": "application/pdf"}


def ext_of(path: str) -> str:
    base = os.path.basename(path)
    return base.rsplit(".", 1)[-1].lower() if "." in base.lstrip(".") else ""


def _decode(data: bytes, truncated: bool) -> tuple[str, str] | None:
    """Return (text, encoding) or None if the data looks binary."""
    head = data[:8192]
    if b"\x00" in head:
        return None
    if head:
        ctrl = sum(1 for b in head if b < 9 or 13 < b < 32)
        if ctrl / len(head) > 0.1:
            return None
    # a truncated read may cut a multi-byte char in half
    for cut in (0, 1, 2, 3) if truncated else (0,):
        try:
            return data[:len(data) - cut].decode("utf-8"), "UTF-8"
        except UnicodeDecodeError:
            continue
    for enc in ("cp949",):
        try:
            return data.decode(enc), enc.upper()
        except UnicodeDecodeError:
            pass
    return data.decode("latin-1"), "Latin-1"


def _hexdump(data: bytes) -> str:
    lines = []
    for off in range(0, len(data), 16):
        row = data[off:off + 16]
        hexpart = " ".join(f"{b:02x}" for b in row)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append(f"{off:08x}  {hexpart:<47}  {asc}")
    return "\n".join(lines)


def list_dir(pool: AgentPool, alias: str, path: str) -> dict:
    with pool.acquire(alias) as a:
        resp, _ = a.call("list", path=path)
        resp["home"] = a.info["home"]
        return resp


def mkdir(pool: AgentPool, alias: str, path: str) -> dict:
    with pool.acquire(alias) as a:
        return a.call("mkdir", path=path)[0]


def preview(pool: AgentPool, alias: str, path: str) -> dict:
    with pool.acquire(alias) as a:
        entry = a.call("stat", path=path)[0]["entry"]
        out = {"entry": entry, "home": a.info["home"]}
        if entry["type"] == "dir":
            out["kind"] = "dir"
            return out
        if entry["type"] != "file":
            out["kind"] = "special"
            return out
        ext, size = ext_of(path), entry["size"] or 0
        if ext in IMAGE:
            out["kind"] = "image" if size <= IMAGE_MAX else "toolarge"
            return out
        if ext in VIDEO or ext in AUDIO:
            out["kind"] = "video" if ext in VIDEO else "audio"
            return out
        if ext == "pdf":
            out["kind"] = "pdf" if size <= PDF_MAX else "toolarge"
            return out
        data = a.call("read", path=path, offset=0, length=TEXT_PREVIEW)[1] if size else b""
        truncated = size > len(data)
        dec = _decode(data, truncated)
        if dec is None:
            out.update(kind="binary", hex=_hexdump(data[:4096]))
        else:
            out.update(kind="csv" if ext in ("csv", "tsv") else "text", text=dec[0],
                       encoding=dec[1], truncated=truncated)
        return out


def _parse_range(header: str | None, size: int) -> tuple[int, int] | None:
    m = re.fullmatch(r"bytes=(\d*)-(\d*)", (header or "").strip())
    if not m or (not m.group(1) and not m.group(2)):
        return None
    if m.group(1):
        start = int(m.group(1))
        end = int(m.group(2)) if m.group(2) else size - 1
    else:  # suffix range: last N bytes
        start, end = max(0, size - int(m.group(2))), size - 1
    if start >= size or end < start:
        return None
    return start, min(end, size - 1)


def _disposition(name: str) -> str:
    ascii_name = re.sub(r'[^A-Za-z0-9._-]', "_", name) or "download"
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(name)}"


def send_raw(h, pool: AgentPool, alias: str, path: str, download: bool):
    """Stream a file to the browser, with HTTP Range support (video seeking)."""
    with pool.acquire(alias) as a:
        entry = a.call("stat", path=path)[0]["entry"]
        if entry["type"] != "file":
            raise RemoteError("파일이 아닙니다", "notfile")
        size = entry["size"] or 0
        rng = _parse_range(h.headers.get("Range"), size) if size else None
        start, end = rng if rng else (0, size - 1)
        h.send_response(206 if rng else 200)
        ext = ext_of(path)
        if download:
            h.send_header("Content-Type", "application/octet-stream")
            h.send_header("Content-Disposition", _disposition(os.path.basename(path)))
        else:
            h.send_header("Content-Type", INLINE_TYPES.get(ext, "application/octet-stream"))
        if ext != "pdf":  # browsers refuse to render PDFs in a sandboxed document
            h.send_header("Content-Security-Policy", "sandbox; default-src 'none'; style-src 'unsafe-inline'")
        h.send_header("X-Content-Type-Options", "nosniff")
        h.send_header("Accept-Ranges", "bytes")
        h.send_header("Cache-Control", "no-store")
        h.send_header("Content-Length", str(end - start + 1 if size else 0))
        if rng:
            h.send_header("Content-Range", f"bytes {start}-{end}/{size}")
        h.end_headers()
        h.pfm_streaming = True
        pos = start
        while size and pos <= end:
            data = a.call("read", path=path, offset=pos, length=min(CHUNK, end - pos + 1))[1]
            if not data:
                break
            pos += len(data)
            try:
                h.wfile.write(data)
            except OSError:
                return  # browser went away (seek / cancel); agent is still in sync


def send_archive(h, pool: AgentPool, alias: str, path: str):
    with pool.acquire(alias) as a:
        name = os.path.basename(path.rstrip("/")) or os.path.basename(a.info["home"]) or "home"
        h.send_response(200)
        h.send_header("Content-Type", "application/gzip")
        h.send_header("Content-Disposition", _disposition(name + ".tar.gz"))
        h.send_header("Cache-Control", "no-store")
        h.send_header("Connection", "close")
        h.end_headers()
        h.pfm_streaming = True
        h.close_connection = True
        # if the browser cancels, the write raises and the lease marks the agent broken
        for chunk in a.stream("tar", path=path):
            h.wfile.write(chunk)


def receive_upload(h, pool: AgentPool, alias: str, path: str, overwrite: bool) -> dict:
    length = int(h.headers.get("Content-Length") or 0)
    with pool.acquire(alias) as a:
        handle = a.call("open_write", path=path, overwrite=overwrite)[0]["handle"]
        remaining = length
        try:
            while remaining > 0:
                data = h.rfile.read(min(CHUNK, remaining))
                if not data:
                    raise ConnectionError("업로드가 중간에 끊겼습니다")
                remaining -= len(data)
                a.call("write", data, handle=handle)
        except BaseException:
            try:
                a.call("close_write", handle=handle, abort=True)
            except Exception:
                pass
            raise
        return a.call("close_write", handle=handle)[0]
