# Copied from mr-sentinel/socket_mode.py: stdlib-only and kept decoupled from mr-sentinel.
"""Slack Socket Mode over a minimal stdlib WebSocket client.

Why Socket Mode: buttons and Events API normally need Slack to call *in* to a
public Request URL, which a laptop-hosted watcher does not have. Socket Mode
inverts that — we dial out to Slack over a WebSocket and Slack pushes button
clicks and @mentions down it. Needs an app-level token (`xapp-…`, scope
`connections:write`) and "Socket Mode" switched on in the Slack app settings.

Only what Slack uses is implemented: client-side masking, text frames (with
continuation), ping/pong and close. RFC 6455 framing and the handshake are pure
functions so they test offline.

Delivery contract: every envelope is ACKed *before* it is handled (Slack wants
an ack within 3s, and a slow handler must never cause a redelivery that would
run a command twice) — the same at-most-once policy as the polling listener.
The reader thread only reads, acks and answers pings; handlers run one at a
time on a worker thread, so a slow rerun can never hold up the next ack.
"""
import base64
import hashlib
import json
import logging
import os
import queue
import socket
import ssl
import struct
import threading
import time
import urllib.parse

from alert_doctor import slack_io as slack_client

log = logging.getLogger("alert_doctor.socket_mode")

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
OP_CONT, OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG = 0x0, 0x1, 0x2, 0x8, 0x9, 0xA

IDLE_SECONDS = 30          # no frame for this long -> we ping
DEAD_SECONDS = 90          # still nothing -> the link is dead, reconnect
MAX_FRAME = 16 * 1024 * 1024
BACKOFF_MAX = 60


# ---------- pure RFC 6455 pieces ----------


def accept_key(key: str) -> str:
    return base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()


def handshake_request(host: str, path: str, key: str) -> bytes:
    return (f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n").encode()


def check_handshake(response: bytes, key: str) -> None:
    """Raise unless `response` is a 101 that echoes our key correctly."""
    head = response.decode("latin-1").split("\r\n")
    if not head or " 101 " not in f"{head[0]} ":
        raise ConnectionError(f"websocket upgrade refused: {head[0] if head else '?'}")
    headers = {}
    for line in head[1:]:
        name, sep, value = line.partition(":")
        if sep:
            headers[name.strip().lower()] = value.strip()
    if headers.get("sec-websocket-accept") != accept_key(key):
        raise ConnectionError("websocket upgrade: bad Sec-WebSocket-Accept")


def encode_frame(opcode: int, payload: bytes, mask: bytes | None = None) -> bytes:
    """One final frame. Clients must mask (RFC 6455 §5.3), so mask defaults to random."""
    mask = os.urandom(4) if mask is None else mask
    head = bytes([0x80 | opcode])
    n = len(payload)
    if n < 126:
        head += bytes([0x80 | n])
    elif n < 1 << 16:
        head += bytes([0x80 | 126]) + struct.pack("!H", n)
    else:
        head += bytes([0x80 | 127]) + struct.pack("!Q", n)
    return head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))


def parse_frame(buf: bytes) -> tuple[bool, int, bytes, int] | None:
    """Parse one frame from the front of `buf` without consuming anything.

    Returns (fin, opcode, payload, bytes_used), or None while the frame is still
    incomplete — so a read timeout mid-frame can never desync the stream.
    """
    if len(buf) < 2:
        return None
    b0, b1 = buf[0], buf[1]
    fin, opcode = bool(b0 & 0x80), b0 & 0x0F
    n, pos = b1 & 0x7F, 2
    if n == 126:
        if len(buf) < 4:
            return None
        n, pos = struct.unpack("!H", buf[2:4])[0], 4
    elif n == 127:
        if len(buf) < 10:
            return None
        n, pos = struct.unpack("!Q", buf[2:10])[0], 10
    if n > MAX_FRAME:
        raise ConnectionError(f"websocket frame too large ({n} bytes)")
    mask = None
    if b1 & 0x80:
        if len(buf) < pos + 4:
            return None
        mask, pos = buf[pos:pos + 4], pos + 4
    if len(buf) < pos + n:
        return None
    payload = buf[pos:pos + n]
    if mask:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return fin, opcode, payload, pos + n


# ---------- the connection ----------


class WebSocket:
    """A blocking client WebSocket over TLS. `recv_text` answers pings itself."""

    def __init__(self, sock):
        self.sock = sock
        self._buf = b""
        self._parts: list[bytes] = []      # fragments of a message, kept across timeouts

    @classmethod
    def connect(cls, url: str, timeout: float = 10) -> "WebSocket":
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "wss":
            raise ValueError(f"expected a wss:// url, got {parts.scheme}://")
        host, port = parts.hostname, parts.port or 443
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        raw = socket.create_connection((host, port), timeout=timeout)
        sock = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
        key = base64.b64encode(os.urandom(16)).decode()
        sock.sendall(handshake_request(host, path, key))
        ws = cls(sock)
        check_handshake(ws._read_until(b"\r\n\r\n"), key)
        return ws

    def _read_until(self, marker: bytes) -> bytes:
        while marker not in self._buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("connection closed during handshake")
            self._buf += chunk
            if len(self._buf) > 65536:
                raise ConnectionError("handshake response too large")
        head, _, self._buf = self._buf.partition(marker)
        return head

    def next_frame(self) -> tuple[bool, int, bytes]:
        while True:
            frame = parse_frame(self._buf)
            if frame:
                fin, opcode, payload, used = frame
                self._buf = self._buf[used:]
                return fin, opcode, payload
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("connection closed")
            self._buf += chunk

    def send(self, opcode: int, payload: bytes = b"") -> None:
        self.sock.sendall(encode_frame(opcode, payload))

    def send_text(self, text: str) -> None:
        self.send(OP_TEXT, text.encode())

    def recv_text(self, on_frame=lambda: None) -> str | None:
        """Next complete text message; None when the server closes. Raises
        socket.timeout if nothing at all arrives within the socket timeout.

        Pings are answered in here and never returned, so `on_frame()` is the
        caller's only sign of life on a quiet connection — Slack pings far more
        often than it sends events."""
        while True:
            fin, opcode, payload = self.next_frame()
            on_frame()
            if opcode == OP_PING:
                self.send(OP_PONG, payload)
                continue
            if opcode == OP_PONG:
                continue
            if opcode == OP_CLOSE:
                try:
                    self.send(OP_CLOSE, payload[:2])
                except OSError:
                    pass
                return None
            if opcode in (OP_TEXT, OP_CONT, OP_BINARY):
                self._parts.append(payload)
                if fin:
                    data, self._parts = b"".join(self._parts), []
                    return data.decode("utf-8", errors="replace")

    def close(self) -> None:
        try:
            self.send(OP_CLOSE, struct.pack("!H", 1000))
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


# ---------- Slack Socket Mode ----------


def handle_envelope(raw: str, ack, on_event) -> str | None:
    """Process one Socket Mode message. Returns "reconnect" when Slack asks us to.

    `ack(text)` sends on the socket; `on_event(kind, payload)` runs the bot.
    """
    try:
        envelope = json.loads(raw)
    except ValueError:
        log.warning("non-JSON socket message ignored")
        return None
    kind = envelope.get("type")
    if kind == "hello":
        log.info("socket mode connected (%s)",
                 (envelope.get("debug_info") or {}).get("host", "?"))
        on_event("hello", envelope)
        return None
    if kind == "disconnect":
        log.info("slack asked to reconnect: %s", envelope.get("reason"))
        return "reconnect"
    envelope_id = envelope.get("envelope_id")
    if envelope_id:
        ack(json.dumps({"envelope_id": envelope_id}))       # ack first: at-most-once
    try:
        on_event(kind, envelope.get("payload") or {})
    except Exception:
        log.exception("socket event %s failed", kind)
    return None


def _worker(jobs: "queue.Queue", on_event) -> None:
    while True:
        kind, payload = jobs.get()
        try:
            on_event(kind, payload)
        except Exception:
            log.exception("socket event %s failed", kind)
        finally:
            jobs.task_done()


def run_forever(app_token: str, on_event, stop=lambda: False, sleep=time.sleep,
                connect=WebSocket.connect, open_url=None, heartbeat=lambda: None) -> None:
    """Connect, dispatch, reconnect with backoff — until `stop()` is true.

    `heartbeat()` is called at least every IDLE_SECONDS while connected, so other
    processes can tell a live listener from a configured-but-dead one."""
    open_url = open_url or slack_client.apps_connections_open
    jobs: queue.Queue = queue.Queue()
    threading.Thread(target=_worker, args=(jobs, on_event), daemon=True,
                     name="socket-events").start()

    def enqueue(kind, payload):
        jobs.put((kind, payload))

    backoff = 1
    while not stop():
        ws = None
        try:
            ws = connect(open_url(app_token))
            ws.sock.settimeout(IDLE_SECONDS)
            backoff = 1
            last_frame = [time.monotonic()]

            def alive() -> None:
                last_frame[0] = time.monotonic()
                heartbeat()

            alive()
            while not stop():
                try:
                    raw = ws.recv_text(alive)
                except socket.timeout:
                    if time.monotonic() - last_frame[0] > DEAD_SECONDS:
                        raise ConnectionError("socket silent too long")
                    ws.send(OP_PING, b"ad")          # its pong counts as a frame
                    continue
                if raw is None:
                    log.info("socket closed by slack")
                    break
                if handle_envelope(raw, ws.send_text, enqueue) == "reconnect":
                    break
        except Exception as exc:
            log.warning("socket mode error: %s (retry in %ss)", exc, backoff)
            sleep(backoff)
            backoff = min(backoff * 2, BACKOFF_MAX)
        finally:
            if ws is not None:
                ws.close()
    jobs.join()                                # let queued events finish on shutdown
