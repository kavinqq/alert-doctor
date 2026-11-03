"""Tests for the stdlib WebSocket framing and the Socket Mode envelope loop (offline)."""
import json
import socket
import struct
import unittest
from unittest import mock

from alert_doctor import socket_mode as sm


def server_frame(opcode: int, payload: bytes, fin: bool = True) -> bytes:
    """Servers never mask (RFC 6455 §5.1)."""
    n = len(payload)
    head = bytes([(0x80 if fin else 0) | opcode])
    if n < 126:
        head += bytes([n])
    elif n < 1 << 16:
        head += bytes([126]) + struct.pack("!H", n)
    else:
        head += bytes([127]) + struct.pack("!Q", n)
    return head + payload


class FakeSock:
    """recv() hands out pre-scripted chunks; an Exception chunk is raised."""

    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.sent = b""

    def recv(self, _n):
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        if isinstance(chunk, Exception):
            raise chunk
        return chunk

    def sendall(self, data):
        self.sent += data

    def settimeout(self, _t):
        pass

    def close(self):
        pass


class TestHandshake(unittest.TestCase):
    def test_accept_key_matches_rfc_example(self):
        self.assertEqual(sm.accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
                         "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")

    def test_good_upgrade_passes(self):
        key = "dGhlIHNhbXBsZSBub25jZQ=="
        sm.check_handshake(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                           b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", key)

    def test_refused_or_bad_accept_raises(self):
        with self.assertRaises(ConnectionError):
            sm.check_handshake(b"HTTP/1.1 403 Forbidden", "k")
        with self.assertRaises(ConnectionError):
            sm.check_handshake(b"HTTP/1.1 101 OK\r\nSec-WebSocket-Accept: nope", "k")

    def test_request_carries_path_and_key(self):
        req = sm.handshake_request("wss.slack.com", "/link/?ticket=1", "KEY").decode()
        self.assertTrue(req.startswith("GET /link/?ticket=1 HTTP/1.1\r\n"))
        self.assertIn("Sec-WebSocket-Key: KEY", req)


class TestFrames(unittest.TestCase):
    def test_client_frames_are_masked_and_round_trip(self):
        for size in (5, 300, 70000):
            payload = b"x" * size
            frame = sm.encode_frame(sm.OP_TEXT, payload, mask=b"\x01\x02\x03\x04")
            self.assertTrue(frame[1] & 0x80)
            fin, op, got, used = sm.parse_frame(frame)
            self.assertEqual((fin, op, got, used), (True, sm.OP_TEXT, payload, len(frame)))

    def test_incomplete_frame_consumes_nothing(self):
        frame = server_frame(sm.OP_TEXT, b"hello world")
        for cut in range(len(frame)):
            self.assertIsNone(sm.parse_frame(frame[:cut]))

    def test_oversized_frame_refused(self):
        with self.assertRaises(ConnectionError):
            sm.parse_frame(bytes([0x81, 127]) + struct.pack("!Q", sm.MAX_FRAME + 1))


class TestWebSocket(unittest.TestCase):
    def test_ping_answered_and_fragments_joined_across_chunks(self):
        stream = (server_frame(sm.OP_PING, b"p") + server_frame(sm.OP_TEXT, b"he", fin=False)
                  + server_frame(sm.OP_CONT, "llo 中".encode()))
        sock = FakeSock([stream[:3], stream[3:9], stream[9:]])
        ws = sm.WebSocket(sock)
        self.assertEqual(ws.recv_text(), "hello 中")
        _, op, payload, _ = sm.parse_frame(sock.sent)
        self.assertEqual((op, payload), (sm.OP_PONG, b"p"))

    def test_every_frame_including_pings_is_a_sign_of_life(self):
        """Regression: pings never surface from recv_text, so a quiet connection
        used to look dead and buttons stopped being attached."""
        stream = (server_frame(sm.OP_PING, b"1") + server_frame(sm.OP_PING, b"2")
                  + server_frame(sm.OP_TEXT, b"x"))
        frames = []
        sm.WebSocket(FakeSock([stream])).recv_text(lambda: frames.append(1))
        self.assertEqual(len(frames), 3)

    def test_timeout_mid_frame_does_not_desync(self):
        frame = server_frame(sm.OP_TEXT, b'{"type":"hello"}')
        sock = FakeSock([frame[:4], socket.timeout(), frame[4:]])
        ws = sm.WebSocket(sock)
        with self.assertRaises(socket.timeout):
            ws.recv_text()
        self.assertEqual(ws.recv_text(), '{"type":"hello"}')

    def test_close_returns_none(self):
        ws = sm.WebSocket(FakeSock([server_frame(sm.OP_CLOSE, struct.pack("!H", 1000))]))
        self.assertIsNone(ws.recv_text())


class TestEnvelopes(unittest.TestCase):
    def test_ack_is_sent_before_the_handler_runs(self):
        order = []
        raw = json.dumps({"type": "interactive", "envelope_id": "E1", "payload": {"a": 1}})
        sm.handle_envelope(raw, lambda t: order.append(("ack", json.loads(t))),
                           lambda kind, p: order.append((kind, p)))
        self.assertEqual(order, [("ack", {"envelope_id": "E1"}), ("interactive", {"a": 1})])

    def test_handler_crash_is_contained(self):
        raw = json.dumps({"type": "events_api", "envelope_id": "E1", "payload": {}})
        with self.assertLogs("alert_doctor.socket_mode", "ERROR"):
            sm.handle_envelope(raw, lambda t: None, mock.Mock(side_effect=RuntimeError("x")))

    def test_disconnect_asks_for_reconnect(self):
        self.assertEqual(sm.handle_envelope('{"type":"disconnect","reason":"refresh"}',
                                            mock.Mock(), mock.Mock()), "reconnect")

    def test_hello_is_forwarded_without_ack(self):
        ack, on_event = mock.Mock(), mock.Mock()
        sm.handle_envelope('{"type":"hello"}', ack, on_event)
        ack.assert_not_called()
        self.assertEqual(on_event.call_args.args[0], "hello")


class TestRunForever(unittest.TestCase):
    def test_reconnects_with_backoff_after_errors(self):
        events, sleeps = [], []
        hello = server_frame(sm.OP_TEXT, b'{"type":"hello"}')
        connects = iter([ConnectionError("down"),
                         sm.WebSocket(FakeSock([hello]))])     # then closed by EOF

        def connect(url):
            item = next(connects)
            if isinstance(item, Exception):
                raise item
            return item

        calls = {"n": 0}

        def stop():
            calls["n"] += 1
            return bool(events) and calls["n"] > 4

        with self.assertLogs("alert_doctor.socket_mode", "WARNING"):
            sm.run_forever("xapp", lambda k, p: events.append(k), stop=stop,
                           sleep=sleeps.append, connect=connect, open_url=lambda t: "wss://x/")
        self.assertEqual(events, ["hello"])
        self.assertEqual(sleeps[0], 1)

    def test_heartbeat_follows_pings_on_a_quiet_connection(self):
        pings = b"".join(server_frame(sm.OP_PING, b"p") for _ in range(5))
        beats, calls = [], {"n": 0}

        def stop():
            calls["n"] += 1
            return calls["n"] > 2

        sm.run_forever("xapp", lambda k, p: None, stop=stop, sleep=lambda s: None,
                       connect=lambda url: sm.WebSocket(FakeSock([pings])),
                       open_url=lambda t: "wss://x/", heartbeat=lambda: beats.append(1))
        self.assertGreaterEqual(len(beats), 6)            # connect + one per ping


if __name__ == "__main__":
    unittest.main()
