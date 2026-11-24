"""A bounded RFB client over an approved TLS WebSocket. Agent I/O is pixels and input."""
from base64 import b64encode
from contextlib import ExitStack
from hashlib import sha1, sha256
import os
from struct import pack, unpack
from time import monotonic
from urllib.parse import urlencode, urlsplit
import zlib

from .access_settings import credential_headers
from .result_delivery import _connection


MAX_WIDTH, MAX_HEIGHT = 2048, 1536
MAX_MESSAGE = MAX_WIDTH * MAX_HEIGHT * 4 + 65536
MAX_PNG = 700_000
WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
class ConsoleTimeoutError(TimeoutError):
    """Raised when a console operation times out at a clean WebSocket/RFB boundary."""


KEYS = {
    "BackSpace": 0xff08, "Tab": 0xff09, "Enter": 0xff0d, "Escape": 0xff1b,
    "Home": 0xff50, "Left": 0xff51, "Up": 0xff52, "Right": 0xff53, "Down": 0xff54,
    "PageUp": 0xff55, "PageDown": 0xff56, "End": 0xff57, "Insert": 0xff63,
    "Delete": 0xffff, "Del": 0xffff,
    **{f"F{n}": 0xffbd + n for n in range(1, 13)},
}
MODIFIERS = {
    "ctrl": 0xffe3, "control": 0xffe3,
    "alt": 0xffe9,
    "shift": 0xffe1,
    "super": 0xffeb, "meta": 0xffeb,
}
SHIFTED_US_KEYS = frozenset('~!@#$%^&*()_+{}|:"<>?')


def _parse_key(spec):
    if not isinstance(spec, str):
        raise ValueError("Invalid key specification.")
    if spec in KEYS or len(spec) == 1 and " " <= spec <= "~":
        return (), spec
    if "+" in spec:
        parts = [*spec[:-2].split("+"), "+"] if spec.endswith("++") else spec.split("+")
        mod_parts, base = parts[:-1], parts[-1]
        if 1 <= len(mod_parts) <= 4 and all(mod_parts) and (base in KEYS or len(base) == 1 and " " <= base <= "~"):
            mod_codes = []
            for part in mod_parts:
                code = MODIFIERS.get(part.lower())
                if code is None or code in mod_codes:
                    raise ValueError("Unsupported key modifier.")
                mod_codes.append(code)
            return tuple(mod_codes), base
    raise ValueError("Unsupported key specification.")


def _key_event(code, down):
    return pack("!BBHI", 4, down, 0, code)


def _key_press(key):
    mod_codes, base = _parse_key(key)
    if not mod_codes:
        code = KEYS[base] if base in KEYS else ord(base)
        press = _key_event(code, 1) + _key_event(code, 0)
        # QEMU's graphical VNC console maps key symbols to physical keys.
        # Send the Shift modifier explicitly for US-layout ASCII.
        if len(base) == 1 and ("A" <= base <= "Z" or base in SHIFTED_US_KEYS):
            shift = 0xffe1
            return _key_event(shift, 1) + press + _key_event(shift, 0)
        return press
    if 0xffe3 in mod_codes and 0xffe1 not in mod_codes and len(base) == 1 and "A" <= base <= "Z":
        base = base.lower()
    code = KEYS[base] if base in KEYS else ord(base)
    down = b"".join(_key_event(mod, 1) for mod in mod_codes)
    up = b"".join(_key_event(mod, 0) for mod in reversed(mod_codes))
    return down + _key_event(code, 1) + _key_event(code, 0) + up


def validate_inputs(events):
    if not isinstance(events, list) or not 1 <= len(events) <= 16:
        raise ValueError("Use one to sixteen console input events.")
    for event in events:
        if not isinstance(event, dict):
            raise ValueError("Invalid console input.")
        if set(event) == {"key"}:
            try:
                _parse_key(event["key"])
                continue
            except ValueError:
                pass
        elif set(event) == {"text"}:
            text = event["text"]
            if isinstance(text, str) and 1 <= len(text) <= 160 and all(" " <= ch <= "~" for ch in text):
                continue
        elif set(event) == {"x", "y"} and all(type(event[k]) is int and 0 <= event[k] < 2048 for k in event):
            continue
        raise ValueError("Use a supported key, printable ASCII text, or a click coordinate.")
    return events


class WebSocket:
    def __init__(self, stack, origin, pin, expires, path, headers, query, gate):
        connection = stack.enter_context(_connection(origin, pin, expires))
        self.socket = connection.sock
        self.incoming = bytearray()
        self.payload = bytearray()
        self.remaining = 0
        self.fragmented = False
        self.deadline = min(expires, monotonic() + 6)
        key = b64encode(os.urandom(16))
        authority = urlsplit(origin).netloc
        target = path + ("?" + urlencode(query) if query else "")
        lines = [
            f"GET {target} HTTP/1.1", f"Host: {authority}",
            "Connection: Upgrade", "Upgrade: websocket", "Sec-WebSocket-Version: 13",
            "Sec-WebSocket-Protocol: binary", f"Sec-WebSocket-Key: {key.decode('ascii')}",
            f"Origin: {origin.rstrip('/')}",
        ]
        for name, value in credential_headers(headers):
            if name.lower() == "origin" or name.lower().startswith("sec-websocket-"):
                raise ValueError("Reserved WebSocket header.")
            lines.append(f"{name}: {value}")
        if not gate():
            raise PermissionError
        self.send_bytes(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
        while b"\r\n\r\n" not in self.incoming:
            if len(self.incoming) >= 16384:
                raise ValueError("WebSocket response headers too large.")
            self.receive_bytes()
        raw, _, self.incoming = self.incoming.partition(b"\r\n\r\n")
        if len(raw) > 16384:
            raise ValueError("WebSocket response headers too large.")
        status, *lines = raw.decode("ascii").split("\r\n")
        if status.split()[:2] != ["HTTP/1.1", "101"]:
            raise ValueError("The service did not open a WebSocket.")
        received = {}
        for line in lines:
            name, sep, value = line.partition(":")
            if not sep or not name or line[0].isspace():
                raise ValueError("Malformed WebSocket response.")
            name = name.lower()
            if name in ("upgrade", "connection", "sec-websocket-accept", "sec-websocket-protocol", "sec-websocket-extensions"):
                if name in received:
                    raise ValueError("Ambiguous WebSocket response.")
                received[name] = value.strip()
        if (received.get("upgrade", "").lower() != "websocket"
                or "upgrade" not in {value.strip() for value in received.get("connection", "").lower().split(",")}
                or received.get("sec-websocket-accept") != b64encode(sha1(key + WS_GUID).digest()).decode("ascii")
                or received.get("sec-websocket-protocol", "binary") != "binary"
                or "sec-websocket-extensions" in received):
            raise ValueError("Invalid WebSocket handshake.")

    def time_limit(self):
        seconds = self.deadline - monotonic()
        if seconds <= 0:
            raise TimeoutError
        self.socket.settimeout(min(seconds, 4))

    def send_bytes(self, data):
        self.time_limit()
        self.socket.sendall(data)

    def receive_bytes(self):
        self.time_limit()
        data = self.socket.recv(16384)
        if not data:
            raise EOFError
        self.incoming.extend(data)

    def wire(self, size):
        while len(self.incoming) < size:
            self.receive_bytes()
        data = bytes(self.incoming[:size])
        del self.incoming[:size]
        return data

    def send(self, data, opcode=2):
        size = len(data)
        if size < 126:
            count = pack("!B", size | 128)
        elif size <= 65535:
            count = pack("!BH", 254, size)
        else:
            count = pack("!BQ", 255, size)
        mask = os.urandom(4)
        masked = bytes(byte ^ mask[i % 4] for i, byte in enumerate(data))
        self.send_bytes(pack("!B", 128 | opcode) + count + mask + masked)

    def read(self, size):
        # Both frame boundaries and fragmented WebSocket messages are independent
        # of RFB message boundaries. Consume only binary data and bounded controls.
        result = bytearray()
        while len(result) < size:
            if self.remaining:
                count = min(size - len(result), self.remaining, 16384)
                result.extend(self.wire(count))
                self.remaining -= count
                continue
            flags, length = self.wire(2)
            fin, opcode = bool(flags & 128), flags & 15
            if flags & 112 or length & 128:
                raise ValueError("Unsupported WebSocket frame.")
            if opcode >= 8:
                if not fin or length > 125 or opcode not in (8, 9, 10):
                    raise ValueError("Invalid WebSocket control.")
                data = self.wire(length)
                if opcode == 8:
                    raise EOFError
                if opcode == 9:
                    self.send(data, opcode=10)
                continue
            if opcode != (0 if self.fragmented else 2):
                raise ValueError("Expected binary console frames.")
            self.fragmented = not fin
            if length == 126:
                length, = unpack("!H", self.wire(2))
            elif length == 127:
                length, = unpack("!Q", self.wire(8))
            if length > MAX_MESSAGE:
                raise ValueError("WebSocket frame too large.")
            self.remaining = length
        return bytes(result)


def _auth(challenge, password):
    # VNC authentication is defined as DES with bit-reversed password bytes.
    # It is used only inside the verified TLS channel.
    from Cryptodome.Cipher import DES
    key = bytes(int(f"{value:08b}"[::-1], 2) for value in password.encode("ascii")[:8].ljust(8, b"\0"))
    return DES.new(key, DES.MODE_ECB).encrypt(challenge)


def _png(width, height, rgb, step):
    columns = (width + step - 1) // step
    rows = (height + step - 1) // step
    stride = width * 3
    scanlines = bytearray()
    for y in range(0, height, step):
        scanlines.append(0)
        row = rgb[y * stride:(y + 1) * stride]
        if step == 1:
            scanlines.extend(row)
        else:
            sampled = bytearray(columns * 3)
            for channel in range(3):
                sampled[channel::3] = row[channel::step * 3]
            scanlines.extend(sampled)

    def chunk(kind, data):
        return pack("!I", len(data)) + kind + data + pack("!I", zlib.crc32(kind + data))

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", pack("!IIBBBBB", columns, rows, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(scanlines, level=3)) + chunk(b"IEND", b""))


class Console:
    def __init__(self, origin, pin, expires, path, headers, query, password, gate):
        self.stack = ExitStack()
        self.expires = expires
        try:
            self.ws = WebSocket(self.stack, origin, pin, expires, path, headers, query, gate)
            self.ws.deadline = min(expires, monotonic() + 6)
            self._initialize(password, gate)
        except BaseException:
            self.close()
            raise

    def close(self):
        self.stack.close()

    def _initialize(self, password, gate):
        ws = self.ws
        version = ws.read(12)
        if version not in (b"RFB 003.007\n", b"RFB 003.008\n"):
            raise ValueError("Unsupported RFB version.")
        ws.send(version)
        count = ws.read(1)[0]
        if not count or count > 32:
            raise ValueError("The console rejected the handshake.")
        offered = ws.read(count)
        security = 2 if password else 1
        if security not in offered:
            raise ValueError("The console did not offer the requested authentication.")
        ws.send(bytes([security]))
        if security == 2:
            challenge = ws.read(16)
            if not gate():
                raise PermissionError
            ws.send(_auth(challenge, password))
        if (security == 2 or version == b"RFB 003.008\n") and ws.read(4) != bytes(4):
            raise ValueError("The console rejected authentication.")
        ws.send(b"\x01")  # Shared mode does not evict other viewers.
        self.width, self.height, _, name_size = unpack("!HH16sI", ws.read(24))
        if not (1 <= self.width <= MAX_WIDTH and 1 <= self.height <= MAX_HEIGHT and name_size <= 4096):
            raise ValueError("Console dimensions or title exceed the limit.")
        ws.read(name_size)  # A remote title may include private values.
        # 32-bit little-endian RGB and only raw updates. No clipboard extension is enabled.
        ws.send(pack("!BBBBBBBBHHHBBBxxx", 0, 0, 0, 0, 32, 24, 0, 1, 255, 255, 255, 16, 8, 0))
        ws.send(pack("!BBHii", 2, 0, 2, 0, -223))  # Raw pixels and desktop resizing.
        self.rgb = bytearray(self.width * self.height * 3)
        self.previous_frame = None

    def _clean_boundary(self):
        ws = self.ws
        return ws.remaining == 0 and not ws.fragmented and not ws.incoming

    def view(self, *, status_only=False):
        ws = self.ws
        ws.deadline = min(self.expires, monotonic() + 6)
        try:
            ws.send(pack("!BBHHHH", 3, 0, 0, 0, self.width, self.height))
        except TimeoutError:
            if self._clean_boundary():
                raise ConsoleTimeoutError from None
            raise
        for _ in range(32):
            try:
                kind = ws.read(1)[0]
            except TimeoutError:
                if self._clean_boundary():
                    raise ConsoleTimeoutError from None
                raise
            if kind == 0:
                self._update()
                dimensions = {"width": self.width, "height": self.height}
                frame = (self.width, self.height, sha256(self.rgb).digest())
                changed = frame != self.previous_frame
                self.previous_frame = frame
                if status_only:
                    return {"changed": changed, **dimensions}
                for step in (1, 2, 4, 8):
                    png = _png(self.width, self.height, self.rgb, step)
                    if len(png) <= MAX_PNG:
                        return {"png_base64": b64encode(png).decode("ascii"), **dimensions, "scale": step}
                raise ValueError("Console image exceeds the output limit.")
            if kind == 2:  # bell
                continue
            if kind == 3:  # server clipboard; consume but never return it
                _, size = unpack("!3sI", ws.read(7))
                if size <= 65536:
                    ws.read(size)
                    continue
            raise ValueError("Unsupported console message.")
        raise ValueError("The console did not send an image.")

    def _update(self):
        _, count = unpack("!BH", self.ws.read(3))
        pixels = 0
        if count > 128:
            raise ValueError("Too many framebuffer rectangles.")
        for _ in range(count):
            x, y, width, height, encoding = unpack("!HHHHi", self.ws.read(12))
            if encoding == -223:
                if not (x == y == 0 and 1 <= width <= MAX_WIDTH and 1 <= height <= MAX_HEIGHT):
                    raise ValueError("Invalid console dimensions.")
                self.width, self.height = width, height
                self.rgb = bytearray(width * height * 3)
                continue
            pixels += width * height
            if (encoding != 0 or not width or not height or x + width > self.width
                    or y + height > self.height or pixels > self.width * self.height * 2):
                raise ValueError("Invalid framebuffer rectangle.")
            raw = self.ws.read(width * height * 4)
            rgb = bytearray(width * height * 3)
            rgb[0::3], rgb[1::3], rgb[2::3] = raw[2::4], raw[1::4], raw[0::4]
            for row in range(height):
                offset = ((y + row) * self.width + x) * 3
                self.rgb[offset:offset + width * 3] = rgb[row * width * 3:(row + 1) * width * 3]

    def input(self, events):
        self.ws.deadline = min(self.expires, monotonic() + 6)
        data = bytearray()
        for event in validate_inputs(events):
            if "x" in event:
                x, y = event["x"], event["y"]
                if x >= self.width or y >= self.height:
                    raise ValueError("Click outside the console.")
                data.extend(pack("!BBHHBBHH", 5, 1, x, y, 5, 0, x, y))
            else:
                for key in ([event["key"]] if "key" in event else list(event["text"])):
                    data.extend(_key_press(key))
        try:
            self.ws.send(data)
        except TimeoutError:
            if self._clean_boundary():
                raise ConsoleTimeoutError from None
            raise
