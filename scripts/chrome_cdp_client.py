import socket
import json
import struct
import time

class ChromeCDPClient:
    def __init__(self, devtools_port_file=r"C:\Users\SATYAJEET\AppData\Local\Google\Chrome\User Data\DevToolsActivePort"):
        with open(devtools_port_file, "r") as f:
            lines = [l.strip() for l in f if l.strip()]
        self.port = int(lines[0])
        self.ws_path = lines[1]
        self.sock = None
        self.msg_id = 0
        self._connect()

    def _connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(('127.0.0.1', self.port))
        req = (
            f"GET {self.ws_path} HTTP/1.1\r\n"
            f"Host: localhost:{self.port}\r\n"
            f"Origin: http://127.0.0.1:{self.port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(req.encode('utf-8'))
        resp = self.sock.recv(4096)
        if b"101" not in resp:
            raise ConnectionError("Failed to handshake WebSocket with Chrome DevTools")

    def _encode_frame(self, payload_str):
        data = payload_str.encode('utf-8')
        length = len(data)
        mask_key = b'\x12\x34\x56\x78'
        if length <= 125:
            header = bytes([0x81, 0x80 | length]) + mask_key
        elif length <= 65535:
            header = bytes([0x81, 0x80 | 126]) + struct.pack('!H', length) + mask_key
        else:
            header = bytes([0x81, 0x80 | 127]) + struct.pack('!Q', length) + mask_key

        masked_data = bytearray(length)
        for i in range(length):
            masked_data[i] = data[i] ^ mask_key[i % 4]
        return header + masked_data

    def _decode_frame(self, timeout=10.0):
        self.sock.settimeout(timeout)
        try:
            data = self.sock.recv(2)
        except socket.timeout:
            return None, None
        if not data or len(data) < 2:
            return None, None
        b1, b2 = data[0], data[1]
        opcode = b1 & 0x0f
        masked = bool(b2 & 0x80)
        payload_len = b2 & 0x7f
        if payload_len == 126:
            ext = self.sock.recv(2)
            payload_len = struct.unpack('!H', ext)[0]
        elif payload_len == 127:
            ext = self.sock.recv(8)
            payload_len = struct.unpack('!Q', ext)[0]

        mask = None
        if masked:
            mask = self.sock.recv(4)

        raw_payload = b''
        while len(raw_payload) < payload_len:
            chunk = self.sock.recv(payload_len - len(raw_payload))
            if not chunk:
                break
            raw_payload += chunk

        if masked and mask:
            unmasked = bytearray(len(raw_payload))
            for i in range(len(raw_payload)):
                unmasked[i] = raw_payload[i] ^ mask[i % 4]
            return opcode, bytes(unmasked)
        return opcode, raw_payload

    def send_command(self, method, params=None, session_id=None, timeout=10.0):
        self.msg_id += 1
        req_id = self.msg_id
        msg = {"id": req_id, "method": method}
        if params is not None:
            msg["params"] = params
        if session_id:
            msg["sessionId"] = session_id

        self.sock.sendall(self._encode_frame(json.dumps(msg)))

        start = time.time()
        while time.time() - start < timeout:
            op, raw = self._decode_frame(timeout=timeout)
            if not raw:
                break
            try:
                res = json.loads(raw.decode('utf-8'))
                if res.get("id") == req_id:
                    return res
            except Exception:
                pass
        return None

    def get_targets(self):
        res = self.send_command("Target.getTargets")
        if res and "result" in res:
            return res["result"].get("targetInfos", [])
        return []

    def create_tab(self, url="about:blank"):
        res = self.send_command("Target.createTarget", {"url": url})
        if res and "result" in res:
            return res["result"].get("targetId")
        return None

    def close_tab(self, target_id):
        return self.send_command("Target.closeTarget", {"targetId": target_id})

    def attach_to_target(self, target_id):
        res = self.send_command("Target.attachToTarget", {"targetId": target_id, "flatten": True})
        if res and "result" in res:
            return res["result"].get("sessionId")
        return None

    def evaluate(self, session_id, expression, await_promise=True):
        res = self.send_command("Runtime.evaluate", {
            "expression": expression,
            "awaitPromise": await_promise,
            "returnByValue": True
        }, session_id=session_id)
        if res and "result" in res:
            return res["result"].get("result", {}).get("value")
        return None

    def navigate(self, session_id, url):
        return self.send_command("Page.navigate", {"url": url}, session_id=session_id)

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None

if __name__ == "__main__":
    cdp = ChromeCDPClient()
    targets = cdp.get_targets()
    print(f"Connected to CDP. Found {len(targets)} targets.")
    for t in targets:
        if t.get('type') == 'page':
            print(f"- {t.get('title')}: {t.get('url')}")
    cdp.close()

