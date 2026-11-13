import socket
import json
import struct

def encode_ws_frame(payload_str):
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

def decode_ws_frame(sock):
    sock.settimeout(5.0)
    data = sock.recv(2)
    if not data or len(data) < 2:
        return None
    b1, b2 = data[0], data[1]
    opcode = b1 & 0x0f
    masked = bool(b2 & 0x80)
    payload_len = b2 & 0x7f
    if payload_len == 126:
        ext = sock.recv(2)
        payload_len = struct.unpack('!H', ext)[0]
    elif payload_len == 127:
        ext = sock.recv(8)
        payload_len = struct.unpack('!Q', ext)[0]

    mask = None
    if masked:
        mask = sock.recv(4)

    raw_payload = b''
    while len(raw_payload) < payload_len:
        chunk = sock.recv(payload_len - len(raw_payload))
        if not chunk:
            break
        raw_payload += chunk

    if masked and mask:
        unmasked = bytearray(len(raw_payload))
        for i in range(len(raw_payload)):
            unmasked[i] = raw_payload[i] ^ mask[i % 4]
        return opcode, bytes(unmasked)
    return opcode, raw_payload

with open(r"C:\Users\SATYAJEET\AppData\Local\Google\Chrome\User Data\DevToolsActivePort", "r") as f:
    lines = [line.strip() for line in f if line.strip()]
port = int(lines[0])
ws_path = lines[1]

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', port))
req = (
    f"GET {ws_path} HTTP/1.1\r\n"
    f"Host: 127.0.0.1:{port}\r\n"
    f"Upgrade: websocket\r\n"
    f"Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    f"Sec-WebSocket-Version: 13\r\n\r\n"
)
s.sendall(req.encode('utf-8'))
resp = s.recv(4096)

s.sendall(encode_ws_frame(json.dumps({"id": 1, "method": "Target.getTargets"})))
op, res = decode_ws_frame(s)
targets_data = json.loads(res.decode('utf-8'))
targets = targets_data.get('result', {}).get('targetInfos', [])

print(f"Total Targets: {len(targets)}")
for t in targets:
    if t.get('type') == 'page':
        print(f"PAGE: targetId={t.get('targetId')} | title={t.get('title')} | url={t.get('url')}")
    else:
        print(f"OTHER ({t.get('type')}): {t.get('title')} | {t.get('url')[:60]}")

s.close()

