import socket
import json
import struct

def encode_ws_frame(payload_str):
    data = payload_str.encode('utf-8')
    length = len(data)
    # Client to server frames MUST be masked according to RFC 6455
    # Byte 1: FIN (0x80) | opcode text (0x01) -> 0x81
    # Byte 2: Mask (0x80) | length
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

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 9222))
path = '/devtools/browser/6608d397-f67d-4486-84f0-ee98b55e8151'
req = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: 127.0.0.1:9222\r\n"
    f"Upgrade: websocket\r\n"
    f"Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    f"Sec-WebSocket-Version: 13\r\n\r\n"
)
s.sendall(req.encode('utf-8'))
resp = s.recv(4096)
print("Handshake done.")

msg = json.dumps({"id": 1, "method": "Browser.getVersion"})
s.sendall(encode_ws_frame(msg))

op, res = decode_ws_frame(s)
print(f"Browser.getVersion response (op={op}):", res.decode('utf-8', errors='replace'))

msg2 = json.dumps({"id": 2, "method": "Target.getTargets"})
s.sendall(encode_ws_frame(msg2))
op2, res2 = decode_ws_frame(s)
print(f"Target.getTargets response (op={op2}):", res2.decode('utf-8', errors='replace')[:400])

s.close()

