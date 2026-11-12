import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 9222))
path = '/devtools/browser/6608d397-f67d-4486-84f0-ee98b55e8151'

# Test 1: Handshake WITHOUT Origin header
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
print("Handshake Response (No Origin):")
print(resp.decode('utf-8', errors='replace'))
s.close()

# Test 2: Handshake WITH Origin header
s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s2.connect(('127.0.0.1', 9222))
req2 = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: 127.0.0.1:9222\r\n"
    f"Upgrade: websocket\r\n"
    f"Connection: Upgrade\r\n"
    f"Origin: http://127.0.0.1:9222\r\n"
    f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    f"Sec-WebSocket-Version: 13\r\n\r\n"
)
s2.sendall(req2.encode('utf-8'))
resp2 = s2.recv(4096)
print("Handshake Response (With Origin):")
print(resp2.decode('utf-8', errors='replace'))
s2.close()

