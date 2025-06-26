import socket, signal, sys

HOST, PORT = '', 8080
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server.listen(5)
print(f"Serving on http://localhost:{PORT}")

# Allow Ctrl-C to exit cleanly
signal.signal(signal.SIGINT, lambda *_: (server.close(), sys.exit(0)))

BODY = b"<h1>Hello, World!</h1>"
HEADER = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/html; charset=utf-8\r\n"
    b"Content-Length: " + str(len(BODY)).encode() + b"\r\n"
    b"Connection: close\r\n\r\n"
)

while True:
    conn, addr = server.accept()
    conn.recv(1024)          # ignore request details for now
    conn.sendall(HEADER + BODY)
    conn.close()