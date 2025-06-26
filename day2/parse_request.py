"""
Parse HTTP request line and a couple of headers

Usage:
    python parse_request.py

"""

import socket
import sys
from typing import Dict, Tuple

HOST = '0.0.0.0'
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
BACKLOG = 5
BUFFER_SIZE = 1024 # bytes
HEADER_TERMINATOR = b'\r\n\r\n'

def read_http_request(conn : socket.socket) -> bytes:
    """
    Read from *conn* until we hit the HEADER_TERMINATOR CR-LF CR-LF
    """
    data  = bytearray()
    while HEADER_TERMINATOR not in data:
        chunk = conn.recv(BUFFER_SIZE)
        if not chunk: # client closed connection prematurely
            break
        data.extend(chunk)
        if len(data) > 10 * 1024: # safety guard: 10 KB header max
            break
    return bytes(data)


def parse_request(raw : bytes) -> Tuple[str, str, str, Dict[str, str]]:
    """
    Return(method, path, version, headers)
    """
    try:
        text = raw.decode(errors='replace')
    except UnicodeDecodeError:
        text = raw.decode("latin-1", errors='replace')

    lines = text.split('\r\n')
    request_line = lines[0]
    method, path, version = request_line.split()
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            break # empty line means no more headers
        if ":" not in line:
            continue # ignore malformed headers
        name, value = line.split(":", 1)
        headers[name.strip()] = value.lstrip() # remove leading space
    return method, path, version, headers

def build_response(body: str) -> bytes:
    body_bytes = body.encode()
    headers = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        "Connection: close\r\n\r\n"
    )
    return headers.encode() + body_bytes



def main()-> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(BACKLOG)
        print(f"Server is running on {HOST}:{PORT}")
        try:
            while True:
                conn, addr = server_socket.accept()
                with conn:
                    raw_request = read_http_request(conn)
                    if not raw_request:
                        continue
                    method, path, version, headers = parse_request(raw_request)

                    # Log the interesting parts
                    ua = headers.get("User-Agent", "<no UA>")
                    host_header = headers.get("Host", "<no host>")

                    print(
                            f"{addr[0]}:{addr[1]} → {method} {path} {version} | Host: {host_header} | UA: {ua}"
                        )
                    response_body = (
                        f"Hello!\n\n"
                        f"Method: {method}\n"
                        f"Path: {path}\n"
                        f"HTTP Version: {version}\n"
                        f"Host Header: {host_header}\n"
                        f"User-Agent: {ua}\n"
                    )
                    conn.sendall(build_response(response_body))
        except KeyboardInterrupt:
            print("\nServer shutting down...")
            server_socket.close()
            sys.exit(0)

if __name__ == "__main__":
    main()