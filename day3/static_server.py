"""
serves static files from a designated root directory.

Usage:
    python static_server.py [port] [root]

    port: The port to listen on. Defaults to 8080.
    root: The root directory to serve files from. Defaults to the directory of this script.

"""

from __future__ import annotations

import mimetypes
import socket
import sys
from pathlib import Path
from typing import Dict, Tuple

HOST = "0.0.0.0"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
ROOT = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(__file__).with_suffix("").parent / "www"
BACKLOG = 5
BUFFER_SIZE = 1024
HEADER_TERMINATOR = b"\r\n\r\n"

# Ensure mimetypes knows about common text types
mimetypes.init()
# Ensure .js is recognised on all platforms
mimetypes.add_type("application/javascript", ".js")

def read_http_request(conn: socket.socket) -> bytes:
    data = bytearray()
    while HEADER_TERMINATOR not in data:
        chunk = conn.recv(BUFFER_SIZE)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > 10 * 1024:
            break
    return bytes(data)


def parse_request(raw: bytes) -> Tuple[str, str, str, Dict[str, str]]:
    try:
        text = raw.decode(errors="replace")
    except UnicodeDecodeError:
        text = raw.decode("latin-1", errors="replace")

    lines = text.split("\r\n")
    request_line = lines[0]
    # Defensive split – if malformed request, fallback values
    parts = request_line.split(" ")
    if len(parts) != 3:
        return "GET", "/", "HTTP/1.0", {}
    method, path, version = parts

    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            break
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip()] = value.lstrip()
    return method, path, version, headers

def build_headers(status_code: int, reason: str, extra_headers: Dict[str, str] | None = None) -> str:
    hdr = [f"HTTP/1.1 {status_code} {reason}"]
    if extra_headers:
        for k, v in extra_headers.items():
            hdr.append(f"{k}: {v}")
    hdr.append("Connection: close")
    return "\r\n".join(hdr) + "\r\n\r\n"

def handle_request(method: str, url_path: str) -> bytes:
    # Support only GET and HEAD for now
    if method not in ("GET", "HEAD"):
        body = f"Method {method} not supported".encode()
        headers = build_headers(
            405,
            "Method Not Allowed",
            {"Content-Type": "text/plain", "Content-Length": str(len(body))},
        )
        return headers.encode() + body

    # Strip query string (anything after ?)
    url_path = url_path.split("?", 1)[0]

    # Default path → index.html
    if url_path == "/":
        url_path = "/index.html"
    
    # Sanitize path
    target_path = (ROOT / url_path.lstrip("/")).resolve()
    try:
        target_path.relative_to(ROOT.resolve())
    except ValueError:
        body = b"Forbidden"
        headers = build_headers(403, "Forbidden", {"Content-Type": "text/plain", "Content-Length": str(len(body))})
        return headers.encode() + body
    
    if not target_path.exists() or not target_path.is_file():
        body = b"Not found"
        headers = build_headers(404, "Not Found", {"Content-Type": "text/plain", "Content-Length": str(len(body))})
        return headers.encode() + body
    
    try:
        data = target_path.read_bytes()
    except PermissionError:
        body = b"Forbidden"
        headers = build_headers(403, "Forbidden", {"Content-Type": "text/plain", "Content-Length": str(len(body))})
        return headers.encode() + body
    
    except Exception as exc:
        body = f"Internal Server Error: {exc}".encode()
        headers = build_headers(500, "Internal Server Error", {"Content-Type": "text/plain", "Content-Length": str(len(body))})
        return headers.encode() + body
    
    mime_type, _ = mimetypes.guess_type(str(target_path))
    if mime_type is None:
        mime_type = "application/octet-stream"

    headers = build_headers(200, "OK", {"Content-Type": mime_type, "Content-Length": str(len(data))})

    # For HEAD requests, only send headers
    if method == "HEAD":
        return headers.encode()

    return headers.encode() + data


def main() -> None:
    ROOT.mkdir(parents=True, exist_ok=True)
    print(f"Serving files from {ROOT.resolve()}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(BACKLOG)
        print(f"Static file server listening on http://{HOST or 'localhost'}:{PORT}")

        try:
            while True:
                conn, addr = server_socket.accept()
                with conn:
                    raw = read_http_request(conn)
                    if not raw:
                        continue
                    method, path, version, headers = parse_request(raw)
                    print(f"{addr[0]}:{addr[1]} - {method} {path}")
                    response = handle_request(method, path)
                    conn.sendall(response)
        except KeyboardInterrupt:
            print("\nServer shutting down...")
            server_socket.close()
            sys.exit(0)

if __name__ == "__main__":
    main()