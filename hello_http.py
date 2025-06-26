"""
HTTP server that returns a simple "Hello, World!" response.

Usage:
    python hello_http.py

This server listens on port 8080 and returns a simple "Hello, World!" response.

"""

import socket

# Define socket host and port
SERVER_HOST = '0.0.0.0'
SERVER_PORT = 8080

# Create socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind((SERVER_HOST, SERVER_PORT))
server_socket.listen(1)

print(f"Server is running on {SERVER_HOST}:{SERVER_PORT}")

while True:
    # Accept incoming connections
    client_connection, client_address = server_socket.accept()
    # Receive request data
    request = client_connection.recv(1024).decode()
    print(f"New connection from {client_address}")

    headers = request.split('\n')
    filename = headers[0].split()[1]
    if filename == '/':
        filename = '/index.html'
    try:
        fin = open('htdocs' + filename)
        content = fin.read()
        fin.close()
        response = 'HTTP/1.0 200 OK\n\n' + content
    except FileNotFoundError:
        response = 'HTTP/1.0 404 Not Found\n\nFile Not Found'
    except PermissionError:
        response = 'HTTP/1.0 403 Forbidden\n\nPermission Denied'
    except Exception as e:
        response = 'HTTP/1.0 500 Internal Server Error\n\n' + str(e)

    # Print request data
    print(request)
    # Send response
    
    # response = 'HTTP/1.0 200 OK\n\nHello, World!'
    # response = "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><body><h1>Hello, World!</h1></body></html>"
    # response = "HTTP/1.1 404 Not Found\nContent-Type: text/html\n\n<html><body><h1>404 Not Found</h1></body></html>"
    
    client_connection.sendall(response.encode())
    client_connection.close()
# Close server socket
server_socket.close()