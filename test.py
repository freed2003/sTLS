import socket

def send_get_request(host, port, path):
    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Connect to the server
    client_socket.connect((host, port))
    
    # Create the GET request
    request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    print(request)
    # Send the GET request to the server
    client_socket.sendall(request.encode())
    
    # Receive the response from the server
    response = b""
    while True:
        part = client_socket.recv(1024)
        if not part:
            break
        response += part
    
    # Close the socket
    client_socket.close()
    
    # Decode the response
    return response.decode()

if __name__ == "__main__":
    host = "amazon.com"
    port = 80  # HTTP uses port 80; HTTPS uses port 443
    path = "/"
    
    response = send_get_request(host, port, path)
    print(response)
