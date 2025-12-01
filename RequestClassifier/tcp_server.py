import socket

target_ip = "127.0.0.1"  # Change to the target IP
target_port = 8004

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((target_ip, target_port))
server_socket.listen(1)

print(f"TCP server listening on {target_ip}:{target_port}...")

while True:
    client_socket, client_address = server_socket.accept()
    print(f"Connection established with {client_address}")
    client_socket.close()
