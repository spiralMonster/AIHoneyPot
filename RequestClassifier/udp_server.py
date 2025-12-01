import socket

from netifaces import AF_INET

target_ip="127.0.0.1"
target_port=8003

server_socket=socket.socket(AF_INET,socket.SOCK_DGRAM)
server_socket.bind((target_ip,target_port))

print(f"UDP server up and listening on {target_ip}:{target_port}")

while True:
    data, addr = server_socket.recvfrom(1024)  # Buffer size is 1024 bytes
    print(f"Received message from {addr}: {data.decode()}")
