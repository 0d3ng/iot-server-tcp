# Python TCP Client A
import socket

host = socket.gethostname() #silakan disesuaikan dengan alamat host server
print("host: " + host)
port = 2004 # silakan disesuaikan dengan port server
BUFFER_SIZE = 2000
MESSAGE = input("Enter message/ Enter exit:")

tcpClientA = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcpClientA.connect(("localhost", port))

while MESSAGE != 'exit':
    tcpClientA.send(MESSAGE.encode("utf8"))
    data = tcpClientA.recv(BUFFER_SIZE)
    print("Received data:", data)
    MESSAGE = input("Enter message to continue/ Enter exit:")

tcpClientA.close()
