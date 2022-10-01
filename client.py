"""
client.py Made By: Andrew Erickson
"""
import socket

HEADER = 64  # define msg length
FORMAT = "utf-8"
DISCONNECT_MSG = "EXIT"
SERVER = "10.0.2.15"  # TODO change to the cmd args
PORT = 38501
ADDR = (SERVER, PORT)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # makes server with IPv4 and set to a stream of data
client.connect(ADDR)


def send(msg):
    message = msg.encode(FORMAT)
    msg_len = len(message)
    send_len = str(msg_len).encode(FORMAT)
    send_len += b' ' * (HEADER - len(send_len))
    client.send(send_len)
    client.send(message)
    print(client.recv(2048).decode(FORMAT))


for i in range(0, 10):
    send(str(i))

send(DISCONNECT_MSG)  # exit from server
