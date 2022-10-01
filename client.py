"""
client.py Made By: Andrew Erickson
"""
import socket
import defns


SERVER = "10.0.2.15"  # TODO change to the cmd args
PORT = 38501
ADDR = (SERVER, PORT)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # makes server with IPv4 and set to a stream of data
client.connect(ADDR)


def send(msg):
    message = msg.encode(defns.FORMAT)
    msg_len = len(message)
    send_len = str(msg_len).encode(defns.FORMAT)
    send_len += b' ' * (defns.HEADER - len(send_len))
    client.send(send_len)
    client.send(message)
    ack = client.recv(2048).decode(defns.FORMAT)
    if ack == defns.DISCONNECT_MSG:
        print("Server disconnected. Stopping")
        raise defns.Disconnected


def start():
    try:
        for i in range(0, 10):
            s = input("msg: ")
            send(s)
        send(defns.DISCONNECT_MSG)  # exit from server
    except KeyboardInterrupt:
        print("\nCaught keyboard interrupt...Stopping")
        send(defns.DISCONNECT_MSG)  # exit from server
    except defns.Disconnected:
        pass  # server stopped do nothing and end


start()
