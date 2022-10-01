"""
server.py Made By: Andrew Erickson
"""

import socket
import threading
import sys
import defns

# look to jason or pickle for sending objs
if len(sys.argv) < 2:
    print("PORT NOT DEFINED")
    exit(-1)

# verify that port is valid
p = int(sys.argv[1])
if p and defns.PORT_RANGE[0] <= p <= defns.PORT_RANGE[1]:
    PORT = p
else:
    print("PORT OUT OF RANGE. USING DEFAULT PORT OF 38500")
    PORT = 38500

# SERVER = "127.0.0.1"  # can put in IP manually
SERVER_IP = socket.gethostbyname(socket.gethostname())  # or just have socket get it auto
ADDR = (SERVER_IP, PORT)


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # makes server with IPv4 and set to a stream of data
server.bind(ADDR)  # binds socket to IP PORT

# can store the user info in a dictionary (Handle, usr_obj)

def log(s: str):
    print("server: " + s)


def handle_client(conn: socket.socket, addr):
    log(f"New client on IP: {addr[0]} Port: {addr[1]}\tActive users: {threading.activeCount() - 1}")
    connected = True
    try:
        while connected:
            # recv length can be bigger than msg, just try to make it as small as possible
            msg_length = conn.recv(defns.HEADER).decode(defns.FORMAT)  # Blocking get msg length
            if msg_length:  # when first connecting an empty packet is sent, we won't handle it
                msg_length = int(msg_length)
                msg = conn.recv(msg_length).decode(defns.FORMAT)  # Blocking get message then decode to str
                if msg == defns.DISCONNECT_MSG:
                    connected = False
                else:
                    # process message
                    log(f"[{addr}] {msg}")
                    conn.send("Msg received".encode(defns.FORMAT))  # ack msg
    except KeyboardInterrupt:
        log("Caught keyboard interrupt...Stopping")
        conn.send(defns.DISCONNECT_MSG.encode(defns.FORMAT))
        raise KeyboardInterrupt
    finally:
        conn.close()  # when a keyboard interrupt happens close the connection
        log(f"[{addr}] disconnected Active users: {threading.activeCount() - 2}")


def start():
    server.listen()
    while True:
        try:
            conn, addr = server.accept()  # blocks until a connection is made and returns info about connection
            # pass off client to a new thread
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.start()
        except KeyboardInterrupt:
            log("Stopped")
            exit(0)


log(f"Server is starting with IP: {SERVER_IP} and port: {PORT}")
start()
