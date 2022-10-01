import socket
import threading
import sys
# look to jason or pickle for sending objs
if len(sys.argv) < 2:
    print("PORT NOT DEFINED")
    exit(-1)
PORT_RANGE = (38500, 38999)
# verify that port is valid
p = int(sys.argv[1])
if p and PORT_RANGE[0] <= p <= PORT_RANGE[1]:
    PORT = p
else:
    print("PORT OUT OF RANGE. USING DEFAULT PORT OF 38500")
    PORT = 38500

HEADER = 64  # define msg length can change later to be max buff may use 256 need to check max size that can be sent
# SERVER = "127.0.0.1"  # can put in IP manually
SERVER_IP = socket.gethostbyname(socket.gethostname())  # or just have socket get it auto
ADDR = (SERVER_IP, PORT)
FORMAT = "utf-8"
DISCONNECT_MSG = "EXIT"

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # makes server with IPv4 and set to a stream of data
server.bind(ADDR)  # binds socket to IP PORT

# can store the user info in a dictionary (Handle, usr_obj)

def log(s: str):
    print("server: " + s)


def handle_client(conn: socket.socket, addr):
    log(f"New client on IP: {addr[0]} Port: {addr[1]}\tActive users: {threading.activeCount() - 1}")
    connected = True
    while connected:
        # recv length can be bigger than msg, just try to make it as small as possible
        msg_length = conn.recv(HEADER).decode(FORMAT)  # Blocking get msg length
        if msg_length:  # when first connecting an empty packet is sent, we won't handle it
            msg_length = int(msg_length)
            msg = conn.recv(msg_length).decode(FORMAT)  # Blocking get message then decode to str
            if msg == DISCONNECT_MSG:
                connected = False
            else:
                # process message
                log(f"[{addr}] {msg}")
                conn.send("Msg received".encode(FORMAT))  # ack msg
    conn.close()
    log(f"[{addr}] disconnected Active users: {threading.activeCount() - 2}")


def start():
    server.listen()
    while True:
        conn, addr = server.accept()  # blocks until a connection is made and returns info about connection
        # pass off client to a new thread
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()


log(f"Server is starting with IP: {SERVER_IP} and port: {PORT}")
start()
