"""
server.py Made By: Andrew Erickson
"""
import json
import socket
import threading
import sys
import defns
import server_cmds as cmds

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

# SERVER_IP = "0.0.0.0"  # can put in IP manually, set to all interfaces
SERVER_IP = socket.gethostbyname_ex(socket.getfqdn())[2][0]  # or just have socket get it auto
ADDR = (SERVER_IP, PORT)
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # makes server with IPv4 and set to a stream of data

try:
    server.bind(ADDR)  # binds socket to IP PORT
except OSError:
    print(f"Error: cannot resolve host IP automatically. Manual entry required, use ifconfig to get address")
    SERVER_IP = input("IP: ")
    ADDR = (SERVER_IP, PORT)
    server.bind(ADDR)

def log(s: str):
    print("server: " + s)

def send(conn: socket.socket, msg_json):
    conn.send(json.dumps(msg_json).encode(defns.FORMAT))

def run_cmd(conn: socket.socket, addr, msg):
    cmd = msg['cmd']
    if cmd == 'p':  # just a basic ping
        conn.send(json.dumps(msg).encode(defns.FORMAT))  # ack msg
    elif cmd == 'r':
        log("Registering new user")
        newU = defns.User(addr[0], addr[1])
        ret = cmds.register_user(msg, newU)
        if ret == "SUCCESS":
            log(f"New user {newU.handle} made")
            send(conn, defns.ack_json("SUCCESS"))  # send ok ack
        else:
            log(f"New user {newU.handle} NOT made. Reason: {ret}")
            send(conn, defns.ack_json("FAIL"))  # send fail ack
    elif cmd == 'q':
        log("Querying handles")
        cmds.query(conn)
    elif cmd == 'f':
        cmds.follow(conn, msg)
    elif cmd == 'd':
        cmds.drop(conn, msg)
    elif cmd == 't':
        pass
    elif cmd == 'e':
        pass
    elif cmd == 'x':
        pass
    else:
        send(conn, defns.ack_json(f"unknown cmd: {cmd}"))  # send cmd not known ack

def handle_client(conn: socket.socket, addr):
    log(f"New client on IP: {addr[0]} Port: {addr[1]}\tActive users: {threading.activeCount() - 1}")
    connected = True
    try:
        while connected:
            # recv length can be bigger than msg, just try to make it as small as possible
            msg_json = conn.recv(defns.MAXBUFF).decode(defns.FORMAT)  # Blocking get msg
            if msg_json:  # when first connecting an empty packet is sent, we won't handle it
                msg = json.loads(msg_json)
                if 'EXIT' in msg:
                    connected = False
                else:
                    # process message
                    log(f"[{addr}] {msg}")
                    run_cmd(conn, addr, msg)
    except KeyboardInterrupt:
        log("Caught keyboard interrupt...Stopping")
        conn.send(json.dumps({'EXIT': defns.DISCONNECT_MSG}).encode(defns.FORMAT))
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
