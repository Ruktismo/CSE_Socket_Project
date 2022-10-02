"""
client.py Made By: Andrew Erickson
"""
import json
import socket
import sys
import random as r
import defns

SERVER = ""  # default DO NOT USE
PORT = 38501
if len(sys.argv) == 3:
    SERVER = sys.argv[1]
    # verify that port is valid
    p = int(sys.argv[2])
    if p and defns.PORT_RANGE[0] <= p <= defns.PORT_RANGE[1]:
        PORT = p
    else:
        print("PORT OUT OF RANGE. USING DEFAULT PORT OF 38501")
ADDR = (SERVER, PORT)
# CLIENT_IP = socket.gethostbyname(socket.gethostname())
CLIENT_IP = "0.0.0.0"
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # makes server with IPv4 and set to a stream of data

# generate a random port between 38500 and 38999
# if it raises an OSError roll again
CLIENT_ADDR = None
while CLIENT_ADDR is None:
    temp = r.randint(38500, 38999)
    try:
        client.bind((CLIENT_IP, temp))  # this excepts OSError if port is in use
        # if it's not in use then we reach here
        CLIENT_ADDR = (CLIENT_IP, temp)
    except OSError:
        continue
client.connect(ADDR)

Local_Users = {}  # holds any local info about users

def log(s):
    print(f"Client: {s}")

def send2(msg):
    message = msg.encode(defns.FORMAT)
    msg_len = len(message)
    send_len = str(msg_len).encode(defns.FORMAT)
    send_len += b' ' * (defns.HEADER - len(send_len))
    client.send(send_len)
    client.send(message)
    ack = client.recv(2048).decode(defns.FORMAT)
    if ack == defns.DISCONNECT_MSG:
        log("Server disconnected. Stopping")
        raise defns.Disconnected
    else:
        return ack

def send_exit():
    # sends an exit msg and expects nothing back
    s = json.dumps({'EXIT': defns.DISCONNECT_MSG})
    client.send(s.encode(defns.FORMAT))
    client.close()

def send(msg):
    s = json.dumps(msg)
    client.send(s.encode(defns.FORMAT))
    ack_json = client.recv(defns.MAXBUFF).decode(defns.FORMAT)
    print(ack_json)
    ack = json.loads(ack_json)
    if 'EXIT' in ack:
        log("Server disconnected. Stopping")
        raise defns.Disconnected
    else:
        return ack

def register(s):
    args = s.split(' ')
    if len(args) != 5:
        log("Wrong number of args")
        return
    newU = defns.User(CLIENT_ADDR[0], CLIENT_ADDR[1])
    # check is handle is used locally
    ret = newU.register(args[1][1:], args[3], args[4])
    if ret == "Handle In Use":
        log("Handle In Use")
        return
    elif ret == "Port in use":
        return
    # send request to server
    # build and send register json cmd
    ack = send(newU.reg_json())
    if ack['ack'] == "SUCCESS":
        log(f"SUCCESS: {newU.handle} registered")
    else:
        log("Handle In Use")


def start():
    log(f"Connected to server using IP: {CLIENT_ADDR[0]}, Port: {CLIENT_ADDR[1]}")
    try:
        connected = True
        while connected:
            cmd = input()
            if cmd.startswith("register"):
                register(cmd)
            elif cmd == "query handles":
                pass
            elif cmd.startswith("follow"):
                pass
            elif cmd.startswith("drop"):
                pass
            elif cmd.startswith("exit"):
                connected = False
            else:
                log("Command not recognised")

        for i in range(0, 3):
            s = input("msg: ")
            js = {'cmd': 'p', 'msg': s}
            send(js)
        send_exit()  # exit from server
    except KeyboardInterrupt:
        log("\nCaught keyboard interrupt...Stopping")
        send_exit()  # exit from server
    except defns.Disconnected:
        pass  # server stopped do nothing and end


start()
