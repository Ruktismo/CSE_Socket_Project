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

def send_exit():
    # sends an exit msg and expects nothing back
    s = json.dumps({'EXIT': defns.DISCONNECT_MSG})
    client.send(s.encode(defns.FORMAT))
    client.close()

def send(msg):
    s = json.dumps(msg)
    client.send(s.encode(defns.FORMAT))
    ack_json = client.recv(defns.MAXBUFF).decode(defns.FORMAT)
    # log(ack_json)
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
    ret = newU.register(args[1][1:], int(args[3]), int(args[4]), True)
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

def query():
    ack = send({'cmd': 'q'})
    if 'ack' in ack:
        log(f"Number of users: {ack['userC']}")
        log("Users:")
        for u in ack['users']:
            log('\t' + u)
    else:
        log(f"Unknown ack: {ack}")

def follow(m):
    # check that user exist
    args = m.split(' ')
    if len(args) != 3:
        log("Wrong number of args")
        return
    handle = args[1][1:]
    if handle not in defns.UserList:
        log(f"{args[1]} is not a user")
        return
    u = defns.UserList[handle].follow_json(args[2][1:])
    ack = send(u)
    if 'ack' in ack:
        if ack['ack'] == "follow complete":
            defns.UserList[handle].following.append(args[2][1:])
            log(f'@{handle} is now following {args[2]}')
        else:
            log(f"Follow failed, {ack}")
    else:
        log(f'Follow failed, Unknown ack: {ack}')
    return

def start():
    log(f"Connected to server using IP: {CLIENT_ADDR[0]}, Port: {CLIENT_ADDR[1]}")
    try:
        connected = True
        while connected:
            cmd = input()
            if cmd.startswith("register"):
                register(cmd)
            elif cmd == "query handles":
                query()
            elif cmd.startswith("follow"):
                follow(cmd)
            elif cmd.startswith("drop"):
                pass
            elif cmd.startswith("exit"):
                connected = False
            else:
                log("Command not recognised")
        send_exit()  # exit from server
    except KeyboardInterrupt:
        log("Caught keyboard interrupt...Stopping")
        send_exit()  # exit from server
    except defns.Disconnected:
        pass  # server stopped do nothing and end


start()
