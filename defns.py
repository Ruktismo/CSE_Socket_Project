import json
import socket
import threading
import random as r

import defns

# shared vars for server and client
HEADER = 64  # define msg length can change later to be max buff may use 256 need to check max size that can be sent
FORMAT = "utf-8"
DISCONNECT_MSG = "EXIT"
PORT_RANGE = (38500, 38999)
MAXBUFF = 2048
UserList = {}  # hold all user obj
# TODO follow, drop, exit(on client)

def client_in(ip, port, user):
    print(f'Client: User @{user.handle} opening port {port}')
    user_in = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    user_in.bind((ip, port))
    user_in.listen()  # open socket to listen
    print(f'Client: User @{user.handle} now listening on port {port}')
    while True:
        conn, addr = user_in.accept()  # when a connection is made
        msg_json = conn.recv(MAXBUFF).decode(FORMAT)  # it should just be one message long
        msg = json.loads(msg_json)
        print(f"Client: Received for user: @{user.handle}, {msg}")
        if 'f' in msg['cmd']:
            # someone is following us. add there handle to the list
            user.followers.append(msg['handle'])
            conn.send(json.dumps({'ack': 'follow complete'}).encode(FORMAT))
        elif 'd' in msg['cmd']:
            # someone has unfollowed us. remove them
            user.followers.remove(msg['handle'])
        elif 't' in msg['cmd']:
            pass
        else:
            print("Client: Unknown msg")
        conn.close()

def ack_json(ack):
    return {'ack': ack}

class User:
    def __init__(self, ip, port_server):
        self.following = []  # hold handles that they are following
        self.followers = []  # hold handles that are following them
        self.ip = ip  # IP addr of client
        self.port_server = port_server  # port client is using to talk to server
        self.port_in = None  # port used to listen for tweets
        self.port_out = None  # port used to send tweets
        self.handle = None
        self.in_thread = None

    def register(self, handle: str, port_in, port_out, is_client):
        self.handle = handle
        # check if handle is in use
        if handle not in UserList:
            UserList[handle] = self  # if not then register user
            self.port_in = port_in
            self.port_out = port_out
            # TODO verify that ports are unique on client and make sockets
            # TODO branch new thread for port in look at
            if is_client:
                # spawn off new thread
                print(f"spawning off new thread for: @{self.handle}")
                self.in_thread = threading.Thread(target=client_in, args=(self.ip, self.port_in, self))
                self.in_thread.start()
            return "SUCCESS"
        else:
            return "Handle In Use"

    # make a to_json for each type of msg that can be sent
    def reg_json(self):
        return {
            'cmd': 'r',
            'handle': self.handle,
            'ip': self.ip,
            'port_in': self.port_in,
            'port_out': self.port_out
        }

    def follow_json(self, user):
        return {
            'cmd': 'f',
            'h1': self.handle,
            'h2': user
        }

def get_sock(ip, toADDR):
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bound = False
    port = r.randint(PORT_RANGE[0], PORT_RANGE[1])
    while not bound:
        try:
            soc.bind((ip, port))
            bound = True
        except OSError:
            port = r.randint(PORT_RANGE[0], PORT_RANGE[1])
    print(f'server: Attempting to make a connection between {ip, port} and {toADDR}')
    soc.connect(toADDR)
    print(f"server: Connection made between {ip, port} and {toADDR}")
    return soc, port

# exception class to handle sudden disconnects
class Disconnected(Exception):
    pass  # it does not need to do anything
