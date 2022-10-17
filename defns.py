import json
import socket
import threading
import random as r

# shared vars for server and client
FORMAT = "utf-8"
DISCONNECT_MSG = "EXIT"
PORT_RANGE = (38500, 38999)
MAXBUFF = 2048  # largest msg that can be sent
UserList = {}  # hold all user obj

def log(s: str, is_client):
    if is_client:
        print(f"[Client]: {s}")
    else:
        print(f"[Server]: {s}")


def client_in(ip, port, user):
    log(f'User @{user.handle} opening port {port}', True)
    user_in = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    user_in.bind((ip, port))
    user_in.listen()  # open socket to listen
    log(f'User @{user.handle} now listening on port {port}', True)
    while user.alive:
        conn, addr = user_in.accept()  # when a connection is made
        msg_json = conn.recv(MAXBUFF).decode(FORMAT)  # it should just be one message long
        msg = json.loads(msg_json)
        log(f"Received for user: @{user.handle}, {msg}", True)
        if 'f' in msg['cmd']:  # add follower
            # someone is following us. add there handle to the list
            # user.followers.append(msg['handle'])
            user.add_to_ring(msg['handle'], msg['ip'], msg['port_in'])
            ack = {'ack': 'follow complete'}
            conn.send(json.dumps(ack).encode(FORMAT))
        elif 'd' in msg['cmd']:  # drop follower
            # someone has unfollowed us. remove them
            user.followers.remove(msg['handle'])
            conn.send(json.dumps({'ack': 'drop complete'}).encode(FORMAT))
        elif 'u' in msg['cmd']:  # update ring
            for i in range(len(user.following)):
                # find follow in question
                if user.following[i][0] is msg['handle']:
                    # update ip/port for that link
                    user.following[i] = (msg['handle'], msg['ip'], msg['port'])
                    break  # stop searching
        elif 't' in msg['cmd']:  # tweet
            pass
        else:
            log(f"Unknown msg {msg}", True)
        conn.close()
    return

def ack_json(ack):
    return {'ack': ack}

class User:
    def __init__(self, ip, port_server):
        # followers/ing wil have tuple format (handle, forward_ip, forward_port)
        self.following = []  # hold handles that they are following (just their part of each ring they are a part of)
        self.followers = []  # hold handles that are following them (the whole logical ring)
        self.ip = ip  # IP addr of client
        self.port_server = port_server  # port client is using to talk to server
        self.port_in = None  # port used to listen for tweets
        self.port_out = None  # port used to send tweets
        self.handle = None
        self.in_thread = None  # reference to users listening thread
        self.alive = True  # shutdown signaler for thread

    def register(self, handle: str, port_in, port_out, is_client):
        self.handle = handle
        # check if handle is in use
        if handle not in UserList:
            UserList[handle] = self  # if not then register user
            self.port_in = port_in
            self.port_out = port_out
            # TODO verify that ports are unique on client

            # put ring owner as the first member of the ring who just loops back to self
            self.followers.append((self.handle, self.ip, self.port_in))

            if is_client:
                # spawn off new thread
                log(f"Spawning off new thread for: @{self.handle}", True)
                self.in_thread = threading.Thread(target=client_in, args=(self.ip, self.port_in, self), daemon=True)
                self.in_thread.start()
            return "SUCCESS"
        else:
            return "Handle In Use"

    """
        updates the users logical ring by adding in the new follower.
        returns the two tuples that have changed.
            u1, u2 = user inserted, user updated
        note that the ring owner is always the first node in their ring
    """
    def add_to_ring(self, handle, ip, port):
        # find the point of insertion
        i = 0
        # starting at index 1 to skip ring owner
        for a in range(1, len(self.followers)):
            if self.followers[a][0].lower() > handle.lower():
                i = a
                break
        if i == 0:  # if none match then they go at the end
            i = len(self.followers)

        # get all update info
        # get the old pointer in the link
        old_point = (self.followers[i-1][1], self.followers[i-1][2])

        # add in the new user pointing to the old point
        u1 = (handle, old_point[0], old_point[1])
        self.followers = self.followers[:i] + [u1] + self.followers[i:]

        # update the handel that had old_point to point to the new user
        u2 = (self.followers[i-1][0], ip, port)
        self.followers[i-1] = u2
        return u1, u2  # return the two users that had information updated

    """
        updates the users logical ring by removing the follower.
        returns the tuple that has changed.
    """
    def drop_from_ring(self, handle):
        pass

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
            'ip': self.ip,
            'port_in': self.port_in,
            'h2': user
        }

    def drop_json(self, user):
        return {
            'cmd': 'd',
            'h1': self.handle,
            'h2': user
        }


def get_sock(ip, toADDR, is_client):
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bound = False
    port = r.randint(PORT_RANGE[0], PORT_RANGE[1])
    while not bound:
        try:
            soc.bind((ip, port))
            bound = True
        except OSError:
            port = r.randint(PORT_RANGE[0], PORT_RANGE[1])
    log(f'Attempting to make a connection between {ip, port} and {toADDR}', is_client)
    soc.connect(toADDR)
    log(f"Connection made between {ip, port} and {toADDR}", is_client)
    return soc, port

# exception class to handle sudden disconnects
class Disconnected(Exception):
    pass  # it does not need to do anything
