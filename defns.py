
# shared vars for server and client
HEADER = 64  # define msg length can change later to be max buff may use 256 need to check max size that can be sent
FORMAT = "utf-8"
DISCONNECT_MSG = "EXIT"
PORT_RANGE = (38500, 38999)
MAXBUFF = 2048
UserList = {}  # hold all user obj
# TODO register, query, follow, drop, exit(on client)

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

    def register(self, handle: str, port_in, port_out):
        self.handle = handle
        # check if handle is in use
        if handle not in UserList:
            UserList[handle] = self  # if not then register user
            self.port_in = port_in
            self.port_out = port_out
            # TODO verify that ports are unique on client and make sockets
            # TODO branch new thread for port in look at
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

# exception class to handle sudden disconnects
class Disconnected(Exception):
    pass  # it does not need to do anything
