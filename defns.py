import json
import socket
import threading
import random as r
import time

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

def timer(user, conn: socket.socket):
    log(f"Starting timer for {len(user.followers)*2}sec", True)
    time.sleep(len(user.followers)*2)  # sleep for follow_count * 2 sec
    # if user is still locked to tweeting
    if user.is_tweeting:
        log(f"Timeout: @{user.handle}'s Tweet did not return", True)
        # send error status to server and end tweet
        conn.send(json.dumps(user.end_tweet_error_json(user.handle)).encode(FORMAT))
        user.is_tweeting = False


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
            if user.is_tweeting:
                conn.send(json.dumps({'ack': 'Tweet in progress'}).encode(FORMAT))
                continue
            # someone is following us. add there handle to the list
            user.add_to_ring(msg['handle'], msg['ip'], msg['port_in'])
            log(f"@{msg['handle']} is now following @{user.handle}", True)
            ack = {'ack': 'follow complete'}
            conn.send(json.dumps(ack).encode(FORMAT))
        elif 'd' in msg['cmd']:  # drop follower
            if user.is_tweeting:
                conn.send(json.dumps({'ack': 'Tweet in progress'}).encode(FORMAT))
                continue
            # someone has unfollowed us. remove them
            user.drop_from_ring(msg['handle'])
            log(f"@{msg['handle']} Dropped @{user.handle}", True)
            conn.send(json.dumps({'ack': 'drop complete'}).encode(FORMAT))
        elif 'u' in msg['cmd']:  # update ring
            user.update_ring((msg['handle'], msg['ip'], msg['port']))
        elif 't' in msg['cmd']:  # tweet
            # check if the tweet is yours
            if user.handle in msg['sh']:
                # send end tweet to the server
                user.server_conn.send(json.dumps(user.end_tweet_json()).encode(FORMAT))
                # log that tweet has completed
                log(f"@{user.handle}: Tweet has gone the through whole ring.", True)
                # unlock the user
                user.is_tweeting = False
                continue
            # if not check, if the tweet is from one of the people the user is following
            has_proped = False
            for f in user.following:
                if f[0] in msg['sh']:
                    # display tweet for user
                    log(f"For @{user.handle} from @{msg['fh']}: @{msg['sh']} tweeted\n\t\"{msg['tweet']}\"\n", True)
                    # prop tweet to next user in the ring
                    msg['fh'] = user.handle  # set the from handle to be us
                    soc = get_sock(user.ip, f[1:], True)  # get connection to next user in the ring
                    if soc is None:
                        # Send end-tweet-error to the server
                        user.server_conn.send(json.dumps(user.end_tweet_error_json(msg['sh'])).encode(FORMAT))
                        has_proped = True  # prevent other error form triggering as well
                        break  # don't attempt to send
                    soc[0].send(json.dumps(msg).encode(FORMAT))
                    soc[0].close()  # we expect no reply so close the connection after sending
                    has_proped = True
                    break  # stop searching
            # if we reach here then user is not following tweeter. Send error to server
            if not has_proped:
                user.server_conn.send(json.dumps(user.end_tweet_error_json(msg['sh'])).encode(FORMAT))
        elif 'ee' in msg['cmd']:
            # something went wrong with the tweet and a user in the ring has killed the propagation
            log(f'Error sending tweet. @{msg["bh"]} was unable to propagate', True)
            user.is_tweeting = False
        else:
            log(f"Unknown msg {msg}", True)
        conn.close()
    return

def ack_json(ack):
    return {'ack': ack}

class User:
    def __init__(self, ip, port_server, is_client, server_conn: socket.socket = None):
        # followers/ing wil have tuple format (handle, forward_ip, forward_port)
        self.following = []  # hold handles that they are following (just their part of each ring they are a part of)
        self.followers = []  # hold handles that are following them (the whole logical ring)
        self.ip = ip  # IP addr of client
        self.port_server = port_server  # port client is using to talk to server
        self.port_in = None  # port used to listen for tweets
        self.port_out = None  # port used to send tweets
        self.handle = None
        self.is_tweeting = False  # locks the user to a tweeting state. All follows and drops are ignored
        self.is_client = is_client  # to track weather this obj was made by server or client
        # client only vars, will be None on server side
        self.in_thread = None  # reference to users listening thread
        self.alive = True  # shutdown signaler for thread
        self.server_conn = server_conn  # hold link to server

    def register(self, handle: str, port_in, port_out):
        self.handle = handle
        # check if handle is in use
        if handle not in UserList:
            UserList[handle] = self  # if not then register user
            self.port_in = port_in
            self.port_out = port_out
            # TODO verify that ports are unique on client

            # put ring owner as the first member of the ring who just loops back to self
            self.followers.append((self.handle, self.ip, self.port_in))

            if self.is_client:
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
        # find point of deletion
        i = 0
        # starting at index 1 to skip ring owner
        for a in range(1, len(self.followers)):
            if self.followers[a][0].lower() == handle.lower():
                i = a
                break
        # safe to assume that there will be a match since sending client and server both check if following
        # get update info
        uNew = (self.followers[i-1][0], self.followers[i][1], self.followers[i][2])
        self.followers[i-1] = uNew  # apply update
        # slice out node i
        self.followers = self.followers[:i] + self.followers[i+1:]
        return uNew

    def update_ring(self, u1):
        for i in range(len(self.following)):
            # find follow in question
            if self.following[i][0] == u1[0]:
                # update ip/port for that link
                log(f"@{self.handle} updated info for @{self.following[i][0]}", self.is_client)
                self.following[i] = u1
                break  # stop searching

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

    def tweet_json(self, tweet, fh):
        return {
            'cmd': 't',
            'sh': self.handle,  # handle of tweeter
            'tweet': tweet,  # the contents of the tweet
            'fh': fh  # the handle of the user that passed the tweet to you
        }

    def end_tweet_json(self):
        return {
            'cmd': 'e',
            'h': self.handle
        }

    def end_tweet_error_json(self, sh):
        return {
            'cmd': 'ee',
            'sh': sh,
            'bh': self.handle
        }


def get_sock(ip, toADDR, is_client):
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bound = False
    port = r.randint(PORT_RANGE[0], PORT_RANGE[1])  # bind to a valid port in our range
    while not bound:
        try:
            soc.bind((ip, port))
            bound = True
        except OSError:
            port = r.randint(PORT_RANGE[0], PORT_RANGE[1])
    log(f'Attempting to make a connection between {ip, port} and {toADDR}', is_client)
    try:
        soc.connect(toADDR)
    except ConnectionRefusedError:
        log(f"Connection between {ip, port} and {toADDR} failed. Host unreachable", is_client)
        return None
    except TimeoutError:
        log(f"Connection timeout between {ip, port} and {toADDR}. Connection failed", is_client)
        return None
    log(f"Connection made between {ip, port} and {toADDR}", is_client)
    return soc, port

# exception class to handle sudden disconnects
class Disconnected(Exception):
    pass  # it does not need to do anything
