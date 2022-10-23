"""
client.py Made By: Andrew Erickson
"""
import json
import socket
import sys
import random as r
import threading

import defns
from defns import log

SERVER = ""  # default DO NOT USE
PORT = 38501
if len(sys.argv) == 3:
    SERVER = sys.argv[1]
    # verify that port is valid
    p = int(sys.argv[2])
    if p and defns.PORT_RANGE[0] <= p <= defns.PORT_RANGE[1]:
        PORT = p
    else:
        log("PORT OUT OF RANGE. USING DEFAULT PORT OF 38501", True)
ADDR = (SERVER, PORT)
CLIENT_IP = socket.gethostbyname_ex(socket.getfqdn())[2][0]
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

def send_exit():
    # sends an exit msg and expects nothing back
    s = json.dumps({'EXIT': defns.DISCONNECT_MSG})
    client.send(s.encode(defns.FORMAT))
    client.close()

def send(msg):
    s = json.dumps(msg)
    client.send(s.encode(defns.FORMAT))
    ack_json = client.recv(defns.MAXBUFF).decode(defns.FORMAT)
    log(ack_json, True)
    ack = json.loads(ack_json)
    if 'EXIT' in ack:
        log("Server disconnected. Stopping", True)
        raise defns.Disconnected
    else:
        return ack

def register(s):
    args = s.split(' ')
    if len(args) != 5:
        log("Wrong number of args", True)
        return
    newU = defns.User(CLIENT_ADDR[0], CLIENT_ADDR[1], True, client)
    # check is handle is used locally
    ret = newU.register(args[1][1:], int(args[3]), int(args[4]))
    if ret == "Handle In Use":
        log("Handle In Use", True)
        return
    elif ret == "Port in use":
        log("Port in use", True)
        return
    # send request to server
    # build and send register json cmd
    ack = send(newU.reg_json())
    if ack['ack'] == "SUCCESS":
        log(f"SUCCESS: {newU.handle} registered", True)
    else:
        log("Handle In Use", True)

def query():
    ack = send({'cmd': 'q'})
    if 'ack' in ack:
        log(f"Number of users: {ack['userC']}", True)
        log("Users:", True)
        for u in ack['users']:
            log('\t' + u, True)
    else:
        log(f"Unknown ack: {ack}", True)

def follow(m):
    args = m.split(' ')
    if len(args) != 3:
        log("Wrong number of args", True)
        return
    handle = args[1][1:]
    # check that user exist
    if handle not in defns.UserList:
        log(f"{args[1]} is not a user", True)
        return
    # check that user1 is not already following user2
    if [U for U in defns.UserList[handle].following if args[2][1:] in U]:
        log(f"Already following {args[2]}", True)
        return
    u = defns.UserList[handle].follow_json(args[2][1:])
    # ack expects format ack: follow complete and  ip/port of next person in that follower ring
    ack = send(u)
    if 'ack' in ack:
        if ack['ack'] == "follow complete":
            newF = (args[2][1:], ack['ip'], ack['port'])
            defns.UserList[handle].following.append(newF)
            log(f'@{handle} is now following {args[2]}', True)
        else:
            log(f"Follow failed, {ack['ack']}", True)
    else:
        log(f'Follow failed, Unknown ack: {ack}', True)
    return

def drop(m):
    # check that user exist
    args = m.split(' ')
    if len(args) != 3:
        log("Wrong number of args", True)
        return
    handle = args[1][1:]
    if handle not in defns.UserList:
        log(f"{args[1]} is not a user", True)
        return
    if not [U for U in defns.UserList[handle].following if args[2][1:] in U]:
        log(f"Not following {args[2]}", True)
        return
    u = defns.UserList[handle].drop_json(args[2][1:])
    ack = send(u)
    if 'ack' in ack:
        if ack['ack'] == "drop complete":
            # loop over following list to find drop
            for a in range(1, len(defns.UserList[handle].following)):
                # splice out user from following list
                if defns.UserList[handle].following[a][0] == args[2][1:]:
                    defns.UserList[handle].following = defns.UserList[handle].following[:a] +\
                                                       defns.UserList[handle].following[a+1:]
                    break
            log(f'@{handle} is no longer following {args[2]}', True)
        else:
            log(f"drop failed, {ack['ack']}", True)
    else:
        log(f'drop failed, Unknown ack: {ack}', True)
    return

def send_tweet(m):
    # setting split to only separate the cmd and handle and leave the rest of the input string alone.
    # since the tweet may have spaces, and we don't want to split that
    args = m.split(' ', maxsplit=2)
    if len(args) != 3:
        log("Wrong number of args", True)
        return
    # verify that handle is real and that tweet is <= 140 chars
    handle = args[1][1:]
    if handle not in defns.UserList:
        log(f"{args[1]} is not a user", True)
        return
    tweet = args[2][1:-1]  # cut off "" from the arg
    if len(tweet) > 140:
        log(f"Tweet is too long. {len(tweet)} > 140", True)
        return
    # send the tweet to the server to log it and lock your ring until tweet is done
    t_json = defns.UserList[handle].tweet_json(tweet, handle)
    s_ack = send(t_json)
    if s_ack['ack'] == "SUCCESS":
        defns.UserList[handle].is_tweeting = True  # lock the user to a tweeting state
        # send the tweet to the first member of the ring to start the propagation to the followers
        follower = defns.UserList[handle].followers[0][1:]
        soc, port = defns.get_sock(CLIENT_IP, follower, True)
        soc.send(json.dumps(t_json).encode(defns.FORMAT))
        soc.close()  # we expect no reply so close the connection after sending
        log(f"Tweet for @{handle} sent.", True)
        # start a timer thread that will send ete to server after timeout
        threading.Thread(target=defns.timer, args=(defns.UserList[handle], client), daemon=True)
    else:
        log(f"Something went wrong with the server. {s_ack}", True)

def exit_user(u):
    args = u.split(' ')
    if len(args) != 2:
        log("Wrong number of args", True)
        return
    handle = args[1][1:]
    if handle not in defns.UserList:
        log(f"{args[1]} is not a user", True)
        return
    ack = send({'cmd': 'x', 'handle': handle})
    if 'ack' in ack:
        if ack['ack'] == "User removed":
            # attempt to kill thread, if it does not close before main it will silent fault
            defns.UserList[handle].alive = False  # signal in thread to die
            defns.UserList.pop(handle)  # remove user for list
            log(f'@{handle} is logged out', True)
        else:
            log(f"Exit failed, {ack['ack']}", True)
    else:
        log(f'Exit failed, Unknown ack: {ack}', True)
    if len(defns.UserList) == 0:
        log("All users logged out, closing program.", True)
        exit(0)
    return

def print_users():
    for h, u in defns.UserList.items():
        log(f'@{h}:\n\tfollowing: {u.following}\n\tfollowers: {u.followers}', True)

def start():
    log(f"Connected to server using IP: {CLIENT_ADDR[0]}, Port: {CLIENT_ADDR[1]}", True)
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
                drop(cmd)
            elif cmd.startswith("tweet"):
                send_tweet(cmd)
            elif cmd.startswith("exit"):
                exit_user(cmd)
            elif cmd == "status":
                print_users()
            elif cmd == "kill":
                exit(-1)  # debug: exit program ungracefully
            else:
                log("Command not recognised", True)
        send_exit()  # exit from server
    except KeyboardInterrupt:
        log("Caught keyboard interrupt...Stopping", True)
        try:
            for h in list(defns.UserList):
                log(f"logging out user: @{defns.UserList[h].handle}", True)
                exit_user(f'exit @{defns.UserList[h].handle}')  # attempt to drop all users from the server
            send_exit()  # exit from server
        except Exception:
            log("Unable to gracefully exit form server, it may have died", True)
    except defns.Disconnected:
        pass  # server stopped do nothing and end


start()
