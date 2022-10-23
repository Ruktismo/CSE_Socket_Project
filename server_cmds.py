import json
import socket
import defns
from defns import log

def register_user(msg, conn: socket.socket, addr):
    log("Registering new user", False)
    newU = defns.User(addr[0], addr[1], False)
    # extract data
    handle = msg['handle']
    ip = msg['ip']  # this is already gotten from the connection, but will be used in error checks
    port_in = int(msg['port_in'])
    port_out = int(msg['port_out'])
    # run error checks
    # attempt to register
    ret = newU.register(handle, port_in, port_out)
    if ret == "SUCCESS":
        log(f"New user {newU.handle} made", False)
        conn.send(json.dumps(defns.ack_json("SUCCESS")).encode(defns.FORMAT))  # send ok ack
    else:
        log(f"New user {newU.handle} NOT made. Reason: {ret}", False)
        conn.send(json.dumps(defns.ack_json("FAIL")).encode(defns.FORMAT))  # send fail ack
    return

def query(conn: socket.socket, addr):
    log(f"Received query from {addr}", False)
    handles = list(defns.UserList)
    ack = {'ack': 1, 'userC': len(handles), 'users': handles}
    conn.send(json.dumps(ack).encode(defns.FORMAT))
    return

def follow(conn: socket.socket, msg):
    log(f"@{msg['h1']} wants to follow @{msg['h2']}", False)
    # check if handles are in use
    if (msg['h1'] not in defns.UserList) or (msg['h2'] not in defns.UserList):
        conn.send(json.dumps({'ack': 'follow failed, user not found'}).encode(defns.FORMAT))  # send error ack
        return
    # check if user is tweeting
    if defns.UserList[msg['h2']].is_tweeting:
        # send error ack
        conn.send(json.dumps({'ack': 'follow failed, user is tweeting. Try again later'}).encode(defns.FORMAT))
        return
    # pass follower info to handle2
    log(f"Pass follower request to @{msg['h2']}", True)
    f2 = (defns.UserList[msg['h2']].ip, defns.UserList[msg['h2']].port_in)
    soc, port = defns.get_sock(socket.gethostbyname_ex(socket.getfqdn())[2][0], f2, False)

    follow_cmd = {'cmd': 'f', 'handle': msg['h1'], 'ip': msg['ip'], 'port_in': msg['port_in']}
    soc.send(json.dumps(follow_cmd).encode(defns.FORMAT))

    ack = json.loads(soc.recv(defns.MAXBUFF).decode(defns.FORMAT))
    soc.close()
    if 'ack' in ack and ack['ack'] == 'follow complete':
        # update ring on server end
        u1, u2 = defns.UserList[msg['h2']].add_to_ring(msg['h1'], msg['ip'], msg['port_in'])

        # connect to u2 and push update
        log(f"Follower added for @{msg['h2']} pass update to @{u2[0]}", True)
        u2ADDR = (defns.UserList[u2[0]].ip, defns.UserList[u2[0]].port_in)
        u2SOC, u2PORT = defns.get_sock(socket.gethostbyname_ex(socket.getfqdn())[2][0], u2ADDR, False)
        update_cmd = {'cmd': 'u', 'handle': msg['h2'], 'ip': u2[1], 'port': u2[2]}
        u2SOC.send(json.dumps(update_cmd).encode(defns.FORMAT))
        u2SOC.close()  # no reply is expected

        # send back to caller their ip port for the follow
        u1ack = {'ack': 'follow complete', 'ip': u1[1], 'port': u1[2]}
        conn.send(json.dumps(u1ack).encode(defns.FORMAT))  # follow complete
    elif ack['ack'] == 'Tweet in progress':
        conn.send(json.dumps(ack).encode(defns.FORMAT))  # follow failed
        return
    else:
        conn.send(json.dumps({'ack': 'follow failed'}).encode(defns.FORMAT))  # follow failed
        return
    log(f"@{msg['h1']} is now following @{msg['h2']}", False)
    return

def drop(conn: socket.socket, msg):
    log(f"@{msg['h1']} wants to drop @{msg['h2']}", False)
    # check if handles are in use
    if (msg['h1'] not in defns.UserList) or (msg['h2'] not in defns.UserList):
        conn.send(json.dumps({'ack': 'drop failed, user not found'}).encode(defns.FORMAT))  # send error ack
        return
    # check if user is tweeting
    if defns.UserList[msg['h2']].is_tweeting:
        # send error ack
        conn.send(json.dumps({'ack': 'drop failed, user is tweeting. Try again later'}).encode(defns.FORMAT))
        return
    # pass drop info to handle2
    log(f"Pass follower request to @{msg['h2']}", True)
    f2 = (defns.UserList[msg['h2']].ip, defns.UserList[msg['h2']].port_in)
    soc, port = defns.get_sock(socket.gethostbyname_ex(socket.getfqdn())[2][0], f2, False)

    drop_cmd = {'cmd': 'd', 'handle': msg['h1']}
    soc.send(json.dumps(drop_cmd).encode(defns.FORMAT))

    ack = json.loads(soc.recv(defns.MAXBUFF).decode(defns.FORMAT))
    soc.close()
    if 'ack' in ack and ack['ack'] == 'drop complete':
        # update ring on server end
        u2 = defns.UserList[msg['h2']].drop_from_ring(msg['h1'])

        # connect to u2 and push update
        log(f"Follower removed for @{msg['h2']} pass update to @{u2[0]}", True)
        u2ADDR = (defns.UserList[u2[0]].ip, defns.UserList[u2[0]].port_in)
        u2SOC, u2PORT = defns.get_sock(socket.gethostbyname_ex(socket.getfqdn())[2][0], u2ADDR, False)
        update_cmd = {'cmd': 'u', 'handle': msg['h2'], 'ip': u2[1], 'port': u2[2]}
        u2SOC.send(json.dumps(update_cmd).encode(defns.FORMAT))
        u2SOC.close()  # no reply is expected

        # send back to caller their ip port for the follow
        u1ack = {'ack': 'drop complete'}
        conn.send(json.dumps(u1ack).encode(defns.FORMAT))  # follow complete
    elif ack['ack'] == 'Tweet in progress':
        conn.send(json.dumps(ack).encode(defns.FORMAT))  # follow failed
        return
    else:
        conn.send(json.dumps({'ack': 'drop failed'}).encode(defns.FORMAT))  # follow failed
        return
    log(f"@{msg['h1']} is no longer following @{msg['h2']}", False)
    return

def tweet(conn: socket.socket, msg):
    # log tweet
    log(f"@{msg['sh']} has tweeted: \n\t\"{msg['tweet']}\"\n", False)
    # lock the user
    defns.UserList[msg['sh']].is_tweeting = True
    ack = defns.ack_json("SUCCESS")
    conn.send(json.dumps(ack).encode(defns.FORMAT))  # tell user that they are good to tweet
    return

def end_tweet(conn: socket.socket, msg):
    log(f"@{msg['h']} has completed tweeting", False)
    defns.UserList[msg['h']].is_tweeting = False  # unlock user
    return

def end_tweet_error(conn: socket.socket, msg):
    log(f"@{msg['bh']} has sent an error for a tweet form @{msg['sh']}. End tweeting for @{msg['sh']}", False)
    shADDR = (defns.UserList[msg['sh']].ip, defns.UserList[msg['sh']].port_in)
    soc, port = defns.get_sock(socket.gethostbyname_ex(socket.getfqdn())[2][0], shADDR, False)
    soc.send(json.dumps(msg).encode(defns.FORMAT))  # send error tweet cmd to original tweeter
    soc.close()  # no reply expected, close connection
    defns.UserList[msg['sh']].is_tweeting = False  # unlock user
    return

def exit_user(conn: socket.socket, msg):
    # check that user exist
    if msg['handle'] not in defns.UserList:
        conn.send(json.dumps({'ack': 'User not found'}).encode(defns.FORMAT))  # send error ack
        return
    # send a drop to all users in handles follow list
    exiter = defns.UserList[msg['handle']]
    for user in exiter.following:
        # make socket
        u2 = (defns.UserList[user[0]].ip, defns.UserList[user[0]].port_in)
        soc, port = defns.get_sock(socket.gethostbyname_ex(socket.getfqdn())[2][0], u2, False)
        drop_cmd = {'cmd': 'd', 'handle': exiter.handle}
        # send cmd and wait for ack
        soc.send(json.dumps(drop_cmd).encode(defns.FORMAT))
        json.loads(soc.recv(defns.MAXBUFF).decode(defns.FORMAT))
        # ack is not needed. if error is returned we do nothing
        soc.close()
    # all users dropped remove user obj
    defns.UserList.pop(msg['handle'])
    log(f"@{msg['handle']} has exited", False)
    conn.send(json.dumps({'ack': 'User removed'}).encode(defns.FORMAT))
    return
