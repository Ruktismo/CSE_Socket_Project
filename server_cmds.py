import json
import socket
import defns
from defns import log

def register_user(msg, conn: socket.socket, addr):
    log("Registering new user", False)
    newU = defns.User(addr[0], addr[1])
    # extract data
    handle = msg['handle']
    ip = msg['ip']  # this is already gotten from the connection, but will be used in error checks
    port_in = int(msg['port_in'])
    port_out = int(msg['port_out'])
    # run error checks
    # attempt to register
    ret = newU.register(handle, port_in, port_out, False)
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

def follow_old(conn: socket.socket, msg):
    # check if handles are in use
    if (msg['h1'] not in defns.UserList) or (msg['h2'] not in defns.UserList):
        conn.send(json.dumps({'ack': 'follow failed, user not found'}).encode(defns.FORMAT))  # send error ack
        return

    # add handle2 to following handle1
    defns.UserList[msg['h1']].following.append(msg['h2'])
    # add handle1 as follower of handle2
    defns.UserList[msg['h2']].followers.append(msg['h1'])

    # pass follower info to handle2
    u2 = (defns.UserList[msg['h2']].ip, defns.UserList[msg['h2']].port_in)
    soc, port = defns.get_sock(socket.gethostbyname_ex(socket.getfqdn())[2][0], u2, False)

    follow_cmd = {'cmd': 'f', 'handle': msg['h1']}
    soc.send(json.dumps(follow_cmd).encode(defns.FORMAT))

    ack = json.loads(soc.recv(defns.MAXBUFF).decode(defns.FORMAT))
    if 'ack' in ack and ack['ack'] == 'follow complete':
        conn.send(json.dumps(ack).encode(defns.FORMAT))  # follow complete
    else:
        conn.send(json.dumps({'ack': 'follow failed'}).encode(defns.FORMAT))  # follow failed
    soc.close()
    # log(f"H2: {defns.UserList[msg['h2']].followers}\nH1: {defns.UserList[msg['h1']].following}", True)
    return

def follow(conn: socket.socket, msg):
    # check if handles are in use
    if (msg['h1'] not in defns.UserList) or (msg['h2'] not in defns.UserList):
        conn.send(json.dumps({'ack': 'follow failed, user not found'}).encode(defns.FORMAT))  # send error ack
        return

    # pass follower info to handle2
    f2 = (defns.UserList[msg['h2']].ip, defns.UserList[msg['h2']].port_in)
    soc, port = defns.get_sock(socket.gethostbyname_ex(socket.getfqdn())[2][0], f2, False)

    follow_cmd = {'cmd': 'f', 'handle': msg['h1'], 'ip': msg['ip'], 'port_in': msg['port_in']}
    soc.send(json.dumps(follow_cmd).encode(defns.FORMAT))

    ack = json.loads(soc.recv(defns.MAXBUFF).decode(defns.FORMAT))
    if 'ack' in ack and ack['ack'] == 'follow complete':
        # update ring on server end
        u1, u2 = defns.UserList[msg['h2']].add_to_ring(msg['h1'], msg['ip'], msg['port_in'])

        # connect to u2 and push update
        u2ADDR = (defns.UserList[u2[0]].ip, defns.UserList[u2[0]].port_in)
        u2SOC, u2PORT = defns.get_sock(socket.gethostbyname_ex(socket.getfqdn())[2][0], u2ADDR, False)
        update_cmd = {'cmd': 'u', 'handle': msg['h2'], 'ip': u2[1], 'port': u2[2]}
        u2SOC.send(json.dumps(update_cmd).encode(defns.FORMAT))
        u2SOC.close()  # no reply is expected

        # send back to caller their ip port for the follow
        u1ack = {'ack': 'follow complete', 'ip': u1[1], 'port': u1[2]}
        conn.send(json.dumps(u1ack).encode(defns.FORMAT))  # follow complete
    else:
        conn.send(json.dumps({'ack': 'follow failed'}).encode(defns.FORMAT))  # follow failed
    soc.close()
    return

def drop(conn: socket.socket, msg):
    # check if handles are in use
    if (msg['h1'] not in defns.UserList) or (msg['h2'] not in defns.UserList):
        conn.send(json.dumps({'ack': 'user not found'}).encode(defns.FORMAT))  # send error ack
        return
    try:
        # remove handle2 to following handle1
        defns.UserList[msg['h1']].following.remove(msg['h2'])
        # remove handle1 as follower of handle2
        defns.UserList[msg['h2']].followers.remove(msg['h1'])
    except ValueError:
        conn.send(json.dumps({'ack': 'not following'}).encode(defns.FORMAT))
        return
    # pass drop info to handle2
    u2 = (defns.UserList[msg['h2']].ip, defns.UserList[msg['h2']].port_in)
    soc, port = defns.get_sock(socket.gethostbyname_ex(socket.getfqdn())[2][0], u2, False)
    follow_cmd = {'cmd': 'd', 'handle': msg['h1']}
    soc.send(json.dumps(follow_cmd).encode(defns.FORMAT))
    ack = json.loads(soc.recv(defns.MAXBUFF).decode(defns.FORMAT))
    if 'ack' in ack and ack['ack'] == 'drop complete':
        conn.send(json.dumps(ack).encode(defns.FORMAT))  # follow complete
    else:
        conn.send(json.dumps({'ack': 'drop failed'}).encode(defns.FORMAT))  # follow failed
    soc.close()
    log(f"H2: {defns.UserList[msg['h2']].followers}\nH1: {defns.UserList[msg['h2']].following}", False)
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
        u2 = (defns.UserList[user].ip, defns.UserList[user].port_in)
        soc, port = defns.get_sock(socket.gethostbyname_ex(socket.getfqdn())[2][0], u2, False)
        follow_cmd = {'cmd': 'd', 'handle': exiter.handle}
        # send cmd and wait for ack
        soc.send(json.dumps(follow_cmd).encode(defns.FORMAT))
        json.loads(soc.recv(defns.MAXBUFF).decode(defns.FORMAT))
        # ack is not needed. if error is returned we do nothing
        soc.close()
    # all users dropped remove user obj
    defns.UserList.pop(msg['handle'])
    log(f"@{msg['handle']} has exited", False)
    conn.send(json.dumps({'ack': 'User removed'}).encode(defns.FORMAT))
    return
