import json
import socket
import defns

def register_user(msg, newU):
    # extract data
    handle = msg['handle']
    ip = msg['ip']  # this is already gotten from the connection, but will be used in error checks
    port_in = int(msg['port_in'])
    port_out = int(msg['port_out'])
    # run error checks
    # attempt to register
    ret = newU.register(handle, port_in, port_out, False)
    return ret

def query(conn: socket.socket):
    handles = list(defns.UserList)
    ack = {'ack': 1, 'userC': len(handles), 'users': handles}
    conn.send(json.dumps(ack).encode(defns.FORMAT))
    return

def follow(conn: socket.socket, msg):
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
    soc, port = defns.get_sock(socket.gethostbyname_ex(socket.getfqdn())[2][0], u2)
    follow_cmd = {'cmd': 'f', 'handle': msg['h1']}
    soc.send(json.dumps(follow_cmd).encode(defns.FORMAT))
    ack = json.loads(soc.recv(defns.MAXBUFF).decode(defns.FORMAT))
    if 'ack' in ack and ack['ack'] == 'follow complete':
        conn.send(json.dumps(ack).encode(defns.FORMAT))  # follow complete
    else:
        conn.send(json.dumps({'ack': 'follow failed'}).encode(defns.FORMAT))  # follow failed
    soc.close()
    print(f"H2: {defns.UserList[msg['h2']].followers}\nH1: {defns.UserList[msg['h1']].following}")
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
    soc, port = defns.get_sock(socket.gethostbyname_ex(socket.getfqdn())[2][0], u2)
    follow_cmd = {'cmd': 'd', 'handle': msg['h1']}
    soc.send(json.dumps(follow_cmd).encode(defns.FORMAT))
    ack = json.loads(soc.recv(defns.MAXBUFF).decode(defns.FORMAT))
    if 'ack' in ack and ack['ack'] == 'drop complete':
        conn.send(json.dumps(ack).encode(defns.FORMAT))  # follow complete
    else:
        conn.send(json.dumps({'ack': 'drop failed'}).encode(defns.FORMAT))  # follow failed
    soc.close()
    print(f"H2: {defns.UserList[msg['h2']].followers}\nH1: {defns.UserList[msg['h2']].following}")
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
        soc, port = defns.get_sock(socket.gethostbyname_ex(socket.getfqdn())[2][0], u2)
        follow_cmd = {'cmd': 'd', 'handle': exiter.handle}
        # send cmd and wait for ack
        soc.send(json.dumps(follow_cmd).encode(defns.FORMAT))
        ack = json.loads(soc.recv(defns.MAXBUFF).decode(defns.FORMAT))
        # ack is not needed. if error is returned we do nothing
        soc.close()
    # all users dropped remove user obj
    defns.UserList.pop(msg['handle'])
    conn.send(json.dumps({'ack': 'User removed'}).encode(defns.FORMAT))
    return
