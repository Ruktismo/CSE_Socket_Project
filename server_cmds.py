import json
import socket
import defns

def register_user(msg, newU):
    # extract data
    handle = msg['handle']
    ip = msg['ip']  # this is already gotten from the connection, but will be used in error checks
    port_in = msg['port_in']
    port_out = msg['port_out']
    # run error checks
    # attempt to register
    ret = newU.register(handle, port_in, port_out)
    return ret
