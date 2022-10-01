
# shared vars for server and client
HEADER = 64  # define msg length can change later to be max buff may use 256 need to check max size that can be sent
FORMAT = "utf-8"
DISCONNECT_MSG = "EXIT"
PORT_RANGE = (38500, 38999)

# exception class to handle sudden disconnects
class Disconnected(Exception):
    pass  # it does not need to do anything
