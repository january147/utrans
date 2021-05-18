#!/usr/bin/python3
'''
Author: January
Date: 2021-05-18 00:00:53
'''

from utrans.network import *
from utrans.core import *

session = None
def server():
    lk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lk.bind(session.src_addr.tcp_addr)
    lk.listen()
    
    while True:
        sk, addr = lk.accept()
        sts = STS(sk, STS.Peer_B)
        msg_bytes = sts.recv()
        msg = unpack_bytes(msg_bytes)
        if msg[0] == Message.MT_SESSION_INIT:
            session.accept_by_password(msg_bytes, sk, b"hello_password")
        else:
            session.accept_backwards(msg_bytes, msg)

def utrans():
    global session
    if sys.argv[1] == "A":
        session = UtransSession(UtransAddr("A", ("127.0.0.1", 9998)), UtransAddr("B",("127.0.0.1", 9999)))
        _thread.start_new_thread(server, ())
        session.connect_by_password(b'hello_password')
        input()
    else:
        session = UtransSession(UtransAddr("B", ("127.0.0.1", 9999)), UtransAddr("A",("127.0.0.1", 9998)))
        _thread.start_new_thread(server, ())
        input()


if __name__ == "__main__":
    import sys
    import _thread
    utrans()

