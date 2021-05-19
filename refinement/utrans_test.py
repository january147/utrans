#!/usr/bin/python3
'''
Author: January
Date: 2021-05-18 00:00:53
'''

from utrans.network import *
from utrans.core import *
import logging
import sys
import _thread
import time

logging.basicConfig(level = logging.DEBUG)


class MyFileTransHandle(UtransFileTransHandle):

    def on_progress(self, progress):
        print("working: %.2f/100"%(progress), end="\r")
        time.sleep(0.1)

class Test2:
    def get_src_addr(self):
        return UtransAddr("B", ("127.0.0.1", 9999))

    def get_password(self):
        return input("please input password:").encode("utf8")
    
    def get_session_listener(self):
        return UtransSessionListener()
    
    def run(self):
        if sys.argv[1] == "A":
            session = UtransSession("A")
            session.connect_by_password(b'hello_password', ("127.0.0.1", 9999))
            while True:
                session.send_text(input("input to send: "))

        else:
            server = UtransServer(self)
            server.run()

class Test1:
    def server(self):
        lk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        lk.bind(("127.0.0.1", 9999))
        lk.listen()
        while True:
            sk, addr = lk.accept()
            session = UtransSession("B")
            session.accept_by_password(sk, b'hello_password')
            session.send_file("t1.tar.gz", MyFileTransHandle())
            session.send_text("message comes to you")
    
    def run(self):
        if sys.argv[1] == "A":
            session = UtransSession("A")
            session.connect_by_password(b'hello_password', ("127.0.0.1", 9999))
            input()
        else:
            self.server()
        

if __name__ == "__main__":
    Test2().run()
