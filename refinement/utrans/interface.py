#!/usr/bin/python3
'''
Author: January
Date: 2021-05-18 21:34:49
'''
import logging

logger = logging.getLogger("interface")

class UtransFileTransHandle:
    
    def __init__(self):
        self.stoped = False

    def stop(self):
        self.stoped = True
    
    def on_start(self):
        print("File trans start")

    def on_error(self, error):
        print("File trans Error")
    
    def on_finished(self):
        print("File trans Finished")

    def on_progress(self, progress):
        print("progress %.2f"%(progress), end="\r")

class UtransSessionListener():
    
    def on_connected(self, session):
        print("connect to [%s]"%(session.des_name))

    def on_disconnected(self, session):
        print("disconnect from [%s]"%(session.des_name))
    
    def on_recv_text(self, text):
        print("recv text [%s]"%(text))
    
    def on_recv_file(self, filename, filesize):
        print("recv file [%s], size [%d]"%(filename, filesize))
        return UtransFileTransHandle()

class UtransContext():
    def get_src_addr(self):
        return ("127.0.0.1", 9999)

    def get_password(self):
        return b'hothotdogdog'
    
    def get_session_listener(self) -> UtransSessionListener:
        return UtransSessionListener()
    