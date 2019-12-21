#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Date: Sat Oct 19 20:45:17 2019
# Author: January

import os
import socket
import sys
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("utrans")

usage='''
trans_file receive [-p <port>] [-o <filename>]
trans_file send -f <file> -d <ip> [-p <port>]
'''

class CommandManager:
    S_NULL = 'null'
    S_RECEIVING = 'receiving'
    S_OK = 'ok'
    S_ABORT = "abort"
    F_START = ord('^')
    F_END = ord('$')
    MSG_MAX = 100

    def __init__(self):
        self.init()

    def init(self):
        self.values = dict()
        self.status = CommandManager.S_NULL
        self.raw_cmd = b""
        self.split_raw_cmd = None

    # You can call receiveCmd several times to receive a complete cmd.
    def parse_cmd_from_bytes(self, cmd_data:bytes):
        if len(cmd_data) == 0:
            self.status = CommandManager.S_ABORT
            return True
        if self.status == CommandManager.S_OK:
            raise RuntimeError('No more data needed')
        if self.status == CommandManager.S_NULL and cmd_data[0] != CommandManager.F_START:
            import pdb; pdb.set_trace()
            logger.debug(cmd_data)
            raise RuntimeError("invalid cmd")
        if self.status == CommandManager.S_ABORT:
            raise RuntimeError("cmd aborted")
        self.raw_cmd += cmd_data
        if self.raw_cmd[-1] == CommandManager.F_END:
            self.status = CommandManager.S_OK
            self.do_parse_cmd()
            return True
        else:
            self.status = CommandManager.S_RECEIVING
            return False
    
    def parse_cmd_from_ssk(self, ssk):
        while True:
            data = ssk.recv(4096)
            if self.parse_cmd_from_bytes(data) is True:
                return self.status

    def get(self):
        cmd_dict = self.values
        self.init()
        return cmd_dict

    # when receiveCmd return true, call this methodc      
    def do_parse_cmd(self):
        self.split_raw_cmd = self.raw_cmd.decode(encoding="utf8").strip("^$").split("/")
        for key_value in self.split_raw_cmd:
            key, value = key_value.split(":")
            self.values[key] = value

    @staticmethod
    def pack_cmd(cmd:dict):
        cmd_str = '^'
        for key in cmd.keys():
            cmd_str += "%s:%s/"%(key, cmd[key])
        cmd_str = cmd_str[0:-1] + '$'
        raw_cmd = cmd_str.encode(encoding="utf8")
        return raw_cmd 

    @staticmethod
    def pack_send_message_cmd(msg):
        cmd = dict()
        cmd["type"] = "ask"
        cmd["cmd"] = "send"
        cmd["datatype"] = "msg"
        if len(msg) > CommandManager.MSG_MAX:
            cmd["size"] = len(msg)
        else:
            cmd["content"] = msg
        return CommandManager.pack_cmd(cmd)

    @staticmethod
    def pack_send_file_cmd(filename:str, filesize:int):
        cmd = dict()
        cmd["type"] = "ask"
        cmd["cmd"] = "semd"
        cmd["datatype"] = "file"
        cmd["name"] = filename
        cmd["size"] = filesize
        return CommandManager.pack_cmd(cmd)
    
    @staticmethod
    def pack_ok_reply(extra_data:dict = None):
        if extra_data != None:
            cmd = extra_data
        else:
            cmd = dict()
        cmd["type"] = "res"
        cmd["status"] = "ok"
        return CommandManager.pack_cmd(cmd)
    
    @staticmethod
    def pack_failed_reply(extra_data:dict = None):
        if extra_data != None:
            cmd = extra_data
        else:
            cmd = dict()
        cmd["type"] = "res"
        cmd["status"] = "failed"
        return CommandManager.pack_cmd(cmd)

    @staticmethod
    def pack_accept_reply(extra_data:dict = None):
        if extra_data != None:
            cmd = extra_data
        else:
            cmd = dict()
        cmd["type"] = "res"
        cmd["status"] = "accept"
        return CommandManager.pack_cmd(cmd)
    
    @staticmethod
    def pack_reject_reply(extra_data:dict = None):
        if extra_data != None:
            cmd = extra_data
        else:
            cmd = dict()
        cmd["type"] = "res"
        cmd["status"] = "reject"
        return CommandManager.pack_cmd(cmd)

class Utrans:

    def __init__(self, ssk, cmd_mngr):
        self.ssk = ssk
        self.cmd_mngr = cmd_mngr
    
    def authenticate(self):
        pass
    
    def send_file(self, filepath):
        filesize = os.path.getsize(filepath)
        filename = os.path.basename(filepath)
        packed_cmd = CommandManager.pack_send_file_cmd(filename, filesize)
        ssk = self.ssk
        cmd_mngr = self.cmd_mngr
        ssk.send(packed_cmd)
        if cmd_mngr.parse_cmd_from_ssk(ssk) == CommandManager.S_ABORT:
            logger.debug("connection closed by peer")
            return False
        cmd = cmd_mngr.get()
        if cmd["status"] != "accept":
            logger.debug("peer reject")
            return False
        with open(filepath, "rb") as f:
            while True:
                data = f.read(4096)
                if len(data) == 0:
                    break
                ssk.send(data)
        if cmd_mngr.parse_cmd_from_ssk(ssk) == CommandManager.S_ABORT:
            logger.debug("connection closed by peer")
            return False
        cmd = cmd_mngr.get()
        if cmd["status"] != "ok":
            logger.debug("peer responsed failed")
            return False
        return True
        
    def send_message(self, message):
        pass

    def request_file(self, filepath):
        pass

    def receive_file(self, cmd):
        filename = cmd["name"]
        filesize = int(cmd["size"])
        packed_cmd = self.cmd_mngr.pack_accept_reply()
        self.ssk.send(packed_cmd)
        # todo: There may be a file with the same name, so check it.
        left_size = filesize
        with open(filename, "wb") as f:
            # todo: change this to be configurable in config
            self.ssk.settimeout(5)
            while True:
                try:
                    data = self.ssk.recv(4096)
                except:
                    break
                split_size = len(data)
                if split_size == 0:
                    break
                if left_size >= split_size:
                    left_size -= split_size
                else:
                    split_size = left_size
                    left_size = 0
                f.write(data[0:split_size])
                if left_size == 0:
                    break
        self.ssk.settimeout(None)
        if left_size > 0:
            if split_size == 0:
                logger.debug("peer close connection")
            else:
                logger.debug("data not complete")
                packed_cmd = self.cmd_mngr.pack_failed_reply()
                self.ssk.send(packed_cmd)
            return False
        packed_cmd = self.cmd_mngr.pack_ok_reply()
        self.ssk.send(packed_cmd)
        return True

    def receive_message(self, cmd):
        pass
    

class Server:
    def __init__(self):
        pass
    def run(self):
        listen_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_s.bind(('0.0.0.0', 9999))
        listen_s.listen(2)
        print("server started")
        try:
            while True:
                ssk, addr = listen_s.accept()
                print("connected with " + str(addr))
                cmd_mngr = CommandManager()
                utrans = Utrans(ssk, cmd_mngr)
                while True:
                    if cmd_mngr.parse_cmd_from_ssk(ssk) == CommandManager.S_ABORT:
                        print("peer close connection")
                        break
                    cmd = cmd_mngr.get()
                    if cmd["datatype"] == "file":
                        utrans.receive_file(cmd)
        except:
            logger.debug("server exception")
        finally:
            listen_s.close()

class Client:
    
    def __init__(self):
        pass

    def run(self):
        ssk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssk.connect(("127.0.0.1", 9999))
        cmd_mngr = CommandManager()
        utrans = Utrans(ssk, cmd_mngr)
        while True:
            try:
                filepath = input("please input the filepath:\n")
            except:
                print("exit")
                break
            utrans.send_file(filepath)


def main():
    if sys.argv[1].startswith('c'):
        client = Client()
        client.run()
    else:
        server = Server()
        server.run()


if __name__ == "__main__":
    main()
