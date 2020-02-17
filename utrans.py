#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Date: Sat Oct 19 20:45:17 2019
# Author: January

import os
import socket
import sys
import logging
import threading
import _thread
import time

# current problems
# 1. not yet deal with exceptions

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("utrans")

usage='''
trans_file receive [-p <port>] [-o <filename>]
trans_file send -f <file> -d <ip> [-p <port>]
'''

BLANK_STR = ""

class CommandManager:
    S_NULL = 'null'
    S_RECEIVING = 'receiving'
    S_OK = 'ok'
    S_ABORT = "abort"
    F_START = ord('^')
    F_END = ord('$')
    MSG_MAX = 100

    def __init__(self):
        self.reset()

    def reset(self):
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
    
    # The method takes a socket object as parameter and calls its recv method to receive data.
    # It calls parse_cmd_from_bytes several times if necessary to try receiving a complete cmd,
    # and then returns the status of the operation.
    def parse_cmd_from_ssk(self, ssk):
        while True:
            data = ssk.recv(4096)
            if self.parse_cmd_from_bytes(data) is True:
                return self.status

    def get(self):
        cmd_dict = self.values
        self.reset()
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
    DATA_REV_TIMEOUT = 5
    SERVICE_DISCOVERY_PORT = 9999
    SERVICE_DISCOVERY_BROADCAST_ADDRESS = ("255.255.255.255", 9999)
    SERVICE_DISCOVERY_RECEIVE_ADDRESS = ("0.0.0.0", 9999)
    
    def __init__(self, cmd_mngr = None, session_sk = None):
        self.ssk = session_sk
        self.cmd_mngr = cmd_mngr
        self.available_servers = []
        self.service_discovering = False
        self.srvc_dscvr_sk = None
        if self.cmd_mngr == None:
            self.cmd_mngr = CommandManager()

        # A connection session may not start when the object is created, and we can't create a session socket.

    def init_service_discovery(self):
        if self.srvc_dscvr_sk == None:
            self.srvc_dscvr_sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # To enable broadcast
            self.srvc_dscvr_sk.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.srvc_dscvr_sk.bind(Utrans.SERVICE_DISCOVERY_RECEIVE_ADDRESS)

    def new_session(self, ssk):
        self.ssk = ssk         
    
    def authenticate(self):
        pass
    
    def send_file(self, filepath):
        # read filename and file size
        filesize = os.path.getsize(filepath)
        filename = os.path.basename(filepath)
        packed_cmd = CommandManager.pack_send_file_cmd(filename, filesize)
        ssk = self.ssk
        cmd_mngr = self.cmd_mngr
        # send cmd
        ssk.send(packed_cmd)
        # get reply
        if cmd_mngr.parse_cmd_from_ssk(ssk) == CommandManager.S_ABORT:
            logger.debug("connection closed by peer")
            return False
        cmd = cmd_mngr.get()
        if cmd["status"] != "accept":
            logger.debug("peer reject")
            return False
        # start sending file
        with open(filepath, "rb") as f:
            while True:
                data = f.read(4096)
                if len(data) == 0:
                    break
                ssk.send(data)
        # get reply
        if cmd_mngr.parse_cmd_from_ssk(ssk) == CommandManager.S_ABORT:
            logger.debug("connection closed by peer")
            return False
        cmd = cmd_mngr.get()
        if cmd["status"] != "ok":
            logger.debug("peer responsed failed")
            return False
        return True
        
    def send_message(self, message):
        msg_size = len(message)
        packed_cmd = self.cmd_mngr.pack_send_message_cmd(message)
        self.ssk.send(packed_cmd)
        if msg_size > CommandManager.MSG_MAX:
            if self.cmd_mngr.parse_cmd_from_ssk(self.ssk) == CommandManager.S_ABORT:
                logger.debug("connection closed by peer")
                return False
            cmd = self.cmd_mngr.get()
            if cmd["status"] != "accept":
                logger.debug("peer reject")
                return False
            self.ssk.send(message.encode(encoding="utf8"))
        if self.cmd_mngr.parse_cmd_from_ssk(self.ssk) == CommandManager.S_ABORT:
                logger.debug("connection closed by peer")
                return False
        cmd = self.cmd_mngr.get()
        if cmd["status"] != "ok":
            logger.debug("peer responsed failed")
            return False
        return True
        
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
            return (False, filename, filesize)
        packed_cmd = self.cmd_mngr.pack_ok_reply()
        self.ssk.send(packed_cmd)
        return (True, filename, filesize)

    def receive_message(self, cmd):
        if "size" not in cmd.keys():
            msg = cmd["content"].decode(encoding="utf8")
        else:
            msg_size = int(cmd["size"])
            left_size = msg_size
            if msg_size > 4*1024*1024:
                packed_cmd = self.cmd_mngr.pack_reject_reply()
                self.ssk.send(packed_cmd)
                return ''
            msg = ''
            # todo: change this to be configurable in config
            self.ssk.settimeout(5)
            while left_size > 0:
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
                msg += data[0:split_size].decode(encoding="utf8")
            if left_size > 0:
                if split_size == 0:
                    logger.debug("peer close connection")
                else:
                    logger.debug("data not complete")
                    packed_cmd = self.cmd_mngr.pack_failed_reply()
                    self.ssk.send(packed_cmd)
                return ''
        # success to receive message
        packed_cmd = self.cmd_mngr.pack_ok_reply()
        self.ssk.send(packed_cmd)
        return msg
    
    def send_service_discovery_message(self):
        if self.srvc_dscvr_sk == None:
            logger.warning("service discovery not init")
            return
        self.srvc_dscvr_sk.sendto(b"utrans/9999", Utrans.SERVICE_DISCOVERY_BROADCAST_ADDRESS)

    def do_discover_service(self):
        if self.srvc_dscvr_sk == None:
            logger.warning("service discovery not init")
            return
        sk = self.srvc_dscvr_sk
        sk.settimeout(2)
        while self.service_discovering:
            try:
                data, address = sk.recvfrom(4096)
            except Exception as e:
                print(e)
                logger.debug("service discovery timeout")
                continue
            try:
                data = data.decode(encoding="utf8")
                data.index("utrans")
            except:
                logger.debug("Receive invalid service discovery message")
                continue

            if address not in self.available_servers:
                self.available_servers.append(address)

    def stop_service_discover(self):
        self.service_discovering = False
        logger.debug("stop service discovery")
    
    def start_discover_service(self, timeout = 0):
        if self.srvc_dscvr_sk == None:
            logger.warning("service discovery not init")
            return
        self.service_discovering = True
        _thread.start_new_thread(self.do_discover_service, ())
        logger.debug("start service discovery")
        if timeout != 0:
            time.sleep(timeout)
            self.stop_service_discover()



class UtransServer:

    def __init__(self):
        self.lsk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.lsk.bind(('0.0.0.0', 9999))
        self.lsk.listen(2)
        print("server start to listen")

    def handle_client(self, ssk):
        cmd_mngr = CommandManager()
        utrans = Utrans(cmd_mngr, ssk)
        while True:
            if cmd_mngr.parse_cmd_from_ssk(ssk) == CommandManager.S_ABORT:
                print("peer close connection")
                break
            cmd = cmd_mngr.get()
            if cmd["type"] != "ask":
                print("invalid request")
                continue

            if cmd["cmd"] == "send":
                if cmd["datatype"] == "msg":
                    msg = utrans.receive_message(cmd)
                    if msg == '':
                        print("Receive nothing")
                        continue
                    print("Get msg:")
                    print(msg)
                elif cmd["datatype"] == "file":
                    status, filename, filesz = utrans.receive_file(cmd)
                    if status == False:
                        print("File transmission failed")
                        continue
                    print("Receive File [%s], total_size %d"%(filename, filesz))
            elif cmd["cmd"] == "auth":
                print("unsupport operation")
            else:
                print("unknown operation: %s"%(cmd["cmd"]))
    
    def run(self):
        try:
            while True:
                ssk, addr = self.lsk.accept()
                print("connected with " + str(addr))
                _thread.start_new_thread(self.handle_client, (ssk, ))
        except Exception as e:
            print(e)
            logger.debug("server exception")
        finally:
            self.lsk.close()

class UtransClient:
    def __init__(self):
        pass

    def run(self):
        ssk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        ssk.connect(("127.0.0.1", 9999))
        cmd_mngr = CommandManager()
        utrans = Utrans(cmd_mngr, ssk)
        while True:
            try:
                filepath = input("please input the filepath:\n")
            except:
                print("exit")
                break
            utrans.send_file(filepath)

class SD_test:
    
    def __init__(self):
        pass
    
    def broadcast(self):
        cmd_mgnr = CommandManager()
        utrans = Utrans(cmd_mgnr)
        utrans.init_service_broadcast()
        while True:
            utrans.send_service_discovery_message()
            time.sleep(1)
    
    def receive_broadcast(self):
        cmd_mgnr = CommandManager()
        utrans = Utrans(cmd_mgnr)
        utrans.init_service_broadcast()
        utrans.start_service_discover(5)
        print(utrans.available_servers)

        

def main():
    mode = sys.argv[1]
    if mode == "c":
        client = Client()
        client.run()
    elif mode == "s":
        server = Server()
        server.run()
    elif mode == "cd":
        test = SD_test()
        test.broadcast()
    elif mode == "sd":
        test = SD_test()
        test.receive_broadcast()


if __name__ == "__main__":
    main()
