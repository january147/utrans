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
import re
import base64

# current problems
# 1. not yet deal with exceptions

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("utrans")

usage='''
trans_file receive [-p <port>] [-o <filename>]
trans_file send -f <file> -d <ip> [-p <port>]
'''

BLANK_STR = ""

def link_args(args):
    new_args = []
    arg_continue = False
    arg_saved = ""
    for item in args:
        if arg_continue is True:
            if item[-1] == "\"":
                arg_continue = False
                arg_saved += item.strip("\"")
                new_args.append(arg_saved)
                arg_saved = ""
            else:
                arg_saved += item
            continue

        if item[0] != "\"":
            new_args.append(item)
            continue

        if item[0] == "\"":
            if item[-1] == "\"":
                new_args.append(item.strip("\""))
            else:
                arg_saved += item.strip("\"")
                arg_continue = True
            continue
        
    if arg_continue == True:
        logger.debug("arg not complete")
        return None
    return new_args

def get_options(args, option_list:list):
    arg_p = 1
    total_arg = len(args)
    options = {}
    raw_arg = []
    options_with_arg = []
    accpet_all = False
    for i in range(len(option_list)):
        option_description = option_list[i]
        if option_description == ':':
            accpet_all = True
            continue
        if option_description[-1] == ':':
            option = option_description[:-1]
            options_with_arg.append(option)
            option_list[i] = option


    while arg_p < total_arg:
        arg = args[arg_p]
        if arg.startswith('--'):
            name = arg[2:]
            if not accpet_all and name not in option_list:
                print("invalid option '%s', pos '%d'"%(name, arg_p))
                exit(1)
            if name not in options_with_arg:
                options[name] = ''
            else:
                arg_p += 1
                if arg_p >= len(args) or args[arg_p].startswith('-'):
                    print("option '%s' requires an argument, pos %d"%(name, arg_p))
                    exit(1)
                value = args[arg_p]
                options[name] = value
        elif arg.startswith('-'):
            names = arg[1:]
            if len(names) <= 1:
                name_likely_with_arg = names
            else:
                for name in names[:-1]:
                    if not accpet_all and name not in option_list:
                        print("invalid option '%s', pos %d"%(name, arg_p))
                        exit(1)
                    if name in options_with_arg:
                        print("option '%s' requiring an argument can be put between options, pos %d"%(name, arg_p))
                        exit(1)
                    options[name] = ''
                name_likely_with_arg = names[-1]
            if not accpet_all and name_likely_with_arg not in option_list:
                print("invalid option '%s', pos %d"%(name_likely_with_arg, arg_p))
                exit(1)
            if name_likely_with_arg not in options_with_arg:
                options[name_likely_with_arg] = ''
            else:
                arg_p += 1
                if arg_p >= len(args) or args[arg_p].startswith('-'):
                    print("option '%s' requires an argument, pos %d"%(name_likely_with_arg, arg_p))
                    exit(1)
                value = args[arg_p]
                options[name_likely_with_arg] = value
        else:
            raw_arg.append(arg)
        arg_p += 1

    return (raw_arg, options)

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
        self.split_raw_cmd = self.raw_cmd.decode(encoding="utf8").strip("^$").split("&")
        logger.debug(self.raw_cmd)
        for key_value in self.split_raw_cmd:
            key, value = key_value.split(":")
            self.values[key] = value

    # use '&' to split key-value tuple in cmd, because '/' is a character used by base64
    @staticmethod
    def pack_cmd(cmd:dict):
        cmd_str = '^'
        for key in cmd.keys():
            cmd_str += "%s:%s&"%(key, cmd[key])
        cmd_str = cmd_str[0:-1] + '$'
        raw_cmd = cmd_str.encode(encoding="utf8")
        return raw_cmd 

    @staticmethod
    def pack_send_message_cmd(msg, encode = "plain"):
        cmd = dict()
        cmd["type"] = "ask"
        cmd["cmd"] = "send"
        cmd["datatype"] = "msg"
        cmd["encode"] = encode
        if len(msg) > CommandManager.MSG_MAX:
            cmd["size"] = len(msg)
        else:
            cmd["content"] = msg
        return CommandManager.pack_cmd(cmd)

    @staticmethod
    def pack_send_file_cmd(filename:str, filesize:int):
        cmd = dict()
        cmd["type"] = "ask"
        cmd["cmd"] = "send"
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

    def get_available_servers(self):
        result = self.available_servers
        self.available_servers = []
        return result

    def init_service_discovery(self):
        if self.srvc_dscvr_sk == None:
            self.srvc_dscvr_sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # To enable broadcast
            self.srvc_dscvr_sk.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.srvc_dscvr_sk.bind(Utrans.SERVICE_DISCOVERY_RECEIVE_ADDRESS)

    def set_session(self, ssk):
        self.ssk = ssk         
    
    def base64_encode_str(self, string:str):
        return base64.b64encode(string.encode("utf8")).decode("utf8")
    
    def base64_decode_str(self, string:str):
        return base64.b64decode(string.encode("utf8")).decode("utf8")

    def authenticate(self):
        self.send_not_support_info()
    
    def send_not_support_info(self):
        info = {
            "info" : "unsupported operation"
        }
        packed_msg = self.cmd_mngr.pack_failed_reply(info)
        self.ssk.send(packed_msg)

    def send_file(self, filepath):
        # read filename and file size
        filesize = os.path.getsize(filepath)
        filename = os.path.basename(filepath)
        filename = self.base64_encode_str(filename)
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
        sended = 0
        with open(filepath, "rb") as f:
            while True:
                data = f.read(4096)
                if len(data) == 0:
                    break
                ssk.send(data)
                sended += len(data)
                print("sended/total: %d/%d"%(sended, filesize), end='\r')
        # get reply
        print()
        if cmd_mngr.parse_cmd_from_ssk(ssk) == CommandManager.S_ABORT:
            logger.debug("connection closed by peer")
            return False
        cmd = cmd_mngr.get()
        if cmd["status"] != "ok":
            logger.debug("peer responsed failed")
            return False
        return True
        
    def send_message(self, message:str):
        msg_size = len(message)
        encode = "plain"
        if msg_size <= CommandManager.MSG_MAX:
            if re.search(r"[:/]", message) != None:
                message = self.base64_encode_str(message)
                encode = "base64"
        packed_cmd = self.cmd_mngr.pack_send_message_cmd(message, encode)
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
        filename = self.base64_decode_str(cmd["name"])
        filesize = int(cmd["size"])
        packed_cmd = self.cmd_mngr.pack_accept_reply()
        self.ssk.send(packed_cmd)
        # todo: There may be a file with the same name, so check it.
        left_size = filesize
        start_time = time.time()
        with open(filename, "wb") as f:
            # todo: change this to be configurable in config
            self.ssk.settimeout(5)
            while True:
                interval_start = time.time()
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
                interval = time.time() - interval_start
                print("left/total: %d/%d, speed: %.2f"%(filesize - left_size, filesize, len(data) / interval), end='\r')
                if left_size == 0:
                    break
        print()
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
        time_used = time.time() - start_time
        print("speed %.2f"%(filesize / time_used))
        return (True, filename, filesize)

    def receive_message(self, cmd):
        if "size" not in cmd.keys():
            msg = cmd["content"]
            if cmd["encode"] == "base64":
                msg = self.base64_decode_str(msg)
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
        self.enable_broadcast = True
        self.broadcast_interval = 2
        self.lsk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.lsk.bind(('0.0.0.0', 9999))
        self.lsk.listen(2)
        print("server start to listen")
        self.broadcast_service()
        print("start broadcasting service")

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
                utrans.send_not_support_info()
                print("unsupport operation")
            else:
                utrans.send_not_support_info()
                print("unknown operation: %s"%(cmd["cmd"]))
    

    def broadcast_service(self):
        _thread.start_new_thread(self.do_broadcast, ())

    def do_broadcast(self):
        utrans = Utrans()
        utrans.init_service_discovery()
        while self.enable_broadcast:
            utrans.send_service_discovery_message()
            time.sleep(self.broadcast_interval)
        
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

class UtransSession:
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"

    def __init__(self, name, address, sk):
        self.name = name
        self.address = address
        self.sk = sk
        self.status = UtransSession.CONNECTED
    
    def __str__(self):
        return self.name

class UtransClient:
    def __init__(self, name = "utrans"):
        self.name = name
        self.current_session = None
        self.sessions = {}
        self.available_servers = {}
        self.scanner = Utrans()
        self.scanner.init_service_discovery()

    def command_line(self):
        while True:
            try:
                argv = input("%s@%s: "%(self.name, str(self.current_session))).split()
            except:
                return 
            if len(argv) <= 0:
                continue
            argv = link_args(argv)
            cmd = argv[0]
            raw_args, options = get_options(argv, [":"])
            if cmd == "send_file":
                for filename in raw_args:
                    if not os.path.isfile(filename):
                        print("%s is not a file", filename)
                        continue
                    self.send_file(filename)
            elif cmd == "send_msg":
                if len(raw_args) <= 0:
                    try:
                        self.message_send_mode()
                    except:
                        print("exit message send mode")
                        continue
                else:
                    msg = " ".join(raw_args)
                self.send_message(msg)
            elif cmd == "ls":
                if len(raw_args) <= 0:
                    print("current connect to [%s]"%(str(self.current_session)))
                    print("All sessions:")
                    print(self.sessions)
                    print("Avaliable servers: ")
                    print(self.available_servers)
            elif cmd == "connect":
                if len(raw_args) <= 0:
                    available_server_num = len(self.available_servers)
                    if available_server_num > 1:
                        print("more than one available server, can't auto connect, please specify the target")
                    elif available_server_num <= 0:
                        print("no available server, please specify the target")
                    else:
                        for key in self.available_servers.keys():
                            self.connect(self.available_servers[key])
                    continue
                for item in raw_args:
                    if item in self.available_servers.keys():
                        addr = self.available_servers[item]
                    else:
                        addr_pattern = re.compile(r'((?:[0-9]+\.){3}[0-9]+)@([0-9]+)')
                        result = addr_pattern.match(item)
                        if result == None:
                            print("not valid address: %s"%(item))
                            continue
                        else:
                            addr = result.groups()[0]
                            if len(addr) != 2:
                                print("not valid address: %s"%(item))
                                continue
                            addr[1] = int(addr[1])
                    self.connect(addr)
            elif cmd == "switch":
                if len(raw_args) <= 0:
                    print("please specify a session")
                    continue
                session_name = raw_args[0]
                if session_name not in self.sessions.keys():
                    print("No such session")
                    continue
                self.current_session = self.sessions[session_name]
            elif cmd == "scan":
                self.scan_server()
            elif cmd == "q":
                return
            else:
                print("unknown command: %s"%(cmd))

    def transform_available_server(self, server_addrs):
        result = {}
        for addr in server_addrs:
            name = "%s@%d"%(addr[0], addr[1])
            result[name] = addr
        return result

    def scan_server(self):
        self.scanner.start_discover_service()
        print("scanning, press ctrl+c to stop")
        while True:
            try:
                input()
            except:
                break
        self.scanner.stop_service_discover()
        self.available_servers = self.transform_available_server(self.scanner.get_available_servers())

    def message_send_mode(self):
        while True:
            msg = input("please input message to send:")
            self.send_message(msg)

    def set_current_connection(self, connection_num):
        self.current_connection = connection_num

    def connect(self, address):
        sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sk.connect(address)
        session = UtransSession("%s@%d"%(address[0], address[1]), address, sk)
        # save the session
        self.sessions[session.name] = session
        self.current_session = session
        return session

    def send_file(self, filename, session:UtransSession = None):
        if session is None:
            session = self.current_session
        utrans = Utrans(session_sk = session.sk)
        utrans.send_file(filename)

    def send_message(self, msg, session:UtransSession = None):
        if session is None:
            session = self.current_session
        utrans = Utrans(session_sk = session.sk)
        utrans.send_message(msg)
    
    def autenticate(self, session:UtransSession):
        print("not support")

    def run(self):
        self.command_line()

def main():
    mode = sys.argv[1]
    if mode == "c":
        client = UtransClient("client")
        client.run()
    elif mode == "s":
        server = UtransServer()
        server.run()
  

if __name__ == "__main__":
    main()
