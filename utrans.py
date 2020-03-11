#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Date: Sat Oct 19 20:45:17 2019
# Author: January

from utils import *
from callback import *
import os
import socket
import sys
import logging
import threading
import _thread
import time
import re
import base64
import queue
import signal
import progressbar

# current problems
# 1. not yet deal with exceptions

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("utrans")

usage='''
trans_file receive [-p <port>] [-o <filename>]
trans_file send -f <file> -d <ip> [-p <port>]
'''

BLANK_STR = ""

data_channel_mngr = DataChannelManager()

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

    def parse_broadcast_msg(self, data):
        try:
            data = data.decode(encoding="utf8")
            data.index("utrans")
        except:
            logger.debug("Not utrans flag, or fail to decode")
            return None

        data = data.split("&")
        if len(data) < 3:
            logger.debug("hello data not complete")
            return None
        try:
            data[2] = int(data[2])
        except:
            logger.debug("Port field not valid")
            return None
        return data

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
    SERVICE_BROADCAST_PORT = 9999
    SERVICE_SCAN_ADDR = ("0.0.0.0", 9999)
    DEFAULT_SERVICE_PORT = 9999
    SPLIT_LEN = 409600
    M_NORMAL = 1
    M_BROADCAST = 2
    M_SCAN = 3
    
    def __init__(self, mode):
        self.mode = mode
        self.is_init = False
        self.lock = _thread.allocate_lock()
        if mode == Utrans.M_NORMAL:
            self.init_normal_mode()
        elif mode == Utrans.M_SCAN:
            self.init_scan_mode()
        elif mode == Utrans.M_BROADCAST:
            self.init_broadcast_mode()
        self.cmd_mngr = CommandManager()
        self.is_init = True
        # A connection session may not start when the object is created, and we can't create a session socket.

    def init_normal_mode(self):
        if self.is_init is not True:
            self.ssk = None

    def init_scan_mode(self):
        if self.is_init is not True:
            self.__discovered_servers = set()
            self.scanning = False
            self.scan_sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.scan_sk.settimeout(0.1)
            self.scan_sk.bind(Utrans.SERVICE_SCAN_ADDR)

    def init_broadcast_mode(self, name = None, port = None):
        if self.is_init is not True:
            self.broadcast_sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # To enable broadcast
            self.broadcast_sk.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            if name == None:
                self.broadcast_name = socket.gethostname()
            else:
                self.broadcast_name = name

            if port == None:
                self.service_port = Utrans.DEFAULT_SERVICE_PORT
            else:
                self.service_port = port
            # set broadcast message
            self.broadcast_msg = "utrans&{name}&{port}".format(name=self.broadcast_name, port=self.service_port).encode("utf8")
            # set broadcast addr
            ip = socket.gethostbyname(socket.gethostname()).split(".")
            ip[3] = "255"
            broadcast_ip = '.'.join(ip)
            self.broadcast_addr = (broadcast_ip, Utrans.SERVICE_BROADCAST_PORT)
            
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

    def send_file(self, filepath, uuid, callback:UtransCallback):
        # read filename and file size
        if self.ssk == None or self.mode != Utrans.M_NORMAL:
            logger.debug("invalid operation for mode", self.mode)
            callback.on_error("Utrans core config error")
            return False
        #deprecated
        callback.on_start_scan()
        filesize = os.path.getsize(filepath)
        filename = os.path.basename(filepath)
        # new start callback
        if callback.new_callback:
            callback.on_file_send_start(filename, filesize, uuid)
        
        filename = self.base64_encode_str(filename)
        packed_cmd = CommandManager.pack_send_file_cmd(filename, filesize)
        ssk = self.ssk
        cmd_mngr = self.cmd_mngr
        # send cmd
        try:
            ssk.send(packed_cmd)
        except Exception as e:
            logger.debug(e)
            if callback.new_callback:
                callback.on_file_send_error(UtransError.CONNECTION_ERROR, uuid)
        # get reply
        if cmd_mngr.parse_cmd_from_ssk(ssk) == CommandManager.S_ABORT:
            logger.debug("connection closed by peer")
            callback.on_error("connection closed by peer")
            if callback.new_callback:
                callback.on_file_send_error(UtransError.CONNECTION_ERROR, uuid)
            return False
        cmd = cmd_mngr.get()
        if cmd["status"] != "accept":
            logger.debug("peer reject")
            callback.on_error("file rejected")
            if callback.new_callback:
                callback.on_file_send_error(UtransError.PEER_REJECT, uuid)
            return False
        # start sending file
        sended = 0
        with open(filepath, "rb") as f:
            while True:
                try:
                    data = f.read(Utrans.SPLIT_LEN)
                except Exception as e:
                    print(e)
                    if callback.new_callback:
                        callback.on_file_send_error(UtransError.CONNECTION_ERROR, uuid)
                # finish read
                if len(data) == 0:
                    break
                ssk.send(data)
                sended += len(data)
                # sending progress callback
                if callback.new_callback:
                    callback.on_file_sending(sended/ filesize, uuid)
                callback.on_progress(sended / filesize)
        # get reply
        print()
        if cmd_mngr.parse_cmd_from_ssk(ssk) == CommandManager.S_ABORT:
            logger.debug("connection closed by peer")
            callback.on_error("connection closed by peer")
            if callback.new_callback:
                callback.on_file_send_error(UtransError.CONNECTION_ERROR, uuid)
            return False
        cmd = cmd_mngr.get()
        if cmd["status"] != "ok":
            logger.debug("peer responsed failed")
            callback.on_finished("peer responsed failed")
            return False
        if callback.new_callback:
            callback.on_file_send_finished(UtransError.OK, uuid)
        callback.on_finished("ok")
        return True
        
    def send_message(self, message:str, callback:UtransCallback):
        if self.ssk == None or self.mode != Utrans.M_NORMAL:
            logger.debug("invalid operation for mode", self.mode)
            callback.on_error("Utrans core config error")
            return False
        msg_size = len(message)
        encode = "plain"
        if msg_size <= CommandManager.MSG_MAX:
            if re.search(r"[:&]", message) != None:
                message = self.base64_encode_str(message)
                encode = "base64"
        packed_cmd = self.cmd_mngr.pack_send_message_cmd(message, encode)
        self.ssk.send(packed_cmd)
        if msg_size > CommandManager.MSG_MAX:
            if self.cmd_mngr.parse_cmd_from_ssk(self.ssk) == CommandManager.S_ABORT:
                logger.debug("connection closed by peer")
                callback.on_error("connection closed by peer")
                return False
            cmd = self.cmd_mngr.get()
            if cmd["status"] != "accept":
                logger.debug("peer reject")
                callback.on_error("peer reject")
                return False
            self.ssk.send(message.encode(encoding="utf8"))
        if self.cmd_mngr.parse_cmd_from_ssk(self.ssk) == CommandManager.S_ABORT:
                logger.debug("connection closed by peer")
                callback.on_error("connection closed by peer")
                return False
        cmd = self.cmd_mngr.get()
        if cmd["status"] != "ok":
            logger.debug("peer responsed failed")
            callback.on_error("peer responsed failed")
            return False
        callback.on_finished("ok")
        return True
        
    def request_file(self, filepath):
        if self.ssk == None or self.mode != Utrans.M_NORMAL:
            logger.debug("invalid operation for mode", self.mode)
            return False
        pass

    def receive_file(self, cmd, callback:UtransCallback):
        if self.ssk == None or self.mode != Utrans.M_NORMAL:
            logger.debug("invalid operation for mode", self.mode)
            callback.on_error("Utran core config error")
            return False
        callback.on_start()
        filename = self.base64_decode_str(cmd["name"])
        filesize = int(cmd["size"])
        packed_cmd = self.cmd_mngr.pack_accept_reply()
        self.ssk.send(packed_cmd)
        # todo: There may be a file with the same name, so check it.
        start_time = time.time()
        with open(filename, "wb") as f:
            # todo: change this to be configurable in config
            self.ssk.settimeout(5)
            left_size = filesize
            split_size = 0
            while True:
                interval_start = time.time()
                try:
                    data = self.ssk.recv(Utrans.SPLIT_LEN)
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
                callback.on_progress(1 - (left_size/filesize))
                if left_size == 0:
                    break
        print()
        self.ssk.settimeout(None)
        if left_size > 0:
            if split_size == 0:
                logger.debug("data not complete, peer close connection")
                callback.on_error("data not complete, peer close connection")
            else:
                logger.debug("data not complete")
                packed_cmd = self.cmd_mngr.pack_failed_reply()
                self.ssk.send(packed_cmd)
            return (False, filename, filesize)
        packed_cmd = self.cmd_mngr.pack_ok_reply()
        self.ssk.send(packed_cmd)
        time_used = time.time() - start_time
        print("speed %.2f"%(filesize / time_used / (1024*1024)))
        callback.on_finished("ok")
        return (True, filename, filesize)

    def receive_message(self, cmd):
        if self.ssk == None or self.mode != Utrans.M_NORMAL:
            logger.debug("invalid operation for mode", self.mode)
            return None
        
        if "size" not in cmd.keys():
            if "content" not in cmd.keys():
                logger.debug("No content in message")
                return None
            msg = cmd["content"]
            if "encode" in cmd.keys() and cmd["encode"] == "base64":
                msg = self.base64_decode_str(msg)
        else:
            try:
                msg_size = int(cmd["size"])
            except:
                logger.debug("size is not int")
                return None

            left_size = msg_size
            if msg_size > 4*1024*1024:
                packed_cmd = self.cmd_mngr.pack_reject_reply()
                self.ssk.send(packed_cmd)
                return None

            msg = ''
            
            packed_cmd = self.cmd_mngr.pack_accept_reply()
            self.ssk.send(packed_cmd)

            # todo: change this to be configurable in config
            # self.ssk.settimeout(5)
            while left_size > 0:
                try:
                    data = self.ssk.recv(4096)
                except:
                    logger.debug("msg receive error")
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
        if self.broadcast_sk == None or self.mode != Utrans.M_BROADCAST:
            logger.debug("invalid operation for mode", self.mode)
            return False
        self.broadcast_sk.sendto(self.broadcast_msg, self.broadcast_addr)

    def __do_scan_service(self, callback:UtransCallback):
        sk = self.scan_sk
        self.ip = socket.gethostbyname(socket.gethostname())
        callback.on_start_scan()
        while self.scanning:
            try:
                data, address = sk.recvfrom(4096)
            except Exception as e:
                continue
            # 过滤本机发出的数据包
            if self.ip == address[0]:
                continue
            parsed_data = self.cmd_mngr.parse_broadcast_msg(data)
            if parsed_data == None:
                logger.debug("Receive invalid service discovery message")
                logger.debug(data)
                continue

            address = (address[0], parsed_data[2])
            if address not in self.__discovered_servers:
                self.__discovered_servers.add(address)
                new_server = UtransServerInfo(parsed_data[1], address)
                callback.on_new_server(new_server)
        callback.on_stop_scan()

    def stop_scan_service(self):
        if self.mode != Utrans.M_SCAN:
            logger.debug("invalid operation for mode", self.mode)

        if self.scanning == True:
            self.scanning = False
            self.__discovered_servers.clear()
            logger.debug("stop service discovery")
    
    def start_scan_service(self, callback, time):
        if self.scan_sk == None or self.mode != Utrans.M_SCAN:
            logger.debug("invalid operation for mode", self.mode)
            return False
        if self.scanning == True:
            logger.debug("already in scanning")
            return False
        self.scanning = True
        _thread.start_new_thread(self.__do_scan_service, (callback, ))
        logger.debug("start service discovery")
        if time != 0:
            stop_task = Runnable(self.stop_scan_service, (), time)
            _thread.start_new_thread(stop_task.run, ())

class UtransServer:

    def __init__(self, callback:UtransCallback = None):
        self.name = "server"
        self.enable_broadcast = True
        self.broadcast_interval = 2
        self.lsk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.lsk.bind(('0.0.0.0', Utrans.DEFAULT_SERVICE_PORT))
        self.lsk.listen(2)
        print("server start to listen")
        self.broadcast_service()
        print("start broadcasting service")

        self.register_callback(callback)
        self.init_communication()
    
    def init_communication(self):
        self.event_channel = queue.Queue()
        data_channel_mngr.register_data_channel(self.event_channel, self.name)

    def register_callback(self, callback:UtransCallback):
        self.callback = callback

    def handle_client(self, ssk:socket.socket):
        cmd_mngr = CommandManager()
        utrans = Utrans(Utrans.M_NORMAL)
        utrans.set_session(ssk)
        callback = self.callback
        while True:
            if cmd_mngr.parse_cmd_from_ssk(ssk) == CommandManager.S_ABORT:
                logger.debug("peer close connection")
                break
            cmd = cmd_mngr.get()
            if cmd["type"] != "ask":
                logger.debug("invalid request")
                continue

            if cmd["cmd"] == "send":
                if cmd["datatype"] == "msg":
                    if callback != None and callback.prompt_continue("Receive message?") == False:
                        pack_msg = cmd_mngr.pack_reject_reply()
                        ssk.send(pack_msg)
                        continue
                    msg = utrans.receive_message(cmd)
                    print("Get msg:")
                    print(msg)
                elif cmd["datatype"] == "file":
                    if callback != None and callback.prompt_continue("Receive file[%s %s]?"%(cmd["name"], cmd["size"])) == False:
                        pack_msg = cmd_mngr.pack_reject_reply()
                        ssk.send(pack_msg)
                        continue
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
    
    # open a new thread to broadcast
    def broadcast_service(self):
        _thread.start_new_thread(self.do_broadcast, ())

    def do_broadcast(self):
        utrans = Utrans(Utrans.M_BROADCAST)
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


class UtransClient:
    def __init__(self, name = "client"):
        self.name = name
        self.current_session = None
        self.sessions = {}
        self.available_servers = []
        self.scanner = Utrans(Utrans.M_SCAN)
        self.init_communication()
    
    # Utranscallback interface
    def on_new_server(self, server_info):
        self.above_callback.on_new_server(server_info)
        self.available_servers.append(server_info)

    def on_start_scan(self):
        self.above_callback.on_start_scan()
    
    def on_stop_scan(self):
        self.above_callback.on_stop_scan()

    def init_communication(self):
        self.event_channel = queue.Queue()
        data_channel_mngr.register_data_channel(self.name, self.event_channel)
    
    def set_current_session(self, name):
        if name not in self.sessions.keys():
            return False
        self.current_session = self.sessions[name]

    def get_current_session(self):
        return self.current_session
    
    def get_available_server(self, name):
        for item in self.available_servers:
            if item.name == name:
                return item
        return None

    def start_scan(self, callback, time = 0):
        self.available_servers.clear()
        self.above_callback = callback
        self.scanner.start_scan_service(self, time)
    
    def has_new_server(self):
        if len(self.available_servers) > 0:
            return True
        else:
            return False

    def stop_scan(self):
        self.scanner.stop_scan_service()

    def get_available_servers():
        return self.available_servers

    def connect(self, server:UtransServerInfo):
        sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sk.settimeout(10)
        logger.debug("connect")
        try:
            sk.connect(server.addr)
        except Exception as e:
            print(e)
            return None
        logger.debug("ok")
        session = UtransSession(server.name, server.addr, sk)
        # save the session
        self.sessions[session.name] = session
        self.current_session = session
        return session

    def send_file(self, filename, callback, uuid = None, block = True, session:UtransSession = None):
        if session is None:
            session = self.current_session
        utrans = Utrans(Utrans.M_NORMAL)
        utrans.set_session(session.sk)
        if block:
            return utrans.send_file(filename, uuid, callback)
        else:
            _thread.start_new_thread(utrans.send_file, (filename, uuid, callback))
            return True
    
    def send_files(self, filenames, callback, uuids = None, session:UtransSession = None):
        if session is None:
            session = self.current_session
        _thread.start_new_thread(self.__do_send_files, (filenames, callback, uuids, session))

    def __do_send_files(self, filenames, callback, uuids, session):
        if uuids == None:
            uuids = (i for i in range(len(filenames)))

        for filename, uuid in zip(filenames, uuids):
            if not os.path.exists(filename):
                callback.on_error("No such file %s"%(filename))
                continue
            self.send_file(filename, callback, uuid = uuid, block=True, session=session)
       
    
    def send_message(self, msg, callback, block = False, session:UtransSession = None):
        if session is None:
            session = self.current_session
        utrans = Utrans(Utrans.M_NORMAL)
        utrans.set_session(session.sk)
        if block:
            utrans.send_message(msg,callback)
        else:
            _thread.start_new_thread(utrans.send_message, (msg, callback))
    
    def authenticate(self, session:UtransSession):
        print("not support")

    def async_test(self, callback):
        _thread.start_new_thread(time.sleep, (3,))
        callback.on_finished("ok")

class UtransCmdCallback(UtransCallback):
    def __init__(self):
        self.data_channel = queue.Queue()
        # use to receive user input from main thread
        data_channel_mngr.register_data_channel("prompt", self.data_channel)
    
    def set_file(self, filename):
        widgets = [filename + ' ', progressbar.Percentage(), ' ', progressbar.Bar('='),' ', progressbar.Timer(),
           ' ', progressbar.ETA(), ' ', ' ']
        self.pb = progressbar.ProgressBar(maxval=1, widgets=widgets)

    def prompt_continue(self, info):
        print(info)
        # send a request to main thread, ask for confirm
        channel = data_channel_mngr.get_data_channel("cmd")
        channel.put("ask_yes_no")
        # receive reponse from main thread
        cmd = self.data_channel.get()
        if cmd == "y":
            return True
        else:
            return False

    def on_new_server(self, server_info):
        print(server_info)

    def on_start(self):
        self.pb.start()

    def on_progress(self, progress):
        #print("sended:%.2f"%(progress), end="\r")
        self.pb.update(progress)
    
    def on_finished(self, info):
        self.pb.finish()

class UtransCmdMode:
    CLIENT = 1
    SERVER = 2
    def __init__(self, mode):
        self.name = "cmd"
        if mode & UtransCmdMode.CLIENT:
            self.client = UtransClient()
        
        if mode & UtransCmdMode.SERVER:
            self.server = UtransServer(UtransCallback())
            _thread.start_new_thread(self.server.run, ())
        self.init_cmd_mode()
        
    def init_cmd_mode(self):
        self.event_channel = queue.Queue()
        data_channel_mngr.register_data_channel(self.name, self.event_channel)
        self.callback = UtransCmdCallback()
        self.finished = False
        
    def exit_cmd_mode(self):
        pass

    def run(self):
        input_trans_channel = data_channel_mngr.get_data_channel("prompt")
        client = self.client
        while True:
            try:
                raw_data = input("%s@%s: "%(self.name, str(client.current_session)))
            except BaseException as e:
                if type(e) != KeyboardInterrupt:
                    print(e)
                self.exit_cmd_mode
                return

            if len(raw_data) <= 0:
                continue

            if not self.event_channel.empty():
                self.event_channel.get_nowait()
                input_trans_channel.put(raw_data)
                continue

            # deal with args with space surrounded by ""
            argv = link_args(raw_data.split())
            # parse args
            cmd = argv[0]
            raw_args, options = get_options(argv, [":"])
            if cmd == "send_file":
                for filename in raw_args:
                    if not os.path.isfile(filename):
                        print("%s is not a file", filename)
                    else:
                        self.callback.set_file(filename)
                        client.send_file(filename, self.callback)

            elif cmd == "send_msg":
                if len(raw_args) <= 0:
                    try:
                        self.message_send_mode()
                    except:
                        print("exit message send mode")
                else:
                    msg = " ".join(raw_args)
                    client.send_message(msg, self.callback)
            elif cmd == "ls":
                if len(raw_args) <= 0:
                    print("current connect to [%s]"%(str(client.current_session)))
                    print("All sessions:")
                    print(client.sessions)
                    print("Avaliable servers: ")
                    print(client.available_servers)
            elif cmd == "connect":
                if len(raw_args) <= 0:
                    available_server_num = len(client.available_servers)
                    if available_server_num > 1:
                        print("more than one available server, can't auto connect, please specify the target")
                    elif available_server_num <= 0:
                        print("no available server, please specify the target")
                    else:
                        client.connect(client.available_servers[0])
                    continue
                for item in raw_args:
                    server_info = client.get_available_server(item)
                    if server_info == None:
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
                        server_info = UtransServerInfo(item, addr)
                    client.connect(server_info)
            elif cmd == "switch":
                if len(raw_args) <= 0:
                    print("please specify a session")
                    continue
                session_name = raw_args[0]
                if session_name not in client.sessions.keys():
                    print("No such session")
                    continue
                client.current_session = client.sessions[session_name]
            elif cmd == "scan":
                self.scan_server(True)
            elif cmd == "test":
                client.async_test(self.callback)
            elif cmd == "q":
                self.exit_cmd_mode()
                return
            else:
                print("unknown command: %s"%(cmd))
        
    def scan_server(self, one_to_exit = False):
        self.client.start_scan(self.callback)
        if one_to_exit:
            try:
                while not self.client.scanner.has_available_server:
                    time.sleep(0.2)
            except Exception as e:
                pass
            self.client.stop_scan()
            return

        print("scanning, press ctrl+c to stop")
        try:
            while True:
                time.sleep(10)
        except:
            pass
        self.client.stop_scan()

    def message_send_mode(self):
        print("doesn't support")


def main():
    cmd_mode = UtransCmdMode(UtransCmdMode.CLIENT | UtransCmdMode.SERVER)
    cmd_mode.run()
  

if __name__ == "__main__":
    main()
