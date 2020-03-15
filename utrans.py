#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Date: Sat Oct 19 20:45:17 2019
# Author: January

from utrans_utils import *
from utrans_interface import *
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

# current problems
# 1. not yet deal with exceptions

#logging.basicConfig(level=logging.DEBUG)
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
            try:
                data = ssk.recv(4096)
            except Exception as e:
                print(e)
                data = b''
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
        if encode == "base64":
            ratio = 4 / 3
        else:
            ratio = 1
        if len(msg) > CommandManager.MSG_MAX * ratio:
            cmd["size"] = len(msg.encode(encoding="utf8"))
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
    
    @staticmethod
    def pack_init_msg(name, extra_data:dict = None):
        if extra_data != None:
            cmd = extra_data
        else:
            cmd = dict()
        cmd["type"] = "init"
        cmd["name"] = name
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

    def _send_init_message(self, name):
        packed_cmd = self.cmd_mngr.pack_init_msg(name)
        self.ssk.send(packed_cmd)
    
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

    def send_file(self, filepath, task_info:UtransTask, callback:UtransCallback):
        # read filename and file size
        if self.ssk == None or self.mode != Utrans.M_NORMAL:
            logger.debug("invalid operation for mode", self.mode)
            callback.on_file_send_error(UtransError.UTRANS_CONFIG_ERROR, task_info)
            return False
        # make sure the file exists in high level APIs of UtransClient
        ssk = self.ssk
        cmd_mngr = self.cmd_mngr
        filesize = os.path.getsize(filepath)
        filename = os.path.basename(filepath)
        
        # new start callback
        callback.on_file_send_start(filename, filesize, task_info)
        
        # send control info
        filename = self.base64_encode_str(filename)
        packed_cmd = CommandManager.pack_send_file_cmd(filename, filesize)
        try:
            ssk.send(packed_cmd)
        except Exception as e:
            logger.debug(e)
            callback.on_file_send_error(UtransError.CONNECTION_ERROR, task_info)
        
        # get reply
        self.ssk.settimeout(15)
        if cmd_mngr.parse_cmd_from_ssk(ssk) == CommandManager.S_ABORT:
            logger.debug("connection closed by peer")
            callback.on_file_send_error(UtransError.CONNECTION_ERROR, task_info)
            return False
        cmd = cmd_mngr.get()
        if "status" not in cmd.keys():
            callback.on_file_send_error(UtransError.INVALID_CMD, task_info)
            return False

        if cmd["status"] != "accept":
            logger.debug("peer reject")
            callback.on_file_send_error(UtransError.PEER_REJECT, task_info)
            return False

        # start sending file
        self.ssk.settimeout(3)
        sended = 0
        with open(filepath, "rb") as f:
            while True:
                try:
                    data = f.read(Utrans.SPLIT_LEN)
                except Exception as e:
                    print(e)
                    callback.on_file_send_error(UtransError.LOCAL_ERROR, task_info)
                # finish read
                if len(data) == 0:
                    break
                try:
                    ssk.send(data)
                except Exception as e:
                    print(e)
                    callback.on_file_send_error(UtransError.CONNECTION_ERROR, task_info)
                sended += len(data)
                # sending progress callback
                progress = sended / filesize
                # on progress callback
                callback.on_file_sending(progress, task_info)
                if task_info.running == False:
                    callback.on_file_send_stop(task_info)
                    return False

        # get reply
        if cmd_mngr.parse_cmd_from_ssk(ssk) == CommandManager.S_ABORT:
            logger.debug("connection closed by peer")
            callback.on_file_send_error(UtransError.CONNECTION_ERROR, uuid)
            return False
        cmd = cmd_mngr.get()
        if cmd["status"] != "ok":
            logger.debug("peer responsed failed")
            callback.on_file_send_error(UtransError.PEER_SAY_FAILED, task_info)
            return False
        # success sending file
        callback.on_file_send_finished(UtransError.OK, task_info)
        return True
        
    def send_message(self, message:str, callback:UtransCallback, task_info:UtransTask):
        if self.ssk == None or self.mode != Utrans.M_NORMAL:
            logger.debug("invalid operation for mode", self.mode)
            callback.on_msg_send_error(UtransError.UTRANS_CONFIG_ERROR, task_info)
            return False

        msg_size = len(message)
        encode = "plain"
        if msg_size <= CommandManager.MSG_MAX:
            if re.search(r"[:&]", message) != None:
                message = self.base64_encode_str(message)
                encode = "base64"
        
        # send short message
        packed_cmd = self.cmd_mngr.pack_send_message_cmd(message, encode)
        try:
            self.ssk.send(packed_cmd)
        except Exception as e:
            print(e)
            callback.on_msg_send_error(UtransError.CONNECTION_ERROR, task_info)

        # send long message
        if msg_size > CommandManager.MSG_MAX:
            self.ssk.settimeout(15)
            if self.cmd_mngr.parse_cmd_from_ssk(self.ssk) == CommandManager.S_ABORT:
                logger.debug("connection closed by peer")
                callback.on_msg_send_error(UtransError.CONNECTION_ERROR, task_info)
                return False
            self.ssk.settimeout(3)
            cmd = self.cmd_mngr.get()
            if "status" not in cmd.keys():
                callback.on_msg_send_error(UtransError.INVALID_CMD, task_info)
                return False
            
            if cmd["status"] != "accept":
                logger.debug("peer reject")
                callback.on_msg_send_error(UtransError.PEER_REJECT, task_info)
                return False
            try:
                self.ssk.send(message.encode(encoding="utf8"))
            except Exception as e:
                print(e)
                callback.on_msg_send_error(UtransError.INVALID_CMD, task_info)
                
        if self.cmd_mngr.parse_cmd_from_ssk(self.ssk) == CommandManager.S_ABORT:
                logger.debug("connection closed by peer")
                callback.on_msg_send_error(UtransError.CONNECTION_ERROR, task_info)
                return False
        cmd = self.cmd_mngr.get()
        if "status" not in cmd.keys():
            logger.debug("invalid cmd")
            callback.on_msg_send_error(UtransError.INVALID_CMD, task_info)
            return False
        if cmd["status"] != "ok":
            logger.debug("peer responsed failed")
            callback.on_msg_send_error(UtransError.PEER_SAY_FAILED, task_info)
            return False
        callback.on_msg_send_finished(UtransError.OK, task_info)
        return True
        
    def request_file(self, filepath):
        if self.ssk == None or self.mode != Utrans.M_NORMAL:
            logger.debug("invalid operation for mode", self.mode)
            return False
        pass

    def receive_file(self, cmd, callback:UtransCallback, task_info = None):
        if self.ssk == None or self.mode != Utrans.M_NORMAL:
            logger.debug("invalid operation for mode", self.mode)
            callback.on_error("Utran core config error")
            return False

        if task_info == None:
            task_info = UtransTask()
        
        if "name" not in cmd.keys() or "size" not in cmd.keys():
            logger.debug("invalid file send cmd")
            callback.on_file_send_error(UtransError.INVALID_CMD, task_info)
            return False
        
        try:
            filename = self.base64_decode_str(cmd["name"])
            filesize = int(cmd["size"])
        except Exception as e:
            print(e)
            callback.on_file_send_error(UtransError.INVALID_CMD, task_info)
            return False
        
        if callback.on_need_decision("Receive file[%s %s]?"%(filename, filesize)) == False:
            packed_cmd = self.cmd_mngr.pack_reject_reply()
            try:
                self.ssk.send(packed_cmd)
            except Exception as e:
                callback.on_file_send_error(UtransError.CONNECTION_ERROR, task_info)
                return False
            callback.on_file_send_error(UtransError.USER_REJECT, task_info)
            return False

        # start to receive file callback
        callback.on_file_receive_start(filename, filesize, task_info)
        packed_cmd = self.cmd_mngr.pack_accept_reply()
        try:
            self.ssk.send(packed_cmd)
        except Exception as e:
            print(e)
            callback.on_file_send_error(UtransError.CONNECTION_ERROR, task_info)

        # todo: There may be a file with the same name, so check it.
        self.ssk.settimeout(5)
        left_size = filesize
        split_size = 0
        with open(filename + ".downloading", "wb") as f:
            # todo: change this to be configurable in config
            while True:
                try:
                    data = self.ssk.recv(Utrans.SPLIT_LEN)
                except Exception as e:
                    print(e)
                    callback.on_file_send_error(UtransError.CONNECTION_ERROR, task_info)
                    break
                split_size = len(data)
                if split_size == 0:
                    logger.log("peer close connection")
                    callback.on_file_send_error(UtransError.CONNECTION_ERROR, task_info)
                    return False
                if left_size >= split_size:
                    left_size -= split_size
                else:
                    split_size = left_size
                    left_size = 0
                try:
                    f.write(data[0:split_size])
                except Exception as e:
                    print(e)
                    callback.on_file_send_error(UtransError.LOCAL_ERROR,task_info)
                    return False
                progress = (filesize - left_size) / filesize
                # on pregress callback
                callback.on_file_sending(progress, task_info)
                if left_size == 0:
                    break
        self.ssk.settimeout(None)
        if left_size > 0:
            logger.debug("data not complete")
            packed_cmd = self.cmd_mngr.pack_failed_reply()
            try:
                self.ssk.send(packed_cmd)
            except Exception as e:
                print(e)
                callback.on_file_send_error(UtransError.CONNECTION_ERROR, task_info)
            return False
        
        packed_cmd = self.cmd_mngr.pack_ok_reply()
        try:
            self.ssk.send(packed_cmd)
        except Exception as e:
            print(e)
            callback.on_file_send_error(UtransError.CONNECTION_ERROR, task_info)
            return False
        org_filename = filename
        for i in range(1000):
            if not os.path.exists(filename):
                break
            filename = str(i) + org_filename
        
        if os.path.exists(filename):
            print("two many files with the same name")
            callback.on_file_send_error(UtransError.REPEAT_FILE, task_info)
            return False

        os.rename(org_filename + ".downloading", filename)
        callback.on_file_send_finished(UtransError.OK, task_info)
        return True

    def receive_message(self, cmd, callback:UtransCallback, task_info = None):
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
            if msg_size > 4*1024*10:
                packed_cmd = self.cmd_mngr.pack_reject_reply()
                self.ssk.send(packed_cmd)
                return None

            msg = b''
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
                msg += data[0:split_size]
            if left_size > 0:
                if split_size == 0:
                    logger.debug("peer close connection")
                else:
                    logger.debug("data not complete")
                    packed_cmd = self.cmd_mngr.pack_failed_reply()
                    self.ssk.send(packed_cmd)
                return False
            msg = msg.decode(encoding="utf8")
        # success to receive message
        packed_cmd = self.cmd_mngr.pack_ok_reply()
        try:
            self.ssk.send(packed_cmd)
        except Exception as e:
            print(e)
        
        callback.on_msg_receive(msg, task_info)
        return True
    
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
            stop_task.async_run()
    
    @staticmethod
    def send_init_message(sk, name):
        packed_cmd = CommandManager.pack_init_msg(name)
        sk.send(packed_cmd)
    
class UtransServer:

    def __init__(self):
        self.name = "server"
        self.running = False
        self.enable_broadcast = True
        self.broadcast_interval = 2
        self.lsk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def init(self):
        logger.debug("server start to listen")
        self.lsk.bind(('0.0.0.0', Utrans.DEFAULT_SERVICE_PORT))
        self.lsk.listen(2)
        self.broadcast_service()
    
    def handle_client(self, ssk:socket.socket, addr):
        cmd_mngr = CommandManager()
        utrans = Utrans(Utrans.M_NORMAL)
        utrans.set_session(ssk)
        callback = self.callback

        # get init info
        if cmd_mngr.parse_cmd_from_ssk(ssk) == CommandManager.S_ABORT:
            logger.debug("peer close connection")
            return
        cmd = cmd_mngr.get()
        if "type" not in cmd.keys():
            logger.debug("client send invalid init message")
            ssk.close()
            return
        elif cmd["type"] != "init":
            logger.debug("init message has invalid type")
            ssk.close()
            return 
        
        if "name" in cmd.keys():
            client_name = cmd["name"]
        else:
            client_name = "%s@%s"%(addr[0], addr[1])
        session = UtransSession(client_name, addr, ssk, UtransSession.T_RECV)
        session_index = callback.on_new_session(session)

        # ok, start handling requests
        while True:
            if cmd_mngr.parse_cmd_from_ssk(ssk) == CommandManager.S_ABORT:
                logger.debug("peer close connection")
                callback.on_session_close(session_index)
                break
            cmd = cmd_mngr.get()
            if cmd["type"] != "ask":
                logger.debug("invalid request")
                continue
            
            if "cmd" not in cmd.keys():
                logger.debug("invalid ask request")
                continue

            if cmd["cmd"] == "send":
                if cmd["datatype"] == "msg":
                    task_info = UtransTask(session_index = session_index)
                    utrans.receive_message(cmd, callback, task_info)
                elif cmd["datatype"] == "file":
                    # ask for confirmation
                    task_info = UtransTask(session_index = session_index)
                    utrans.receive_file(cmd, callback, task_info)
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
        logger.debug("start broadcasting service")
        self.enable_broadcast = True
        utrans = Utrans(Utrans.M_BROADCAST)
        try:
            while self.enable_broadcast:
                utrans.send_service_discovery_message()
                time.sleep(self.broadcast_interval)
        except Exception as e:
            print(e)
        finally:
            self.enable_broadcast = False
        
    def run(self, callback):
        self.init()
        self.callback = callback
        self.running = True
        try:
            while True:
                ssk, addr = self.lsk.accept()
                logger.debug("connected with " + str(addr))
                _thread.start_new_thread(self.handle_client, (ssk, addr))
        except Exception as e:
            print(e)
            logger.debug("server exception")
        finally:
            self.running = False
            self.lsk.close()

    def stop_broadcast(self):
        self.enable_broadcast = False
    
    def stop_server(self):
        if self.running == True:
            self.lsk.close()
            self.running = False
    
    def async_run(self, callback):
        _thread.start_new_thread(self.run, (callback,))


class UtransClient:
    def __init__(self, id = "client"):
        self.id = id
        self.current_session = None
        self.scanner = Utrans(Utrans.M_SCAN)
    
    def set_current_session(self, session):
        self.current_session = session

    def get_current_session(self):
        return self.current_session
    
    def start_scan(self, callback, time = 0):
        self.scanner.start_scan_service(callback, time)

    def stop_scan(self):
        self.scanner.stop_scan_service()

    def connect(self, server:UtransServerInfo, callback):
        sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sk.settimeout(3)
        logger.debug("connect")
        try:
            sk.connect(server.addr)
        except Exception as e:
            print(e)
            callback.on_connect_error(UtransError.CONNECTION_ERROR)
            return False
        session = UtransSession(server.name, server.addr, sk)
        # save the session
        self.current_session = session
        # new session
        Utrans.send_init_message(sk, socket.gethostname())
        callback.on_new_session(session)
        return True

    def send_file(self, filename, callback, task_info:UtransTask = None, block = True, session:UtransSession = None):
        if session is None:
            session = self.current_session
        if task_info == None:
            task_info = UtransTask()
        if not os.path.exists(filename):
            callback.on_file_send_error(UtransError.NO_SUCH_FILE, task_info)
            return False
        utrans = Utrans(Utrans.M_NORMAL)
        utrans.set_session(session.sk)
        if block:
            return utrans.send_file(filename, task_info, callback)
        else:
            _thread.start_new_thread(utrans.send_file, (filename, task_info, callback))
            return True
    
    def send_files(self, filenames, callback, task_infos = None, session:UtransSession = None):
        if session is None:
            session = self.current_session
        
        if task_infos == None:
            task_infos = (UtransTask() for i in range(len(filenames)))
        _thread.start_new_thread(self.__do_send_files, (filenames, callback, task_infos, session))

    def __do_send_files(self, filenames, callback, task_infos, session):

        for filename, task_info in zip(filenames, task_infos):
            self.send_file(filename, callback, task_info = task_info, block=True, session=session)
       
    def send_message(self, msg, callback, task_info:UtransTask = None, block = False, session:UtransSession = None):
        if session is None:
            session = self.current_session
        utrans = Utrans(Utrans.M_NORMAL)
        utrans.set_session(session.sk)
        if task_info == None:
            task_info = UtransTask()
        if block:
            utrans.send_message(msg, callback, task_info)
        else:
            _thread.start_new_thread(utrans.send_message, (msg, callback, task_info))
    
    def authenticate(self, session:UtransSession):
        print("not support")

    def async_test(self, callback):
        _thread.start_new_thread(time.sleep, (3,))
        callback.on_finished("ok")

