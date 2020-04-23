#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Date: Wed Apr 15 09:09:51 2020
# Author: January

from utrans.utils import *
from utrans.interface import *
from utrans.network import *
import hashlib
import hmac
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
import traceback
import termcolor

logger = logging.getLogger("utranscore")

class UtransDefault:
    SERVICE_PORT = 9999
    SCAN_PORT = 9999

class Message:
    msg_char_check = re.compile(r"[&@]")
    FIELD_SPLIT_CHAR = "&"
    KEY_VALUE_SPLIT_CHAR = "@"

    MT_SEND_FILE = "send_file"
    MT_SEND_MSG = "send_msg"
    MT_SCAN_REQ = "scan_req"
    MT_SCAN_REPLY = "scan_reply"
    MT_COM_REPLY = "common_reply"
    MT_REGISTER = "register"
    MT_SESSION_INIT = "session_init"
    MT_SESSION_REPLY = "session_reply"
    MT_SESSION_RECONNECT = "session_reconnect"
    MT_SESSION_FINAL = "session_final"
    MT_SESSION_CLOSE ="close_session"

    R_OK = "ok"
    R_REJECT = "reject"
    R_FAILED = "failed"

    MSG_TYPE = None

    @staticmethod
    def load_type():
        Message.MSG_TYPE = {
            Message.MT_SEND_FILE : ("msg_type", "name", "size"),
            Message.MT_SEND_MSG : ("msg_type", "size", "data"),
            Message.MT_COM_REPLY : ("msg_type", "status", "info"),
            Message.MT_SCAN_REQ : ("msg_type", ),
            Message.MT_SCAN_REPLY : ("msg_type", "name", "addr"),

            # new session setup procedure
            Message.MT_REGISTER : ("msg_type", "name", "uuid", "data"),
            Message.MT_SESSION_INIT : ("msg_type", "name", "uuid", "data"),
            Message.MT_SESSION_RECONNECT : ("msg_type", "name", "uuid", "data"),
            Message.MT_SESSION_CLOSE : ("msg_type", ),
            Message.MT_SESSION_REPLY : ("msg_type", "name", "uuid", "data"),

            Message.MT_SESSION_FINAL : ("msg_type", "recv_port", "data")
    }
    
    def __init__(self, values):
        self.type = values[0]
        self.keys = Message.MSG_TYPE[self.type]
        self.values = values
    
    def get_data(self):
        if self.keys[-1] == "data":
            return self.values[-1]
        else:
            raise Exception("%s has not data"%(self.type))
    
    def set_data(self, data:bytes):
        if self.keys[-1] == "data":
            self.values[-1] = data
        else:
            raise Exception("%s has not data"%(self.type))
    
    def to_dict(self):
        msg_dict = {}
        for key, value in zip(self.keys, self.values):
            msg_dict[key] = value
        return msg_dict
    
    def to_bytes(self):
        keys = self.keys
        values = self.values
        if self.keys[-1] == "data":
            values[-1] = base64_encode(values[-1])
        
        Message.check_ctrl_char(values)
        msg_str = '%s@%s'%(keys[0], values[0])
        for i in range(1, len(keys)):
            key = keys[i]
            value = values[i]
            msg_str += "&%s@%s"%(key, value)
        return msg_str.encode("utf8")

    @staticmethod
    def from_bytes(bytes_msg):
        split_bytes_msg = bytes_msg.decode(encoding="utf8").split(Message.FIELD_SPLIT_CHAR)
        keys = []
        values = []
        for key_value in split_bytes_msg:
            key, value = key_value.split(Message.KEY_VALUE_SPLIT_CHAR)
            keys.append(key)
            values.append(value)
        Message.check_msg(keys, values)
        if keys[-1] == "data":
            values[-1] = base64_decode(values[-1])
        msg = Message(values)
        return msg
    
    @staticmethod
    def check_msg(msg_keys, msg_values):
        if len(msg_keys) != len(msg_values):
            raise Exception("key value size not match")

        if msg_keys[0] != "msg_type":
            raise Exception("invalid msg with first key [%s]"%(msg_keys[0]))

        msg_type = msg_values[0]
        if msg_type not in Message.MSG_TYPE.keys():
            raise Exception("unknown msg type:[%s]"%(msg_type))
        
        msg_fields = Message.MSG_TYPE[msg_type]
        if len(msg_keys) != len(msg_fields):
            raise Exception("key size not match msg type")
        for key_a, key_b in zip(msg_fields, msg_keys):
            if key_a != key_b:
                raise Exception("invalid key in msg type [%s]"%(msg_type))

    @staticmethod
    def check_ctrl_char(datas):
        if datas == None:
            return
        logger.debug("checking msg:\n%s"%(str(datas)))
        for data in datas:
            if data == None:
                continue
            if Message.msg_char_check.search(data) != None:
                raise Exception("Data can't contains [:&]")
    
    @staticmethod
    def pack_session_init(name, uuid, data = None):
        values = [Message.MT_SESSION_INIT, name, uuid, data]
        return Message(values)
    @staticmethod
    def pack_session_final(server_port, data = None):
        values = [Message.MT_SESSION_FINAL, str(server_port), data]
        return Message(values)
    # ("msg_type", "name", "uuid", "encode", "data")
    @staticmethod
    def pack_session_reply(name, uuid, data = None):
        values = [Message.MT_SESSION_REPLY, name, uuid, data]
        return Message(values)
    
    @staticmethod
    def pack_session_reconnect(name, uuid, data = None):
        values = [Message.MT_SESSION_RECONNECT, name, uuid, data]
        return Message(values)

    @staticmethod
    def pack_register(name, uuid, data = None):
        values = [Message.MT_REGISTER, name, uuid, data]
        return Message(values)

    # ("msg_type")
    @staticmethod
    def pack_scan_request():
        values = [Message.MT_SCAN_REQ]
        return Message(values)
    
    # ("msg_type", "name", "ip", "port")
    @staticmethod
    def pack_scan_reply(name, server_addr):
        values = [Message.MT_SCAN_REPLY, name, server_addr]
        return Message(values)

    # ("msg_type", "size", "encode", "data")
    @staticmethod
    def pack_send_message(msg:str):
        b_msg = msg.encode("utf8")
        values = [Message.MT_SEND_MSG, str(len(b_msg)), b_msg]
        return Message(values)

    # ("msg_type", "name", "size")
    @staticmethod
    def pack_send_file(filename:str, filesize:int):
        values = [Message.MT_SEND_FILE, filename, str(filesize)]
        return Message(values)

    # ("msg_type", "status", "info")
    @staticmethod
    def pack_common_reply(reply_status, info = None):
        values = [Message.MT_COM_REPLY, reply_status, info]
        return Message(values)

Message.load_type()

class MessageHandler:

    def __init__(self, ssk:FrameSocket = None):
        self.ssk = ssk
    
    def set_socket(self, ssk:FrameSocket = None):
        self.ssk = ssk

    def recv_msg(self):
        ssk = self.ssk
        b_msg, finished = ssk.recv_frame()
        logger.debug("Receive raw msg:\n%s"%(b_msg))
        if not finished:
            raise Exception("msg not in a normal frame")
        msg = Message.from_bytes(b_msg)
        return msg
    
    def send_msg(self, msg):
        ssk = self.ssk
        b_msg = msg.to_bytes()
        ssk.send_frame(b_msg)

# seperate scanner from Utrans
class UtransScanner:

    def __init__(self, scan_port = UtransDefault.SCAN_PORT):
        # init state
        self.scanning = False
        # init socket
        self.scan_sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.scan_sk.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.scan_sk.settimeout(0.1)
        # other data
        self.__discovered_servers = set()
        self.ip = get_self_ip()

        # scan request broadcast addr
        ip = self.ip.split(".")
        ip[3] = "255"
        broadcast_ip = '.'.join(ip)
        self.broadcast_addr = (broadcast_ip, scan_port)
        self.scan_request_msg = Message.pack_scan_request().to_bytes()
    
    def __do_scan_service(self, callback:UtransCallback):
        callback.on_start_scan()
        count = 0
        logger.debug("self ip is [%s]"%(self.ip))
        while self.scanning:
            try:
                data, address = self.scan_sk.recvfrom(4096)
            except socket.timeout:
                count += 1
                if count >= 10:
                    count = 0
                    self.__send_scan_request()
                continue

            # 过滤本机发出的数据包
            if self.ip == address[0] or address[0] == "127.0.0.1":
                continue
            
            logger.debug("scanner recv [%s] from %s"%(data, str(address)))
            try:
                msg = Message.from_bytes(data)
            except:
                traceback.print_exc()
                logger.debug("fail to parse message")
                logger.debug(data)
                continue
            if msg.type != Message.MT_SCAN_REPLY:
                logger.debug("Receive invalid scan reply message, msg_type[%s]"%(msg["msg_type"]))
                continue
            msg_dict = msg.to_dict()
            server_name = msg_dict["name"]
            raw_server_addr = msg_dict["addr"]
            try:
                addr = upack_addr(raw_server_addr)
            except:
                logger.debug("invalid addr in scan reply")
                continue
            address = (address[0], addr[1])
            if self.scanning and address not in self.__discovered_servers:
                self.__discovered_servers.add(address)
                new_server = UtransServerInfo(server_name, address)
                callback.on_new_server(new_server)
        callback.on_stop_scan()

    def __send_scan_request(self):
        self.scan_sk.sendto(self.scan_request_msg, self.broadcast_addr)
    
    def set_scan_port(self, port:int):
        self.broadcast_addr = (self.broadcast_addr[0], port)

    def stop_scan(self):
        if self.scanning == True:
            self.scanning = False
            self.__discovered_servers.clear()
            logger.debug("stop service discovery")
    
    def start_scan(self, callback, time = 0):
        # broadcast scan request
        self.__send_scan_request()
        if self.scanning == True:
            logger.debug("already in scanning")
            return True
        self.scanning = True
        _thread.start_new_thread(self.__do_scan_service, (callback, ))
        logger.debug("start service discovery")
        if time != 0:
            stop_task = Runnable(self.stop_scan_service, (), time)
            stop_task.async_run()

class UtransScanResponder:
    def __init__(self, name = None, server_ip = None, port = 9999):
        if name == None:
            self.name = socket.gethostname()
        else:
            self.name = name
        
        if server_ip == None:
            self.server_ip = get_self_ip()
        else:
            self.server_ip = server_ip
        
        self.service_port = port
        self.scan_server_addr = ("0.0.0.0", port)

        # set scan response message
        self.update_response_msg()
        self.running = False
    
    def init_socket(self):
        self.sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sk.bind(self.scan_server_addr)

    def update_response_msg(self):
        self.scan_response_msg = Message.pack_scan_reply(self.name, "%s:%d"%(self.server_ip, self.service_port)).to_bytes()

    def set_name(self, name):
        self.name = name
        self.update_response_msg()
    
    def set_port(self, port):
        self.service_port = port 
        self.update_response_msg()

    def start(self):
        self.running = True
        self.init_socket()
        while self.running:
            try:
                data, addr = self.sk.recvfrom(1024)
            except Exception as e:
                logger.debug("scan reponder failure")
                return
            logging.debug("scan server recv [%s] from %s"%(data, str(addr)))
            try:
                msg = Message.from_bytes(data)
            except:
                continue
            if msg.type == Message.MT_SCAN_REQ:
                # response
                self.sk.sendto(self.scan_response_msg, addr)
    
    def stop(self):
        self.sk.close()
        self.running = False
    
    def asyn_start(self):
        _thread.start_new_thread(self.start, ())

class UtransCore:
    NETWORK_TIMEOUT = 3
    SPLIT_LEN = 4096

    def __init__(self, sk:FrameSocket = None):
        self.msg_handler = MessageHandler()
        self.set_socket(sk)
    
    def set_socket(self, sk:FrameSocket):
        self.ssk = sk
        self.msg_handler.set_socket(sk)

    def authenitcate_client_normal(self, session_init_msg, context:UtransContext):
        ssk = self.ssk
        msg_handler = self.msg_handler
        msg = session_init_msg
        session_manager = context.get_session_manager()
        auth_manager = context.get_auth_manager()
        name = auth_manager.get_name() 
        uuid = auth_manager.get_uuid()

        if msg.type != Message.MT_SESSION_INIT:
            return None
        msg_dict = msg.to_dict()
        peer_name = msg_dict["name"]
        peer_uuid = msg_dict["uuid"]

        # session manager to deal with session lookup
        session = session_manager.get_session_by_uuid(peer_uuid)
        if session != None and session.is_recv_enabled():
            return None
        session = UtransSession(context, name = peer_name, uuid = peer_uuid)

        if not auth_manager.check_register(peer_uuid):
            register_msg = Message.pack_register(name, uuid)
            # auth manager to deal with auth data of msg
            auth_manager.set_auth_data(register_msg)
            msg_handler.send_msg(register_msg)
            try:
                register_reply = msg_handler.recv_msg()
            except:
                traceback.print_exc()
                return None
            if not auth_manager.register_peer(register_reply):
                return None
        
        # reject connection if it alreadly exists here.
        if not auth_manager.auth_msg(msg, session):
            return None

        session_reply_msg = Message.pack_session_reply(name, uuid)
        auth_manager.set_auth_data(session_reply_msg, session)
        msg_handler.send_msg(session_reply_msg)

        try:
            msg = msg_handler.recv_msg()
        except:
            traceback.print_exc()
            return None
        
        if msg.type == Message.MT_REGISTER:
            if not auth_manager.register_peer(register_reply):
                return None
            register_msg = Message.pack_register(name, uuid)
            auth_manager.set_auth_data(register_msg, session)
            msg_handler.send_msg(register_msg)
            try:
                msg = msg_handler.recv_msg()
            except:
                traceback.print_exc()
                return None

        if msg.type != Message.MT_SESSION_FINAL:
            return None
        
        if not auth_manager.auth_msg(msg, session):
            return None
        msg_dict = msg.to_dict()
        try:
            recv_port = int(msg_dict["recv_port"])
            peer_addr = (ssk.getpeername()[0], recv_port) 
        except:
            traceback.print_exc()
            logger.warning("peer server addr is invalid")
            peer_addr = None
        session.set_peer_addr(peer_addr)
        session.finish_init()
        return session

    def authenticate_client_fast(self, msg, context):
        sk = self.ssk
        msg_handler = self.msg_handler
        auth_manager = context.get_auth_manager()
        session_manager = context.get_session_manager()
        name = auth_manager.get_name()
        uuid = auth_manager.get_uuid()
        if msg.type != Message.MT_SESSION_RECONNECT:
            return None
        msg_dict = msg.to_dict()
        peer_name = msg_dict["name"]
        peer_uuid = msg_dict["uuid"]
        session = session_manager.get_session_by_uuid(peer_uuid)
        if session == None:
            return None
        if not auth_manager.auth_msg(msg, session):
            return None
        auth_result_msg = Message.pack_session_reconnect(name, uuid)
        auth_manager.set_auth_data(auth_result_msg, session)
        msg_handler.send_msg(auth_result_msg)
        return session

    def authenticate_client(self, context:UtransContext):
        ssk = self.ssk
        msg_handler = self.msg_handler
        ssk.settimeout(3)
        session = None
        try:
            msg = msg_handler.recv_msg()
        except BaseException as e:
            logger.error("fail to recv init data")
            traceback.print_exc()
            return None
        # deal with register
        if msg.type == Message.MT_SESSION_INIT:
            session = self.authenitcate_client_normal(msg, context)
        elif msg.type == Message.MT_SESSION_RECONNECT:
            session =  self.authenticate_client_fast(msg, context)
        ssk.settimeout(None)
        if session != None:
            session.set_recv_sk(ssk)
        return session

    # used by client
    def authenticate_server_fast(self, session, context:UtransCallback) -> bool:
        ssk = self.ssk
        msg_handler = self.msg_handler
        session_manager = context.get_session_manager()
        auth_manager = context.get_auth_manager()
        name = auth_manager.get_name()
        uuid = auth_manager.get_uuid()

        if session == None or not session.is_init():
            raise Exception("Invalid session for fast authentication")

        session_reconnect_msg = Message.pack_session_reconnect(name, uuid)
        if not auth_manager.set_auth_data(session_reconnect_msg, session):
            return False
        try:
            msg_handler.send_msg(session_reconnect_msg)
        except:
            traceback.print_exc()
            return False

        try:
            msg = msg_handler.recv_msg()
        except:
            traceback.print_exc()
            return False
        if msg.type != Message.MT_SESSION_RECONNECT:
            logger.debug("expect msg[%s], but recv [%s]"%(Message.MT_SESSION_RECONNECT, msg.type))
            return False
        if not auth_manager.auth_msg(msg, session):
            return False
        session.set_send_sk(ssk)
        return True

    # used by client
    def authenticate_server_normal(self, session, context:UtransScanResponder) -> bool:
        ssk = self.ssk
        msg_handler = self.msg_handler
        session_manager = context.get_session_manager()
        auth_manager = context.get_auth_manager()
        name = auth_manager.get_name()
        uuid = auth_manager.get_uuid()
        
        if session == None or session.is_init():
            raise Exception("invalid session for normal authentication")

        session_init_msg = Message.pack_session_init(name, uuid)
        if not auth_manager.set_auth_data(session_init_msg, session):
            return False
        msg_handler.send_msg(session_init_msg)

        try:
            msg = msg_handler.recv_msg()
        except:
            traceback.print_exc()
            return False
        
        if msg.type == Message.MT_REGISTER:
            if not auth_manager.register_peer(msg):
                return False
            register_msg = Message.pack_register(name, uuid)
            if not auth_manager.set_auth_data(register_msg, session):
                return False
            msg_handler.send_msg(register_msg)

            try:
                msg = msg_handler.recv_msg()
            except:
                traceback.print_exc()
                return False
        
        if msg.type != Message.MT_SESSION_REPLY:
            return False
        
        msg_dict = msg.to_dict()
        peer_name = msg_dict["name"]
        peer_uuid = msg_dict["uuid"]
        if not auth_manager.check_register(peer_uuid):
            register_msg = Message.pack_register(name, uuid)
            if not auth_manager.set_auth_data(register_msg, session):
                return False
            msg_handler.send_msg(register_msg)
            try:
                register_msg = msg_handler.recv_msg()
            except:
                traceback.print_exc()
                return False
            if not auth_manager.register_peer(register_msg):
                return False
        if not auth_manager.auth_msg(msg, session):
            return False
        session.set_name(peer_name)
        session.set_uuid(peer_uuid)
        recv_port = context.get_self_server_port()
        session_final_msg = Message.pack_session_final(recv_port)
        if not auth_manager.set_auth_data(session_final_msg, session):
            return False
        msg_handler.send_msg(session_final_msg)
        session.set_send_sk(ssk)
        session.set_peer_addr(ssk.getpeername())
        session.finish_init()
        return True
    
    def authenticate_server(self, session, context:UtransContext):
        if not session.is_init():
            return self.authenticate_server_normal(session, context)
        else:
            return self.authenticate_server_fast(session, context)
    
    # The "task_info" is used to discriminate and control(i.e. to stop) every asynchronous call to "send_file" in callback function
    def send_file(self, filepath, callback:UtransCallback, task_info:UtransTaskInfo = None):
        # read filename and file size
        # make sure the file exists in high level APIs of UtransClient
        ssk = self.ssk
        if task_info == None:
            task_info = UtransTaskInfoInfo()
        task_info.type = UtransTaskInfo.T_S_FILE
        msg_handler = self.msg_handler
        filesize = os.path.getsize(filepath)
        filename = os.path.basename(filepath)
        # file send start callback
        task_info.set_extra_data((filename, filesize))
        callback.on_task_start(task_info)
        
        # send file-send request
        file_send_msg = Message.pack_send_file(filename, filesize)
        try:
            msg_handler.send_msg(file_send_msg)
        except:
            traceback.print_exc()
            callback.on_task_finished(UtransError.CONNECTION_ERROR, task_info)
            return False
        
        # get reply
        ssk.settimeout(20)
        try:
            msg = msg_handler.recv_msg()
        except:
            traceback.print_exc()
            callback.on_task_finished(UtransError.CONNECTION_ERROR, task_info)
            return False
        msg = msg.to_dict()
        if msg["msg_type"] != Message.MT_COM_REPLY:
            logger.debug("protocol error")
            callback.on_task_finished(UtransError.PROTOCAL_ERROR, task_info)
            return False

        if msg["status"] != Message.R_OK:
            logger.debug("peer reject")
            callback.on_task_finished(UtransError.PEER_REJECT, task_info)
            return False

        # start sending file
        ssk.settimeout(UtransCore.NETWORK_TIMEOUT)
        ssk.start_transmit_large_frame(filesize)
        with open(filepath, "rb") as f:
            while True:
                try:
                    data = f.read(UtransCore.SPLIT_LEN)
                except:
                    traceback.print_exc()
                    #logger.error("[send_file] fail to read file [%s]"%(e))
                    callback.on_task_finished(UtransError.LOCAL_ERROR, task_info)
                    return False
                # finish read
                if len(data) == 0:
                    break
                try:
                    status = ssk.transmit_large_frame(data)
                except:
                    traceback.print_exc()
                    callback.on_task_finished(UtransError.CONNECTION_ERROR, task_info)
                    return False
                progress = ssk.get_transmit_progress()
                # on progress callback
                callback.on_task_progress(progress, task_info)
                # stop sending file
                if task_info.running == False:
                    callback.on_file_send_stop(task_info)
                    return False
        if status == False:
            logger.error("file transmit not finish")
            return False

        # get reply
        try:
            msg = msg_handler.recv_msg()
        except:
            traceback.print_exc()
            return False
        msg = msg.to_dict()
        if msg["msg_type"] != Message.MT_COM_REPLY:
            logger.debug("ProtocalError: Not a reply message")
            callback.on_task_finished(UtransError.PROTOCAL_ERROR, task_info)
            return False
        
        if msg["status"] != Message.R_OK:
            logger.debug("peer responsed failed")
            callback.on_task_finished(UtransError.PEER_SAY_FAILED, task_info)
            return False
        # success sending file
        callback.on_task_finished(UtransError.OK, task_info)
        return True
        
    def send_message(self, message:str, callback:UtransCallback, task_info:UtransTask = None):
        msg_handler = self.msg_handler
        msg_send_msg = Message.pack_send_message(message)
        if task_info == None:
            task_info = UtransTaskInfoInfo()
        task_info.type = UtransTaskInfo.T_S_MSG
        try:
            msg_handler.send_msg(msg_send_msg)
        except:
            traceback.print_exc()
            callback.on_task_finished(UtransError.CONNECTION_ERROR, task_info)
            return False
        callback.on_task_finished(UtransError.OK, task_info)
        return True
        
    def request_file(self, filepath):
        logger.debug("invalid operation for mode", self.mode)
        return False

    def receive_file(self, msg, callback:UtransCallback, task_info = None):
        ssk = self.ssk
        msg_handler = self.msg_handler

        if task_info == None:
            task_info = UtransTaskInfoInfo()
        task_info.type = UtransTaskInfo.T_R_FILE
        msg = msg.to_dict()
        filename = msg["name"]
        try:
            filesize = int(msg["size"])
        except:
            traceback.print_exc()
            callback.on_task_finished(UtransError.INVALID_CMD, task_info)
            return False
        callback.on_receive_file(filename, filesize, task_info)
        if not callback.on_need_decision("Receive file[%s %s]?"%(filename, filesize)):
            reply_msg = Message.pack_common_reply(Message.R_REJECT)
            try:
                msg_handler.send_msg(reply_msg)
            except:
                traceback.print_exc()
                callback.on_task_finished(UtransError.CONNECTION_ERROR, task_info)
                return False
            logger.debug("User reject receiving file")
            return False
        # reply ok
        reply_msg = Message.pack_common_reply(Message.R_OK)
        try:
            msg_handler.send_msg(reply_msg)
        except:
            traceback.print_exc()
            callback.on_task_finished(UtransError.CONNECTION_ERROR, task_info)
            return False
        # start to receive file callback
        task_info.set_extra_data((filename, filesize))
        callback.on_task_start(task_info)
        
        # todo: There may be a file with the same name, so check it.
        with open(filename + ".downloading", "wb") as f:
            # todo: change this to be configurable in config
            while True:
                try:
                    data, finish = ssk.recv_frame(UtransCore.SPLIT_LEN)
                except:
                    traceback.print_exc()
                    return False
                try:
                    f.write(data)
                except:
                    traceback.print_exc()
                    callback.on_task_finished(UtransError.LOCAL_ERROR,task_info)
                    return False
                progress = ssk.get_transmit_progress()
                callback.on_task_progress(progress, task_info)
                if finish:
                    break
                if task_info.running == False:
                    callback.on_file_send_stop(task_info)
                    return False
        reply_msg = Message.pack_common_reply(Message.R_OK)
        try:
            msg_handler.send_msg(reply_msg)
        except:
            traceback.print_exc()
            callback.on_task_finished(UtransError.CONNECTION_ERROR, task_info)
            return False
        org_filename = filename
        for i in range(1000):
            if not os.path.exists(filename):
                break
            filename = "%d_%s"%(i, org_filename)
        
        if os.path.exists(filename):
            print("two many files with the same name")
            callback.on_task_finished(UtransError.REPEAT_FILE, task_info)
            return False
        os.rename(org_filename + ".downloading", filename)
        callback.on_task_finished(UtransError.OK, task_info)
        return True

    def receive_message(self, msg, callback:UtransCallback, task_info = None):
        msg_data = msg.get_data()
        msg_content = msg_data.decode("utf8")
        callback.on_receive_msg(msg_content, task_info)
        return True

class UtransServer():

    def __init__(self, context:UtransContext, port = UtransDefault.SERVICE_PORT):
        self.running = False
        self.context = context
        self.port = port
        self.scan_responder = UtransScanResponder(name = context.get_auth_manager().get_name(), port = self.port)
        logger.debug("server port: %d"%(port))

    def init(self):
        self.lsk = FrameSocket(socket.AF_INET, socket.SOCK_STREAM)
        self.lsk.bind(('0.0.0.0', self.port))
        self.lsk.listen(2)
        logger.debug("server start to listen")
        self.scan_responder.asyn_start()
        logger.debug("scan server starts")

    def handle_client(self, ssk:socket.socket, addr):
        msg_handler = MessageHandler(ssk)
        utrans = UtransCore(ssk)
        callback = self.callback
        session = utrans.authenticate_client(self.context)
        if session == None:
            logger.debug("fail to authenticate")
            return 
        else:
            logger.debug("authenticate ok")
            session.print_info()
        callback.on_new_session(session)

        # ok, start handling requests
        while True:
            try:
                msg = msg_handler.recv_msg()
            except:
                traceback.print_exc()
                callback.on_session_close(session)
                break
            logger.debug("acquire lock")
            self.context.display_lock.acquire()
            task_info = UtransTaskInfo(session_index = session.id)
            if msg.type == Message.MT_SEND_FILE:
                utrans.receive_file(msg, callback, task_info)
            elif msg.type == Message.MT_SEND_MSG:
                utrans.receive_message(msg, callback, task_info)
            else:
                utrans.send_not_support_info()
                print("unknown operation: %s"%(msg_type))
            self.context.display_lock.release()
            logger.debug("release lock")

    # open a new thread to broadcast
    def run(self, callback):
        self.init()
        self.callback = callback
        self.running = True
        try:
            while True:
                ssk, addr = self.lsk.accept()
                logger.debug("connection from" + str(addr))
                _thread.start_new_thread(self.handle_client, (ssk, addr))
        except:
            logger.debug("server exit")
        finally:
            self.running = False
            self.lsk = None
    
    def stop_scan_service(self):
        self.scan_responder.stop()

    def stop_server(self):
        if self.running == True:
            if self.lsk != None:
                self.lsk.close()
                self.lsk = None
            self.running = False
            self.stop_scan_service()
    
    def async_run(self, callback):
        return _thread.start_new_thread(self.run, (callback,))

class UtransSession():
    F_INIT = 0x1
    F_RECV_OK = 0x2
    F_SEND_OK = 0x4
    F_KEEP = 0X8

    def __init__(self, context, name = None, uuid = None, peer_addr = None, session_key = None, send_sk = None, recv_sk = None):
        self.context = context
        self.peer_name = name
        self.peer_uuid = uuid
        self.session_key = session_key
        self.peer_addr = peer_addr
        self.send_sk = send_sk
        self.recv_sk = recv_sk
        # index in session manager
        self.id = -1
        self.auth_counter = 0
        self.peer_auth_counter = 0
        self.send_lock = _thread.allocate_lock()
        self.status = 0

    def set_id(self, id):
        self.id = id
    
    def set_name(self, peer_name):
        self.peer_name = peer_name
    
    def set_uuid(self, peer_uuid):
        self.peer_uuid = peer_uuid

    def set_session_key(self, key):
        self.session_key = key
    
    def set_peer_addr(self, addr):
        self.peer_addr = addr
    
    def set_peer_auth_counter(self, peer_auth_counter):
        self.peer_auth_counter = int.from_bytes(peer_auth_counter, "little")
    
    def check_peer_auth_counter(self, peer_auth_counter):
        peer_auth_counter = int.from_bytes(peer_auth_counter, "little")
        if peer_auth_counter != self.peer_auth_counter:
            return False
        self.peer_auth_counter += 1
        return True
    
    def get_auth_counter(self):
        auth_counter =  self.auth_counter.to_bytes(16, "little")
        self.auth_counter += 1
        return auth_counter

    def set_auth_counter(self, auth_counter):
        auth_counter = int.from_bytes(auth_counter, "little")
        self.auth_counter = auth_counter
    
    def set_send_sk(self, sk:socket.socket):
        if sk != None:
            self.status |= UtransSession.F_SEND_OK
        else:
            self.status &= ~UtransSession.F_SEND_OK
        self.send_sk = sk
    
    def set_recv_sk(self, sk:socket.socket):
        if sk != None:
            self.status |= UtransSession.F_RECV_OK
        else:
            self.status &= ~UtransSession.F_RECV_OK
        self.recv_sk = sk
    
    def get_session_key(self):
        return self.session_key    

    def is_recv_enabled(self):
        if self.recv_sk != None:
            return True
        else:
            return False
    
    def is_send_enabled(self):
        if self.send_sk != None:
            return True
        else:
            return False

    def close_send_sk(self):
        if self.send_sk != None:
            self.send_sk.close()
            self.send_sk = None
            self.status &= ~UtransSession.F_RECV_OK

    def close_recv_sk(self):
        if self.recv_sk != None:
            self.recv_sk.close()
            self.recv_sk = None
            self.status &= ~UtransSession.F_RECV_OK

    def close(self):
        self.close_send_sk()
        self.close_recv_sk()

    def finish_init(self):
        self.status |= UtransSession.F_INIT
    
    def check_send_sk(self):
        logger.debug("check session")
        if self.send_sk == None:
            logger.debug("sk None")
            return False
        
        if self.send_lock.locked():
            logger.debug("sk locked")
            return True
        else:
            self.send_lock.acquire()

        timeout = self.send_sk.gettimeout()
        self.send_sk.settimeout(0)
        try:
            data = self.send_sk.recv(1024)
        except socket.timeout:
            self.send_sk.settimeout(timeout)
            logger.debug("sk ok")
            ret = True
        except:
            traceback.print_exc()
            ret = False
        finally:
            self.send_lock.release()
        if len(data) == 0:
            logger.debug("sk closed")
            ret = False
        else:
            raise Exception("socket checker recv unexpected data")
        return ret
        
    def is_init(self):
        if self.status & UtransSession.F_INIT:
            return True
        else:
            return False

    def connect(self, callback, block = True):
        task_info = UtransTaskInfo(type = UtransTaskInfo.T_CONN)
        if block:
            self.__do_connect(callback, task_info)
        else:
            _thread.start_new_thread(self.__do_connect, (callback, task_info))
        return task_info
        
    def __do_connect(self, callback, task_info):
        context = self.context
        ssk = FrameSocket(socket.AF_INET, socket.SOCK_STREAM)
        ssk.settimeout(8)

        if self.peer_addr == None:
            logger.error("No target to connect")
            callback.on_task_finished(UtransError.CONNECTION_ERROR, task_info)
            return False
        addr = self.peer_addr
        try:
            ssk.connect(addr)
        except:
            traceback.print_exc()
            callback.on_task_finished(UtransError.CONNECTION_ERROR, task_info)
            return False
        ##################### New authentication ###########################
        ucore = UtransCore(ssk)
        if not ucore.authenticate_server(self, context):
            print("fail to authenticate")
            callback.on_task_finished(UtransError.CONNECTION_ERROR, task_info)
            return False
        else:
            print("authenticate ok")
            self.print_info()
        ##########################################################
        task_info.set_extra_data(self)
        callback.on_task_finished(UtransError.OK, task_info)
        return True

    def send_file(self, filename, callback, block = True):
        if not self.is_send_enabled():
            raise Exception("Session not ready for send, try connecting to a server")
        if not os.path.exists(filename):
            raise Exception("No such file %s"%(filename))
        task_info = UtransTaskInfo(session_index=self.id, type = UtransTaskInfo.T_S_FILE)
        utrans = UtransCore(self.send_sk)
        if block:
            utrans.send_file(filename, callback, task_info)
        else:
            _thread.start_new_thread(utrans.send_file, (filename, callback, task_info))
        return task_info

    def send_message(self, msg, callback, block = False):
        if not self.is_send_enabled():
            raise Exception("Session not ready for send, try connecting to a server")
        utrans = UtransCore(self.send_sk)
        task_info = UtransTaskInfo(session_index = self.id, type = UtransTaskInfo.T_S_MSG)
        if block:
            utrans.send_message(msg, callback, task_info)
        else:
            _thread.start_new_thread(utrans.send_message, (msg, callback, task_info))
        return task_info

    def print_info(self):
        msg = (
            "peer_name: %s\n"
            "peer_uuid: %s\n"
            "session_key: %s\n"
            "peer_addr: %s\n"
            "recv_sk: %s\n"
            "send_sk: %s\n"%(self.peer_name, self.peer_uuid, self.session_key.hex(), str(self.peer_addr), str(self.recv_sk), str(self.send_sk))
        )
        logger.debug(msg)
    
    def __str__(self):
        return "%s"%(self.peer_name)
    
    def __repr__(self):
        return "[%s]%s@%s"%(self.id, self.name, self.peer_addr)

from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as cipher
from Crypto.Signature import PKCS1_v1_5 as signature

class UtransAuth:
    
    def __init__(self, context, name, pubkey_file, private_key_file, peer_pubkey_dir):
        if not (os.path.isfile(pubkey_file) and os.path.isfile(private_key_file)):
            UtransAuth.generate_key_pair(pubkey_file, private_key_file)
        self.pubkey_file = pubkey_file
        self.private_key_file = private_key_file
        self.peer_pubkey_dir = peer_pubkey_dir
        self.name = name
        self.uuid = None
        self.context = context

    @staticmethod
    def get_mac_ob(key):
        return hmac.new(key, digestmod="sha256")
    
    @staticmethod
    def get_hash_ob():
        return SHA256.new()
    
    @staticmethod
    def generate_key_pair(pubkey_file = "rsa_pub.pem", private_key_file = "rsa.pem", type = "rsa", key_bit_size = 1024):
        random_num_generator = Random.new().read
        rsakey = RSA.generate(key_bit_size, random_num_generator)
        private_key = rsakey.exportKey()
        pubkey = rsakey.publickey().exportKey()
        with open(private_key_file, "wb") as f:
            f.write(private_key)
        with open(pubkey_file, "wb") as f:
            f.write(pubkey)
        print("key generate ok")

    def get_name(self):
        return self.name
    
    def get_name(self):
        return self.name
    
    def get_uuid(self):
        if self.uuid == None:
            hash_ob = self.get_hash_ob()
            pubkey = self.get_self_pubkey()
            hash_ob.update(pubkey)
            uuid = hash_ob.hexdigest()
        else:
            uuid = self.uuid
        return uuid
    
    # use to sign or decrypt
    def get_priv_cipher(self, type = "decrypt"):
        with open(self.private_key_file, "rb") as f:
            priv_key = f.read()
        rsakey = RSA.importKey(priv_key)
        if type == "decrypt":
            priv_cipher = cipher.new(rsakey)
        else:
            priv_cipher = signature.new(rsakey)
        return priv_cipher
    # use to verify or encrypt
    def get_pub_cipher(self, pubkey = None, uuid = None, type = "encrypt"):
        if pubkey == None:
            if uuid == None:
                raise Exception("You have to specify either pubkey or uuid")
            pubkey = self.get_peer_pubkey(uuid)
        rsakey = RSA.importKey(pubkey)
        if type == "encrypt":
            pub_cipher = cipher.new(rsakey)
        else:
            pub_cipher= signature.new(rsakey)
        return pub_cipher
    
    def get_rnd_auth_counter(self, size = 16):
        return Random.new().read(size)
    
    def get_rnd_session_key(self, size = 16):
        return Random.new().read(size)

    def check_peer_pubkey(self, uuid):
        return os.path.isfile("%s/%s"%(self.peer_pubkey_dir, uuid))

    def save_peer_pubkey(self, uuid, pubkey):
        with open("%s/%s"%(self.peer_pubkey_dir, uuid), "wb") as f:
            f.write(pubkey)
        return True
    
    def get_peer_pubkey(self, uuid):
        with open("%s/%s"%(self.peer_pubkey_dir, uuid), "rb") as f:
            key = f.read()
        return key

    def get_self_pubkey(self):
        with open(self.pubkey_file, "rb") as f:
            pubkey = f.read()
        return pubkey

    def auth_msg(self, msg, session):
        auth_data = msg.get_data()
        if msg.type == Message.MT_SESSION_INIT:
            auth_counter = auth_data
            session.set_auth_counter(auth_counter)
            logger.debug("set self auth counter[%s]"%(int.from_bytes(auth_counter, "little")))
            return True
        elif msg.type == Message.MT_SESSION_RECONNECT or msg.type == Message.MT_SESSION_FINAL:
            peer_auth_counter, mac_data = unpack_bytes(auth_data)
            if not session.check_peer_auth_counter(peer_auth_counter):
                logger.debug("invalid auth_counter, expect %s, but recv %s"%(session.peer_auth_counter.to_bytes(16, "little"), peer_auth_counter))
                return False
            session_key = session.get_session_key()
            mac_ob = self.get_mac_ob(session_key)
            for item in msg.values[:-1]:
                mac_ob.update(item.encode("utf8"))
            mac_ob.update(peer_auth_counter)
            real_mac_data = mac_ob.digest()
            if real_mac_data != mac_data:
                logger.debug("invalid mac")
                return False
            return True
        elif msg.type == Message.MT_SESSION_REPLY:
            auth_counter, peer_auth_counter, enc_session_key, sig = unpack_bytes(auth_data)

            ####### verify this msg #########
            hash_ob = self.get_hash_ob()
            for item in msg.values[:-1]:
                hash_ob.update(item.encode("utf8"))
            hash_ob.update(auth_counter)
            hash_ob.update(peer_auth_counter)
            hash_ob.update(enc_session_key)
            
            if not session.check_peer_auth_counter(peer_auth_counter):
                logger.debug("invalid auth_counter, expect %d, but recv %s"%(session.peer_auth_counter, int.from_bytes(peer_auth_counter, "little")))
                return False
            peer_uuid = msg.values[2]
            verifier = self.get_pub_cipher(uuid = peer_uuid, type="verify")
            if not verifier.verify(hash_ob, sig):
                logger.debug("invalid sig")
                return False
            #################################
            session.set_auth_counter(auth_counter)
            logger.debug("set self auth counter to [%d]"%(int.from_bytes(auth_counter, "little")))
            ####### decrypt session_key ######
            decryptor = self.get_priv_cipher()
            session_key = decryptor.decrypt(enc_session_key, b"error")
            if session_key == b"error":
                logger.debug("fail to decrypt session key")
                return False
            ##################################
            session.set_session_key(session_key)
            return True
        else:
            raise Exception("unknown message type [%s]"%(msg.type))
            
    def set_auth_data(self, msg, session:UtransSessionNew = None):
        
        if msg.type == Message.MT_SESSION_INIT:
            peer_auth_counter = self.get_rnd_auth_counter()
            data = peer_auth_counter
            session.set_peer_auth_counter(peer_auth_counter)
            logger.debug("set peer auth counter to [%d]"%(int.from_bytes(peer_auth_counter, "little")))
            ret = True
        elif msg.type == Message.MT_REGISTER:
            self_pubkey = self.get_self_pubkey()
            hash_ob = self.get_hash_ob()
            for item in msg.values[:-1]:
                hash_ob.update(item.encode("utf8"))
            hash_ob.update(self_pubkey)
         
            signer = self.get_priv_cipher(type = "sign")
            sig = signer.sign(hash_ob)
            data = pack_bytes((self_pubkey, sig))
            ret = True
        elif msg.type == Message.MT_SESSION_REPLY:
            peer_uuid = session.peer_uuid
            encryptor = self.get_pub_cipher(uuid = peer_uuid)
            signer = self.get_priv_cipher(type = "sign")
            session_key = self.get_rnd_session_key()
            session.set_session_key(session_key)
            enc_session_key = encryptor.encrypt(session_key)
            auth_counter = session.get_auth_counter()
            peer_auth_counter = self.get_rnd_auth_counter()
            session.set_peer_auth_counter(peer_auth_counter)
            logger.debug("set peer auth counter to [%d]"%(int.from_bytes(peer_auth_counter, "little")))
            hash_ob = self.get_hash_ob()
            for item in msg.values[:-1]:
                hash_ob.update(item.encode("utf8"))
            hash_ob.update(peer_auth_counter + auth_counter + enc_session_key)
          
            sig = signer.sign(hash_ob)
            data = pack_bytes((peer_auth_counter, auth_counter, enc_session_key, sig))
            ret = True
        elif msg.type == Message.MT_SESSION_RECONNECT or msg.type == Message.MT_SESSION_FINAL:
            session_key = session.get_session_key()
            if session_key == None:
                logger.debug("No session key, can't use mac")
                return False
            mac_ob = self.get_mac_ob(session_key)
            for item in msg.values[:-1]:
                mac_ob.update(item.encode("utf8"))
            auth_counter = session.get_auth_counter()
            mac_ob.update(auth_counter)
            mac_data = mac_ob.digest()
            data = pack_bytes((auth_counter, mac_data))
            ret = True
        else:
            raise Exception("unkown msg type"%(msg.type))
        if ret:
            msg.set_data(data)
        return ret

    def register_peer(self, msg):
        peer_name = msg.values[1]
        peer_uuid = msg.values[2]
        register_data = msg.get_data()
        peer_pubkey, sig = unpack_bytes(register_data)
        notice_info = ( termcolor.colored("Peer request register, make sure you know who he is:\n", "red") + 
                        "Peer name: %s\n"
                        "Peer uuid: %s\n"
                        "Peer Pubkey:\n %s")%(peer_name, peer_uuid, peer_pubkey.decode("utf8"))
        if not self.context.prompt_user_decision(notice_info):
            return False
        # check if uuid is corresponding to pubkey
        hash_ob = self.get_hash_ob()
        hash_ob.update(peer_pubkey)
        real_uuid = hash_ob.hexdigest()
        if real_uuid != peer_uuid:
            logger.error("uuid not corresponding to pubkey")
            return False
        # check signature
        verifier = self.get_pub_cipher(peer_pubkey, type="verify")
        hash_ob = self.get_hash_ob()
        for item in msg.values[:-1]:
            hash_ob.update(item.encode("utf8"))
        hash_ob.update(peer_pubkey)
        
        if not verifier.verify(hash_ob, sig):
            return False
        self.save_peer_pubkey(peer_uuid, peer_pubkey)
        return True
    
    def check_register(self, peer_uuid):
        return self.check_peer_pubkey(peer_uuid)

class UtransSessionManager():

    def __init__(self):
        self.sessions = DictList()
    
    def append(self, session:UtransSession):
        if self.has_session(session):
            logger.warning("try to append existed session")
            return session.id
        else:
            index = self.sessions.append(session)
            session.set_id(index)
            return index
    
    def has_session(self, session):
        if session.id in self.sessions.keys():
            return True
        else:
            return False

    def remove(self, index):
        if index in self.sessions.keys():
            session = self.sessions.pop(index)
            session.close()
        else:
            logger.debug("remove non-exist session")
    
    def get_session_by_index(self, index):
        if index not in self.sessions.keys():
            return None
        else:
            return self.sessions[index]

    def get_session_by_uuid(self, uuid):
        return self.sessions.search(uuid, lambda x,y : x.peer_uuid == y)

    def get_session_by_name(self, name):
        return self.sessions.search(name, lambda x,y : x.peer_name == y)
    
    def print_info(self):
        self.sessions.show()
    
    def start_connection_checker(self, interval = 2):
        _thread.start_new_thread(self.__do_connection_check, (interval, ))
    
    def __do_connection_check(self, interval):
        while True:
            for index in self.sessions.keys():
                session = self.sessions[index]
                if not session.check_send_sk():
                    session.send_sk = None
                    if session.recv_sk == None:
                        self.sessions.remove(index)
            time.sleep(interval)

def main():
    m = MessageHandler()

if __name__ == "__main__":
    main()
