#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Date: Sat Oct 19 20:45:17 2019
# Author: January

from utrans_utils import *
from utrans_interface import *
from crypto import openssl as crypto
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

    MSG_TYPE = {
        "send_file" : ("type", "msg_type", "filename", "filesize", "encode"),
        "send_message" : ("type", "msg_type", "msg_size", "encode", "content"),
        "common_reply" : ("type", "msg_type", "status", "info"),
        "auth_init" : ("type", "msg_type", "name", "uuid", "fast_auth", "auth_data"),
        "auth_finish" : ("type", "msg_type", "name", "uuid", "auth_data"),
        "auth_ask_pubkey" : ("type", "msg_type"),
        "auth_ask_pubkey_reply" : ("type", "msg_type", "key_type", "pubkey", "status"),
        "auth_challenge" : ("type", "msg_type", "challenge_type", "data"),
        "auth_challenge_reply" : ("type", "msg_type", "data", "status")
    }

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
            except:
                traceback.print_exc()
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
    def pack_auth_init(name, uuid, fast_auth = False, auth_data = None, server_addr:str = None):
        cmd = dict()
        cmd["type"] = "ask"
        cmd["cmd"] = "init"
        cmd["name"] = name
        cmd["uuid"] = uuid
        cmd["status"] = "auth_start"
        if fast_auth == True:
            cmd["fast_auth"] = "true"
        else:
            cmd["fast_auth"] = "false"
        cmd["auth_data"] = auth_data
        cmd["server_addr"] = server_addr

        return CommandManager.pack_cmd(cmd)
    
    @staticmethod
    def pack_auth_finish(status, name = None, uuid = None, auth_data = None):
        cmd = dict()
        cmd["type"] = "ask"
        cmd["cmd"] = "finish"
        cmd["name"] = name
        cmd["uuid"] = uuid
        cmd["status"] = status
        cmd["auth_data"] = auth_data

        return CommandManager.pack_cmd(cmd)
    
    @staticmethod
    def pack_auth_ask_pubkey():
        cmd = dict()
        cmd["type"] = "ask"
        cmd["cmd"] = "ask_pubkey"
        cmd["status"] = "auth_ing"
        return CommandManager.pack_cmd(cmd)
    
    @staticmethod
    def pack_auth_pubkey_reply(pubkey):
        cmd = dict()
        cmd["type"] = "res"
        cmd["cmd"] = "reg_pubkey"
        cmd["pubkey"] = pubkey
        cmd["status"] = "auth_ing"
        return CommandManager.pack_cmd(cmd)
    
    @staticmethod
    def pack_auth_challenge(challenge_msg):
        cmd = dict()
        cmd["type"] = "ask"
        cmd["cmd"] = "challenge"
        cmd["data"] = challenge_msg
        cmd["status"] = "auth_ing"
        return CommandManager.pack_cmd(cmd)
    
    @staticmethod
    def pack_auth_challenge_reply(reply_data):
        cmd = dict()
        cmd["type"] = "res"
        cmd["cmd"] = "challenge_reply"
        cmd["data"] = reply_data
        cmd["status"] = "auth_ing"
        return CommandManager.pack_cmd(cmd)

    @staticmethod
    def pack_init_msg(name, uuid = None, extra_data:dict = None):
        if extra_data != None:
            cmd = extra_data
        else:
            cmd = dict()
        cmd["type"] = "init"
        cmd["name"] = name
        if uuid == None:
            cmd["uuid" ] = name
        else:
            cmd["uuid"] = uuid
        return CommandManager.pack_cmd(cmd)
    
    ##### message type #####
    # message type                  ask/res                 description
    # send_file                     ask                     
    # send_message                  ask                     
    # common_reply                  res                     ok, failed, reject, accept
    # auth_init                     ask                     
    # auth_finish                   res                     
    # auth_challenge                ask                     
    # auth_challange_reply          res                     
    # auth_ask_pubkey               ask                     
    # auth_ask_pubkey_reply         res
    # scan_request                  ask
    # scan_response                 res                    

    ##### message field #####
    # only [res] type messages have the [status] field.
    # send_file(type, msg_type, filename, filesize, encode)
    # send_message(type, msg_type, msg_size, encode, content) --> for long message, set the content field to the value of msg_size field
    # common_reply(type, msg_type, status, info)
    # auth_init(type, msg_type, name, uuid, fast_auth, auth_data)
    # auth_finish(type, msg_type, name, uuid, auth_data)
    # auth_ask_pubkey(type, msg_type)
    # auth_ask_pubkey_reply(type, msg_type, key_type, pubkey, status)
    # auth_challenge(type, msg_type, challenge_type, data)
    # auth_challenge_reply(type, msg_type, data, status)
    # scan_request(type, msg_type)
    # scan_response(type, msg_type, name, ip, port)

    
    @staticmethod
    def check_msg(msg):
        if "msg_type" not in msg.keys():
            return False
        msg_type = msg["msg_type"]
        if msg_type not in CommandManager.MSG_TYPE.keys():
            return False
        fields = CommandManager.MSG_TYPE[msg_type]
        for field in fields:
            if field not in msg.keys():
                return False
        return True
    
class UtransDefault:
    SERVICE_PORT = 9999
    SCAN_PORT = 9999

# seperate scanner from Utrans
class UtransScanner:

    def __init__(self, scan_port = UtransDefault.SCAN_PORT):
        # init state
        self.scanning = False
        # init socket
        self.cmd_mngr = CommandManager()
        self.scan_sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.scan_sk.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.scan_sk.settimeout(0.1)
        # other data
        self.__discovered_servers = set()
        self.ip = socket.gethostbyname(socket.gethostname())

        # scan request broadcast addr
        ip = socket.gethostbyname(socket.gethostname()).split(".")
        ip[3] = "255"
        broadcast_ip = '.'.join(ip)
        self.broadcast_addr = (broadcast_ip, scan_port)
        self.scan_request_msg = b"utrans&scan_request"
    
    def __do_scan_service(self, callback:UtransCallback):
        callback.on_start_scan()
        while self.scanning:
            try:
                data, address = self.scan_sk.recvfrom(4096)
            except socket.timeout:
                continue

            # 过滤本机发出的数据包
            if self.ip == address[0] or address[0] == "127.0.0.1":
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

    def __send_scan_request(self):
        self.scan_sk.sendto(self.scan_request_msg, self.broadcast_addr)
    
    def set_scan_port(self, port:int):
        self.broadcast_addr = (self.broadcast_addr[0], port)

    def stop_scan(self):
        if self.scanning == True:
            self.scanning = False
            self.__discovered_servers.clear()
            logger.debug("stop service discovery")
    
    def start_scan(self, callback, time):
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
    def __init__(self, name = None, port = 9999):
        if name == None:
            self.name = socket.gethostname()
        else:
            self.name = name

        self.service_port = port
        self.scan_server_addr = ("0.0.0.0", port)

        # set scan response message
        self.scan_response_msg = "utrans&{name}&{port}".format(name=self.name, port=self.service_port).encode("utf8")
        self.running = False
    
    def init_socket(self):
        self.sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sk.bind(self.scan_server_addr)

    def start(self):
        self.running = True
        self.init_socket()
        while self.running:
            try:
                data, addr = self.sk.recvfrom(1024)
            except Exception as e:
                logger.debug("scan reponder failure")
                print(e)
            msg = data.decode(encoding="utf8")
            try:
                msg.index("utrans&scan_request")
            except:
                continue
            # response
            self.sk.sendto(self.scan_response_msg, addr)
    
    def stop(self):
        self.sk.close()
        self.running = False
    
    def asyn_start(self):
        _thread.start_new_thread(self.start, ())

class UtransCore:
    NETWORK_TIMEOUT = 3
    SPLIT_LEN = 409600

    def __init__(self, sk:socket.socket = None):
        self.cmd_mngr = CommandManager()
        self.set_socket(sk)
    
    def set_socket(self, sk:socket.socket):
        self.ssk = sk

    def authenticate(self):
        self.send_not_support_info()
    
    def authenticate_server(self, name, uuid, callback:UtransCallback):
        sk = self.ssk
        cmd_mngr = self.cmd_mngr
        if cmd_mngr.parse_cmd_from_ssk(sk) == CommandManager.S_ABORT:
            logger.debug("connection closed by peer")
            return False
        cmd = cmd_mngr.get()
        if not self.check_cmd_key(("name", "uuid", "fast_auth", "auth_data"), cmd):
            logging.debug("protocol error")
            return None

        peer_name = cmd["name"]
        peer_uuid = cmd["uuid"]
        peer_auth_data = cmd["auth_data"]

        session = callback.on_search_session(peer_uuid)
        if cmd["fast_auth"] == "true" and session != None:
            session_key = session.session_key
            auth_counter = session.get_auth_counter()
            auth_counter_mac = hmac.new(session_key, auth_counter, digestmod="sha256").hexdigest()
            if peer_auth_data != auth_counter_mac:
                auth_result_msg = cmd_mngr.pack_auth_finish("failed")
                sk.send(auth_result_msg)
                return None
        else:
            if session == None:
                session = UtransSessionNew(peer_name, peer_uuid)
            has_pubkey = callback.on_check_client_pubkey(peer_uuid)
            if not has_pubkey:
                ask_pubkey_msg = cmd_mngr.pack_auth_ask_pubkey()
                sk.send(ask_pubkey_msg)
                if cmd_mngr.parse_cmd_from_ssk(sk) == CommandManager.S_ABORT:
                    logger.debug("connection closed by peer")
                    return None
                cmd = cmd_mngr.get()
                if not self.check_cmd_key(("status", "cmd", "pubkey"), cmd):
                    logger.warning("protocol error")
                    return None
                if cmd["status"] != "auth_ing" or cmd["cmd"] != "reg_pubkey":
                    return None
                
                pubkey = base64_decode(cmd["pubkey"])
                ret = callback.on_register_pubkey(peer_uuid, pubkey)
                if ret is False:
                    auth_result_msg = cmd_mngr.pack_auth_finish("failed")
                    sk.send(auth_result_msg)
                    return None
            session_key = callback.on_need_session_key(16)
            encrypted_session_key = callback.on_encrypt_session_key(peer_uuid, session_key)
            challenge_msg = cmd_mngr.pack_auth_challenge(base64_encode(encrypted_session_key))
            sk.send(challenge_msg)
            if cmd_mngr.parse_cmd_from_ssk(sk) == CommandManager.S_ABORT:
                logger.debug("connection closed by peer")
                return None
            cmd = cmd_mngr.get()
            if not self.check_cmd_key(("status", "cmd", "data"), cmd):
                logger.warning("protocol error")
                return None
            if cmd["status"] != "auth_ing" or cmd["cmd"] != "challenge_reply":
                logger.warning("protocol error")
                return None
            auth_data = cmd["data"]
            peer_uuid_mac = hmac.new(session_key, peer_uuid.encode("utf8"), digestmod="sha256").hexdigest()
            if auth_data != peer_uuid_mac:
                logger.warning("authentication failed")
                return None
            session.set_session_key(session_key)
        session.set_recv_sk(sk)
        auth_data = hmac.new(session_key, uuid.encode("utf8"), digestmod="sha256").hexdigest()    
        auth_result_msg = cmd_mngr.pack_auth_finish("auth_ok", name, uuid, auth_data)
        sk.send(auth_result_msg)
        return session

    
    def authenticate_client(self, name, uuid, callback:UtransCallback, fast_auth_data = None):
        sk = self.ssk
        cmd_mngr = self.cmd_mngr

        # For all bytes data, use base64 to encode it to str
        if fast_auth_data == None:
            init_msg = cmd_mngr.pack_auth_init(name, uuid)
        else:
            init_msg = cmd_mngr.pack_auth_init(name, uuid, True, fast_auth_data)
        sk.send(init_msg)
        if cmd_mngr.parse_cmd_from_ssk(sk) == CommandManager.S_ABORT:
            logger.debug("connection closed by peer")
            return None
        cmd = cmd_mngr.get()

        if "status" not in cmd.keys():
            logging.warning("protocol error")
            return None
        
        if cmd["status"] == "auth_ing":
            if "cmd" not in cmd.keys():
                logger.warning("protocol error")
                return None
            # registe public key
            if cmd["cmd"] == "ask_pubkey":
                pubkey = callback.on_need_pubkey()
                pubkey_msg = cmd_mngr.pack_auth_pubkey_reply(base64_encode(pubkey))
                sk.send(pubkey_msg)
                if cmd_mngr.parse_cmd_from_ssk(sk) == CommandManager.S_ABORT:
                    logger.debug("connection closed by peer")
                    return None
                cmd = cmd_mngr.get()
                if "cmd" not in cmd.keys() or "status" not in cmd.keys():
                    logger.warning("protocol error")
                    return None
                if cmd["status"] != "auth_ing":
                    logger.warning("authentication abort")
                    return None
            # regular auth
            if cmd["cmd"] == "challenge":
                encrypted_session_key = cmd["data"]
                encrypted_session_key = base64_decode(encrypted_session_key)
                session_key = callback.on_decrypt_session_key(encrypted_session_key)
                mac = hmac.new(session_key, uuid.encode("utf8"), digestmod="sha256")
                hmac_data = mac.hexdigest()

                challenge_reply = cmd_mngr.pack_auth_challenge_reply(hmac_data)
                sk.send(challenge_reply)
            else:
                logger.warn("protocol error")
            
            if cmd_mngr.parse_cmd_from_ssk(sk) == CommandManager.S_ABORT:
                logger.debug("connection closed by peer")
                return None
            cmd = cmd_mngr.get()

        if not self.check_cmd_key(("status", "name", "uuid", "auth_data"), cmd):
            logger.debug("protocol error")
            return None
        
        if cmd["status"] != "auth_ok":
            logger.debug("authentication failed")
            return None
        
        peer_name = cmd["name"]
        peer_auth_data = cmd["auth_data"]
        peer_uuid = cmd["uuid"]
        peer_uuid_mac = hmac.new(session_key, peer_uuid.encode("utf8"), digestmod="sha256").hexdigest()
        if peer_auth_data != peer_uuid_mac:
            logger.debug("Server's authentication data Invalid")
            return None
        session = callback.on_search_session(uuid)
        if session == None:
            session = UtransSessionNew(peer_name, peer_uuid, session_key = session_key)
        else:
            session.peer_name = peer_name
            session.sesion_key = session_key
        session.set_send_sk(sk)
        return session
            

    def check_cmd_key(self, keys, cmd):
        for key in keys:
            if key not in cmd.keys():
                return False
        return True


    def send_not_support_info(self):
        info = {
            "info" : "unsupported operation"
        }
        packed_msg = self.cmd_mngr.pack_failed_reply(info)
        self.ssk.send(packed_msg)

    # The "task_info" is used to discriminate and control(i.e. to stop) every asynchronous call to "send_file" in callback function
    def send_file(self, filepath, task_info:UtransTaskInfo, callback:UtransCallback):
        # read filename and file size
        # make sure the file exists in high level APIs of UtransClient
        ssk = self.ssk
        cmd_mngr = self.cmd_mngr
        filesize = os.path.getsize(filepath)
        filename = os.path.basename(filepath)
        
        # file send start callback
        callback.on_file_send_start(filename, filesize, task_info)
        
        # send file-send request
        filename = self.base64_encode_str(filename)
        packed_cmd = CommandManager.pack_send_file_cmd(filename, filesize)
        try:
            ssk.send(packed_cmd)
        except Exception as e:
            logger.debug(e)
            callback.on_file_send_finished(UtransError.CONNECTION_ERROR, task_info)
        
        # get reply
        if cmd_mngr.parse_cmd_from_ssk(ssk) == CommandManager.S_ABORT:
            logger.debug("connection closed by peer")
            callback.on_file_send_finished(UtransError.CONNECTION_ERROR, task_info)
            return False
        cmd = cmd_mngr.get()
        if "status" not in cmd.keys():
            callback.on_file_send_finished(UtransError.PROTOCAL_ERROR, task_info)
            return False

        if cmd["status"] != "accept":
            logger.debug("peer reject")
            callback.on_file_send_finished(UtransError.PEER_REJECT, task_info)
            return False

        # start sending file
        self.ssk.settimeout(UtransCore.NETWORK_TIMEOUT)
        sended = 0
        with open(filepath, "rb") as f:
            while True:
                try:
                    data = f.read(Utrans.SPLIT_LEN)
                except Exception as e:
                    print("[send_file] fail to read file", e)
                    callback.on_file_send_finished(UtransError.LOCAL_ERROR, task_info)
                # finish read
                if len(data) == 0:
                    break
                try:
                    ssk.send(data)
                except Exception as e:
                    print("[send_file] fail to send data", e)
                    callback.on_file_send_finished(UtransError.CONNECTION_ERROR, task_info)
                sended += len(data)
                # sending progress callback
                progress = sended / filesize
                # on progress callback
                callback.on_file_sending(progress, task_info)
                # stop sending file
                if task_info.running == False:
                    callback.on_file_send_stop(task_info)
                    return False

        # get reply
        if cmd_mngr.parse_cmd_from_ssk(ssk) == CommandManager.S_ABORT:
            logger.debug("connection closed by peer")
            callback.on_file_send_finished(UtransError.CONNECTION_ERROR, uuid)
            return False
        cmd = cmd_mngr.get()

        if "status" not in cmd:
            logger.debug("ProtocalError: No status in reponse")
            callback.on_file_send_finished(UtransError.PROTOCAL_ERROR, task_info)
            return False
        
        if cmd["status"] != "ok":
            logger.debug("peer responsed failed")
            callback.on_file_send_finished(UtransError.PEER_SAY_FAILED, task_info)
            return False
        # success sending file
        callback.on_file_send_finished(UtransError.OK, task_info)
        return True
        
    def send_message(self, message:str, callback:UtransCallback, task_info:UtransTask):
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
    
class UtransServer():

    def __init__(self, port = Utrans.DEFAULT_SERVICE_PORT):
        self.name = socket.gethostname()
        self.uuid = None
        self.running = False
        self.port = port
        self.lsk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.scan_responder = UtransScanResponder(self.name, self.port)
        logger.debug("server port: %d"%(port))
        # deprecated, will be remove soon
        self.enable_broadcast = True
        self.broadcast_interval = 2

    def set_name(self, name):
        self.name = name

    def set_uuid(self, uuid):
        self.uuid = uuid

    def init(self):
        logger.debug("server start to listen")
        self.lsk.bind(('0.0.0.0', self.port))
        self.lsk.listen(2)
        self.scan_responder.asyn_start()
        # deprecated, will be removed
        self.broadcast_service()
    
    def handle_client(self, ssk:socket.socket, addr):
        cmd_mngr = CommandManager()
        utrans = Utrans(Utrans.M_NORMAL)
        utrans.set_session(ssk)
        callback = self.callback

        ##################### New authentication ######################
        ucore = UtransCore()
        ucore.set_socket(ssk)
        session = ucore.authenticate_server(self.name, self.uuid, self.callback)
        if session == None:
            print("fail to authenticate")
        else:
            print("authenticate ok")
            session.print_info()
        ###############################################################
        session_index = callback.on_new_session(session)

        # ok, start handling requests
        while True:
            if cmd_mngr.parse_cmd_from_ssk(ssk) == CommandManager.S_ABORT:
                logger.debug("peer close connection")
                callback.on_session_close_recv(session_index)
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
    @deprecatedBy(UtransScanResponder)
    def broadcast_service(self):
        _thread.start_new_thread(self.do_broadcast, ())

    @deprecatedBy(UtransScanResponder)
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

    @deprecated
    def stop_broadcast(self):
        self.enable_broadcast = False
    
    def stop_scan_service(self):
        self.scan_responder.stop()

    def stop_server(self):
        if self.running == True:
            self.lsk.close()
            self.running = False
    
    def async_run(self, callback):
        _thread.start_new_thread(self.run, (callback,))

class UtransClient:
    def __init__(self, id = "client"):
        self.name = id
        self.uuid = None
        self.current_session = None
        self.scanner = UtransScanner()
    
    def set_name(self, name):
        self.name = name
    
    def set_uuid(self, uuid):
        self.uuid = uuid
    
    def set_current_session(self, session):
        self.current_session = session

    def get_current_session(self):
        return self.current_session
    
    def set_scan_port(self, port:int):
        self.scanner.set_scan_port(port)

    def start_scan(self, callback, time = 0):
        self.scanner.start_scan(callback, time)

    def stop_scan(self):
        self.scanner.stop_scan()

    def connect(self, server:UtransServerInfo, callback):
        ssk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssk.settimeout(3)
        logger.debug("connect")
        try:
            ssk.connect(server.addr)
        except Exception as e:
            print(e)
            callback.on_connect_error(UtransError.CONNECTION_ERROR)
            return False

        ##################### New authentication ###########################
        ucore = UtransCore()
        ucore.set_socket(ssk)
        session = ucore.authenticate_client(self.name, self.uuid, callback)
        if session == None:
            print("fail to authenticate")
        else:
            print("authenticate ok")
            session.print_info()
        ##########################################################
        callback.on_new_session(session)
        self.current_session = session
        return True

    def send_file(self, filename, callback, task_info:UtransTask = None, block = True, session:UtransSessionNew = None):
        if session == None:
            session = self.current_session
        if task_info == None:
            task_info = UtransTask()
        if not os.path.exists(filename):
            callback.on_file_send_error(UtransError.NO_SUCH_FILE, task_info)
            return False
        utrans = Utrans(Utrans.M_NORMAL)
        utrans.set_session(session.send_sk)
        if block:
            return utrans.send_file(filename, task_info, callback)
        else:
            _thread.start_new_thread(utrans.send_file, (filename, task_info, callback))
            return True
    
    def send_files(self, filenames, callback, task_infos = None, session:UtransSession = None):
        if session == None:
            session = self.current_session
        if task_infos == None:
            task_infos = (UtransTask() for i in range(len(filenames)))
        _thread.start_new_thread(self.__do_send_files, (filenames, callback, task_infos, session))

    def __do_send_files(self, filenames, callback, task_infos, session):

        for filename, task_info in zip(filenames, task_infos):
            self.send_file(filename, callback, task_info = task_info, block=True, session=session)
       
    def send_message(self, msg, callback, task_info:UtransTask = None, block = False, session:UtransSessionNew = None):
        if session == None:
            session = self.current_session
        utrans = Utrans(Utrans.M_NORMAL)
        utrans.set_session(session.send_sk)
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

