#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Date: Wed Apr 15 09:09:51 2020
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
logger = logging.getLogger("utrans_new")
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

class UtransDefault:
    SERVICE_PORT = 9999
    SCAN_PORT = 9999

class Message:
    MT_SEND_FILE = "send_file"
    MT_SEND_MSG = "send_msg"
    MT_SCAN_REQ = "scan_req"
    MT_SCAN_REPLY = "scan_reply"
    MT_AUTH_INIT = "auth_init"
    MT_AUTH_FINISH = "auth_finish"
    MT_COM_REPLY = "common_reply"
    MT_AUTH_REQ_PUBKEY = "auth_request_pubkey" 
    MT_AUTH_PUBKEY_REPLY = "auth_pubkey_reply"
    MT_AUTH_CLG = "auth_challenge"
    MT_AUTH_CLG_REPLY = "auth_challenge_reply"
    MT_CLOSE_SESSION ="close_session"

    R_OK = "ok"
    R_REJECT = "reject"
    R_FAILED = "failed"

    MSG_TYPE = None

    @staticmethod
    def load_type():
        Message.MSG_TYPE = {
        Message.MT_SEND_FILE : ("msg_type", "name", "size"),
        Message.MT_SEND_MSG : ("msg_type", "size", "encode", "data"),
        Message.MT_COM_REPLY : ("msg_type", "status", "info"),
        Message.MT_AUTH_INIT : ("msg_type", "name", "uuid", "auth_type", "encode", "data", "ip", "port"),
        Message.MT_AUTH_FINISH : ("msg_type", "name", "uuid", "auth_type", "encode", "data", "status"),
        Message.MT_AUTH_REQ_PUBKEY : ("msg_type", ),
        Message.MT_AUTH_PUBKEY_REPLY : ("msg_type", "key_type", "encode", "data", "status"),
        Message.MT_AUTH_CLG : ("msg_type", "challenge_type", "encode", "data"),
        Message.MT_AUTH_CLG_REPLY : ("msg_type", "encode", "data", "status"),
        Message.MT_SCAN_REQ : ("msg_type", ),
        Message.MT_SCAN_REPLY : ("msg_type", "name", "ip", "port"),
        Message.MT_CLOSE_SESSION : ("msg_type", )
    }
Message.load_type()
    

class MessageHandler:
    # S incidates Status
    S_NULL = "null"
    S_RECEIVING = "receiving"
    S_OK = "ok"
    S_ABORT = "abort"
    S_ERROR = "error"
    # M indicates message
    M_START = ord('^')
    M_END = ord('$')

    MSG_MAX = 100

    msg_char_check = re.compile(r"[\^\$:&]")

    def __init__(self):
        self.reset()


    def reset(self):
        self.values = dict()
        self.status = MessageHandler.S_NULL
        self.raw_msg = b""
        self.split_raw_msg = None

    # You can call receivemsg several times to receive a complete msg.
    def recv_msg_from_bytes(self, msg_data:bytes):
        if len(msg_data) == 0:
            self.status = MessageHandler.S_ABORT
            return True
        if self.status == MessageHandler.S_OK:
            raise RuntimeError('No more data needed')
        # init state
        if self.status == MessageHandler.S_NULL and msg_data[0] != MessageHandler.M_START:
            logger.debug(msg_data)
            raise RuntimeError("invalid msg")
        if self.status == MessageHandler.S_ABORT:
            raise RuntimeError("msg aborted")
        self.raw_msg += msg_data
        if self.raw_msg[-1] == MessageHandler.M_END:
            self.status = MessageHandler.S_OK
            if not self.unpack_msg():
                self.status = MessageHandler.S_ABORT
            return True
        else:
            self.status = MessageHandler.S_RECEIVING
            return False
    
    # The method takes a socket object as parameter and calls its recv method to receive data.
    # It calls recv_msg_from_bytes several times if necessary to try receiving a complete msg,
    # and then returns the status of the operation.
    def recv_msg_from_ssk(self, ssk):
        while True:
            try:
                data = ssk.recv(4096)
            except BaseException as e:
                traceback.print_exc()
                data = b''
            if self.recv_msg_from_bytes(data) is True:
                break
        if self.status == MessageHandler.S_OK:
            return True
        else:
            return False

    def get_msg(self):
        msg_dict = self.values
        self.reset()
        return msg_dict

    # when receivemsg return true, call this methodc      
    def unpack_msg(self):
        self.split_raw_msg = self.raw_msg.decode(encoding="utf8").strip("^$").split("&")
        logger.debug("Receive raw msg:\n%s"%(self.raw_msg))
        for key_value in self.split_raw_msg:
            key, value = key_value.split(":")
            self.values[key] = value
        # check if the msg is valid
        if not self.check_msg(self.values):
            logger.error("recv invalid message")
            return False
        
        if "encode" in self.values.keys():
            try:
                self.values["data"] = self.decode_data(self.values["encode"], self.values["data"])
            except BaseException as e:
                print(e)
                traceback.print_exc()
                return False
        return True

    @staticmethod
    def decode_data(encode, data):
        if encode == "base64":
            return base64_decode(data)
        elif encode == "plain":
            return data
        else:
            raise RuntimeError("Not support such encoding: %s"%(encode))

    
    # use '&' to split key-value tuple in msg, because '/' is a character used by base64
    @staticmethod
    def pack_msg(values:tuple):
        MessageHandler.check_ctrl_char(values)
        msg = dict()
        msg_type = values[0]
        fields = Message.MSG_TYPE[msg_type]
        for i in range(0, len(values)):
            msg[fields[i]] = values[i]
        msg_str = '^'
        for key in msg.keys():
            msg_str += "%s:%s&"%(key, msg[key])
        msg_str = msg_str[0:-1] + '$'
        raw_msg = msg_str.encode(encoding="utf8")
        logger.debug("packed_raw_msg:\n%s"%(raw_msg))
        return raw_msg 

    # ("msg_type")
    @staticmethod
    def pack_msg_scan_request():
        values = (Message.MT_SCAN_REQ, )
        return MessageHandler.pack_msg(values)
    
    # ("msg_type", "name", "ip", "port")
    @staticmethod
    def pack_msg_scan_reply(name, ip, port):
        values = (Message.MT_SCAN_REPLY, name, ip, port)
        return MessageHandler.pack_msg(values)

    # ("msg_type", "size", "encode", "data")
    @staticmethod
    def pack_msg_send_message(msg:str):
        size = len(msg)
        if size > 1024 * 100:
            raise Exception("msg too long")
        if MessageHandler.msg_char_check.search(msg) != None:
            encode = "base64"
            msg = base64_encode_str(msg)
        else:
            encode = "plain"
        values = (Message.MT_SEND_MSG, str(size), encode, msg)
        return MessageHandler.pack_msg(values)

    # ("msg_type", "name", "size")
    @staticmethod
    def pack_msg_send_file(filename:str, filesize:int):
        values = (Message.MT_SEND_FILE, filename, str(filesize))
        return MessageHandler.pack_msg(values)

    # ("msg_type", "status", "info")
    @staticmethod
    def pack_msg_common_reply(reply_status, info = None):
        values = (Message.MT_COM_REPLY, reply_status, info)
        return MessageHandler.pack_msg(values)

    # ("msg_type", "name", "uuid", "auth_type", "encode", "data", "ip", "port")
    @staticmethod
    def pack_auth_init(name, uuid, auth_type = "basic_auth", encode = "base64", auth_data = None, server_addr:tuple = None):
        if auth_data == None:
            auth_type = "None"
            encode = "plain"
        if server_addr == None:
            server_addr = (None, None)
        if encode == "base64":
            auth_data = base64_encode(auth_data)

        values = (Message.MT_AUTH_INIT, name, uuid, auth_type, encode, auth_data, server_addr[0], server_addr[1])
        return MessageHandler.pack_msg(values)
    # ("msg_type", "name", "uuid", "auth_type", "encode", "data", "status")
    @staticmethod
    def pack_auth_finish(name, uuid, auth_type = "basic_auth", encode = "base64", auth_data = None, status = Message.R_OK):
        if auth_data == None:
            encode = "plain"
        if encode == "base64":
            auth_data = base64_encode(auth_data)
        values = (Message.MT_AUTH_FINISH, name, uuid, auth_type, encode, auth_data, status)
        return MessageHandler.pack_msg(values)
    
    # ("msg_type")
    @staticmethod
    def pack_auth_req_pubkey():
        values = (Message.MT_AUTH_REQ_PUBKEY, )
        return MessageHandler.pack_msg(values)
    
    # ("msg_type", "key_type", "encode", "data", "status")
    @staticmethod
    def pack_auth_pubkey_reply(key_type, pubkey, encode = "base64", status = Message.R_OK):
        if encode == "base64":
            pubkey = base64_encode(pubkey)
        values = (Message.MT_AUTH_PUBKEY_REPLY, key_type, encode, pubkey, status)
        return MessageHandler.pack_msg(values)
    
    # ("msg_type", "challenge_type", "encode", "data")
    @staticmethod
    def pack_auth_challenge(challenge_type, challenge_data, encode = "base64"):
        if encode == "base64":
            challenge_data = base64_encode(challenge_data)
        values = (Message.MT_AUTH_CLG, challenge_type, encode, challenge_data)
        return MessageHandler.pack_msg(values)
    
    # ("msg_type", "encode", "data", "status")
    @staticmethod
    def pack_auth_challenge_reply(reply_data, encode = "base64", status = Message.R_OK):
        if encode == "base64":
            reply_data = base64_encode(reply_data)
        values = (Message.MT_AUTH_CLG_REPLY, encode, reply_data, status)
        return MessageHandler.pack_msg(values)
    
    @staticmethod
    def check_msg(msg):
        if "msg_type" not in msg.keys():
            return False
        msg_type = msg["msg_type"]
        if msg_type not in Message.MSG_TYPE.keys():
            return False
        fields = Message.MSG_TYPE[msg_type]
        for field in fields:
            if field not in msg.keys():
                return False
        return True

    @staticmethod
    def check_ctrl_char(datas):
        if datas == None:
            return
        logger.debug("checking msg:\n%s"%(str(datas)))
        for data in datas:
            if data == None:
                continue
            
            if MessageHandler.msg_char_check.search(data) != None:
                raise Exception("Data can't contains [^$:&]")
    @staticmethod
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

# seperate scanner from Utrans
class UtransScanner:

    def __init__(self, scan_port = UtransDefault.SCAN_PORT):
        # init state
        self.scanning = False
        # init socket
        self.cmd_mngr = MessageHandler()
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
        self.msg_handler = MessageHandler()
        self.set_socket(sk)
    
    def set_socket(self, sk:socket.socket):
        self.ssk = sk
    
    def authenticate_server(self, name, uuid, callback:UtransCallback):
        sk = self.ssk
        msg_handler = self.msg_handler

        if not msg_handler.recv_msg_from_ssk(sk):
            logger.error("fail to recv auth_init")
            return None
        msg = msg_handler.get_msg()
        if msg["msg_type"] != Message.MT_AUTH_INIT:
            logger.error("Protocol error")
            return None
        
        peer_name = msg["name"]
        peer_uuid = msg["uuid"]
        auth_type = msg["auth_type"]
        peer_auth_data = msg["data"]

        session = callback.on_search_session(peer_uuid)
        # Don't allow reconnecting if alreadly connected
        if session != None and session.is_recv_enabled():
            sk.close()
            return None
        if auth_type != "None" and session != None:
            if not callback.on_normal_auth(auth_type, peer_auth_data, session):
                auth_result_msg = msg_handler.pack_msg_common_reply(Message.R_FAILED, "authentication failed")
                try:
                    sk.send(auth_result_msg)
                except BaseException as e:
                    traceback.print_exc()
                    print(e)
                    return None
        else:
            if session == None:
                session = UtransSessionNew(peer_name, peer_uuid)
            has_pubkey = callback.on_check_client_pubkey(peer_uuid)
            if not has_pubkey:
                pubkey_req_msg = msg_handler.pack_auth_req_pubkey()
                try:
                    sk.send(pubkey_req_msg)
                except BaseException as e:
                    traceback.print_exc()
                    print(e)
                    return None
                if not msg_handler.recv_msg_from_ssk(sk):
                    logger.debug("fail to recv pubkey reply")
                    return None
                msg = msg_handler.get_msg()
                if msg["msg_type"] != Message.MT_AUTH_PUBKEY_REPLY:
                    error = "unknown"
                    if "info" in msg.keys():
                        error = msg["info"]
                    logging.error("can't get peer pubkey:%s"%(error))
                    return None
                
                peer_pubkey_type = msg["key_type"]
                peer_pubkey = msg["data"]
                
                if not callback.on_register_pubkey(peer_uuid, peer_pubkey_type, peer_pubkey):
                    auth_fail_msg = msg_handler.pack_msg_common_reply(Message.R_FAILED)
                    try:
                        sk.send(auth_result_msg)
                    except BaseException as e:
                        traceback.print_exc()
                        print(e)
                    return None
            
            # get_session_key
            new_session_key = session.get_session_key()
            if new_session_key == None:
                new_session_key = callback.on_need_session_key(16)
                session.set_session_key(new_session_key)

            
            # start normal auth(including session key exchange)
            challenge_type, challenge_data = callback.on_challenge_peer(session)
            challenge_msg = msg_handler.pack_auth_challenge(challenge_type, challenge_data)
            try:
                sk.send(challenge_msg)
            except BaseException as e:
                traceback.print_exc()
                print(e)
                
            if not msg_handler.recv_msg_from_ssk(sk):
                logger.debug("fail to recv challenge reply")
                return None
            msg = msg_handler.get_msg()
            if msg["msg_type"] != Message.MT_AUTH_CLG_REPLY:
                error = "unknown"
                if "info" in msg.keys():
                    error = msg["info"]
                logging.error("peer can't reply challenge:%s"%(error))
                return None

            challenge_reply_data = msg["data"]
            if not callback.on_verify_challenge(challenge_type, challenge_reply_data, session):
                auth_fail_msg = msg_handler.pack_msg_common_reply(Message.R_FAILED)
                try:
                    sk.send(auth_result_msg)
                except BaseException as e:
                    traceback.print_exc()
                    print(e)
                return None
        
        auth_type, auth_data = callback.on_need_auth_data(session)
        auth_result_msg = msg_handler.pack_auth_finish(name, uuid, auth_type, "base64", auth_data)
        try:
            sk.send(auth_result_msg)
        except BaseException as e:
            traceback.print_exc()
            print(e)
            return None
        session.set_recv_sk(sk)
        return session

    
    def authenticate_client(self, name, uuid, callback:UtransCallback, session = None, server_addr = None):
        sk = self.ssk
        msg_handler = self.msg_handler

        # For all bytes data, use base64 to encode it to str
        if session == None:
            session = UtransSessionNew()
            init_msg = msg_handler.pack_auth_init(name, uuid, server_addr = server_addr)
        else:
            auth_type, auth_data = callback.on_need_auth_data(session)
            init_msg = msg_handler.pack_auth_init(name, uuid, auth_type, "base64", auth_data, server_addr)
        try:
            sk.send(init_msg)
        except BaseException as e:
            traceback.print_exc()
            print(e)
        
        if not msg_handler.recv_msg_from_ssk(sk):
            logger.debug("fail to recv auth init reply")
            return None
        msg = msg_handler.get_msg()
        
        if msg["msg_type"] == Message.MT_AUTH_REQ_PUBKEY:
            key_type, pubkey = callback.on_need_pubkey()
            pubkey_msg = msg_handler.pack_auth_pubkey_reply(key_type, pubkey)
            try:
                sk.send(pubkey_msg)
            except BaseException as e:
                traceback.print_exc()
                print(e)
                return None
            
            if not msg_handler.recv_msg_from_ssk(sk):
                logger.debug("fail to recv auth init reply")
                return None
            msg = msg_handler.get_msg()

        if msg["msg_type"] == Message.MT_AUTH_CLG:
            challenge_type = msg["challenge_type"]
            challenge_data = msg["data"]
            new_session_key, challenge_reply_data = callback.on_solve_challenge(challenge_type, challenge_data, session) 
            challenge_reply_msg = msg_handler.pack_auth_challenge_reply(challenge_reply_data)
            session.set_session_key(new_session_key)
            try:
                sk.send(challenge_reply_msg)
            except BaseException as e:
                traceback.print_exc()
                print(e)
                return None
            
            if not msg_handler.recv_msg_from_ssk(sk):
                logger.debug("fail to recv auth result")
                return None
            msg = msg_handler.get_msg()
        
        if msg["msg_type"] != Message.MT_AUTH_FINISH:
            error = "unknown"
            if "info" in msg.keys():
                error = msg["info"]
            logging.error("authentication failed: %s"%(error))
            return None
        
        peer_name = msg["name"]
        peer_auth_data = msg["data"]
        peer_uuid = msg["uuid"]
        auth_type = msg["auth_type"]

        session.set_name(peer_name)
        session.set_uuid(peer_uuid)
        if not callback.on_normal_auth(auth_type, peer_auth_data, session):
            logging.error("Server's authentication data Invalid")
            return None
        session.set_send_sk(sk)
        return session


    def send_not_support_info(self):
        info = "Not support"
        packed_msg = self.msg_handler.pack_msg_common_reply(Message.R_FAILED, info)
        try:
            self.ssk.send(packed_msg)
        except BaseException as e:
            traceback.print_exc()
            print(e)

    # The "task_info" is used to discriminate and control(i.e. to stop) every asynchronous call to "send_file" in callback function
    def send_file(self, filepath, task_info:UtransTaskInfo, callback:UtransCallback):
        # read filename and file size
        # make sure the file exists in high level APIs of UtransClient
        ssk = self.ssk
        msg_handler = self.msg_handler
        filesize = os.path.getsize(filepath)
        filename = os.path.basename(filepath)
        
        # file send start callback
        callback.on_file_send_start(filename, filesize, task_info)
        
        # send file-send request
        file_send_msg = MessageHandler.pack_msg_send_file(filename, filesize)
        try:
            ssk.send(file_send_msg)
        except Exception as e:
            logger.debug(e)
            callback.on_file_send_finished(UtransError.CONNECTION_ERROR, task_info)
            return False
        
        # get reply
        if msg_handler.recv_msg_from_ssk(ssk) == MessageHandler.S_ABORT:
            logger.debug("connection closed by peer")
            callback.on_file_send_finished(UtransError.CONNECTION_ERROR, task_info)
            return False
        msg = msg_handler.get_msg()

        if msg["msg_type"] != Message.MT_COM_REPLY:
            logger.debug("protocol error")
            callback.on_file_send_finished(UtransError.PROTOCAL_ERROR, task_info)
            return False

        if msg["status"] != Message.R_OK:
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
        if msg_handler.recv_msg_from_ssk(ssk) == MessageHandler.S_ABORT:
            logger.debug("connection closed by peer")
            callback.on_file_send_finished(UtransError.CONNECTION_ERROR, uuid)
            return False
        msg = msg_handler.get()

        if msg["msg_type"] != Message.MT_COM_REPLY:
            logger.debug("ProtocalError: No status in reponse")
            callback.on_file_send_finished(UtransError.PROTOCAL_ERROR, task_info)
            return False
        
        if msg["status"] != Message.R_OK:
            logger.debug("peer responsed failed")
            callback.on_file_send_finished(UtransError.PEER_SAY_FAILED, task_info)
            return False
        # success sending file
        callback.on_file_send_finished(UtransError.OK, task_info)
        return True
        
    def send_message(self, message:str, callback:UtransCallback, task_info:UtransTask):
        
        # send short message
        msg_send_msg = self.msg_handler.pack_msg_send_message(message)
        try:
            self.ssk.send(msg_send_msg)
        except Exception as e:
            print(e)
            callback.on_msg_send_error(UtransError.CONNECTION_ERROR, task_info)
            return False
        callback.on_msg_send_finished(UtransError.OK, task_info)
        return True
        
    def request_file(self, filepath):
        logger.debug("invalid operation for mode", self.mode)
        return False

    def receive_file(self, msg, callback:UtransCallback, task_info = None):
        if task_info == None:
            task_info = UtransTask()
    
        filename = msg["name"]
        try:
            filesize = int(msg["size"])
        except Exception as e:
            print(e)
            callback.on_file_send_error(UtransError.INVALID_CMD, task_info)
            return False
        
        if not callback.on_need_decision("Receive file[%s %s]?"%(filename, filesize)):
            reply_msg = self.msg_handler.pack_msg_common_reply(Message.R_REJECT)
            try:
                self.ssk.send(reply_msg)
            except Exception as e:
                traceback.print_exc()
                callback.on_file_send_error(UtransError.CONNECTION_ERROR, task_info)
                return False
            callback.on_file_send_error(UtransError.USER_REJECT, task_info)
            return False

        # start to receive file callback
        callback.on_file_receive_start(filename, filesize, task_info)
        reply_msg = self.msg_handler.pack_msg_common_reply(Message.R_OK)
        try:
            self.ssk.send(reply_msg)
        except Exception as e:
            traceback.print_exc()
            print(e)
            callback.on_file_send_error(UtransError.CONNECTION_ERROR, task_info)
            return False

        # todo: There may be a file with the same name, so check it.
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
        if left_size > 0:
            logger.debug("data not complete")
            reply_msg = self.msg_handler.pack_msg_common_reply(Message.R_FAILED)
        else:
            reply_msg= self.msg_handler.pack_msg_common_reply(Message.R_OK)
        try:
            self.ssk.send(reply_msg)
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

    def receive_message(self, msg, callback:UtransCallback, task_info = None):
        if msg["encode"] == "base64":
            msg_content = msg["data"].decode("utf8")
        else:
            msg_content = msg["data"]
        
        callback.on_msg_receive(msg_content, task_info)
        return True

class UtransServer():

    def __init__(self, port = UtransDefault.SERVICE_PORT):
        self.name = None
        self.uuid = None
        self.running = False
        self.port = port
        self.lsk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.scan_responder = UtransScanResponder(self.name, self.port)
        logger.debug("server port: %d"%(port))

    def set_name(self, name):
        self.name = name

    def set_uuid(self, uuid):
        self.uuid = uuid

    def init(self):
        logger.debug("server start to listen")
        self.lsk.bind(('0.0.0.0', self.port))
        self.lsk.listen(2)
        self.scan_responder.asyn_start()

    def handle_client(self, ssk:socket.socket, addr):
        msg_handler = MessageHandler()
        utrans = UtransCore(ssk)
        callback = self.callback
        session = utrans.authenticate_server(self.name, self.uuid, self.callback)
        if session == None:
            print("fail to authenticate")
            return 
        else:
            print("authenticate ok")
            session.print_info()
        session_index = callback.on_new_session(session)

        # ok, start handling requests
        while True:
            if not msg_handler.recv_msg_from_ssk(ssk):
                logger.debug("peer close connection")
                callback.on_session_close_recv(session_index)
                break
            msg = msg_handler.get_msg()
            task_info = UtransTask(session_index = session_index)
            msg_type = msg["msg_type"]
            if msg_type == Message.MT_SEND_FILE:
                utrans.receive_file(msg, callback, task_info)
            elif msg_type == Message.MT_SEND_MSG:
                utrans.receive_message(msg, callback, task_info)
            else:
                utrans.send_not_support_info()
                print("unknown operation: %s"%(msg_type))
    
    # open a new thread to broadcast
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
    
    def stop_scan_service(self):
        self.scan_responder.stop()

    def stop_server(self):
        if self.running == True:
            self.lsk.close()
            self.running = False
    
    def async_run(self, callback):
        _thread.start_new_thread(self.run, (callback,))

class UtransClient:
    def __init__(self, name = None, uuid = None):
        self.name = name
        self.uuid = uuid
        self.current_session = None
        self.session = None
        self.scanner = UtransScanner()
    
    def set_name(self, name):
        self.name = name
    
    def set_uuid(self, uuid):
        self.uuid = uuid
    
    def set_current_session(self, session:UtransSessionNew):
        self.current_session = session

    def get_current_session(self):
        return self.current_session
    
    def set_scan_port(self, port:int):
        self.scanner.set_scan_port(port)

    def start_scan(self, callback, time = 0):
        self.scanner.start_scan(callback, time)

    def stop_scan(self):
        self.scanner.stop_scan()

    def connect(self, callback, server:UtransServerInfo = None):
        ssk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssk.settimeout(3)
        logger.debug("connect")
        session = None
        self_server_addr = None
        if server == None:
            session = self.current_session
            if session == None:
                logging.error("Not destination")
                return False
            addr = session.peer_addr
        else:
            addr = server.addr
        try:
            ssk.connect(addr)
        except Exception as e:
            traceback.print_exc()
            print(e)
            callback.on_connect_error(UtransError.CONNECTION_ERROR)
            return False

        ##################### New authentication ###########################
        ucore = UtransCore()
        ucore.set_socket(ssk)
        session = ucore.authenticate_client(self.name, self.uuid, callback, session, self_server_addr)
        if session == None:
            print("fail to authenticate")
            return False
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
            task_info = UtransTaskInfo(session_index = session.id)
        if not os.path.exists(filename):
            callback.on_file_send_error(UtransError.NO_SUCH_FILE, task_info)
            return False
        utrans = UtransCore(session.send_sk)
        if block:
            return utrans.send_file(filename, task_info, callback)
        else:
            _thread.start_new_thread(utrans.send_file, (filename, task_info, callback))
            return True
    
    def send_files(self, filenames, callback, task_infos = None, session:UtransSession = None):
        if session == None:
            session = self.current_session
        if task_infos == None:
            task_infos = (UtransTask(session_index = session.id) for i in range(len(filenames)))
        _thread.start_new_thread(self.__do_send_files, (filenames, callback, task_infos, session))

    def __do_send_files(self, filenames, callback, task_infos, session):
        for filename, task_info in zip(filenames, task_infos):
            self.send_file(filename, callback, task_info = task_info, block=True, session=session)
       
    def send_message(self, msg, callback, task_info:UtransTask = None, block = False, session:UtransSessionNew = None):
        if session == None:
            session = self.current_session
        utrans = UtransCore(session.send_sk)
        if task_info == None:
            task_info = UtransTask()
        if block:
            utrans.send_message(msg, callback, task_info)
        else:
            _thread.start_new_thread(utrans.send_message, (msg, callback, task_info))

    def async_test(self, callback):
        _thread.start_new_thread(time.sleep, (3,))
        callback.on_finished("ok")

def main():
    m = MessageHandler()

if __name__ == "__main__":
    main()