#!/usr/bin/python3
'''
Author: January
Date: 2021-05-17 17:17:05
'''
import socket
import hmac
import hashlib
from utrans.network import STS
from utrans.utils import *
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from utrans.interface import UtransContext, UtransFileTransHandle, UtransSessionListener
import pyDHE
import pdb
import _thread
import logging
import os
import queue

logger = logging.getLogger("core")

class Message:
    # MT 表示 Message Type
    MT_SEND_FILE = b"send_file"
    MT_SEND_MSG = b"send_msg"
    MT_SCAN_REQ = b"scan_req"
    MT_SCAN_REPLY = b"scan_reply"
    MT_COM_REPLY = b"common_reply"
    MT_SESSION_INIT = b"session_init"
    MT_SESSION_REPLY = b"session_reply"
    MT_SESSION_RECONNECT = b"session_reconnect"
    MT_SESSION_FINAL = b"session_final"
    MT_SESSION_CLOSE = b"close_session"
    MT_REGISTER = b"register"

    # 各自消息字段名称
    MSG_FIELD = {            
        # 数据传输
        MT_SEND_FILE : ("type", "name", "size"),
        MT_SEND_MSG : ("type", "size", "data"),
        MT_COM_REPLY : ("type", "status", "info"),

        # 服务发现
        MT_SCAN_REQ : ("type", ),
        MT_SCAN_REPLY : ("type", "name", "addr"),

        # 连接建立和断开
        MT_SESSION_INIT : ("type", "name", "dh_a"),
        MT_SESSION_REPLY : ("type", "name", "dh_b"),
        MT_SESSION_FINAL : ("type", ),
        MT_SESSION_CLOSE : ("type", ),
        # 未使用
        MT_REGISTER : ("type", "name", "uuid", "data"),
        MT_SESSION_RECONNECT : ("type", "name")
    }

    def __init__(self, values):
        logger.debug("Build Message, type [%s]"%values[0].decode("utf8"))

        fields = Message.MSG_FIELD[values[0]]
        self.values = values
        if len(fields) != len(values):
            raise Exception("Invalid Message, fields doesn't match")
        
        for field, value in zip(fields, values):
            self.__dict__[field] = value

        
    def to_bytes(self):
        return pack_bytes(self.values)
    
    @staticmethod
    def from_bytes(bytes_list):
        values = unpack_bytes(bytes_list)
        return Message(values)

    @staticmethod
    def pack_session_init(name : str, dh_a : bytes):
        return Message([Message.MT_SESSION_INIT, name.encode("utf8"), dh_a])
        
    @staticmethod
    def pack_session_final():
        return Message([Message.MT_SESSION_FINAL])
    
    @staticmethod
    def pack_session_close():
        return Message([Message.MT_SESSION_CLOSE])

    @staticmethod
    def pack_session_reply(name : str, dh_b : bytes):
        return Message([Message.MT_SESSION_REPLY, name.encode("utf8"), dh_b])
    
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
    def pack_send_message(msg : bytes, size : int):
        msg_len_size = calculate_num_byte_size(size)
        values = [Message.MT_SEND_MSG, int.to_bytes(size, msg_len_size, "little"), msg]
        return Message(values)

    # ("msg_type", "name", "size")
    @staticmethod
    def pack_send_file(filename:str, filesize:int):
        values = [Message.MT_SEND_FILE, filename.encode("utf8"), int.to_bytes(filesize, calculate_num_byte_size(filesize), 'little')]
        return Message(values)

    # ("msg_type", "status", "info")
    @staticmethod
    def pack_common_reply(reply_status, info = None):
        values = [Message.MT_COM_REPLY, reply_status, info]
        return Message(values)

class UtransAddr:
    def __init__(self, name = "unknown", tcp_addr = None):
        self.name = name
        self.tcp_addr = tcp_addr

class UtransSession:
    NETWORK_TIMEOUT = 3
    RECV_SERVER_TIMEOUT = 5
    LEN_FILE_SEGMENT = 4096

    # S表示status
    S_INIT = 0x0
    S_RECV_OK = 0x1
    S_SEND_OK = 0x2

    def __init__(self, src_name):
        self.src_name = src_name
        self.des_name = None
        self.shared_key = None
        self.status = UtransSession.S_INIT
        self.listener = UtransSessionListener()
        # 传输层对象
        self.s_channel = None
        self.r_channel = None
        self.sts = None
    
    def set_status_listener(self, listener : UtransSessionListener):
        self.listener = listener

    # 客户端使用（发送）
    def connect_by_password(self, password, tcp_addr):
        # 建立tcp连接
        tcp_sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_sk.connect(tcp_addr)
        self.sts = STS(tcp_sk, STS.Peer_A)
        self.s_channel = self.sts.get_channel()
        self.r_channel = self.sts.new_channel()

        # 执行认证Utrans认证流程
        # 口令生成密钥
        # hmac_hash_module在旧版本的pycryotodome中似乎不支持
        key = PBKDF2(password, b'eidhyskodnelwiso', count=1000, hmac_hash_module=SHA256)
        # 生成dh密钥协商数据
        dh_ob = pyDHE.new()
        dh_a_int = dh_ob.getPublicKey()
        dh_a = int.to_bytes(dh_a_int, 256, 'little')
        # 生成session_init数据包
        m_se1 = Message.pack_session_init(self.src_name, dh_a)
        m_se1_bytes = m_se1.to_bytes()
        mac = hmac.new(key, m_se1_bytes, digestmod="sha256").digest()
        self.s_channel.send( m_se1_bytes + mac )
        # 接收session_reply数据包
        pkt = self.s_channel.recv()
        if len(pkt) < hashlib.new("sha256").digest_size:
            raise("Invalid se2 msg, too short")
        m_se2_bytes = pkt[0:-32]
        mac = pkt[-32:]
        m_se2 = Message.from_bytes(m_se2_bytes)
        dh_b = m_se2.dh_b
        self.des_name = m_se2.name.decode("utf8")
        shared_key_int = dh_ob.update(int.from_bytes(dh_b, "little"))
        shared_key = int.to_bytes(shared_key_int, 256, "little")
        real_mac = hmac.new(key, m_se2_bytes + shared_key, digestmod="sha256").digest()
        if hmac.compare_digest(real_mac, mac) == False:
            raise Exception("Invalid mac in se2 msg")

        # 发送session_final数据包
        m_se3_bytes = Message.pack_session_final().to_bytes()
        mac = hmac.new(key, m_se3_bytes + shared_key, digestmod="sha256").digest()
        self.s_channel.send(m_se3_bytes + mac)
        
        # 连接成功
        self.shared_key = shared_key
        self.sts.enable_security(shared_key[20:30], shared_key[30:46])
        self.status |= UtransSession.S_SEND_OK | UtransSession.S_RECV_OK

        # 启动接收服务器
        _thread.start_new_thread(self.handle_request, ())
    
    def send_file(self, filepath, handle : UtransFileTransHandle):
        filesize = os.path.getsize(filepath)
        filename = os.path.basename(filepath)
        left = filesize

        msg = Message.pack_send_file(filename, filesize)
        self.s_channel.send(msg.to_bytes())

        handle.on_start()
        with open(filepath, "rb") as f:
            while not handle.stoped:
                data = f.read(4096)
                if len(data) <= 0:
                    break
                left -= len(data)
                handle.on_progress(1 - (left / filesize))
                self.s_channel.send(data)
        if left <= 0:
            handle.on_finished()
        else:
            handle.on_error("Fail to send file")
            
    def send_text(self, text : str):
        text_bytes = text.encode("utf8")
        size = len(text_bytes)
        msg = Message.pack_send_message(text_bytes, size)
        self.s_channel.send(msg.to_bytes())

    # 服务器使用(接收)
    def handle_request(self):
        logger.debug("Recv server start")
        while self.status & UtransSession.S_RECV_OK != 0:
            try:
                msg_bytes = self.r_channel.recv(timeout = UtransSession.RECV_SERVER_TIMEOUT)
            except queue.Empty:
                continue
            if len(msg_bytes) == 0:
                print("Connection broken, exit recv server")
                self.close_passive()
                return 
            # 处理消息
            msg = Message.from_bytes(msg_bytes)
            if msg.type == Message.MT_SEND_FILE:
                self.handle_send_file(msg)
            elif msg.type == Message.MT_SEND_MSG:
                self.handle_send_text(msg)
            elif msg.type == Message.MT_SESSION_CLOSE:
                self.close_passive()
        print("Recv server exit")

        # 按照msg_bytes的类型进行处理    
    
    def accept_by_password(self, tcp_sk : socket, password):
        self.sts = STS(tcp_sk, STS.Peer_B)
        self.r_channel = self.sts.get_channel()
        self.s_channel = self.sts.new_channel()

        pkt = self.r_channel.recv()
        # 执行认证Utrans认证流程
        # 口令生成密钥
        key = PBKDF2(password, b'eidhyskodnelwiso', count=1000, hmac_hash_module=SHA256)
        if len(pkt) < hashlib.new("sha256").digest_size:
            raise("Invalid se1 msg, too short")
        
        m_se1_bytes = pkt[0:-32]
        mac = pkt[-32:]
        m_se1 = Message.from_bytes(m_se1_bytes)
        real_mac = hmac.new(key, m_se1_bytes, digestmod="sha256").digest()
        if hmac.compare_digest(real_mac, mac) == False:
            raise Exception("Invalid mac in se1 msg")
        dh_a = m_se1.dh_a
        self.des_name = m_se1.name.decode("utf8")
        # 生成dh密钥协商数据
        dh_ob = pyDHE.new()
        dh_b_int = dh_ob.getPublicKey()
        shared_key_int = dh_ob.update(int.from_bytes(dh_a, "little"))
        shared_key = int.to_bytes(shared_key_int, 256, "little")
        # 生成se2数据包
        dh_b = int.to_bytes(dh_b_int, 256, 'little')
        m_se2_bytes = Message.pack_session_reply(self.src_name, dh_b).to_bytes()
        mac = hmac.new(key, m_se2_bytes + shared_key, digestmod="sha256").digest()
        self.r_channel.send(m_se2_bytes + mac)

        # 接收se3数据包
        pkt = self.r_channel.recv()
        if len(pkt) < hashlib.new("sha256").digest_size:
            raise("Invalid se3 msg, too short")
        m_se3_bytes = pkt[0:-32]
        mac = pkt[-32:]
        real_mac = hmac.new(key, m_se3_bytes+ shared_key, digestmod="sha256").digest()
        if hmac.compare_digest(real_mac, mac) == False:
            raise Exception("Invalid mac in session final")

        self.shared_key = shared_key
        # 连接成功
        self.sts.enable_security(shared_key[20:30], shared_key[30:46])
        self.status |= UtransSession.S_RECV_OK | UtransSession.S_SEND_OK
        self.listener.on_connected(self)

    def handle_send_file(self, msg):
        filename = msg.name.decode("utf8")
        filesize = int.from_bytes(msg.size, "little")
        handle = self.listener.on_recv_file(filename, filesize)

        handle.on_start()
        left = filesize
        with open("recv" + filename, "wb") as f:
            while left > 0 and not handle.stoped:
                data = self.r_channel.recv()
                f.write(data)
                left -= len(data)
                handle.on_progress(1 - (left / filesize))
        if left <= 0:
            handle.on_finished()
        else:
            handle.on_error("Fail to receive data")
 
    def handle_send_text(self, msg):
        text_bytes = msg.data
        text = text_bytes.decode("utf8")
        self.listener.on_recv_text(text)
    
    # 主动关闭连接（向对方发送连接关闭的消息）
    def close_active(self):
        if self.status == UtransSession.S_INIT:
            return
        self.s_channel.send(Message.pack_session_close().to_bytes())
        self.__close()
    
    # 被动关闭连接
    def close_passive(self):
        if self.status == UtransSession.S_INIT:
            return
        self.listener.on_disconnected(self)
        self.__close()
    
    # 关闭连接，清理资源
    def __close(self):
        self.status = UtransSession.S_INIT
        self.sts.close()
               
class UtransServer():

    def __init__(self, ctx : UtransContext):
        self.ctx = ctx
        self.running = False
        self.src_addr = ctx.get_src_addr()
        logger.debug("server port: %s"%(str(self.src_addr.tcp_addr)))

    def init(self):
        self.lsk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.lsk.bind(self.src_addr.tcp_addr)
        self.lsk.listen(2)
        logger.debug("server start to listen")

    def handle_client(self, sk, session : UtransSession):
        session.accept_by_password(sk, self.ctx.get_password())
        session.handle_request()

    # open a new thread to broadcast
    def run(self):
        self.init()
        self.running = True

        while self.running:
            sk, addr = self.lsk.accept()
            logger.debug("connection from" + str(addr))
            session = UtransSession(self.src_addr.name)
            session.set_status_listener(self.ctx.get_session_listener())
            _thread.start_new_thread(self.handle_client, (sk, session))

    def stop_server(self):
        if self.running == True:
            if self.lsk != None:
                self.lsk.close()
                self.lsk = None
            self.running = False
    
    def async_run(self):
        return _thread.start_new_thread(self.run, ())
        
