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
import pyDHE
import pdb

class Message:
    # MT 表示 Message Type
    MT_SEND_FILE = b"send_file"
    MT_SEND_MSG = b"send_msg"
    MT_SCAN_REQ = b"scan_req"
    MT_SCAN_REPLY = b"scan_reply"
    MT_COM_REPLY = b"common_reply"
    MT_REGISTER = b"register"
    MT_SESSION_INIT = b"session_init"
    MT_SESSION_REPLY = b"session_reply"
    MT_SESSION_RECONNECT = b"session_reconnect"
    MT_SESSION_FINAL = b"session_final"
    MT_SESSION_CLOSE = b"close_session"

class UtransAddr:
    def __init__(self, name, tcp_addr):
        self.name = name
        self.tcp_addr = tcp_addr

class UtransSession:
    NETWORK_TIMEOUT = 3
    LEN_FILE_SEGMENT = 4096

    # S表示status
    S_INIT = 0x0
    S_RECV_OK = 0x1
    S_SEND_OK = 0x2

    def __init__(self, src_addr : UtransAddr, des_addr : UtransAddr):
        self.src_addr = src_addr
        self.des_addr = des_addr
        self.s_channel = None
        self.r_channel = None
        self.shared_key = None
        self.status = UtransSession.S_INIT
    
    def connect_by_password(self, password):
        # 建立tcp连接
        tcp_sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_sk.connect(self.des_addr.tcp_addr)
        self.s_channel = STS(tcp_sk, STS.Peer_A)

        # 执行认证Utrans认证流程
        # 口令生成密钥
        key = PBKDF2(password, b'eidhyskodnelwiso', count=1000000, hmac_hash_module=SHA256)
        # 生成dh密钥协商数据
        dh_ob = pyDHE.new()
        dh_a_int = dh_ob.getPublicKey()
        dh_a = int.to_bytes(dh_a_int, 256, 'little')
        # 生成session_init数据包
        m_se1_main_bytes = pack_bytes([Message.MT_SESSION_INIT, self.src_addr.name.encode("utf8"), dh_a])
        mac = hmac.new(key, m_se1_main_bytes, digestmod="sha256").digest()
        self.s_channel.send( m_se1_main_bytes + mac )

        # 接收session_reply数据包
        m_se2_bytes = self.s_channel.recv()
        if len(m_se2_bytes) < hashlib.new("sha256").digest_size:
            raise("Invalid se2 msg, too short")
        m_se2 = unpack_bytes(m_se2_bytes[:-32])
        dh_b = m_se2[2]
        shared_key_int = dh_ob.update(int.from_bytes(dh_b, "little"))
        shared_key = int.to_bytes(shared_key_int, 256, "little")
        real_mac = hmac.new(key, m_se2_bytes[0:-32] + shared_key, digestmod="sha256").digest()
        if hmac.compare_digest(real_mac, m_se2_bytes[-32 :]) == False:
            raise Exception("Invalid mac in se2 msg")

        # 发送session_final数据包
        m_se3_main_bytes = pack_bytes([Message.MT_SESSION_FINAL])
        mac = hmac.new(key, m_se3_main_bytes + shared_key, digestmod="sha256").digest()
        self.s_channel.send(m_se3_main_bytes + mac)
        
        # 连接成功
        self.shared_key = shared_key
        self.s_channel.enable_security(shared_key[20:30], shared_key[30:46])
        self.status |= UtransSession.S_SEND_OK
        print("connected")

    def connect_backwards(self):
        tcp_sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_sk.connect(self.des_addr.tcp_addr)

        self.s_channel = STS(tcp_sk, STS.Peer_A)
        m_sr_main_bytes = pack_bytes([Message.MT_SESSION_RECONNECT, self.src_addr.name.encode("utf8")])
        mac = hmac.new(self.shared_key[80:96], m_sr_main_bytes, digestmod="sha256").digest()
        self.s_channel.send(m_sr_main_bytes + mac)
        self.s_channel.enable_security(self.shared_key[100:110], self.shared_key[110:126])
        self.status |= UtransSession.S_SEND_OK
        print("reconnect")


    def handle_request(self):
        while True:
            msg_bytes = self.r_channel.recv()
        # 按照msg_bytes的类型进行处理    
    
    def accept_by_password(self, msg, tcp_sk : socket, password):
        self.r_channel = STS(tcp_sk, STS.Peer_B)

        # 执行认证Utrans认证流程
        # 口令生成密钥
        key = PBKDF2(password, b'eidhyskodnelwiso', count=1000000, hmac_hash_module=SHA256)
        
        m_se1_bytes = msg
        if len(m_se1_bytes) < hashlib.new("sha256").digest_size:
            raise("Invalid se1 msg, too short")
        
        m_se1 = unpack_bytes(m_se1_bytes[:-32])
        real_mac = hmac.new(key, m_se1_bytes[0:-32], digestmod="sha256").digest()
        if hmac.compare_digest(real_mac, m_se1_bytes[-32:]) == False:
            raise Exception("Invalid mac in se1 msg")
        dh_a = m_se1[2]
        # 生成dh密钥协商数据
        dh_ob = pyDHE.new()
        dh_b_int = dh_ob.getPublicKey()
        shared_key_int = dh_ob.update(int.from_bytes(dh_a, "little"))
        shared_key = int.to_bytes(shared_key_int, 256, "little")
        
        # 生成se2数据包
        dh_b = int.to_bytes(dh_b_int, 256, 'little')
        m_se2_main_bytes = pack_bytes([Message.MT_SESSION_REPLY, self.src_addr.name.encode("utf8"), dh_b])
        mac = hmac.new(key, m_se2_main_bytes + shared_key, digestmod="sha256").digest()
        self.r_channel.send(m_se2_main_bytes + mac)

        # 接收se3数据包
        m_se3_bytes = self.r_channel.recv()
        real_mac = hmac.new(key, m_se3_bytes[:-32] + shared_key, digestmod="sha256").digest()
        if hmac.compare_digest(real_mac, m_se3_bytes[-32:]) == False:
            raise Exception("Invalid mac in session final")

        self.shared_key = shared_key
        # 连接成功
        self.r_channel.enable_security(shared_key[40:50], shared_key[60:76])
        self.status |= UtransSession.S_RECV_OK
        print("connected")

        # 建立发送通道
        self.connect_backwards()
    
    def accept_backwards(self, msg, tcp_sk):
        m_sr_bytes = msg
        m_sr = unpack_bytes(m_sr_bytes[:-32])
        if self.status & UtransSession.S_SEND_OK == 0:
            raise Exception("Not connected, can't be connected backwards")
        
        real_mac = hmac.new(self.shared_key[80:96], m_sr_bytes[:-32], digestmod="sha256").digest()
        if hmac.compare_digest(real_mac, m_sr_bytes[-32:]) == False:
            raise Exception("Invalid mac in session reconnect")
        self.r_channel = STS(tcp_sk, STS.Peer_B)
        self.r_channel.enable_security(self.shared_key[100:110], self.shared_key[110:126])
        self.status |= UtransSession.S_RECV_OK
        print("reconnected")

        
