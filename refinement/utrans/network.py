#!/usr/bin/python3
import hmac
import hashlib
import queue
import threading
import _thread
from Crypto.Cipher import AES
import socket
import logging
import traceback

import pdb

'''
Author: January
Date: 2021-05-17 10:51:19
'''

'''
| Magic(1 bytes) | flags(1 byte) | type(1 byte)    | channel (1 byte)  |
|       payload_len(2 bytes)     | mac_len(1 byte) | ophdr_len(1 byte) |
|                          seq (4 bytes)                               |
|                      optional header( may be)                        |
|                      payload(payload len bytes)                      |
|                               mac                                    |
'''

logger = logging.getLogger("network")
class STS_pkt:
    MAGIC = 0xaf
    T_PLAIN = 0
    T_ENC = 1
    T_AUTH = 2
    LEN_FRAME = 65535
    LEN_HEADER = 12

    def __init__(self):
        self.magic = STS_pkt.MAGIC
        self.flags = 0
        self.type = STS_pkt.T_PLAIN
        self.payload_len = 0
        self.channel = 0
        self.mac_len = 0
        self.ophdr_len = 0
        self.seq = 0
        self.payload = None
        self.mac = None
        self.llsk = 0

    # 处理发送的数据包
    def pack(self, nonce = None, enc_key = None, mac_key = None):
        self.raw_frame = bytearray(STS_pkt.LEN_FRAME)
        frame_size = STS_pkt.LEN_HEADER + self.payload_len + self.ophdr_len + self.mac_len
        if frame_size > STS_pkt.LEN_FRAME:
            raise Exception("Data too large to fit in a frame")
        self.raw_frame[0] = self.magic
        self.raw_frame[1] = self.flags
        self.raw_frame[2] = self.type
        # channel
        self.raw_frame[3] = self.channel
        self.raw_frame[4:6] = int.to_bytes(self.payload_len, 2, 'little')
        self.raw_frame[6] = self.mac_len
        self.raw_frame[7] = self.ophdr_len
        self.raw_frame[8:12] = int.to_bytes(self.seq, 4, 'little')

        if self.type & STS_pkt.T_ENC != 0:
            if enc_key == None or nonce == None:
                raise Exception("You have to provide enc key and nonce for enc frame")
            aes_ob = AES.new(enc_key, mode=AES.MODE_CTR, nonce=nonce+self.raw_frame[8:12])
            # encrypt payload
            self.raw_frame[12:(12 + self.payload_len)] = aes_ob.encrypt(self.payload)
        else:
            self.raw_frame[12:(12 + self.payload_len)] = self.payload

        if self.type & STS_pkt.T_AUTH != 0:
            if mac_key == None:
                raise Exception("You have to provide mac key for auth frame")
            hmac_ob = hmac.new(mac_key, digestmod="sha256")
            if self.mac_len != hmac_ob.digest_size:
                raise Exception("mac len doesn't match with hmac algorithm")
            hmac_ob.update(self.raw_frame[0:(12 + self.payload_len)])
            self.mac = hmac_ob.digest()
            self.raw_frame[12 + self.payload_len : 12 + self.payload_len + self.mac_len] = self.mac

        return self.raw_frame[0 : frame_size]

    def set_payload(self, payload, seq = 0):
        self.payload_len = len(payload)
        self.payload = payload 
        self.seq = seq

    def set_channel(self, channel : int):
        assert channel >= 0 and channel <= 255
        self.channel = channel

    def enable_auth(self, mac_len):
        self.mac_len = mac_len
        self.type |= STS_pkt.T_AUTH
    
    def enable_enc(self):
        self.type |= STS_pkt.T_ENC

    # 处理接收的数据包
    def recv_header_bytes(self, header):
        if header[0] != STS_pkt.MAGIC:
            print(header)
            raise Exception("Bad frame header with magic %x"%header[0])
        self.magic = header[0]
        self.flags = header[1]
        self.type = header[2]
        self.channel = header[3]
        self.payload_len = int.from_bytes(header[4:6], 'little')
        self.mac_len = header[6]
        self.ophdr_len = header[7]
        self.seq = int.from_bytes(header[8:12], 'little')
        # 保存原始header
        self.raw_header = header
    
    def recv_payload(self, payload):
        self.payload = payload
    
    def recv_mac(self, mac):
        self.mac = mac

    def unpack(self, nonce = None, enc_key = None, mac_key = None):
        if self.type & STS_pkt.T_AUTH != 0:
            if mac_key == None:
                raise Exception("You have to provide mac key for auth frame")
            hmac_ob = hmac.new(mac_key, digestmod="sha256")
            hmac_ob.update(self.raw_header)
            hmac_ob.update(self.payload)
            real_mac = hmac_ob.digest()
            ret = hmac.compare_digest(real_mac, self.mac)
            if ret == False:
                raise Exception("Invalid frame, mac check failed")
        
        if self.type & STS_pkt.T_ENC != 0:
            if enc_key == None or nonce == None:
                raise Exception("You have to provide enc key and nonce for enc frame")
            aes_ob = AES.new(enc_key, mode=AES.MODE_CTR, nonce=nonce + int.to_bytes(self.seq, 4, "little"))
            # encrypt payload
            data = aes_ob.decrypt(self.payload)
        else:
            data = self.payload
        
        return data

class STS_channel:
    
    def __init__(self, sts, channel_num = 0):
        self.sts = sts
        self.num = channel_num
        self.spkt = STS_pkt()
        self.spkt.set_channel(channel_num)
        self.r_queue = queue.Queue(1024)
    
    def send(self, data):
        self.sts.send(data, self.spkt)
    
    def recv(self, timeout = None):
        return self.r_queue.get(timeout=timeout)

    def enable_auth(self, mac_len):
        self.spkt.enable_auth(mac_len)
    
    def enable_enc(self):
        self.spkt.enable_enc()
    
class STS:
    S_OK = 0
    S_DISCONNECTED = 1

    M_SINGLE = 0
    M_MULTIPLE = 1

    Peer_A = 0
    Peer_B = 1
    
    # llsk表示lower layer socket
    def __init__(self, llsk, peer_type):
        self.send_enc_key = None
        self.send_mac_key = None
        self.recv_enc_key = None
        self.recv_mac_key = None
        self.send_nonce = None
        self.recv_nonce = None
        self.lock = threading.Lock()
        self.send_seq = 0
        self.recv_seq = 0
        self.security = STS_pkt.T_PLAIN
        self.peer_type = peer_type
        self.llsk = llsk
        self.channels = dict()
        # chnum表示channel number
        self.next_chnum = 1
        self.rpkt = STS_pkt()
        self.status = STS.S_OK
        # M_SINGLE表示不使用channel特性（只有一个主channel，直接使用sts发送和接收数据）
        self.mode = STS.M_SINGLE

        # 创建主channel
        self.channels[0] = STS_channel(self)
        
    def enable_auth(self, auth_key):
        hash_ob = hashlib.new("sha256")
        hash_ob.update(auth_key)
        keys = hash_ob.digest()
        self.security |= STS_pkt.T_AUTH
        for channel_num in self.channels.keys():
            self.channels[channel_num].enable_auth(hash_ob.digest_size)
        if self.peer_type == STS.Peer_A:
            self.send_mac_key = keys[0:16]
            self.recv_mac_key = keys[16:]
        else:
            self.recv_mac_key = keys[0:16]
            self.send_mac_key = keys[16:]

    def enable_enc(self, nonce, enc_key):
        hash_ob = hashlib.new("sha256")
        hash_ob.update(enc_key)
        keys = hash_ob.digest()
        hash_ob.update(nonce)
        nonces = hash_ob.digest()
        self.security |= STS_pkt.T_ENC
        for channel_num in self.channels.keys():
            self.channels[channel_num].enable_enc()

        if self.peer_type == STS.Peer_A:
            self.send_enc_key = keys[0:16]
            self.recv_enc_key = keys[16:]
            self.send_nonce = nonces[0:10]
            self.recv_nonce = nonce[10:20]
        else:
            self.recv_enc_key = keys[0:16]
            self.send_enc_key = keys[16:]
            self.recv_nonce = nonces[0:10]
            self.send_nonce = nonce[10:20]

    def enable_security(self, nonce, key):
        hash_ob = hashlib.new("sha256")
        hash_ob.update(key)
        keys = hash_ob.digest()
        self.enable_enc(nonce, keys[0:16])
        self.enable_auth(keys[16:])

    def __get_seq(self):
        ret  = self.send_seq
        # 在启用加密的情况下才设置有效的序列号
        if self.send_enc_key != None:
            self.send_seq += 1
        return ret

    def send(self, data, spkt):
        # default to use channel 0
        self.lock.acquire()
        spkt.set_payload(data, self.__get_seq())
        raw_frame = spkt.pack(self.send_nonce, self.send_enc_key, self.send_mac_key)
        ret = self.llsk.send(raw_frame)
        self.lock.release()
        return ret
    
    def recv(self):
        header = bytearray(12)
        pos = 0
        while pos < STS_pkt.LEN_HEADER:
            try:
                ret = self.llsk.recv_into(memoryview(header)[pos:])
            except socket.timeout:
                if self.status != STS.S_OK:
                    return b''
                else:
                    continue

            if ret == 0:
                self.__connection_broken()
                raise Exception("Connection broke")
            pos += ret
            
        rpkt = self.rpkt
        rpkt.recv_header_bytes(header)

        payload = bytearray(rpkt.payload_len)
        pos = 0
        while pos < rpkt.payload_len:
            try:
                ret = self.llsk.recv_into(memoryview(payload)[pos:])
            except socket.timeout:
                if self.status != STS.S_OK:
                    return b''
                else:
                    continue
            if ret == 0:
                self.__connection_broken()
                raise Exception("Connection broke")
            pos += ret
        payload = bytes(payload)
        rpkt.recv_payload(payload)

        if rpkt.mac_len > 0:
            mac = bytearray(rpkt.mac_len)
            pos = 0
            while pos < rpkt.mac_len:
                try:
                    ret = self.llsk.recv_into(memoryview(mac)[pos:])
                except socket.timeout:
                    if self.status != STS.S_OK:
                        return b''
                    else:
                        continue
                if ret == 0:
                    self.__connection_broken()
                    raise Exception("Connection broke")
                pos += ret
            rpkt.recv_mac(mac)
        
        data = rpkt.unpack(self.recv_nonce, self.recv_enc_key, self.recv_mac_key)
        return data

    def __connection_broken(self):
        if self.status == STS.S_OK:
            self.status = STS.S_DISCONNECTED
            for channel_num in self.channels:
                self.channels[channel_num].r_queue.put(b'')

    def __recv_worker(self):
        self.llsk.settimeout(5)
        while self.status == STS.S_OK:
            data = self.recv()
            r_queue = self.channels[self.rpkt.channel].r_queue
            r_queue.put_nowait(data)

    def new_channel(self) -> STS_channel:
        if self.mode == STS.M_SINGLE:
            self.mode = STS.M_MULTIPLE
            _thread.start_new_thread(self.__recv_worker, ())
        channel = STS_channel(self, self.next_chnum)
        self.next_chnum += 1
        if self.security & STS_pkt.T_AUTH:
            channel.enable_auth(hashlib.new("sha256").digest_size)
        if self.security & STS_pkt.T_ENC:
            channel.enable_enc()
        self.channels[channel.num] = channel
        logger.debug("create new channel %d"%channel.num)
        return channel
    
    def get_channel(self, channel_num = 0) -> STS_channel:
        if self.mode == STS.M_SINGLE:
            self.mode = STS.M_MULTIPLE
            _thread.start_new_thread(self.__recv_worker, ())
        return self.channels[channel_num]

    def delete_channel(self, channel_num):
        # 不允许删除主channel
        assert channel_num != 0
        self.channels.pop(channel_num)

    def resume(self, llsk):
        if self.status == STS.S_DISCONNECTED:
            self.llsk = llsk
            self.status = STS.S_OK
            if self.mode == STS.M_MULTIPLE:
                _thread.start_new_thread(self.__recv_worker, ())
        else:
            raise Exception("Can't resume STS")

    def close(self):
        self.status = self.S_DISCONNECTED
        self.llsk.close()
    
def server():
    lk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lk.bind(("127.0.0.1", 9999))
    lk.listen()

    sk, addr = lk.accept()
    sts = STS(sk, STS.Peer_B)
    sts.enable_security(b'asdfghjklz', b'qazwsxedcrfvtgby')
    sts.new_channel()
    _thread.start_new_thread(recv_file, (sts, "t2_test.tar.gz",1))
    recv_file(sts, "t1_test.tar.gz", 0)
    input()

def recv_file(sts, name, channel):
    f = open(name, "wb")
    while True:
        try:
            data = sts.recv(channel)
        except:
            break
        f.write(data)
    f.close()


def client():
    sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sk.connect(("127.0.0.1", 9999))
    sts = STS(sk, STS.Peer_A)
    sts.enable_security(b'asdfghjklz', b'qazwsxedcrfvtgby')
    sts.new_channel()
    f1 = open("t1.tar.gz", "rb")
    f2 = open("t2.tar.gz", "rb")
    f1_finished = False
    f2_finished = False
    while True:
        if not f1_finished:
            data = f1.read(4096)
            if len(data) != 0:
                sts.send(data)
            else:
                f1_finished = True
        if not f2_finished:
            data = f2.read(4096)
            if len(data) != 0:
                sts.send(data, 1)
            else:
                f2_finished = True
        if f1_finished and f2_finished:
            break
    sts.close()
    
    # while True:
    #     sts.send(input("input data:").encode("utf8"), 1)

if __name__ == "__main__":
    import sys
    if sys.argv[1] == "client":
        client()
    else:
        server()

        




        
    
    
