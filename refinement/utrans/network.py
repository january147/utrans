#!/usr/bin/python3
import hmac
import hashlib
from Crypto.Cipher import AES
import socket

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
class STS_pkt:
    MAGIC = 0xaf
    T_PLAIN = 0
    T_ENC = 1
    T_AUTH = 2
    LEN_FRAME = 1400
    LEN_HEADER = 12

    def __init__(self):
        self.magic = STS_pkt.MAGIC
        self.flags = 0
        self.type = STS_pkt.T_PLAIN
        self.payload_len = 0
        self.mac_len = 0
        self.ophdr_len = 0
        self.seq = 0
        self.payload = None
        self.mac = None
        self.channel = 0

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
    def parse_header_bytes(self, header):
        if header[0] != STS_pkt.MAGIC:
            raise Exception("Bad frame header with magic %x"%header[0])
        self.magic = header[0]
        self.flags = header[1]
        self.type = header[2]
        # 保留字段
        # header[3]
        self.payload_len = int.from_bytes(header[4:6], 'little')
        self.mac_len = header[6]
        self.ophdr_len = header[7]
        self.seq = int.from_bytes(header[8:12], 'little')
        # 保存原始header
        self.raw_header = header
    
    def parse_payload(self, payload):
        self.payload = payload
    
    def parse_mac(self, mac):
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

class STS:
    Peer_A = 0
    Peer_B = 1

    def __init__(self, channel, peer_type):
        self.send_enc_key = None
        self.send_mac_key = None
        self.recv_enc_key = None
        self.recv_mac_key = None
        self.send_nonce = None
        self.recv_nonce = None
        self.send_seq = 0
        self.recv_seq = 0

        self.peer_type = peer_type
        self.channel = channel
        self.spkt = STS_pkt()
        self.rpkt = STS_pkt()

    def enable_auth(self, auth_key):
        hash_ob = hashlib.new("sha256")
        hash_ob.update(auth_key)
        keys = hash_ob.digest()
        self.spkt.enable_auth(hash_ob.digest_size)
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
        self.spkt.enable_enc()

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
        self.spkt.type |= STS_pkt.T_AUTH | STS_pkt.T_ENC
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

    def send(self, data):
        # fill send frame
        self.spkt.set_payload(data, self.__get_seq())
        raw_frame = self.spkt.pack(self.send_nonce, self.send_enc_key, self.send_mac_key)
        self.channel.send(raw_frame)    

    def recv(self):
        header = self.channel.recv(STS_pkt.LEN_HEADER)
        self.rpkt.parse_header_bytes(header)
        self.rpkt.parse_payload(self.channel.recv(self.rpkt.payload_len))
        if self.rpkt.mac_len != 0:
            self.rpkt.parse_mac(self.channel.recv(self.rpkt.mac_len))
        data = self.rpkt.unpack(self.recv_nonce, self.recv_enc_key, self.recv_mac_key)
        return data
    


def server():
    lk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lk.bind(("127.0.0.1", 9999))
    lk.listen()

    while True:
        sk, addr = lk.accept()
        sts = STS(sk, STS.Peer_B)
        sts.enable_security(b'asdfghjklz', b'qazwsxedcrfvtgby')
        while True:
            data = sts.recv()
            print(data)

def client():
    sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sk.connect(("127.0.0.1", 9999))
    sts = STS(sk, STS.Peer_A)
    sts.enable_security(b'asdfghjklz', b'qazwsxedcrfvtgby')
    while True:
        sts.send(input("input data:").encode("utf8"))

if __name__ == "__main__":
    import sys
    if sys.argv[1] == "client":
        client()
    else:
        server()

        




        
    
    
