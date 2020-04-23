import socket
import ctypes
import os
import sys
import logging

logger = logging.getLogger("[network]")

class NewFrameInDataException(Exception):
    def __init__(self, new_frame_data):
        super().__init__("detect frame start in frame payload")
        self.new_frame_data = new_frame_data
    
    def get_new_frame_data(self):
        return self.new_frame_data


class DataInCompleteEXception(Exception):
    def __init__(self):
        super().__init__("data end with 0xff, not complete")

class Cache():

    def __init__(self, max_size = 40960):
        self.data = b''
        self.max_size = max_size


    def get_all(self):
        data = self.data
        self.data = b''
        return data
    
    def get_data(self, size):
        if size < 0:
            raise Exception("size can't be negetive")
        if size < len(self.data):
            result = self.data[:size]
            self.data = self.data[size:]
        else:
            result = self.get_all()
        return result
    
    def put_data(self, data):
        if len(self.data) + len(data) > self.max_size:
            raise Exception("Cache full")

        self.data += data
    
    def get_len(self):
        return len(self.data)
    
    def clear(self):
        self.data = b''

class FrameTransTask():

    def __init__(self):
        self.finished = True
        
    def start(self, frame_header):
        self.frame_header = frame_header
        self.left_size = frame_header.payload_size
        self.total_size = self.left_size
        self.finished = False
    
    def process(self, transmitted_size):
        self.left_size -= transmitted_size
        if self.left_size <= 0:
            self.finished = True  
        return self.left_size
    
    def get_progress(self):
        if self.finished:
            return 1
        else:
            return (1 - (self.left_size / self.total_size))
    
    def reset(self):
        self.finished = True
    
    def is_finished(self):
        return self.finished

class FrameHeader():
    # L indicates length.
    L_HEADER = 5
    L_TYPE = 1
    L_PAYLOAD_SIZE = 4

    def __init__(self, frame_type, payload_size, optional_header = None):
        self.frame_type = frame_type
        self.payload_size = payload_size
        self.op_header = optional_header

    def set_op_header(slef, op_header):
        self.op_header = op_header

    def to_bytes(self):
        b_frame_type = self.frame_type.to_bytes(self.L_TYPE, "little")
        b_payload_size = self.payload_size.to_bytes(self.L_PAYLOAD_SIZE, "little")
        return b_frame_type + b_payload_size
    
    def print_info(self):
        logger.debug("type: %02x"%(self.frame_type))
        logger.debug("payload_size: %d"%(self.payload_size))

    @staticmethod
    def from_bytes(bytes_header):
        if len(bytes_header) != FrameHeader.L_HEADER:
            return None
        frame_type = bytes_header[0]
        payload_size = int.from_bytes(bytes_header[1:], "little")
        header = FrameHeader(frame_type, payload_size)
        return header

class FrameOptionalHeader():
    L_FOPHEADER = 19
    L_CTR = 2
    L_ENC_TYPE = 1
    L_MAC = 16

    def __init__(self, counter, enc_type, mac):
        self.counter = counter
        self.enc_type = enc_type
        if len(self.mac) != self.L_MAC:
            raise Exception("mac should be 16 bytes long")
        self.mac = mac

    def to_bytes(self):
        b_counter = self.counter.to_bytes(self.L_CTR, "little")
        b_enc_type = self.enc_type.to_bytes(self.L_ENC_TYPE, "little")
        
        return b_counter + b_enc_type + self.mac

    
    @staticmethod
    def from_bytes(bytes_header):
        if len(bytes_header) != FrameOptionalHeader.L_FOPHEADER:
            return None
        counter = int.from_bytes(bytes_header[:2], "little")
        enc_type = bytes_header[2]
        mac = bytes_header[3:]
        opheader = FrameOptionalHeader(counter, enc_type, mac)

class FrameSocket(socket.socket):
    FRAME_PAYLOAD_MAX = 4096
    # receiving status
    R_RECEIVING_HEAD = 0x1
    R_RECEIVING_OPHEAD = 0x2
    R_RECEIVING_PAYLOAD = 0x4
    R_END = 0x8
    # frame type
    T_BASIC = 0x0
    T_LARGE = 0x80
    T_OP = 0x1

    def __init__(self, family, type, fileno = None):
        if fileno != None:
            super().__init__(family, type, fileno = fileno)
        else:
            super().__init__(family, type)
        self.cache = Cache()
        self.trans_task = FrameTransTask()

    @staticmethod
    def from_socket(sk:socket.socket):
        fd = sk.detach()
        return FrameSocket(sk.family, sk.type, fileno=fd)
    
    def send_frame(self, data:bytes):
        if not self.trans_task.is_finished():
            return self.transmit_large_frame(data)
        data_len = len(data)
        frame_header =  FrameHeader(self.T_BASIC, data_len)
        b_frame_header = frame_header.to_bytes()
        frame = b_frame_header + data
        self.send(frame)
        return True
    
    def start_transmit_large_frame(self, payload_size):
        if not self.trans_task.is_finished():
            raise Exception("a transmitting is ongoing")
        frame_header = FrameHeader(self.T_LARGE, payload_size)
        b_frame_header = frame_header.to_bytes()
        self.trans_task.start(frame_header)
        self.send(b_frame_header)
    
    def transmit_large_frame(self, data):
        if self.trans_task.is_finished():
            raise Exception("Frame has been transmitted")
        self.send(data)
        self.trans_task.process(len(data))
        if self.trans_task.is_finished():
            if self.trans_task.frame_header.frame_type & self.T_OP:
                mac = bytes(16)
                self.send(mac)
        return self.trans_task.is_finished()

    def recv_frame(self, split_size = 4096):
        status = self.R_RECEIVING_HEAD
        cache = self.cache
        need_data = False

        if not self.trans_task.is_finished():
            return self.recv_large_frame(split_size)
        while status != self.R_END:
            if need_data or cache.get_len() == 0:
                data = self.recv(split_size)
                if len(data) == 0:
                    raise Exception("Peer close connection")
                logger.debug("recv data split, size %d"%(len(data)))
                cache.put_data(data)
            if status == self.R_RECEIVING_HEAD:
                if cache.get_len() < FrameHeader.L_HEADER:
                    need_data = True
                    continue
                else:
                    need_data = False
                    bytes_header = cache.get_data(FrameHeader.L_HEADER)
                    header = FrameHeader.from_bytes(bytes_header)
                    # check validity of frame header
                    if header.frame_type & self.T_LARGE == 0 and header.payload_size > self.FRAME_PAYLOAD_MAX:
                        raise Exception("payload too long for normal frame")
                    # check if there is a optional header
                    if header.frame_type & self.T_OP:
                        status = self.R_RECEIVING_OPHEAD
                    else:
                        status = self.R_RECEIVING_PAYLOAD
            elif status == self.R_RECEIVING_OPHEAD:
                if cache.get_len() < FrameOptionalHeader.L_FOPHEADER:
                    need_data = True
                    continue
                else:
                    need_data = False
                    b_op_header = cache.get_data(FrameOptionalHeader.L_FOPHEADER)
                    op_header = FrameOptionalHeader.from_bytes(b_op_header)
                    header.set_op_header(op_header)
                    status = self.R_RECEIVING_PAYLOAD
            elif status == self.R_RECEIVING_PAYLOAD:
                #####debug####
                header.print_info()
                ##############
                if header.frame_type & self.T_LARGE:
                    payload = cache.get_data(header.payload_size)
                    if len(payload) != header.payload_size:
                        self.trans_task.start(header)
                        self.trans_task.process(len(payload))
                        finished = False
                    else:
                        finished = True
                    status = self.R_END
                elif cache.get_len() < header.payload_size:
                    need_data = True
                    continue
                else:
                    payload = cache.get_data(header.payload_size)
                    finished = True
                    status = self.R_END
            else:
                raise Exception("Unknown receiving status")
        return (payload, finished)

    def recv_large_frame(self, size = 4096):
        data = self.recv(size)
        if len(data) == 0:
            raise Exception("peer close connection")
        left_size = self.trans_task.process(len(data))
        finished = self.trans_task.is_finished()
        if finished:
            if left_size < 0:
                self.cache.put_data(data[left_size:])
            if self.trans_task.frame_header.frame_type & self.T_OP:
                op_header = self.trans_task.frame_header.op_header
                mac = data[-16:]
                data = data[:-16]
                op_header.mac = mac
        return (data, finished)

    def get_transmit_progress(self):
        return self.trans_task.get_progress()
    
    #override
    def accept(self):
        sk, addr = super().accept()
        return (FrameSocket.from_socket(sk), addr)
    
    def __str__(self):
        return "[%d]-self[%s]-peer[%s]"%(self.fileno(), str(self.getsockname()), str(self.getpeername()))
    
    def __repr__(self):
        return self.__str__()
    
def test_server():
    sk = FrameSocket(socket.AF_INET, socket.SOCK_STREAM)
    sk.bind(("127.0.0.1", 8888))
    sk.listen(5)
    print("server start")
    for i in range(3):
        ssk, addr = sk.accept()
        print("connect with %s"%(str(addr)))
        while True:
            data, finished = ssk.recv_frame()
            print("recv data, len:%d"%(len(data)))
            size = len(data)
            while not finished:
                data, finished = ssk.recv_large_frame()
                size += len(data)
                print("recv data split, len: %d, recved: %d"%(len(data), size))
                if finished:
                    print("finish recv data, total len:%d"%(size))

def test_client():
    sk = FrameSocket(socket.AF_INET, socket.SOCK_STREAM)

    sk.connect(("127.0.0.1", 8888))
    data = bytes(40000)
    #sk.send_frame(b'\xff\xff\xff\xff\xff\xff\x00\xff\x00')
    sk.start_transmit_large_frame(len(data))
    sk.send_frame(data)


if __name__ == "__main__":
    if sys.argv[1] == "c":
        test_client()
    else:
        test_server()


                    
                



