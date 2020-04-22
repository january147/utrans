#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Date: Sun Mar  8 17:33:09 2020
# Author: January

from queue import Queue
from utrans_interface import *
from crypto import openssl as crypto
import threading
import ctypes
import time
import _thread
import random
import string
import json
from termcolor import colored
import socket
import base64
import hmac
import hashlib
import os
import re
import sys

#decorators
def deprecatedBy(replace_func):
    def deprecated_deco(func):
        def wrapper(*args, **kwargs):
            text = "[Warning]%s is deprecated, consider use %s instead"%(func.__name__, replace_func.__name__)
            print(colored(text, "yellow"))
            return func(*args, **kwargs)
        return wrapper
    return deprecated_deco

def deprecated(func):
    def wrapper(*args, **kwargs):
        text = "[Warning]%s is deprecated"%(func.__name__)
        print(colored(text, "red"))
        return func(*args, **kwargs)
    return wrapper


def calculate_num_byte_size(num):
    size = 1
    num >>= 8
    while num != 0:
        num >>= 8
        size += 1
    return size
#
def pack_bytes(bytes_list):
    packed_bytes = b""
    for item in bytes_list:
        item_len = len(item)
        if item_len <= 128:
            size_field = item_len.to_bytes(1, "little")
        else:
            item_len_bytes_size = calculate_num_byte_size(item_len)
            len_byte = (128 + item_len_bytes_size).to_bytes(1, "little")
            len_bytes = item_len.to_bytes(item_len_bytes_size, "little")
            size_field = len_byte + len_bytes
        packed_bytes = packed_bytes + size_field + item
    return packed_bytes

def unpack_bytes(packed_bytes):
    bytes_list = []
    p = 0
    while p < len(packed_bytes):
        field_len = packed_bytes[p]
        p += 1
        if field_len <= 128:
            item_end = p + field_len
            item = packed_bytes[p : item_end]
        else:
            len_bytes_size = field_len - 128
            len_bytes = packed_bytes[p : p + len_bytes_size]
            p += len_bytes_size
            field_len = int.from_bytes(len_bytes, byteorder="little")
            item_end = p + field_len
            item = packed_bytes[p : item_end]
        bytes_list.append(item)
        p = item_end
    return bytes_list

def pack_addr(addr:tuple):
    return "%s:%d"%(addr[0], addr[1])

def upack_addr(addr:str):
    if type(addr) == bytes:
        addr = addr.decode("utf8")
    addr_pattern = re.compile(r'((?:[0-9]+\.){3}[0-9]+):([0-9]+)')
    result = addr_pattern.match(addr)
    if result == None:
        raise Exception("invalid addr")
    else:
        addr_list = result.groups()
        if len(addr_list) != 2:
            return None
        ip, port = addr_list
        addr = (ip, int(port))
        return addr

# utils function
def random_str(str_len = 8):
    result_str = ''.join((random.choice(string.ascii_letters) for i in range(str_len)))
    return result_str

def base64_encode_str(string:str):
    return base64.b64encode(string.encode("utf8")).decode("utf8")

def base64_encode(data:bytes):
    return base64.b64encode(data).decode("utf8")

def base64_decode(data:str):
    return base64.b64decode(data.encode("utf8"))

def base64_decode_str(string:str):
    return base64.b64decode(string.encode("utf8")).decode("utf8")

def print_list(l:list):
    if len(l) == 0:
        print("No data")
    else:
        for i in range(len(l)):
            print("[%d] %s"%(i, str(l[i])))

# A comparer receives two parameters. The first is the item in the list.
# The second is the parameter you give to get_index.
class LookUpList(list):

    def __init__(self, comparer = None):
        self.set_comparer(comparer)

    def set_comparer(self, comparer = None):
        if comparer == None:
            comparer = lambda x,y : x == y
        self.comparer = comparer
    
    def search_item_index(self, value, comparer = None):
        if comparer == None:
            comparer == self.comparer
        for i in range(len(self)):
            if comparer(self[i], value) == True:
                return i
        return -1
    
    def search_all_item_index(self, value, comparer):
        if comparer == None:
            comparer == self.comparer
        result = []
        for i in range(len(self.data)):
            if comparer(self[i], value) == True:
                result.append(i)
        return result

class DictList(dict):
    def __init__(self):
        self.__index = 0
        self.comparer = lambda x, y : x == y
    
    def __get_index(self):
        index = self.__index
        self.__index += 1
        return index
    
    def set_comparer(self, comparer):
        self.comparer = comparer
     
    def append(self, item):
        index = self.__get_index()
        self[index] = item
        return index
    
    def search(self, value, comparer = None):
        if comparer == None:
            comparer == self.comparer
        for i in self.keys():
            if comparer(self[i], value) == True:
                return self[i] 
        return None

    def show(self):
        if len(self) == 0:
            print("No data")
        else:
            for i in self.keys():
                print("[%d] %s"%(i, str(self[i])))

# data 
class UtransServerInfo:
    def __init__(self, name, addr):
        self.name = name
        self.addr = addr
    
    def __str__(self):
        return "%s:%s"%(str(self.name), str(self.addr))
    
    def __repr__(self):
        return "%s:%s"%(str(self.name), str(self.addr))

class UtransTaskInfo:
    T_CONN = 0
    T_S_MSG = 1
    T_R_MSG = 2
    T_S_FILE = 3
    T_R_FILE = 4
    def __init__(self, uuid = None, session_index = -1, type = None):
        if uuid == None:
            self.uuid = random_str(10)
        self.session_index = session_index
        self.type = type
        self.running = True
    
    def stop(self):
        self.running = False

    def set_extra_data(self, data):
        self.data = data
    
    def get_extra_data(self):
        data = self.data
        self.data = None
        return data

@deprecated
class UtransSessionNew:
    def __init__(self, name = None, uuid = None, peer_addr = None, session_key = None, send_sk = None, recv_sk = None):
        self.peer_name = name
        self.peer_uuid = uuid
        self.session_key = session_key
        self.peer_addr = peer_addr
        self.send_sk = send_sk
        self.recv_sk = recv_sk
        self.id = -1
        self_counter = 300000000000
        self.peer_auth_counter = 10000000000
        self.status = UtransSession.CONNECTED

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
        auth_counter =  self_counter.to_bytes(16, "little")
        self_counter += 1
        return auth_counter

    def set_auth_counter(self, auth_counter):
        auth_counter = int.from_bytes(auth_counter, "little")
        self_counter = auth_counter
    
    def set_send_sk(self, sk:socket.socket):
        self.status = UtransSession.CONNECTED
        self.send_sk = sk
    
    def set_recv_sk(self, sk:socket.socket):
        self.status = UtransSession.CONNECTED
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
            if self.recv_sk == None:
                self.status = UtransSession.DISCONNECTED

    def close_recv_sk(self):
        if self.recv_sk != None:
            self.recv_sk.close()
            self.recv_sk = None
            if self.send_sk == None:
                self.status = UtransSession.DISCONNECTED

    def close(self):
        self.close_send_sk()
        self.close_recv_sk()
    
    def print_info(self):
        print("peer_name:", self.peer_name)
        print("peer uuid:", self.peer_uuid)
        print("session key:", self.session_key.hex())
        print("peer addr:", self.peer_addr)
        print("recv_sk:", self.recv_sk)
        print("send_sk:", self.send_sk)
    
    def __str__(self):
        return "%s"%(self.peer_name)
    
    def __repr__(self):
        return "[%s]%s@%s"%(self.id, self.name, self.peer_addr)

#deprecate, use UtransTaskInfo instead
@deprecatedBy(UtransTaskInfo)
class UtransTask:

    def __init__(self, uuid = None, session_index = -1):
        if uuid == None:
            self.uuid = random_str(10)
        self.session_index = session_index
        self.running = True
    
    def stop(self):
        self.running = False

class RunnableTask():
    def __init__(self, func, args, delay = 0):
        self.wait = wait
        self.func = func
        self.args = args
        self.ret = None
    
    def run(self):
        if self.wait != 0:
            time.sleep(self.wait)
        self.ret = self.func(*self.args)
    
    def async_run(self):
        return _thread.start_new_thread(self.run, ())
    
    def get_ret(self):
        return self.ret

#deprecate, used RunnableTask instead
@deprecatedBy(RunnableTask)
class Runnable():
    def __init__(self, func, args, wait = 0):
        self.wait = wait
        self.func = func
        self.args = args
        self.ret = None
    
    def run(self):
        if self.wait != 0:
            time.sleep(self.wait)
        self.ret = self.func(*self.args)
    
    def async_run(self):
        _thread.start_new_thread(self.run, ())

class ThreadInputInfo:
    def __init__(self, tid:int, input_queue:Queue):
        self.tid = tid
        self.input = input_queue
        self.lock = threading.Lock()

class DataChannelManager:

    def __init__(self):
        self.data_channels = {}

    def register_data_channel(self, name, data_channel):
        self.data_channels[name] = data_channel
    
    def unregister_data_channel(self, name):
        if name in self.data_channels.keys():
            self.data_channels.pop(name)
    
    def get_data_channel(self, name):
        if name in self.data_channels.keys():
            return self.data_channels[name]
        else:
            return None

class ThreadInputManager:

    def __init__(self):
        self.basic_cmd_prompt = ">>>"
        self.current = -1
        self.alive = 0
        self.threads = {}
        self.finish = True
        self.lock = threading.Lock()
        self.lock.acquire()
    
    def register_thread(self, thread_input_info, name):
        self.threads[name] = thread_input_info
        self.alive += 1
    
    def unregister_thread(self, name):
        self.threads.pop(name)
        self.alive -= 1
    
    def set_prompt(self, prompt:str):
        self.basic_cmd_prompt = prompt
    
    def set_current(self, name, prompt = None):
        if prompt != None:
            self.basic_cmd_prompt = prompt
        if name not in self.threads.keys():
            return False
        self.current = name
        return True
    
    def complete(self):
        if self.finish == False:
            self.lock.release()
            self.finish = True

    def wait_for_task(self):
        try_exit = 0
        while not self.lock.acquire(False):
            try:
                time.sleep(0.05)
            except:
                self.sig_thread(self.current)
                try_exit += 1
                if try_exit >= 3:
                    self.complete()
                    break
                if try_exit > 1:
                    print("if the command doest not finish, try again to force exit")

    def task_start(self):
        self.finish = False
    
    def sig_thread(self, name):
        if name not in self.threads.keys():
            return False
        tid = self.threads[name].tid
        ret = ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(tid), ctypes.py_object(SystemExit))
        if ret > 1:
            return False
        return True
    
    def basic_cmd_mode(self):
        while True:
            try:
                data = input(self.basic_cmd_prompt)
            except Exception as e:
                print(e)
                return
            if len(data) > 0 and data[0] == '.':
                split_data = data.split()
                cmd = split_data[0]
                if cmd == ".switch":
                    if len(split_data) < 2:
                        print("please specify a source to output")
                        continue
                    name = split_data[1]
                    if name in self.input_sources.keys():
                        self.current = name
                    else:
                        print("%s doesn't exist"%(name))
                elif cmd == ".q":
                    return
            elif self.current not in self.threads.keys():
                print("No alive thread")
            else:
                self.finish = False
                thread_info = self.threads[self.current]
                thread_info.input.put(data)
                self.wait_for_task()

            if self.alive <= 0:
                return

def link_args(args):
    new_args = []
    arg_continue = False
    arg_saved = ""
    for item in args:
        if arg_continue is True:
            if item[-1] == "\"":
                arg_continue = False
                arg_saved += item.strip("\"")
                new_args.append(arg_saved)
                arg_saved = ""
            else:
                arg_saved += item
            continue

        if item[0] != "\"":
            new_args.append(item)
            continue

        if item[0] == "\"":
            if item[-1] == "\"":
                new_args.append(item.strip("\""))
            else:
                arg_saved += item.strip("\"")
                arg_continue = True
            continue
        
    if arg_continue == True:
        logger.debug("arg not complete")
        return None
    return new_args

class Waiter():

    def __init__(self, interval, check_freq = 0.1, notice = ""):
        self.counter = 0
        self.counter_full = int(interval / check_freq)
        self.check_freq = check_freq
        self.print_no_cache(notice)
        
    def print_no_cache(self, msg):
        sys.stdout.write(msg)
        sys.stdout.flush()
    
    def wait(self, info):
        if self.counter >= self.counter_full:
            self.print_no_cache(info)
            self.counter = 0
        time.sleep(self.check_freq)
        self.counter += 1


# Change the way of handling faults to raise exception instead of exit
def get_options(args, option_list:list):
    arg_p = 1
    total_arg = len(args)
    options = {}
    raw_arg = []
    options_with_arg = []
    accpet_all = False
    for i in range(len(option_list)):
        option_description = option_list[i]
        if option_description == ':':
            accpet_all = True
            continue
        if option_description[-1] == ':':
            option = option_description[:-1]
            options_with_arg.append(option)
            option_list[i] = option


    while arg_p < total_arg:
        arg = args[arg_p]
        if arg.startswith('--'):
            name = arg[2:]
            if not accpet_all and name not in option_list:
                raise RuntimeError("invalid option '%s', pos '%d'"%(name, arg_p))
            if name not in options_with_arg:
                options[name] = ''
            else:
                arg_p += 1
                if arg_p >= len(args) or args[arg_p].startswith('-'):
                    raise RuntimeError("option '%s' requires an argument, pos %d"%(name, arg_p))
                value = args[arg_p]
                options[name] = value
        elif arg.startswith('-'):
            names = arg[1:]
            if len(names) <= 1:
                name_likely_with_arg = names
            else:
                for name in names[:-1]:
                    if not accpet_all and name not in option_list:
                        raise RuntimeError("invalid option '%s', pos %d"%(name, arg_p))
                    if name in options_with_arg:
                        raise RuntimeError("option '%s' requiring an argument can be put between options, pos %d"%(name, arg_p))
                    options[name] = ''
                name_likely_with_arg = names[-1]
            if not accpet_all and name_likely_with_arg not in option_list:
                raise RuntimeError("invalid option '%s', pos %d"%(name_likely_with_arg, arg_p))
            if name_likely_with_arg not in options_with_arg:
                options[name_likely_with_arg] = ''
            else:
                arg_p += 1
                if arg_p >= len(args) or args[arg_p].startswith('-'):
                    raise RuntimeError("option '%s' requires an argument, pos %d"%(name_likely_with_arg, arg_p))
                value = args[arg_p]
                options[name_likely_with_arg] = value
        else:
            raw_arg.append(arg)
        arg_p += 1
    return (raw_arg, options)
 
 # cryptography


    pass
if __name__ == "__main__":
    main()



