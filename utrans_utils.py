#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Date: Sun Mar  8 17:33:09 2020
# Author: January

from queue import Queue
import threading
import ctypes
import time
import _thread
import random
import string
import json
from termcolor import colored

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


# utils function
def random_str(str_len = 8):
    result_str = ''.join((random.choice(string.ascii_letters) for i in range(str_len)))
    return result_str

def base64_encode_str(string:str):
        return base64.b64encode(string.encode("utf8")).decode("utf8")
    
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
    
    def get_index(self, value, comparer = None):
        if comparer == None:
            comparer == self.comparer
        for i in range(len(self)):
            if comparer(self[i], value) == True:
                return i
        return -1
    
    def get_all_index(self, value, comparer):
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
    
    def get_index(self):
        index = self.__index
        self.__index += 1
        return index
     
    def append(self, item):
        index = self.get_index()
        self[index] = item
        return index
    
    def show(self):
        if len(self) == 0:
            print("No data")
        else:
            for i in self.keys():
                print("[%d] %s"%(i, str(self[i])))




class UtransConfig(dict):

    def __init__(self):
        self.config = dict()

    def load_config(self, filename):
        with open(filename, "r") as f:
            self.config = json.load(f)
    
    def save_config(self, filename):
        with open(filename, "w") as f:
            json.dump(self.config, f)
    
    def __get_item__(self, key):
        return self.config[key]
    
    def __set_item__(self, key, value):
        self.config[key] = value

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
    def __init__(self, uuid = None, session_index = -1):
        if uuid == None:
            self.uuid = random_str(10)
        self.session_index = session_index
        self.running = True
    
    def stop(self):
        self.running = False

class UtransSession:
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    T_RECV = "t_recv"
    T_SEND = "T_send"

    def __init__(self, name, address, sk, session_type = None):
        self.name = name
        self.address = address
        self.sk = sk
        self.status = UtransSession.CONNECTED
        if session_type == None:
            session_type = UtransSession.T_SEND
        self.type = session_type
        self.token = random_str(10)
    
    def close(self):
        self.status = UtransSession.DISCONNECTED
        self.sk.close()
    
    
    def __str__(self):
        return "%s"%(self.name)
    
    def __repr__(self):
        return "[%s]%s@%s"%(self.token, self.name, self.address)


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
 
def main():
    pass
if __name__ == "__main__":
    main()
