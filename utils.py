#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Date: Sun Mar  8 17:33:09 2020
# Author: January

from queue import Queue
import threading
import ctypes
import time

server_notice = False

# interface
class UtransCallback:
    def __init__(self):
        pass

    def prompt_continue(self, info):
        return True
    
    def on_error(self, error):
        pass

    def on_finished(self, info):
        pass

    def on_progress(self, progress):
        pass

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
                print("invalid option '%s', pos '%d'"%(name, arg_p))
                exit(1)
            if name not in options_with_arg:
                options[name] = ''
            else:
                arg_p += 1
                if arg_p >= len(args) or args[arg_p].startswith('-'):
                    print("option '%s' requires an argument, pos %d"%(name, arg_p))
                    exit(1)
                value = args[arg_p]
                options[name] = value
        elif arg.startswith('-'):
            names = arg[1:]
            if len(names) <= 1:
                name_likely_with_arg = names
            else:
                for name in names[:-1]:
                    if not accpet_all and name not in option_list:
                        print("invalid option '%s', pos %d"%(name, arg_p))
                        exit(1)
                    if name in options_with_arg:
                        print("option '%s' requiring an argument can be put between options, pos %d"%(name, arg_p))
                        exit(1)
                    options[name] = ''
                name_likely_with_arg = names[-1]
            if not accpet_all and name_likely_with_arg not in option_list:
                print("invalid option '%s', pos %d"%(name_likely_with_arg, arg_p))
                exit(1)
            if name_likely_with_arg not in options_with_arg:
                options[name_likely_with_arg] = ''
            else:
                arg_p += 1
                if arg_p >= len(args) or args[arg_p].startswith('-'):
                    print("option '%s' requires an argument, pos %d"%(name_likely_with_arg, arg_p))
                    exit(1)
                value = args[arg_p]
                options[name_likely_with_arg] = value
        else:
            raw_arg.append(arg)
        arg_p += 1

    return (raw_arg, options)

class Runnable():
    def __init__(self, func, args):
        self.runnable = func
        self.args = args
        self.ret = None
    
    def run(self):
        self.ret = self.runnable(*self.args)          
        

def main():
    pass
if __name__ == "__main__":
    main()
