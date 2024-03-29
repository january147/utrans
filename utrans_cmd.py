#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Date: Fri Mar 13 21:48:17 2020
# Author: January

from utrans.core import *
from utrans.utils import *
from utrans.interface import *
import progressbar
import sys
import hashlib
import hmac
import logging
import termcolor
import platform
import _thread
import threading

if platform.system() == "Windows":
    import colorama
    colorama.init()

# set logging level
logging.basicConfig(level=logging.ERROR)
data_channel_mngr = DataChannelManager()

class UtransConfig():
    data_dir = "utrans_config"
    pukey_filepath = "rsa_pub.pem"
    private_key_filepath = "rsa.pem"
    peer_key_dirpath = "keys"
    # local udp port
    scan_server_port = 9999
    # remote udp port
    scan_port = 9999
    # local tcp port
    server_port = 9999

    @staticmethod
    def load_config():
        # Default path for config dir is $HOME/.config, otherwise, it will be placed at the same dir as the script itself.
        if platform.system() == "Linux":
            home_config_dir = os.getenv("HOME")+"/.config"
        elif platform.system() == "Windows":
            home_config_dir = os.getenv("UserProfile")
        else:
            home_config_dir = ""
        
        # try to create utrans data dir in home dir, if failed, create utrans data dir in current dir.
        if os.path.isdir(home_config_dir):
            UtransConfig.data_dir = home_config_dir + "/" + UtransConfig.data_dir
        
        if not os.path.isdir(UtransConfig.data_dir):
            os.mkdir(UtransConfig.data_dir)
        UtransConfig.pukey_filepath = UtransConfig.data_dir + "/" + UtransConfig.pukey_filepath
        UtransConfig.private_key_filepath = UtransConfig.data_dir + "/" + UtransConfig.private_key_filepath
        UtransConfig.peer_key_dirpath = UtransConfig.data_dir + "/" + UtransConfig.peer_key_dirpath
        if not os.path.isdir(UtransConfig.peer_key_dirpath):
            os.mkdir(UtransConfig.peer_key_dirpath)

UtransConfig.load_config()

class UtransCmdMode(UtransCallback):
    def __init__(self):
        self.name = socket.gethostname()
        self.read_args()
        self.init_auth()
        self.scanner = UtransScanner(self.scan_port)
        self.server = UtransServer(self, port = self.port)
        self.server.async_run(callback = self)
        self.self_server_addr = (socket.gethostbyname(self.name), self.port)
        self.init_cmd_mode()
        self.init_callback()
        self.display_lock = _thread.allocate_lock()
    
    # implement callback
    def init_callback(self):
        self.data_channel = queue.Queue()
        self.out_data_channel = queue.Queue()
        # use to receive user input from main thread
        data_channel_mngr.register_data_channel("prompt", self.data_channel)
        data_channel_mngr.register_data_channel("response", self.out_data_channel)

    def init_auth(self):
        self.auth_mngr = UtransAuth(self, self.name, UtransConfig.pukey_filepath, UtransConfig.private_key_filepath, UtransConfig.peer_key_dirpath)

    def read_args(self):
        self.port = UtransDefault.SERVICE_PORT
        self.scan_port = UtransDefault.SCAN_PORT
        try:
            raw_args, options = get_options(sys.argv, ['port:', 'scan_port:'])
        except:
            print(e)
        if 'port' in options.keys():
            self.port = int(options['port'])
        if 'scan_port' in options.keys():
            self.scan_port = int(options['scan_port'])
        logger.debug("service port is %d, scan port is %d"%(self.port, self.scan_port))

    def init_cmd_mode(self):
        self.finished = False
        self.find_new_server = False
        self.available_servers = []
        self.current_session = None
        self.session_mngr = UtransSessionManager()

    def on_task_start(self, task_info:UtransTaskInfo):
        if task_info.type == UtransTaskInfo.T_S_FILE or task_info.type == UtransTaskInfo.T_R_FILE:
            filename, filesize = task_info.get_extra_data()
            widgets = [filename + ' ', progressbar.Percentage(), ' ', progressbar.Bar('='),' ', progressbar.Timer(),
           ' ', progressbar.ETA(), ' ', ' ']
            self.pb = progressbar.ProgressBar(maxval=1, widgets=widgets)
            self.pb.start()
        else:
            print("task start")
    
    def on_task_finished(self, status, task_info:UtransTaskInfo):
        task_info.running = False
        if task_info.type == UtransTaskInfo.T_CONN:
            if status != UtransError.OK:
                print("fail to connect, %s"%(status))
            else:
                session = task_info.get_extra_data()
                if self.session_mngr.has_session(session):
                    print("reconnect to %s"%(session.peer_name))
                else:
                    print("connect to %s"%(session.peer_name))
                    self.session_mngr.append(session)
                self.current_session = session
                

        elif task_info.type == UtransTaskInfo.T_R_FILE or task_info.type == UtransTaskInfo.T_S_FILE:
            if status == UtransError.OK:
                self.pb.finish()
            else:
                print("fail to trasmit[%s]"%(status))
        else:
            if status != UtransError.OK:
                print("task failed [%s]"%(status))
    
    def on_task_progress(self, progress, task_info):
        if task_info.type == UtransTaskInfo.T_S_FILE or task_info.type == UtransTaskInfo.T_R_FILE:
            self.pb.update(progress)

    def on_receive_file(self, filename, filesize, task_info):
        session_index = task_info.session_index
        session = self.session_mngr.get_session_by_index(session_index)
        # this is a asynchronous operation, so put a \n before the output msg to make it look better.
        print()
        if session != None:
            notice = "%s@%s[%s]"%(session.peer_name, session.peer_addr, session.id)
        else:
            notice = None
        print(termcolor.colored("File[%s][%d] from %s"%(filename, filesize, notice), "yellow"))
        return task_info
    
    def on_receive_msg(self, message, task_info):
        session_index = task_info.session_index
        session = self.session_mngr.get_session_by_index(session_index)
        # this is a asynchronous operation, so put a \n before the output msg to make it look better.
        print()
        if session != None:
            notice = "%s@%s[%s]"%(session.peer_name, session.peer_addr, session.id)
        else:
            notice = None
        print(termcolor.colored("Message from %s"%(notice), "yellow"))
        print(message)
    
    # connection
    def on_new_session(self, session:UtransSession):
        # new session from server(asyn), put a \n before the output msg to make it look better
        print()
        if self.session_mngr.has_session(session):
            print("reconnect from", str(session))
        else:
            print("connect from", str(session))
            self.session_mngr.append(session)
    
    def on_session_close(self, session):
        self.session_mngr.remove(session.id)
        if self.current_session != None and session.id == self.current_session.id:
            self.current_session = None

    def get_session_manager(self):
        return self.session_mngr
    
    def get_auth_manager(self):
        return self.auth_mngr
    
    def get_self_server_port(self):
        return self.port
    
    def prompt_user_decision(self, info):
        print(info)
        print("(input [yes] for continue, [no] for stop):")
        if threading.current_thread() == threading.main_thread():
            cmd = input()
        else:
            prompt_channel = data_channel_mngr.get_data_channel("prompt")
            response_channel = data_channel_mngr.get_data_channel("response")
            # receive reponse from main thread
            print("send request")
            prompt_channel.put("request_decision")
            print("get result")
            cmd = response_channel.get()
        if cmd.startswith("y"):
            return True
        else:
            return False
    # ask for user's confirmation

    def on_need_decision(self, info):
        return True
    
    # scan server
    def on_new_server(self, server_info):
        print(("New_server: %s\n"
               "addr: %s\n")%(server_info.name, str(server_info.addr)))
        self.available_servers.append(server_info)
        self.find_new_server = True

    def on_stop_scan(self):
        self.find_new_server = False

    def on_start_scan(self):
        self.available_servers = []

    def exit_cmd_mode(self):
        self.server.stop_server()
        

        
    def run(self):
        event_channel = data_channel_mngr.get_data_channel("prompt")
        while True:
            try:
                if self.current_session != None:
                    session = self.current_session
                    prompt = "%s@%s(%d):"%(self.name, session.peer_name, session.id)
                else:
                    prompt = "%s@None:"%(self.name)
                # if sys.argv[2] == "9998":
                #     time.sleep(500)
                if not self.display_lock.locked():
                    termcolor.cprint(prompt, "green", attrs=["bold"], end = " ")
                logger.debug("main thread waiting for input")
                raw_data = input()
            except BaseException as e:
                if type(e) != KeyboardInterrupt:
                    print(e)
                self.exit_cmd_mode()
                return

            if len(raw_data) <= 0:
                continue

            if not event_channel.empty():
                logger.debug("get request")
                event_channel.get_nowait()
                self.out_data_channel.put(raw_data)
                continue

            # deal with args with space surrounded by ""
            argv = link_args(raw_data.split())
            # parse args
            cmd = argv[0]
            raw_args, options = get_options(argv, [":"])
            if cmd == "send_file":
                if self.current_session == None:
                    print("Current session doesn't exist")
                    continue
                for filename in raw_args:
                    if not os.path.isfile(filename):
                        print("%s is not a file"%filename)
                    else:
                        try:
                            self.current_session.send_file(filename, self)
                        except:
                            traceback.print_exc()
            elif cmd == "send_msg":
                if self.current_session == None:
                    print("Current session doesn't exist")
                    continue
                if len(raw_args) <= 0:
                    try:
                        self.message_send_mode()
                    except:
                        print("exit message send mode")
                else:
                    msg = " ".join(raw_args)
                    try:
                        self.current_session.send_message(msg, self)
                    except:
                        traceback.print_exc()
            elif cmd == "ls":
                if len(raw_args) <= 0:
                    if self.current_session != None:
                        current_session_info = str(self.current_session)
                    else:
                        current_session_info = "None"
                    print("current connect to [%s]"%(current_session_info))
                    print("All sessions:")
                    self.session_mngr.print_info()
                    print("Avaliable servers: ")
                    print_list(self.available_servers)
            elif cmd == "connect":
                if len(raw_args) <= 0:
                    if self.current_session != None:
                        self.current_session.connect(self)
                    continue
                for item in raw_args:
                    try:
                        item = int(item)
                        if item >= 0 and item < len(self.available_servers):
                            server_info = self.available_servers[item]
                            addr = server_info.addr
                        else:
                            addr = None
                    except:
                        server_info = None
                    if server_info == None:
                        try:
                            addr = upack_addr(item)
                        except:
                            traceback.print_exc()
                            continue
                    # self is context
                    session = UtransSession(self, peer_addr = addr)
                    # self is callback
                    task_info = session.connect(self)

            elif cmd == "switch":
                if len(raw_args) <= 0:
                    print("please specify a session")
                    continue
                try:
                    index = int(raw_args[0])
                except:
                    print("Not a valid session_index, please use 'ls' to check active sessions")
                session = self.session_mngr.get_session_by_index(index)
                if session == None:
                    print("Not a valid session_index, please use 'ls' to check active sessions")
                else:
                    self.current_session = session

            elif cmd == "close":
                if len(raw_args) <= 0:
                    print("please specify a session")
                    continue
                try:
                    index = int(raw_args[0])
                except:
                    print("Not a valid session_index, please use 'ls' to check active sessions")
                session = self.session_mngr.get_session_by_index(index)
                if session == None:
                    print("Not a valid session_index, please use 'ls' to check active sessions")
                else:
                    self.session_mngr.remove(index)
                    if self.current_session != None and session.id == self.current_session.id:
                        self.current_session = None
            elif cmd == "scan":
                self.scan_server(True)
            elif cmd == "stop":
                if len(raw_args) > 0:
                    if raw_args[0] == "server":
                        self.server.stop_server()
                    elif raw_args[0] == "broadcast":
                        self.server.stop_broadcast()
            elif cmd == "start":
               continue
            elif cmd == "show_session_info":
                if len(raw_args) > 0:
                    try:
                        index = int(raw_args[0])
                    except:
                        print("No such session")
                        continue
                    session = self.session_mngr.get_session_by_index(index)
                    if session == None:
                        print("No such session")
                        continue
                    session.print_info()
            elif cmd == "test":
                Runnable(self.run, ())
            elif cmd == "help":
                print_usage()
            elif cmd == "q":
                self.exit_cmd_mode()
                return
            else:
                print("unknown command: %s"%(cmd))
        
    def scan_server(self, one_to_exit = False):
        self.scanner.start_scan(self)
        print("scanning, press ctrl+c to stop")
        try:
            while True:
                time.sleep(10)
        except:
            pass
        self.scanner.stop_scan()

    def message_send_mode(self):
        print("doesn't support")

def main():
    cmd_mode = UtransCmdMode()
    cmd_mode.run()
  

if __name__ == "__main__":
    main()
