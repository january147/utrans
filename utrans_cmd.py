#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Date: Fri Mar 13 21:48:17 2020
# Author: January

from utrans_utils import *
from utrans_interface import *
from utrans import *
import progressbar
import sys

data_channel_mngr = DataChannelManager()

class UtransCmdMode(UtransCallback):
    def __init__(self):
        self.name = "cmd"
        self.client = UtransClient()
        self.server = UtransServer()
        self.server.async_run(callback = self)
        self.init_cmd_mode()
        self.init_callback()
    
    # implement callback
    def init_callback(self):
        self.data_channel = queue.Queue()
        # use to receive user input from main thread
        data_channel_mngr.register_data_channel("prompt", self.data_channel)

    def on_file_send_start(self, filename, filesz, task_info):
        widgets = [filename + ' ', progressbar.Percentage(), ' ', progressbar.Bar('='),' ', progressbar.Timer(),
           ' ', progressbar.ETA(), ' ', ' ']
        self.pb = progressbar.ProgressBar(maxval=1, widgets=widgets)
        self.pb.start()

    def on_file_receive_start(self, filename, filesz, task_info):
        self.on_file_send_start(filename, filesz, task_info)

    def on_file_send_error(self, error, task_info):
        print(error)

    def on_file_sending(self, progress, uuid):
        self.pb.update(progress)

    def on_file_send_finished(self, state, uuid):
        self.pb.finish()

    def on_msg_receive(self, message, task_info):
        session_index = task_info.session_index
        if session_index in self.sessions.keys():
            session = self.sessions[session_index]
            notice = "%s@%s@%s"%(session.name, session.address, session.token)
        else:
            notice = None
        print("Message from %s"%(notice))
        print(message)
    
    # connection
    def on_new_session(self, session:UtransSession):
        self.sessions[session.token] = session
        self.current_session_index = session.token
        print("connect to client", str(session))
        return session.token
    
    def on_session_close(self, session_token):
        session = self.sessions.pop(session_token)
        session.close()

    def on_connect_error(self, error):
        print("can not connect")

    # ask for user's confirmation
    # def on_need_decision(self, info):
    #     print(info)
    #     # send a request to main thread, ask for confirm
    #     channel = data_channel_mngr.get_data_channel("cmd")
    #     channel.put("ask_yes_no")
    #     # receive reponse from main thread
    #     cmd = self.data_channel.get()
    #     if cmd == "y":
    #         return True
    #     else:
    #         return False

    # scan server
    def on_new_server(self, server_info):
        self.available_servers.append(server_info)
        self.find_new_server = True

    def on_stop_scan(self):
        self.find_new_server = False

    def on_start_scan(self):
        self.available_servers = []

    def init_cmd_mode(self):
        self.event_channel = queue.Queue()
        data_channel_mngr.register_data_channel(self.name, self.event_channel)
        self.finished = False
        self.available_servers = []
        self.sessions = {}
        self.current_session_index = -1
        self.find_new_server = False
        
    def exit_cmd_mode(self):
        self.server.stop_server()
    
    def get_session_by_index(self, session_index):
        if session_index in self.sessions.keys():
            return self.sessions[session_index]
        else:
            return None
    
    def get_session_by_name(self, name):
        result = []
        for key in self.sessions.keys():
            session = self.sessions[key]
            if session.name == name:
                result.append(session)
        return result
    
    def get_session_by_name_interactive(self, name):
        sessions = self.get_session_by_name(name)
        if len(sessions) <= 0:
            return None
        if len(sessions) > 1:
            print("More than one session with host [%s], please specify one"%(name))
            for i in range(len(sessions)):
                print("%d %s %s %s"%(i, name, sessions[i].addr, sessions[i].token))
            try:
                choice = int(input())
            except:
                print("invalid input")
                return None
            if choice >=0 and choice < len(sessions):
                return sessions[choice]
            else:
                print("invalid input")
                return None
        else:
            return sessions[0]
        

    def run(self):
        input_trans_channel = data_channel_mngr.get_data_channel("prompt")
        client = self.client
        while True:
            try:
                raw_data = input("%s@%s: "%(self.name, str(client.current_session)))
            except BaseException as e:
                if type(e) != KeyboardInterrupt:
                    print(e)
                self.exit_cmd_mode()
                return

            if len(raw_data) <= 0:
                continue

            if not self.event_channel.empty():
                self.event_channel.get_nowait()
                input_trans_channel.put(raw_data)
                continue

            # deal with args with space surrounded by ""
            argv = link_args(raw_data.split())
            # parse args
            cmd = argv[0]
            raw_args, options = get_options(argv, [":"])
            if cmd == "send_file":
                if self.current_session_index not in self.sessions.keys():
                    print("Current session doesn't exist")
                    continue
                for filename in raw_args:
                    if not os.path.isfile(filename):
                        print("%s is not a file"%filename)
                    else:
                        client.send_file(filename, self)

            elif cmd == "send_msg":
                if self.current_session_index not in self.sessions.keys():
                    print("Current session doesn't exist")
                    continue
                if len(raw_args) <= 0:
                    try:
                        self.message_send_mode()
                    except:
                        print("exit message send mode")
                else:
                    msg = " ".join(raw_args)
                    client.send_message(msg, self)
            elif cmd == "ls":
                if len(raw_args) <= 0:
                    if self.current_session_index in self.sessions.keys():
                        current_session_info = str(self.sessions[self.current_session_index])
                    else:
                        current_session_info = "None"
                    print("current connect to [%s]"%(current_session_info))
                    print("All sessions:")
                    print(self.sessions)
                    print("Avaliable servers: ")
                    print(self.available_servers)
            elif cmd == "connect":
                if len(raw_args) <= 0:
                    available_server_num = len(self.available_servers)
                    if available_server_num > 1:
                        print("more than one available server, can't auto connect, please specify the target")
                    elif available_server_num <= 0:
                        print("no available server, please specify the target")
                    else:
                        client.connect(self.available_servers[0], self)
                    continue
                for item in raw_args:
                    try:
                        item = int(item)
                        if item >= 0 and item < len(self.available_servers):
                            server_info = self.available_servers[item]
                        else:
                            server_info = None
                    except:
                        server_info = None
                    if server_info == None:
                        addr_pattern = re.compile(r'((?:[0-9]+\.){3}[0-9]+)@([0-9]+)')
                        result = addr_pattern.match(item)
                        if result == None:
                            print("not valid address: %s"%(item))
                            continue
                        else:
                            addr = result.groups()[0]
                            if len(addr) != 2:
                                print("not valid address: %s"%(item))
                                continue
                            addr[1] = int(addr[1])
                        server_info = UtransServerInfo(item, addr)
                    client.connect(server_info, self)
            elif cmd == "switch":
                if len(raw_args) <= 0:
                    print("please specify a session")
                    continue
                name = raw_args[0]
                session = self.get_session_by_name_interactive()
                if session == None:
                    print("No session with host named [%s]"%(name))
                else:
                    self.current_session_index = session.token
            elif cmd == "close":
                if len(raw_args) <= 0:
                    print("please specify a session")
                    continue
                name = raw_args[0]
                session = self.get_session_by_name_interactive(name)
                if session == None:
                    print("No session with host named [%s]"%(name))
                else:
                    session.close()                
            elif cmd == "scan":
                self.scan_server(True)
            elif cmd == "stop":
                if len(raw_args) > 0:
                    if raw_args[0] == "server":
                        self.server.stop_server()
                    elif raw_args[0] == "broadcast":
                        self.server.stop_broadcast()
            elif cmd == "start":
                if len(raw_args) > 0:
                    if raw_args[0] == "server":
                        if not self.server.running:
                            self.server.async_run(self)
                    elif raw_args[0] == "broadcast":
                        if not self.server.enable_broadcast:
                            self.server.broadcast_service()
            elif cmd == "test":
                client.async_test(self.callback)
            elif cmd == "q":
                self.exit_cmd_mode()
                return
            else:
                print("unknown command: %s"%(cmd))
        
    def scan_server(self, one_to_exit = False):
        self.client.start_scan(self)
        if one_to_exit:
            try:
                while not self.find_new_server:
                    time.sleep(0.2)
            except BaseException as e:
                pass
            self.client.stop_scan()
            return
        else:
            print("scanning, press ctrl+c to stop")
            try:
                while True:
                    time.sleep(10)
            except:
                pass
            self.client.stop_scan()

    def message_send_mode(self):
        print("doesn't support")


def main():
    cmd_mode = UtransCmdMode()
    cmd_mode.run()
  

if __name__ == "__main__":
    main()