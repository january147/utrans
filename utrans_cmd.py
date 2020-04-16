#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Date: Fri Mar 13 21:48:17 2020
# Author: January

from utrans_utils import *
from utrans_interface import *
from utrans_new import *
import progressbar
import sys
from crypto import openssl as crypto
import hashlib

data_channel_mngr = DataChannelManager()

class UtransCmdMode(UtransCallback):
    def __init__(self):
        self.name = "cmd"
        self.read_args()
        self.client = UtransClient()
        self.client.set_scan_port(self.scan_port)
        self.server = UtransServer(self.port)

        ############testing#################
        with open("key_pub.rsa", "rb") as f:
            data = f.read()
        sha256 = hashlib.sha256()
        sha256.update(data)
        uuid = sha256.hexdigest()
        name = socket.gethostname()
        self.server.set_name(name)
        self.client.set_name(name)
        self.server.set_uuid(uuid)
        self.client.set_uuid(uuid)
        self.auth = UtransAuth("./key_pub.rsa", "./key.rsa", "./keys")
        ####################################
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
        if error == UtransError.CONNECTION_ERROR:
            self.on_session_close_send(task_info.session_index)
    
    def on_file_sending(self, progress, uuid):
        self.pb.update(progress)

    def on_file_send_finished(self, state, uuid):
        self.pb.finish()

    def on_msg_receive(self, message, task_info):
        session_index = task_info.session_index
        if session_index in self.sessions.keys():
            session = self.sessions[session_index]
            notice = "%s@%s[%s]"%(session.peer_name, session.peer_addr, session.id)
        else:
            notice = None
        print("Message from %s"%(notice))
        print(message)
    
    def on_msg_send_error(self, error, task_info):
        print("[msg send failed]", error)
        if error == UtransError.CONNECTION_ERROR:
            self.on_session_close_send(task_info.session_index)
    # auth
    def on_solve_challenge(self, challenge_type, challenge_data, session):
        if challenge_type == UtransAuth.CLG_BASIC:
            session_key, clg_reply_data, auth_counter = self.auth.basic_clg_solve(challenge_data)
            session.sync_auth_counter(auth_counter)
            result = (session_key, clg_reply_data)
        else:
            raise Exception("not support challenge type: %s"%(challenge_type))
        return result

    # auth_server
    def on_normal_auth(self, auth_type, peer_auth_data, session:UtransSessionNew):
        if auth_type == UtransAuth.AUTH_BASIC:
           result = self.auth.mac_verify(session.get_auth_counter(), session.session_key, peer_auth_data)
        else:
            raise Exception("not support auth type: %s"%(auth_type))
        return result
    # return (challenge_data, verify_aux_data)
    def on_challenge_peer(self, session:UtransSessionNew):
        clg_type = UtransAuth.CLG_BASIC
        clg_data = self.auth.basic_clg(session.peer_uuid, session.session_key, session.look_auth_counter())
        result = (clg_type, clg_data)
        return result
    
    # return (auth_data, aux_data)
    def on_need_auth_data(self, session):
        auth_type = UtransAuth.AUTH_BASIC
        auth_data = self.auth.mac(session.session_key, session.get_auth_counter())
        return (auth_type, auth_data)
    
    def on_verify_challenge(self, clg_type, reply_data, session):
        if clg_type == UtransAuth.CLG_BASIC:
            result = self.auth.basic_clg_verify(reply_data, session.get_auth_counter(), session.session_key)
        else:
            raise Exception("Not support challenge type:%s"%(clg_type))
        return result
        

    def on_check_client_pubkey(self, peer_uuid):
        return self.auth.check_peer_pubkey(peer_uuid)
    
    def on_search_session(self, peer_uuid):
        return self.sessions.search(peer_uuid, lambda x,y: x.peer_uuid == y)

    
    def on_register_pubkey(self, peer_uuid, pubkey):
        with open("./keys/%s"%(peer_uuid), "wb") as f:
            f.write(pubkey)
        return True
    
    def on_need_session_key(self, len):
        return crypto.rand_bytes(len)
    
    def on_need_pubkey(self):
        rsa = crypto.RSA()
        rsa.load_pub_key("key_pub.rsa")
        return rsa.read_pub_key()
    # connection
    def on_new_session(self, session:UtransSessionNew):
        if session.id in self.sessions.keys():
            print("reconnect to", str(session))
            return session.id
        else:
            index = self.sessions.append(session)
            session.id = index
            self.current_session_index = index
            print("connect to", str(session))
            return index
    
    def on_session_close_send(self, session_index):
        if session_index in self.sessions.keys():
            session = self.sessions[session_index]
            session.close_send_sk()
            if session.status == UtransSession.DISCONNECTED:
                self.on_session_close(session_index)
    
    def on_session_close_recv(self, session_index):
        if session_index in self.sessions.keys():
            session = self.sessions[session_index]
            session.close_recv_sk()
            if session.status == UtransSession.DISCONNECTED:
                self.on_session_close(session_index)
    
    def on_session_close(self, session_index):
        if session_index in self.sessions.keys():
            session = self.sessions.pop(session_index)
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

    def on_need_decision(self, info):
        return True
    
    # scan server
    def on_new_server(self, server_info):
        self.available_servers.append(server_info)
        self.find_new_server = True

    def on_stop_scan(self):
        self.find_new_server = False

    def on_start_scan(self):
        self.available_servers = []

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
        self.event_channel = queue.Queue()
        data_channel_mngr.register_data_channel(self.name, self.event_channel)
        self.finished = False
        self.available_servers = []
        self.sessions = DictList()
        self.current_session_index = -1
        self.find_new_server = False
        
    def exit_cmd_mode(self):
        self.server.stop_server()
        
    def run(self):
        input_trans_channel = data_channel_mngr.get_data_channel("prompt")
        client = self.client
        while True:
            try:
                if self.current_session_index in self.sessions.keys():
                    session = self.sessions[self.current_session_index]
                    prompt = "%s@%s(%d): "%(self.name, session.peer_name, self.current_session_index)
                else:
                    prompt = "%s@None: "%(self.name)
                raw_data = input(prompt)
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
                    task_info = UtransTaskInfo(session_index = self.current_session_index)
                    client.send_message(msg, self, task_info)
            elif cmd == "ls":
                if len(raw_args) <= 0:
                    if self.current_session_index in self.sessions.keys():
                        current_session_info = str(self.sessions[self.current_session_index])
                    else:
                        current_session_info = "None"
                    print("current connect to [%s]"%(current_session_info))
                    print("All sessions:")
                    self.sessions.show()
                    print("Avaliable servers: ")
                    print_list(self.available_servers)
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
                        addr_pattern = re.compile(r'((?:[0-9]+\.){3}[0-9]+):([0-9]+)')
                        result = addr_pattern.match(item)
                        if result == None:
                            print("not valid address: %s"%(item))
                            continue
                        else:
                            addr_raw = result.groups()
                            try:
                                addr = (addr_raw[0], int(addr_raw[1]))
                            except:
                                print("not valid address: %s"%(item))
                                continue
                        server_info = UtransServerInfo(item, addr)
                    client.connect(self, server_info)
            elif cmd == "switch":
                if len(raw_args) <= 0:
                    print("please specify a session")
                    continue
                try:
                    index = int(raw_args[0])
                except:
                    print("Not a valid session_index, please use 'ls' to check active sessions")
                if index not in self.sessions.keys():
                    print("Not a valid session_index, please use 'ls' to check active sessions")
                else:
                    self.current_session_index = index
                    client.set_current_session(self.sessions[self.current_session_index])

                
            elif cmd == "close":
                if len(raw_args) <= 0:
                    print("please specify a session")
                    continue
                try:
                    index = int(raw_args[0])
                except:
                    print("Not a valid session_index, please use 'ls' to check active sessions")
                if index not in self.sessions.keys():
                    print("Not a valid session_index, please use 'ls' to check active sessions")
                else:
                    session = self.sessions.pop(index)
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
            elif cmd == "show_session_info":
                if len(raw_args) > 0:
                    try:
                        index = int(raw_args[0])
                    except:
                        print("No such session")
                        continue
                    if index not in self.sessions.keys():
                        print("No such session")
                        continue
                    self.sessions[index].print_info()
            elif cmd == "test":
                Runnable(self.run, ())
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