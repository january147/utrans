#!/usr/bin/python3
'''
Author: January
Date: 2021-05-18 21:38:12
'''
from utrans.core import *
import socket
import argparse
import queue
import logging
import tkinter

logging.basicConfig(level = logging.DEBUG)

parser = argparse.ArgumentParser()
parser.add_argument("-s", "--server", action="store_true", help="server mode")
parser.add_argument("--name", default=socket.gethostname(), help="specify a name")
parser.add_argument("--password", default="hothotdogdog")
parser.add_argument("--mode", metavar="text | file", default="text")
parser.add_argument("--gui", action="store_true")
parser.add_argument("addr", metavar="ip:port", help="listen addr for server")

def get_self_ip():
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sk.connect(("8.8.8.8", 53))
    addr = sk.getsockname()
    ip = addr[0]
    return ip

def readable_size(size):
    if size >= 0x1 << 30:
        return "%.2fG"%(size / (0x1 << 30))
    elif size >= 0x1 << 20:
        return "%.2fM"%(size / (0x1 << 20))
    elif size >= 0x1 << 10:
        return "%.2fK"%(size / (0x1 << 10))
    else:
        return str(size)

class SimpleFrame(tkinter.Frame):
    def __init__(self, master, session):
        super().__init__(master)
        self["bg"] = "yellow"
        self.pack(fill=tkinter.BOTH, expand=1)
        self.init_widget()
        self.session = session
    
    def on_send_text_click(self):
        msg = self.msg_input_text.get("0.0", tkinter.END)
        self.session.send_text(msg)

    def init_widget(self):
        self.msg_input_text = tkinter.Text(self)
        self.msg_input_text.pack()
        self.send_button = tkinter.Button(self, text="发送", command=self.on_send_click)
        self.send_button.pack()

class UtransCLI(UtransContext):
    def __init__(self):
        self.session_queue = queue.Queue()
        self.server_enable = False
        self.name = socket.gethostname()
        self.des_addr = None
        self.src_addr = None

    def get_src_addr(self):
        return self.src_addr

    def get_password(self):
        return self.password
    
    def get_session_listener(self) -> UtransSessionListener:
        return self
    
    def message_send_mode(self, session):
        while True:
            try:
                message = input("Message to send: ")
                if len(message) > 0:
                    session.send_text(message)
            except:
                session.close_active()
                print("\nExit current session to [%s]"%(session.des_name))
                break
    
    def message_send_mode_gui(self, session):
        top = tkinter.Tk()
        frame = SimpleFrame(top, session)
        top.title("Utrans")
        top.mainloop()
        
        session.close_active()
    
    def file_send_mode(self, session):
        while True:
            try:
                filepath = input("File to send: ")
                if os.path.isfile(filepath):
                    session.send_file(filepath, UtransFileTransHandle())
            except:
                session.close_active()
                print("\nExit current session to [%s]"%(session.des_name))
                break

    def run(self):
        # 读取参数
        args = parser.parse_args()
        ip, port = args.addr.split(":")
        port = int(port)
        if args.server == True:
            self.server_enable = True
            if ip == "":
                ip = "0.0.0.0"
            self.src_addr = UtransAddr(args.name, (ip, port))
        else:
            self.src_addr = UtransAddr(args.name)
            self.des_addr = UtransAddr(tcp_addr = (ip, port))
        self.password = args.password
        self.mode = args.mode

        # 启动
        print("Current ip is %s"%(get_self_ip()))
        if self.server_enable:
            server = UtransServer(self)
            server.async_run()
        else:
            session = UtransSession(self.src_addr.name)
            session.set_status_listener(self)
            session.connect_by_password(self.password, self.des_addr.tcp_addr)
            self.session_queue.put(session)
        while True:
            try:
                session = self.session_queue.get(timeout=5)
            except queue.Empty:
                continue
            if self.mode == "file":
                self.file_send_mode(session)
            else:
                if args.gui:
                    self.message_send_mode_gui(session)
                else:
                    self.message_send_mode(session)
            if not self.server_enable:
                break
    
    def on_connected(self, session):
        print("connect to [%s]"%(session.des_name))
        self.session_queue.put(session)

    def on_disconnected(self, session):
        print("disconnect from [%s]"%(session.des_name))
    
    def on_recv_text(self, text):
        print("recv text:\n%s"%(text))
    
    def on_recv_file(self, filename, filesize):
        print("recv file [%s], size [%s]"%(filename, readable_size(filesize)))
        return UtransFileTransHandle()

UtransCLI().run()


    
