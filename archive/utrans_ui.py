#!/usr/bin/python3
# -*- coding: UTF-8 -*-

from utrans_utils import *
from utrans_interface import *
from utrans import *
from tkinter import *
from tkinter import scrolledtext
from tkinter import ttk
import tkinter.messagebox as msgbox
import tkinter.filedialog as filedialog
import tkinter.font as tkfont
import time
import _thread
import re
import math

class Global:
    client = UtransClient()
    server = UtransServer()

class ScrollableFrame(Frame):
    def __init__(self, container, *args, **kwargs):
        super().__init__(container, *args, **kwargs)
        self.canvas = Canvas(self)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = Frame(self.canvas)
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )

        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")

        self.canvas.configure(yscrollcommand=scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

class UtransUISession(UtransSession):
    def __init__(self, record_frame, session:UtransSession):
        super().__init__(session.name, session.address, session.sk, session.type)
        self.record_frame = record_frame
    
    def close(self):
        super().close()
        self.record_frame.destroy()

class FileSendStatusItem(Frame):

    def __init__(self, master, uuid, name = None):
        super().__init__(master)
        self.uuid = uuid
        if name == None:
            self.name = uuid
        else:
            self.name = name
        self.init_content()

    def init_content(self):
        self.columnconfigure(0, weight = 1)
        self.columnconfigure(1, weight = 1)
        self.columnconfigure(2, weight = 1)
        self.columnconfigure(3, weight = 1)
        self.columnconfigure(4, weight = 1)

        self.filename_label = Label(self, text=self.name, width=5, anchor=W)
        self.filename_label.grid(column=0, row=0, sticky=W+E)

        Label(self, text="已用时间：").grid(column=1, row=0)

        self.used_time_label = Label(self, text="00:00:00")
        self.used_time_label.grid(column=2, row = 0)

        Label(self, text="剩余时间：").grid(column=3, row=0)

        self.left_time_label = Label(self, text="00:00:00")
        self.left_time_label.grid(column=4, row=0)

        self.progress_label = Label(self, text="0%")
        self.progress_label.grid(column=0, row=1)

        self.progress_bar = ttk.Progressbar(self, max=1)
        self.progress_bar.grid(column = 1, columnspan=4, row=1, sticky="WE")
    
    def update_progress(self, progress):
        self.progress_bar["value"] = progress
        self.progress_label["text"] = "%d%%"%(progress * 100)
    
    def finish(self):
        self.progress_bar["value"] = 1
        self.progress_label["text"] = "已完成"
    
    def fail(self):
        self.progress_label["text"] = "失败"

class MessagePanel(Frame):

    def __init__(self, master, msg, uuid = None):
        super().__init__(master)
        self.uuid = uuid
        self.label = Label(self, text="传输中...")
        self.label.pack(side=TOP, anchor = W)
        self.text = Text(self, height=20)
        self.text.insert("0.0", msg)
        self.text["state"] = "disabled"
        self.text.pack(side=TOP, anchor = W, fill=X)
        
    def fail(self):
        self.label["text"] = "失败"
    
    def finish(self):
        self.label["text"] = "成功"

class FileSendStatusList(Frame):

    def __init__(self, master):
        super().__init__(master)
        self.items = {}
        canvas = Canvas(self)
        canvas["bg"] = "green"
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        self.scrollable_frame = Frame(canvas)
        self.scrollable_frame["bg"] = "pink"
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )

        self.scrollable_frame_id = canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas = canvas
        canvas.bind("<Configure>", self.resize_frame)

        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def resize_frame(self, e):
        self.canvas.itemconfig(self.scrollable_frame_id, width=e.width)

    def get_item(self, uuid):
        if uuid in self.items.keys():
            return self.items[uuid]
        else:
            return None

    def insert(self, item:FileSendStatusItem):
        item.pack(side=TOP, fill=X)
        self.items[item.uuid] = item
    
    def remove(self, uuid):
        item = self.items.pop(uuid)
        item.destory()
    
    def show(self):
        self.grid(column = 0, columnspan=2, row = 0, sticky = NSEW)
    
    def hide(self):
        self.grid_forget()

class UtransMainFrame(Frame, UtransCallback):
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        self["bg"] = "yellow"
        self.pack(fill=BOTH, expand=1)
        self.init_widgets()
        self.init_data()
        # start server automatically
        self.start_server()
    
    def init_data(self):
        self.current_session_index = -1
        self.sessions = []  
    # interface
    # create new session
    def on_new_session(self, session:UtransSession):
        self.connection_list.insert(END, session.name)
        # create new record frame for this session
        new_record_frame = FileSendStatusList(self.right_frame)
        ui_session = UtransUISession(new_record_frame, session)
        self.sessions.append(ui_session)
        session_index = len(self.sessions) - 1
        self.set_session(session_index)
        return session_index

    def on_connect_error(self, error):
        msgbox.showerror(message=error)

    def on_file_send_error(self, error, task_info):
        session = self.sessions[task_info.session_index]
        item = session.record_frame.get_item(task_info.uuid)
        if item != None:
            item.fail()

    def on_file_sending(self, progress, task_info):
        # slow down to test
        time.sleep(0.5)
        session = self.sessions[task_info.session_index]
        item = session.record_frame.get_item(task_info.uuid)
        if item != None:
            item.update_progress(progress)

    def on_file_send_finished(self, state, task_info):
        session = self.sessions[task_info.session_index]
        item = session.record_frame.get_item(task_info.uuid)
        if item != None:
            item.finish()

    def on_file_receive_start(self, filename, filesz, task_info):
        session = self.sessions[task_info.session_index]
        uuid = task_info.uuid
        new_file_send_item = FileSendStatusItem(session.record_frame.scrollable_frame, uuid, filename)
        session.record_frame.insert(new_file_send_item)
    
    def on_msg_receive(self, msg, task_info):
        session = self.sessions[task_info.session_index]
        uuid = task_info.uuid
        new_message_item = MessagePanel(session.record_frame.scrollable_frame, msg, uuid)
        new_message_item.finish()
        session.record_frame.insert(new_message_item)
        
    def on_msg_send_error(self, msg, task_info):
        session = self.sessions[task_info.session_index]
        item = session.record_frame.get_item(task_info.uuid)
        if item != None:
            item.fail()
    
    def on_msg_send_finished(self, state, task_info):
        session = self.sessions[task_info.session_index]
        item = session.record_frame.get_item(task_info.uuid)
        if item != None:
            item.finish()

    # window event for test
    def on_test_new_task(self):
        #msgbox.showinfo(message="click test")
        #new_task = FileSendStatusItem(self.record_frame.scrollable_frame, "文件名qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq")
        new_task = MessagePanel(self.record_frame.scrollable_frame, "this is a test")
        self.record_frame.insert(new_task)
    
    def on_test_switch_frame(self):
        result = self.connection_list.curselection()
        if len(result) <= 0:
            return
        select = result[0]
        session = self.sessions[select]
        self.record_frame.hide()
        session.record_frame.show()
        self.record_frame = session.record_frame
        if session.type == UtransSession.T_RECV:
            self.disable_input()
        else:
            self.enable_input()
        print(select)
    
    def on_test_new_connection(self):
        test_sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        session = UtransSession("localhost", ("127.0.0.1", 8888), test_sk, UtransSession.T_RECV)
        self.on_new_session(session)
    
    # window event
    def on_click_start_server(self):
        self.start_server()
    
    def on_click_scan(self):
        self.start_scan_window()
        #self.on_test()

    def on_click_pick_file(self):
        filenames = filedialog.askopenfilenames()
        self.input_text.delete("0.0", END)
        for filename in filenames:
            self.input_text.insert(END, "file://" + filename + "\n")
    
    def on_click_switch_session(self, event):
        result = self.connection_list.curselection()
        if len(result) <= 0:
            return
        select = result[0]
        self.set_session(select)
        
    def on_click_send(self):
        if self.current_session_index < 0 or self.current_session_index >= len(self.sessions):
            msgbox.showwarning(message = "No connection")
            return
        message = self.input_text.get("0.0", END)
        task_infos = []
        if message.startswith("file://"):
            filenames = message.split("\n")
            for i in range(len(filenames)):
                if len(filenames[i]) == 0:
                    continue
                filenames[i] = filenames[i][7:]
                task_info = UtransTask(session_index=self.current_session_index)
                task_infos.append(task_info)
                new_item = FileSendStatusItem(self.record_frame.scrollable_frame, task_info.uuid, os.path.basename(filenames[i]))
                self.record_frame.insert(new_item)
            Global.client.send_files(filenames, self, task_infos=task_infos, session = self.sessions[self.current_session_index])
        else:
            task_info = UtransTask(session_index=self.current_session_index)
            new_item = MessagePanel(self.record_frame.scrollable_frame, message, task_info.uuid)
            self.record_frame.insert(new_item)
            Global.client.send_message(message, self, task_info = task_info)
    
    def on_click_close_session(self):
        result = self.connection_list.curselection()
        if len(result) <= 0:
            return
        select = result[0]
        self.close_session(select)

    # functions
    def set_session(self, session_index):
        self.current_session_index = session_index
        session = self.sessions[session_index]
        # switch session record frame
        self.record_frame.hide()
        session.record_frame.show()
        self.record_frame = session.record_frame
        if session.type == UtransSession.T_RECV:
            self.disable_input()
        else:
            self.enable_input()
        self.status_bar["text"] = "%s[%s@%d], 会话编号[%s]"%(session.name, session.address[0], session.address[1], session.token)

    def disable_input(self):
        self.input_text["state"] = "disabled"
        self.pick_file_button["state"] = "disabled"
        self.send_button["state"] = "disabled"
    
    def enable_input(self):
        self.input_text["state"] = "normal"
        self.pick_file_button["state"] = "normal"
        self.send_button["state"] = "normal"

    def close_session(self, session_index):
        session = self.sessions.pop(session_index)
        session.close()
        self.connection_list.delete(session_index)
        self.record_frame = self.default_record_frame
        self.record_frame.show()
        if len(self.sessions) > 0:
            self.status_bar["text"] = "未选择任何会话"
        else:
            self.status_bar["text"] = "未连接"

    def start_server(self):
        if not Global.server.running:
            Global.server.async_run(self)
        else:
            msgbox.showinfo(message = "server already running")

    def get_session_by_token(self, session_token):
        for item in self.sessions:
            if item.session_token == session_token:
                return item
        return None

    def init_widgets(self):
        self.menu = Menu(self)
        self.menu.add_command(label = "扫描", command=self.on_click_scan)
        self.menu.add_command(label = "结束会话", command=self.on_click_close_session)
        # self.menu.add_command(label = "增加任务", command=self.on_test_new_task)
        # self.menu.add_command(label = "新连接", command=self.on_test_new_connection)
        self.menu.add_command(label = "启动服务器", command=self.start_server)
        self.master.config(menu=self.menu)
        

        self.status_bar = Label(self, text="未连接", bd=1, relief=SUNKEN, anchor=W)
        self.status_bar["bg"] = "red"
        self.status_bar.pack(side=BOTTOM, fill=X)

        self.left_frame = Frame(self)
        self.left_frame["bg"] = "green"
        self.left_frame.pack(side=LEFT, fill = Y)
        font = tkfont.Font(family="微软雅黑", size=12)
        self.connection_list = Listbox(self.left_frame, font = font, width=12)
        self.connection_list.bind("<Double-Button-1>", self.on_click_switch_session)
        self.connection_list.pack(fill=Y, expand=1)

        self.right_frame = Frame(self)
        self.right_frame["bg"] = "blue"
        self.right_frame.pack(side=RIGHT, fill = BOTH, expand = 1)
        self.right_frame.columnconfigure(0, weight=1)
        self.right_frame.rowconfigure(0, weight=4)
        self.right_frame.rowconfigure(1, weight=1)
        self.right_frame.rowconfigure(2, weight=1)

        self.record_frame = FileSendStatusList(self.right_frame)
        self.default_record_frame = self.record_frame
        self.record_frame["bg"] = "pink"
        self.record_frame.grid(column = 0, columnspan=2, row = 0, sticky = NSEW)

        # for layout test
        # self.test_frame = Frame(self.right_frame)
        # self.test_frame["bg"] = "black"
        # self.test_frame.grid(column=0, row=1, rowspan=2, sticky=NSEW)
        
        self.send_button = Button(self.right_frame, text="发送", command=self.on_click_send)
        self.send_button.grid(column=1, row=1, sticky = NSEW)

        self.pick_file_button = Button(self.right_frame, text="选择文件", command = self.on_click_pick_file)
        self.pick_file_button.grid(column=1, row=2, sticky = NSEW)
    

        #self.input_text = Text(self.right_frame)
        self.input_text = scrolledtext.ScrolledText(self.right_frame, height=5)
        self.input_text.grid(column=0, row=1, rowspan=2, sticky=NSEW)
    
    
    def start_scan_window(self):
        scan_window = Toplevel(self.master)
        scan_window.geometry("300x400")
        # scan_window.grab_set()
        scan_frame = UtransScanFrame(scan_window, self)

class UtransScanFrame(Frame):
    def __init__(self, master, context):
        super().__init__(master)
        self.master = master
        self["bg"] = "yellow"
        self.pack(fill=BOTH, expand=1)
        self.init_widget()
        self.context = context
        self.init_data()
        self.master.protocol("WM_DELETE_WINDOW", self.on_window_closing)
    def init_data(self):
        self.available_servers = []

    # UtransCallbackInterface
    def on_new_server(self, server_info):
        if self.winfo_exists():
            self.scan_result_list.insert(END, str(server_info))
            self.available_servers.append(server_info)

    def on_start_scan(self):
        if self.winfo_exists():
            self.status_bar["text"] = "扫描中"

    def on_stop_scan(self):
        if self.winfo_exists():
            self.status_bar["text"] = "未扫描"

    # window event
    def on_window_closing(self):
        Global.client.stop_scan()
        self.master.destroy()
    
    def on_scan_click(self):
        self.scan_result_list.delete(0, END)
        Global.client.start_scan(self)

    def on_stop_click(self):
        Global.client.stop_scan()
    
    def on_connect_click(self):
        index = self.scan_result_list.curselection()
        if len(index) == 0:
            msgbox.showwarning(message="No target")
        else:
            index = index[0]
            Global.client.connect(self.available_servers[index], self.context)

    def init_widget(self):
        self.rowconfigure(0, weight = 1)
        self.columnconfigure(0, weight = 1)
        self.columnconfigure(1, weight = 1)
        self.columnconfigure(2, weight = 1)

        self.scan_result_list = Listbox(self)
        self.scan_result_list.grid(column=0, columnspan=3, row=0, sticky=NSEW)

        self.scan_button = Button(self, text="扫描", command=self.on_scan_click)
        self.scan_button.grid(column=0, row=1, sticky=NSEW)

        self.stop_button = Button(self, text="停止", command=self.on_stop_click)
        self.stop_button.grid(column=1, row=1, sticky=NSEW)

        self.connect_button = Button(self, text="连接", command=self.on_connect_click)
        self.connect_button.grid(column=2, row=1, sticky=NSEW)

        self.status_bar = Label(self, text="未扫描", bd=1, relief=SUNKEN, anchor=W)
        self.status_bar["bg"] = "red"

        self.status_bar.grid(column=0, columnspan=3, row=2, sticky=NSEW)
    
class UtransUI:

    def __init__(self):
        self.top = Tk()
        self.top.title("Utrans")
        self.top.geometry("600x400")
        self.config = UtransConfig()

    def load_config(self):
        if os.path.exists("utrans.config"):
            self.config.load_config()
    
    def save_config(self):
        self.config.save_config("utrans.config")
            
    def init_main_window(self):
        self.main_frame = UtransMainFrame(self.top)

    def start_scan_window(self):
        pass

    def run(self):
        self.init_main_window()
        self.top.mainloop()

app = UtransUI()
app.run()
