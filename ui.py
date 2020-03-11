#!/usr/bin/python
# -*- coding: UTF-8 -*-
 
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


class UtransUICallback(UtransCallback):

    def __init__(self):
        pass
    def prompt_continue(self, info):
        return msgbox.askyesno(message=info)
    
    def on_progress(self, progress):
        pass
    
    def on_finished(self, info):
        msgbox.showinfo(message = info)



def send_test():
    client = UtransClient()
    client.start_scan(UtransCallback())
    while not client.has_new_server():
        pass
    client.stop_scan()
    client.connect(client.available_servers[0])
    client.send_file("ever.exe", UtransUICallback(), False)

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
        self.progress_bar["value"] = 0.5
        self.progress_bar.grid(column = 1, columnspan=4, row=1, sticky="WE")
    
    def update_progress(self, progress):
        self.progress_bar["value"] = progress
        self.progress_label["text"] = "%d%%"%(progress * 100)
    
    def finish(self):
        self.progress_bar["value"] = 1
        self.progress_label["text"] = "已完成"
    
    def fail(self):
        self.progress_label["text"] = "失败"
    

        


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

class UtransMainFrame(Frame, UtransCallback):
    def __init__(self, master, context):
        super().__init__(master)
        self.master = master
        self["bg"] = "yellow"
        self.pack(fill=BOTH, expand=1)
        self.context = context
        self.init_widgets()
        self.new_callback = True
    
    # interface
    def on_new_connection(self, session:UtransSession):
        self.connection_list.insert(END, session.name)
        self.status_bar["text"] = "连接到%s[%s@%d]"%(session.name, session.address[0], session.address[1])

    def on_start(self):
        print("传输开始")
    
    def on_finished(self, info):
        print("传输完成")

    def on_file_send_start(self, filename, filesz, uuid):
        pass

    def on_file_send_error(self, error, uuid):
        item = self.record_frame.get_item(uuid)
        if item != None:
            item.fail()

    def on_file_sending(self, progress, uuid):
        item = self.record_frame.get_item(uuid)
        if item != None:
            item.update_progress(progress)

    def on_file_send_finished(self, state, uuid):
        item = self.record_frame.get_item(uuid)
        if item != None:
            item.finish()

    # window event
    def on_test(self):
        #msgbox.showinfo(message="click test")
        new_task = FileSendStatusItem(self.record_frame.scrollable_frame, "文件名qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq")
        self.record_frame.insert(new_task)


    def on_click_scan(self):
        #self.start_scan_window()
        self.on_test()

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
        name = self.connection_list.get(select)
        logger.debug("select session[%s]"%(name))
        self.context.client.set_current_session(name)
        session = self.context.client.get_current_session()
        self.status_bar["text"] = "连接到%s[%s@%d]"%(session.name, session.address[0], session.address[1])

    
    def on_click_send(self):
        message = self.input_text.get("0.0", END)
        if message.startswith("file://"):
            filenames = message.split("\n")
            for i in range(len(filenames)):
                filenames[i] = filenames[i][7:]
                new_item = FileSendStatusItem(self.record_frame.scrollable_frame, filenames[i], os.path.basename(filenames[i]))
                self.record_frame.insert(new_item)
            session = self.context.client.get_current_session()
            self.context.client.send_files(filenames, self, filenames, session)
        else:
            self.context.client.send_message(message, self)

            
    def init_widgets(self):
        self.menu = Menu(self)
        self.menu.add_command(label = "扫描", command=self.on_click_scan)
        self.master.config(menu=self.menu)
        

        self.status_bar = Label(self, text="未连接", bd=1, relief=SUNKEN, anchor=W)
        self.status_bar["bg"] = "red"
        self.status_bar.pack(side=BOTTOM, fill=X)

        self.left_frame = Frame(self)
        self.left_frame["bg"] = "green"
        self.left_frame.pack(side=LEFT, fill = Y)
        font = tkfont.Font(family="微软雅黑", size=12)
        self.connection_list = Listbox(self.left_frame, font = font, width=12)
        self.connection_list.bind("<Button-1>", self.on_click_switch_session)
        self.connection_list.pack(fill=Y, expand=1)

        self.right_frame = Frame(self)
        self.right_frame["bg"] = "blue"
        self.right_frame.pack(side=RIGHT, fill = BOTH, expand = 1)
        self.right_frame.columnconfigure(0, weight=1)
        self.right_frame.rowconfigure(0, weight=4)
        self.right_frame.rowconfigure(1, weight=1)
        self.right_frame.rowconfigure(2, weight=1)

        self.record_frame = FileSendStatusList(self.right_frame)
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
        scan_frame = UtransScanFrame(scan_window, self.context)



class UtransScanFrame(Frame):
    def __init__(self, master, context):
        super().__init__(master)
        self.master = master
        self["bg"] = "yellow"
        self.pack(fill=BOTH, expand=1)
        self.init_widget()
        self.context = context
        self.client = self.context.client
    
    # UtransCallbackInterface
    def on_new_server(self, server_info):
        if self.winfo_exists():
            self.scan_result_list.insert(END, str(server_info))

    def on_start_scan(self):
        if self.winfo_exists():
            self.status_bar["text"] = "扫描中"

    def on_stop_scan(self):
        if self.winfo_exists():
            self.status_bar["text"] = "未扫描"

    # window event
    def on_scan_click(self):
        self.scan_result_list.delete(0, END)
        self.client.start_scan(self, 10)

    def on_stop_click(self):
        self.client.stop_scan()
    
    def on_connect_click(self):
        index = self.scan_result_list.curselection()
        if len(index) == 0:
            msgbox.showwarning(message="No target")
        else:
            index = index[0]
            session =  self.client.connect(self.client.available_servers[index])
            if session != None:
                self.context.on_new_connection(session)
            else:
                msgbox.showerror("连接失败")

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
        self.client = UtransClient()
    
    def on_new_connection(self, session):
        self.main_frame.on_new_connection(session)

    def init_main_window(self):
        self.main_frame = UtransMainFrame(self.top, self)

    def start_scan_window(self):
        pass

    def run(self):
        self.init_main_window()
        self.top.mainloop()

app = UtransUI()
app.run()