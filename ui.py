#!/usr/bin/python
# -*- coding: UTF-8 -*-
 
from utrans import *
import tkinter
import tkinter.messagebox
import time
import _thread

class MyCallback(UtransCallback):
    def __init__(self):
        super(MyCallback).__init__()

    def prompt_continue(self, info):
        return tkinter.messagebox.askyesno(message=info)


top = tkinter.Tk()
# 进入消息循环
server = UtransServer(MyCallback())
_thread.start_new_thread(server.run, ())
top.mainloop()