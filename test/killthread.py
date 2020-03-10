#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Date: Mon Mar  9 12:56:41 2020
# Author: January

import ctypes
import _thread
import time

def hello():
    try:
        while True:
            time.sleep(20)
    except:
        print("exit")
        return

def kill(id):
    ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(id), ctypes.py_object(SystemExit))

def main():
    tid = _thread.start_new_thread(hello, ())
    if input() == "q":
        kill(tid)
    time.sleep(1)


if __name__ == "__main__":
    main()
