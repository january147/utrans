#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Date: Sun Mar  8 17:30:49 2020
# Author: January
import _thread
import queue

t1_input = queue.Queue()
t2_input = queue.Queue()
to = (t1_input, t2_input)

def t1(input_data, flag):
    while True:
        data = input_data.get()
        print(flag, data)


curent = 0
_thread.start_new_thread(t1, (t1_input, "t1"))
_thread.start_new_thread(t1, (t2_input, "t2"))
while True:
    a = input()
    if a == "switch":
        curent = 1 - curent
        continue
    to[curent].put(a)