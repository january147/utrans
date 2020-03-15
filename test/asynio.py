#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Date: Mon Mar  9 10:16:24 2020
# Author: January

import asyncio

def stop():
    a = input()
    print(a)

loop = asyncio.get_event_loop()
loop.call_later(3, print, ("run after 3"))
loop.call_soon(print, ("run now"))
loop.run_in_executor(None, stop)
loop.run_forever()
# Python 3.7+