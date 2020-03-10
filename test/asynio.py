#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Date: Mon Mar  9 10:16:24 2020
# Author: January

import asyncio

async def get_input():
    return input()

async def main():
    print('Hello ...')
    await get_input()
    print('... World!')

async def main2():
    print('ppt ...')
    print('haha')

task1 = asyncio.ensure_future(main())
task2 = asyncio.ensure_future(main2())

loop = asyncio.get_event_loop()
loop.run_until_complete(asyncio.gather(task2, task1))
# Python 3.7+