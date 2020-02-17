#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Date: Tue Jan  7 23:22:23 2020
# Author: January

import socket
import threading
import _thread


def start_tcp_listen():
    lsk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsk.bind(("0.0.0.0", 9001))
    lsk.listen(2)
    while True:
        ssk, address = lsk.accept()
        print("connection from", address)

def receive_udp():
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sk.bind(("0.0.0.0", 9001))
    while True:
        data, address = sk.recvfrom(256)
        print("recv %s from %s"%(str(data), str(address)))

def main():
    _thread.start_new_thread(start_tcp_listen, ())
    _thread.start_new_thread(receive_udp, ())
    while True:
        pass
if __name__ == "__main__":
    main()
