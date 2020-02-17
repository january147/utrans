#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Date: Tue Jan  7 23:51:19 2020
# Author: January
import time
import socket

def main():
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # You have to set this socket option to send broadcast udp package, or the operation will fail.
    sk.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    while True:
        sk.sendto(b"hello", ("255.255.255.255", 9001))
        time.sleep(1)
if __name__ == "__main__":
    main()
