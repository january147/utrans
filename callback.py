#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Date: Wed Mar 11 17:42:22 2020
# Author: January
class UtransError:

    CONNECTION_ERROR = "connetion_error"
    PEER_REJECT = "peer_reject"
    OK = "ok"


class UtransCallbackNew:

    def __init__(self):
        pass
    
    # file
    def on_file_send_start(self, filename, filesz, uuid):
        pass

    def on_file_send_error(self, error, uuid):
        pass

    def on_file_sending(self, progress, uuid):
        pass

    def on_file_send_finished(self, state, uuid):
        pass


def main():
    pass
if __name__ == "__main__":
    main()
