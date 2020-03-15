#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Date: Wed Mar 11 17:42:22 2020
# Author: January
class UtransError:

    CONNECTION_ERROR = "connetion_error"
    LOCAL_ERROR = "local error"
    INVALID_CMD = "invalid_cmd"
    PEER_REJECT = "peer_reject"
    PEER_SAY_FAILED = "peer_say_failed"
    USER_REJECT = "user_reject"
    REPEAT_FILE = "repeat_file"
    NO_SUCH_FILE = "no_such_file"
    UTRANS_CONFIG_ERROR = "utrans_config_error"
    OK = "ok"


class UtransCallback:

    def __init__(self):
        pass
    
    # file send
    def on_file_send_start(self, filename, filesz, uuid):
        pass

    # Note: The server has to create UI item when starting to transmit files whereas the client finish those task before call send file.
    # So I seperate this callback from file_send
    def on_file_receive_start(self, filename, filesz, taskinfo):
        pass

    def on_file_send_error(self, error, uuid):
        pass

    def on_file_sending(self, progress, uuid):
        pass

    def on_file_send_finished(self, state, uuid):
        pass
    
    # message
    def on_msg_send_start(self, error, task_info):
        pass

    def on_msg_send_error(self, error, task_info):
        pass

    def on_msg_send_finished(self, state, task_info):
        pass
    
    def on_msg_receive(self, message, task_info):
        pass

    # connection
    def on_new_session(self, session):
        return -1
    
    def on_session_close(self, session_index):
        pass

    def on_connect_error(self, error):
        pass

    # ask for user's confirmation
    def on_need_decision(self, info):
        pass

    # scan server
    def on_new_server(self, server_info):
        pass

    def on_stop_scan(self):
        pass

    def on_start_scan(self):
        pass


def main():
    pass
if __name__ == "__main__":
    main()
