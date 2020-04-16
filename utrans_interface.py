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
    PROTOCAL_ERROR = "protocal _error"
    OK = "ok"


class UtransCallback:

    # file send
    def on_file_send_start(self, filename, filesz, task_info):
        pass

    # Note: The server has to create UI item when starting to transmit files whereas the client finish those task before call send file.
    # So I seperate this callback from file_send
    def on_file_receive_start(self, filename, filesz, task_info):
        pass

    def on_file_send_error(self, error, task_info):
        pass

    def on_file_sending(self, progress, task_info):
        pass

    def on_file_send_finished(self, state, task_info):
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
    # The method should return an session index
    def on_new_session(self, session):
        return None
    
    def on_session_close(self, session_index):
        pass
    
    def on_session_close_recv(self, session_index):
        pass

    def on_session_close_send(self, session_index):
        pass

    def on_connect_error(self, error):
        pass

    # ask for user's confirmation
    # This method should return True or False.
    def on_need_decision(self, info):
        return False

    # scan server
    def on_new_server(self, server_info):
        pass

    def on_stop_scan(self):
        pass

    def on_start_scan(self):
        pass

    # auth_client
    
    # return (session_key, challange_reply_data)
    def on_solve_challenge(self, challenge_type, challenge_data, session):
        return (b'', b'')

    # auth_server
    def on_normal_auth(self, auth_type, peer_auth_data, session):
        pass
    
    # return (challenge_data, verify_aux_data)
    def on_challenge_peer(self, session):
        return (b"challenge_type", b"challenge_data")
    
    # return (auth_data, aux_data)
    def on_need_auth_data(self, session):
        return (b"auth_type", b"auth_data")
    
    def on_verify_challenge(self, reply_data, session):
        return False
    
    def on_check_client_pubkey(self, uuid):
        return False
    
    def on_register_pubkey(self, peer_uuid, pubkey):
        return False
    
    def on_need_session_key(self, key_len):
        return b''
    
    #auth common
    def on_search_session(self, uuid):
        return None
    
    # common
    def on_need_name(self):
        return ''
    
    def on_need_uuid(self):
        return ''

    
class UtransSKCrypto:

    def set_key(self, key):
        return False

    def set_iv(self, iv):
        return False
    
    def mac(self, data):
        return b''
    
    def encrypt(self, plain_data):
        return b''
    
    def decrypt(self, encrypted_data):
        return b''

    
class UtransAKCrypto:

    def set_pubkey(self, key):
        return False

    def set_private_key(self, key):
        return False

    def get_pubkey(self):
        return b''
    
    def get_uuid(self):
        return ''
    
    def decrypt(self, encrypted_data):
        return b''
    
    def encrypt(self, plain_data):
        return b''
    
    def sign(self, data):
        return b''
    
    def verify(self, data):
        return False
   

def main():
    pass
if __name__ == "__main__":
    main()
