```python
    Message.MT_SEND_FILE : ("msg_type", "name", "size"),
    Message.MT_SEND_MSG : ("msg_type", "size", "encode", "data"),
    Message.MT_COM_REPLY : ("msg_type", "status", "info"),
    Message.MT_AUTH_INIT : ("msg_type", "name", "uuid", "fast_auth", "auth_data", "ip", "port"),
    Message.MT_AUTH_FINISH : ("msg_type", "name", "uuid", "auth_data", "status"),
    Message.MT_AUTH_REQ_PUBKEY : ("msg_type"),
    Message.MT_AUTH_PUBKEY_REPLY : ("msg_type", "key_type", "encode", "data", "status"),
    Message.MT_AUTH_CLG : ("msg_type", "challenge_type", "encode", "data"),
    Message.MT_AUTH_CLG_REPLY : ("msg_type", "encode", "data", "status"),
    Message.MT_SCAN_REQ : ("msg_type"),
    Message.MT_SCAN_REPLY : ("msg_type", "name", "ip", "port")
```