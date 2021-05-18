#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Date: Sun Mar  8 17:33:09 2020
# Author: January

from termcolor import colored

#decorators
def deprecatedBy(replace_func):
    def deprecated_deco(func):
        def wrapper(*args, **kwargs):
            text = "[Warning]%s is deprecated, consider use %s instead"%(func.__name__, replace_func.__name__)
            print(colored(text, "yellow"))
            return func(*args, **kwargs)
        return wrapper
    return deprecated_deco

def deprecated(func):
    def wrapper(*args, **kwargs):
        text = "[Warning]%s is deprecated"%(func.__name__)
        print(colored(text, "red"))
        return func(*args, **kwargs)
    return wrapper


def calculate_num_byte_size(num):
    size = 1
    num >>= 8
    while num != 0:
        num >>= 8
        size += 1
    return size
#
def pack_bytes(bytes_list):
    packed_bytes = b""
    for item in bytes_list:
        item_len = len(item)
        if item_len <= 128:
            size_field = item_len.to_bytes(1, "little")
        else:
            item_len_bytes_size = calculate_num_byte_size(item_len)
            len_byte = (128 + item_len_bytes_size).to_bytes(1, "little")
            len_bytes = item_len.to_bytes(item_len_bytes_size, "little")
            size_field = len_byte + len_bytes
        packed_bytes = packed_bytes + size_field + item
    return packed_bytes

def unpack_bytes(packed_bytes):
    bytes_list = []
    p = 0
    while p < len(packed_bytes):
        field_len = packed_bytes[p]
        p += 1
        if field_len <= 128:
            item_end = p + field_len
            item = packed_bytes[p : item_end]
        else:
            len_bytes_size = field_len - 128
            len_bytes = packed_bytes[p : p + len_bytes_size]
            p += len_bytes_size
            field_len = int.from_bytes(len_bytes, byteorder="little")
            item_end = p + field_len
            item = packed_bytes[p : item_end]
        bytes_list.append(item)
        p = item_end
    return bytes_list



if __name__ == "__main__":
    main()



