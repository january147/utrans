#!/usr/bin/env python
#
# Copyright 2015 clowwindy
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import, division, print_function, \
    with_statement

from ctypes import c_char_p, c_int, c_long, byref,\
    create_string_buffer, c_void_p

from crypto import util

__all__ = ['ciphers']

libcrypto = None
libc = None
loaded = False

buf_size = 2048


def load_libc():
    global libc
    libc = util.find_library(("msvcrt", "c"), "fclose", "libc")
    if libc is None:
        raise Exception("libc not found")
    libc.fopen.restype = c_void_p
    libc.fopen.argtypes = (c_void_p, c_void_p)
    
    libc.fclose.restype = c_int
    libc.fclose.argtypes = (c_void_p, )


def load_openssl():
    global loaded, libcrypto, buf

    libcrypto = util.find_library(('crypto', 'eay32'),
                                  'EVP_get_cipherbyname',
                                  'libcrypto')
    if libcrypto is None:
        raise Exception('libcrypto(OpenSSL) not found')

    libcrypto.EVP_get_cipherbyname.restype = c_void_p
    libcrypto.EVP_CIPHER_CTX_new.restype = c_void_p

    libcrypto.EVP_CipherInit_ex.argtypes = (c_void_p, c_void_p, c_char_p,
                                            c_char_p, c_char_p, c_int)

    libcrypto.EVP_CipherUpdate.argtypes = (c_void_p, c_void_p, c_void_p,
                                           c_char_p, c_int)

    libcrypto.PEM_read_bio_RSA_PUBKEY.restype = c_void_p
    libcrypto.PEM_read_bio_RSA_PUBKEY.argtypes = (c_void_p, c_void_p, c_void_p, c_void_p)

    # RSA *PEM_read_bio_RSAPrivateKey(BIO *bp, RSA **x,
    #                              pem_password_cb *cb, void *u);
    libcrypto.PEM_read_bio_RSAPrivateKey.restype = c_void_p
    libcrypto.PEM_read_bio_RSAPrivateKey.argtypes = (c_void_p, c_void_p, c_void_p, c_void_p)

    libcrypto.RSA_size.restype = c_int
    libcrypto.RSA_size.argtypes = (c_void_p, )

    # void RSA_free(RSA *rsa);
    libcrypto.RSA_free.argtypes = (c_void_p, )

    # int RSA_public_encrypt(int flen, const unsigned char *from,
    #                     unsigned char *to, RSA *rsa, int padding);
    libcrypto.RSA_public_encrypt.restype = c_int
    libcrypto.RSA_public_encrypt.argtypes = (c_int, c_void_p, c_void_p, c_void_p, c_int)

    # int RSA_private_decrypt(int flen, const unsigned char *from,
    #                     unsigned char *to, RSA *rsa, int padding);
    libcrypto.RSA_private_decrypt.restype = c_int
    libcrypto.RSA_private_decrypt.argtypes = (c_int, c_void_p, c_void_p, c_void_p, c_int)

    # BIO *BIO_new_file(const char *filename, const char *mode);
    libcrypto.BIO_new_file.restype = c_void_p
    libcrypto.BIO_new_file.argtypes = (c_void_p, c_void_p)

    #  int BIO_free(BIO *a);
    libcrypto.BIO_free.restype = c_int
    libcrypto.BIO_free.argtypes = (c_void_p, )


    if hasattr(libcrypto, "EVP_CIPHER_CTX_cleanup"):
        libcrypto.EVP_CIPHER_CTX_cleanup.argtypes = (c_void_p,)
    else:
        libcrypto.EVP_CIPHER_CTX_reset.argtypes = (c_void_p,)
    libcrypto.EVP_CIPHER_CTX_free.argtypes = (c_void_p,)

    libcrypto.RAND_bytes.restype = c_int
    libcrypto.RAND_bytes.argtypes = (c_void_p, c_int)

    if hasattr(libcrypto, 'OpenSSL_add_all_ciphers'):
        libcrypto.OpenSSL_add_all_ciphers()

    buf = create_string_buffer(buf_size)
    loaded = True


def load_cipher(cipher_name):
    func_name = 'EVP_' + cipher_name.replace('-', '_')
    cipher = getattr(libcrypto, func_name, None)
    if cipher:
        cipher.restype = c_void_p
        return cipher()
    return None

def rand_bytes(length):
    if not loaded:
        load_openssl()
    buf = create_string_buffer(length)
    r = libcrypto.RAND_bytes(buf, length)
    if r <= 0:
        raise Exception('RAND_bytes return error')
    return buf.raw

class OpenSSLCrypto(object):
    def __init__(self, cipher_name, key, iv, op):
        self._ctx = None
        if not loaded:
            load_openssl()
        cipher = load_cipher(cipher_name)
        if not cipher:
            raise Exception('cipher %s not found in libcrypto' % cipher_name)
        key_ptr = c_char_p(key)
        iv_ptr = c_char_p(iv)
        self._ctx = libcrypto.EVP_CIPHER_CTX_new()
        if not self._ctx:
            raise Exception('can not create cipher context')
        r = libcrypto.EVP_CipherInit_ex(self._ctx, cipher, None,
                                        key_ptr, iv_ptr, c_int(op))
        if not r:
            self.clean()
            raise Exception('can not initialize cipher context')

    def update(self, data):
        global buf_size, buf
        cipher_out_len = c_long(0)
        l = len(data)
        if buf_size < l:
            buf_size = l * 2
            buf = create_string_buffer(buf_size)
        libcrypto.EVP_CipherUpdate(self._ctx, byref(buf),
                                   byref(cipher_out_len), c_char_p(data), l)
        # buf is copied to a str object when we access buf.raw
        return buf.raw[:cipher_out_len.value]

    def __del__(self):
        self.clean()

    def clean(self):
        if self._ctx:
            if hasattr(libcrypto, "EVP_CIPHER_CTX_cleanup"):
                libcrypto.EVP_CIPHER_CTX_cleanup(self._ctx)
            else:
                libcrypto.EVP_CIPHER_CTX_reset(self._ctx)
            libcrypto.EVP_CIPHER_CTX_free(self._ctx)


class RSA():
    PUBKEY = "pubkey"
    PRIVATEKEY = "private_key"

    def __init__(self):
        global loaded
        if not loaded:
            load_openssl()
        self.pubkey = None
        self.private_key = None
        self.key_file = None

    def load_pub_key(self, filename:str):
        self.pubkey_file = filename
        self.pubkey = self.__load_key(filename, RSA.PUBKEY)
        if self.pubkey == None:
            return False
        else:
            return True

    def load_private_key(self, filename:str):
        self.private_key = self.__load_key(filename, RSA.PRIVATEKEY)

    def get_pub_key(self):
        with open(self.pubkey_file, "rb") as f:
            data = f.read()
        return data
    
    def __load_key(self, filename:str, key_type):
        filename = filename.encode(encoding="utf8")
        self.key_file = libcrypto.BIO_new_file(filename, b"rb")
        if self.key_file == None:
            raise Exception("fail to open key file")
        if key_type == RSA.PUBKEY:
            rsa = libcrypto.PEM_read_bio_RSA_PUBKEY(self.key_file, None, None, None)
        else:
            rsa = libcrypto.PEM_read_bio_RSAPrivateKey(self.key_file, None, None, None)
        if rsa == None:
            raise Exception("fail to load key")
        libcrypto.BIO_free(self.key_file)
        self.block_size = libcrypto.RSA_size(rsa)
        self.data_max_len = self.block_size - 11
        return rsa
    
    def encrypt(self, data:bytes):
        if self.pubkey == None and self.private_key == None:
            raise Exception("No key to encrypt, please load key first")
        if len(data) > self.data_max_len:
            raise Exception("Data too long")
        if self.pubkey != None:
            rsa = self.pubkey
        else:
            rsa = self.private_key
        ret = libcrypto.RSA_public_encrypt(len(data), data, byref(buf), rsa, 1)
        encrypt_data = None
        if ret != -1:
            encrypt_data = buf.raw[:ret]
        return encrypt_data
    
    def decrypt(self, data:bytes):
        if self.private_key == None:
            raise Exception("No key to decrypt, please load key first")
        if len(data) != self.block_size:
            raise Exception("Invalid encrypted data")
        rsa = self.private_key
        ret = libcrypto.RSA_private_decrypt(len(data), data, byref(buf), rsa, 1)
        decrypt_data = None
        if ret != -1:
            decrypt_data = buf.raw[:ret]
        return decrypt_data
    
    def clear(self):
        if self.private_key != None:
            libcrypto.RSA_free(self.private_key)
            self.private_key = None
        
        if self.pubkey != None:
            libcrypto.RSA_free(self.pubkey)
            self.pubkey = None
        
    def test(self):

        rsa_pub = self.load_pub_key("key_pub.rsa")
        rsa_private = self.load_private_key("key.rsa")

        data = b"hello, this is a text"
        encrypted_data = self.encrypt(data)
        decrypted_data = self.decrypt(encrypted_data)


        
        

        



ciphers = {
    'aes-128-cbc': (16, 16, OpenSSLCrypto),
    'aes-192-cbc': (24, 16, OpenSSLCrypto),
    'aes-256-cbc': (32, 16, OpenSSLCrypto),
    'aes-128-cfb': (16, 16, OpenSSLCrypto),
    'aes-192-cfb': (24, 16, OpenSSLCrypto),
    'aes-256-cfb': (32, 16, OpenSSLCrypto),
    'aes-128-ofb': (16, 16, OpenSSLCrypto),
    'aes-192-ofb': (24, 16, OpenSSLCrypto),
    'aes-256-ofb': (32, 16, OpenSSLCrypto),
    'aes-128-ctr': (16, 16, OpenSSLCrypto),
    'aes-192-ctr': (24, 16, OpenSSLCrypto),
    'aes-256-ctr': (32, 16, OpenSSLCrypto),
    'aes-128-cfb8': (16, 16, OpenSSLCrypto),
    'aes-192-cfb8': (24, 16, OpenSSLCrypto),
    'aes-256-cfb8': (32, 16, OpenSSLCrypto),
    'aes-128-cfb1': (16, 16, OpenSSLCrypto),
    'aes-192-cfb1': (24, 16, OpenSSLCrypto),
    'aes-256-cfb1': (32, 16, OpenSSLCrypto),
    'bf-cfb': (16, 8, OpenSSLCrypto),
    'camellia-128-cfb': (16, 16, OpenSSLCrypto),
    'camellia-192-cfb': (24, 16, OpenSSLCrypto),
    'camellia-256-cfb': (32, 16, OpenSSLCrypto),
    'cast5-cfb': (16, 8, OpenSSLCrypto),
    'des-cfb': (8, 8, OpenSSLCrypto),
    'idea-cfb': (16, 8, OpenSSLCrypto),
    'rc2-cfb': (16, 8, OpenSSLCrypto),
    'rc4': (16, 0, OpenSSLCrypto),
    'seed-cfb': (16, 16, OpenSSLCrypto),
}


def run_method(method):

    cipher = OpenSSLCrypto(method, b'k' * 32, b'i' * 16, 1)
    decipher = OpenSSLCrypto(method, b'k' * 32, b'i' * 16, 0)

    util.run_cipher(cipher, decipher)


def test_aes_128_cfb():
    run_method('aes-128-cfb')


def test_aes_256_cfb():
    run_method('aes-256-cfb')


def test_aes_128_cfb8():
    run_method('aes-128-cfb8')


def test_aes_256_ofb():
    run_method('aes-256-ofb')


def test_aes_256_ctr():
    run_method('aes-256-ctr')


def test_bf_cfb():
    run_method('bf-cfb')


def test_rc4():
    run_method('rc4')

def test_rsa():
    rsa = RSA()
    rsa.test()

if __name__ == '__main__':
    test_rsa()
    
