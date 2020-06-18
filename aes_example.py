#!/usr/bin/env python
# -*- coding: utf-8 -*-

# python -m pip install pycrypto

"""
@version: v1.0
@author: erdao
@contact:
@software:  VSCode
@file: Json_Plaintext.py
@time: 2019/12/11 14:35
@describe: 加密与解密
"""

import sys
import json
import base64
import random
from Crypto.Cipher import AES

#####################################################################

#
AES128_key = '48484848484848484848484848484848'


#####################################################################


class AESEncrypter(object):
    def __init__(self, key, iv=None):
        self.key = key
        self.iv = iv if iv else bytes(key[0:16], 'utf-8')

    def _pad(self, text):
        text_length = len(text)
        padding_len = AES.block_size - int(text_length % AES.block_size)
        if padding_len == 0:
            padding_len = AES.block_size
        t2 = chr(padding_len) * padding_len
        t2 = t2.encode('utf-8')
        # print('text ', type(text), text)
        # print('t2 ', type(t2), t2)
        t3 = text + t2
        return t3

    def _unpad(self, text):
        text_length = len(text)
        padding_len = int(text_length % AES.block_size)
        if padding_len != 0:
            pad = ord(text[-1])
            return text[:-pad]
        else:
            return text

    def _decode_base64(self, data):
        """
        Decode base64, padding being optional.
        :param data: Base64 data as an ASCII byte string
        :returns: The decoded byte string.
        """
        missing_padding = len(data) % 4
        if missing_padding != 0:
            data += b'=' * (4 - missing_padding)
        return base64.b64decode(data)

    def encrypt(self, raw):
        raw = raw.encode('utf-8')
        raw = self._pad(raw)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        encrypted = cipher.encrypt(raw)
        return base64.b64encode(encrypted).decode('utf-8')

    def decrypt(self, enc):
        enc = enc.encode("utf-8")
        enc = base64.b64decode(enc)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        decrypted = cipher.decrypt(enc)
        decrypted = self._unpad(decrypted.decode('utf-8'))
        decrypted = self._decode_base64(decrypted.encode('utf-8')).decode('utf-8')
        return decrypted


def JsonToPlaintext(esp8266_json):
    try:
        esp8266_data = json.loads(esp8266_json)
    except Exception as e:
        print('Json，data:{},error：{}'.format(esp8266_data, e))
        return
    iv = base64.b64decode(esp8266_data['iv'])  # base64
    cipher = AESEncrypter(bytes.fromhex(AES128_key), iv)
    return cipher.decrypt(esp8266_data['msg'])


def PlaintextToJson(Plaintext):
    esp8266_iv = ''
    for i in range(32):
        esp8266_iv += (random.choice('0123456789abcdef'))
        # esp8266_iv = '00000000000000000000000000000000'
    iv = bytes.fromhex(esp8266_iv)
    esp8266_iv = str(base64.b64encode(iv), 'utf-8')
    b64msg = base64.b64encode(Plaintext.encode('utf-8')).decode('utf-8')
    print('b64msg: %s' % b64msg)
    cipher = AESEncrypter(bytes.fromhex(AES128_key), iv)
    encrypted = cipher.encrypt(b64msg)
    # print('Encrypted: %s' % encrypted)
    esp8266_send_json = {"iv": "%s" % esp8266_iv, "msg": "%s" % encrypted}
    return json.dumps(esp8266_send_json)


def print_hex(bytes):
    l = [hex(int(i)) for i in bytes]
    print(" ".join(l))


if __name__ == "__main__":
    try:
        # for AES test

        print('decrypt：')
        esp8266_data = '{"iv":"E9Mhq/WDtSZkrfGhHDJSRg==","msg":"XHao0wiSLEwegeKIIfmd6YprWYn4tAKjBHE3zKM9P9I="}'
        print('data: %s' % esp8266_data)
        print('Decrypted: %s' % JsonToPlaintext(esp8266_data))

        #####################################################################

        print('encrypt：')
        msg = 'Hello Word Hello Word'
        print('esp8266 json: %s' % PlaintextToJson(msg))

    #####################################################################

    except KeyboardInterrupt:
        sys.exit(0)
