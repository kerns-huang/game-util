#!/usr/bin/env python
# -*- encoding: utf-8 -*-
import base64

import binascii

import chardet
import dpkt
import scapy
from Crypto.Cipher import AES
from scapy.all import *
from scapy.utils import PcapReader, PcapWriter

def _pad(s):
    return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)
def _cipher():
    key = '7854156156611111'
    iv = '1234abcdefgh6789'
    return AES.new(key=key, mode=AES.MODE_CBC, IV=iv)
def encrypt_token(data):
    return _cipher().encrypt(_pad(data))
def decrypt_token(data):
    return _cipher().decrypt(data)
def dataHandle(headPack, body):
    global sn
    sn += 1
    print("第%s个数据包" % sn)
    print("ver:%s, bodySize:%s, cmd:%s" % headPack)
    print(body.decode())
    print("")
if __name__ == '__main__':
    print('Python encrypt: ' + base64.b64encode(encrypt_token('test')))
    print('Python encrypt: ' + decrypt_token(base64.b64decode("FVcqQXjtqEdOIhO8UMdnQA==")))
    f = file("data.pcap")
    dataBuffer = bytes()
    headerSize = 12
    pcap = dpkt.pcap.Reader(f)
    type = sys.getfilesystemencoding()
    for ptime, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        # struct中:!代表Network order，3I代表3个unsigned int数据
        dataBuffer += eth.data.data.data
        headPack = struct.unpack('!3I', dataBuffer[:headerSize])
        bodySize = headPack[1]
        if len(dataBuffer) < headerSize + bodySize:
            print("数据包（%s Byte）不完整（总共%s Byte），跳出小循环" % (len(dataBuffer), headerSize + bodySize))
            break
        body = dataBuffer[headerSize:headerSize + bodySize]
        dataHandle(headPack, body)
        # 粘包情况的处理
        dataBuffer = dataBuffer[headerSize + bodySize:]
        #print eth.data.data.data