#!/usr/bin/env python3
import sys
import socket
import socketserver
import pickle
import threading
import multiprocessing

from padding import Padder #provides PKCS7 padding
from Crypto.Random.random import getrandbits #for nonces
from Crypto import Random #for keys and IVs
from Crypto.Cipher import AES #encryption primitive

AES_KEY_SIZE = 16
NONCE_SIZE = 128
HOST_A = '127.0.0.1'
HOST_B = '127.0.0.1'
HOST_KS = '127.0.0.1'
PORT_A = 1981
PORT_B = 1970
PORT_KS = 1977

class NS_Client(multiprocessing.Process):
    def __init__(self, h, p, hks, pks, kas, hb, pb):
        self.host_a = h
        self.port_a = p
        self.host_ks = hks
        self.port_ks = pks
        self.key_AS = kas
        self.host_b = hb
        self.port_b = pb
        self.socket_a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket_a.bind((self.host_a, self.port_a))
    #end def __init__()

    def begin(self):
        print('NS_Client: Initating NS-SK protocol.')
        nonce_a = getrandbits(NONCE_SIZE)
        #Send M1
        self.socket_a.sendto(b'm1' + pickle.dumps([('A', self.host_a, self.port_a),
                                           ('B', self.host_b, self.port_b), nonce_a]),
                             (self.host_ks, self.port_ks))
        #Receive M2
        m2_raw = self.socket_a.recv(4096)
        if m2_raw[:2] != b'm2':
            print('NS_Client: Protocol Failure: Client does not recognize message:', m2_raw)
            return
        m2_enc = m2_raw[2:]
        cipher_AS = AES.new(self.key_AS, AES.MODE_CBC, m2_enc[:AES.block_size])
        m2 = pickle.loads(Padder().pkcs7_unpad(cipher_AS.decrypt(m2_enc[AES.block_size:]), AES.block_size))
        print('M2:', m2)
        if m2[0] != nonce_a:
            print('NS_Client: Protocol Failure: Nonce returned by key server does not match.')
            return
        if m2[2] != ('B', self.host_b, self.port_b):
            print('NS_Client: Protocol Failure: Remote client identity returned by key server does not match.')
            return
        key_AB = m2[1]
        #Send M3
        self.socket_a.sendto(b'm3' + m2[3], (self.host_b, self.port_b))
        m4_raw = self.socket_a.recv(4096)
        if m4_raw[:2] != b'm4':
            print('NS_Client: Protocol Failure: Client does not recognize message:', m4_raw)
            return
        #Receive M4
        m4_enc = m4_raw[2:]
        cipher_AB = AES.new(key_AB, AES.MODE_CBC, m4_enc[:AES.block_size])
        m4 = pickle.loads(Padder().pkcs7_unpad(cipher_AB.decrypt(m4_enc[AES.block_size:]), AES.block_size))
        print('M4:', m4)
        nonce_ab = m4 - 1
        IV_AB = Random.new().read(AES.block_size)
        cipher_AB = AES.new(key_AB, AES.MODE_CBC, IV_AB)
        #Send M5
        self.socket_a.sendto(b'm5' + IV_AB + cipher_AB.encrypt(
            Padder().pkcs7_pad(pickle.dumps(nonce_ab), AES.block_size)), (self.host_b, self.port_b))
        print('NS_Client: Finished NS-SK protocol')
        self.socket_a.close()
    #end def ns_initiate()
#end class NS_Client

def main():
    with open('AS.keyfile', 'rb') as f:
        key_AS = pickle.load(f)
    ns_a = NS_Client(HOST_A, PORT_A, HOST_KS, PORT_KS, key_AS, HOST_B, PORT_B)
    ns_a.begin()

if __name__ == "__main__":
    main()
