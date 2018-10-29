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

class NS_KS_Handler(socketserver.BaseRequestHandler):

    def handle(self):
        #Check tag on incoming message
        if self.request[0][:2] != b'm1':
            print('NS_KS_Handler: Protocol Failure: Key server does not recognize message:', self.request[0])
            return
        #Receive M1
        m1 = pickle.loads(self.request[0][2:])
        print('M1:', m1)
        session_key = Random.new().read(AES_KEY_SIZE)
        IV_BS = Random.new().read(AES.block_size)
        cipher_BS = AES.new(self.server.key_BS, AES.MODE_CBC, IV_BS)
        pkg_B = IV_BS + cipher_BS.encrypt(Padder().pkcs7_pad(
            pickle.dumps([session_key, m1[0]]), AES.block_size))
        IV_AS = Random.new().read(AES.block_size)
        cipher_AS = AES.new(self.server.key_AS, AES.MODE_CBC, IV_AS)
        pkg_A = IV_AS + cipher_AS.encrypt(Padder().pkcs7_pad(
            pickle.dumps([m1[2], session_key, m1[1], pkg_B]), AES.block_size))
        #Send M2
        self.request[1].sendto(b'm2' + pkg_A, self.client_address)
        self.server.finish()
    #end def handle()
#end class NS_KS_Handler
    
class NS_KS(socketserver.ThreadingUDPServer):
    def __init__(self, h, p, kas, kbs):
        socketserver.ThreadingUDPServer.__init__(self, (h, p), NS_KS_Handler)
        self.host_ks = h
        self.port_ks = p
        self.key_AS = kas
        self.key_BS = kbs
        self.thread_ks = threading.Thread(target=self.serve_forever)
        self.thread_ks.daemon = False
    #end def __init__()

    def begin(self):
        Random.atfork()
        print('Starting NS_KeyServer')
        self.thread_ks.start()
    #end def begin()

    def finish(self):
        self.shutdown()
        self.server_close()
        print('Closed NS_KeyServer')
    #end finish()

def main():
    key_AS = Random.new().read(AES_KEY_SIZE)
    key_BS = Random.new().read(AES_KEY_SIZE)
    with open('AS.keyfile', 'wb') as f:
        pickle.dump(key_AS, f)
    with open('BS.keyfile', 'wb') as f:
        pickle.dump(key_BS, f)
    ns_ks = NS_KS(HOST_KS, PORT_KS, key_AS, key_BS)
    ns_ks.begin()

if __name__ == "__main__":
    main()
