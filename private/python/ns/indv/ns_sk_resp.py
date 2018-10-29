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

class NS_Recv(multiprocessing.Process):

    def __init__(self, h, p, kbs):
        self.host_b = h
        self.port_b = p
        self.key_BS = kbs
        self.socket_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket_b.bind((self.host_b, self.port_b))
    #end __init__()

    def begin(self):
        print('Starting NS_Recv')
        #Receive M3
        m3_raw = self.socket_b.recv(4096)
        #Check tag on incoming message
        if m3_raw[:2] != b'm3':
            print('NS_Recv: Protocol Failure: Receiver does not recognize message:', m3_raw)
            return
        cipher_BS = AES.new(self.key_BS, AES.MODE_CBC, m3_raw[2:(AES.block_size + 2)])
        m3 = pickle.loads(Padder().pkcs7_unpad(cipher_BS.decrypt(m3_raw[(AES.block_size + 2):]), AES.block_size))
        print('M3:', m3) 
        key_AB = m3[0]
        nonce_b = getrandbits(NONCE_SIZE)
        IV_AB = Random.new().read(AES.block_size)
        cipher_AB = AES.new(key_AB, AES.MODE_CBC, IV_AB)
        #send M4
        self.socket_b.sendto(b'm4' + IV_AB + cipher_AB.encrypt(
            Padder().pkcs7_pad(pickle.dumps(nonce_b), AES.block_size)), (m3[1][1], m3[1][2]))
        #Receive M5
        m5_raw = self.socket_b.recv(4096)
        if m5_raw[:2] != b'm5':
            print('NS_Recv: Protocol Failure: Receiver does not recognize message:', m5_raw)
            return
        cipher_AB = AES.new(key_AB, AES.MODE_CBC, m5_raw[2:(AES.block_size + 2)])
        m5 = pickle.loads(Padder().pkcs7_unpad(cipher_AB.decrypt(m5_raw[(AES.block_size + 2):]), AES.block_size))
        if m5 != (nonce_b - 1):
            print('NS_Recv_Handler: Protocol Failure: Decremented nonce returned by',
                  'initiating client does not match.')
            return
        print('M5:', m5)
        print('NS_Recv_Handler: Protocol Success: Key exchange complete.')
        self.socket_b.close()
    #end receive()

def main():
    with open('BS.keyfile', 'rb') as f:
        key_BS = pickle.load(f)
    ns_b = NS_Recv(HOST_B, PORT_B, key_BS)
    ns_b.begin()
if __name__ == "__main__":
    main()
