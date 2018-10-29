#!/usr/bin/env python3
import sys
import time
import socket
import socketserver
import json
import pickle
import threading
import multiprocessing
from Crypto.Random.random import getrandbits #for nonces
from Crypto import Random #for keys and IVs
from Crypto.Cipher import AES #encryption primitive
from padding import Padder #provides PKCS7 padding

AES_KEY_SIZE = 32
NONCE_SIZE = 128
HOST_A = '127.0.0.1'
HOST_B = '127.0.0.1'
HOST_KS = '127.0.0.1'
PORT_A = 1981
PORT_B = 1970
PORT_KS = 1977

class NS_Client(multiprocessing.Process):
    def __init__(self, h, p, hks, pks, kas, hb, pb, l):
        multiprocessing.Process.__init__(self)
        self.host_a = h
        self.port_a = p
        self.host_ks = hks
        self.port_ks = pks
        self.key_AS = kas
        self.host_b = hb
        self.port_b = pb
        self.loops = l
        self.start_time = 0
        self.socket_a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket_a.bind((self.host_a, self.port_a))
    #end def __init__()

    def run(self):
        Random.atfork()
        self.start_time = time.process_time()
        for i in range(self.loops):
            self.ns_client()
        print(json.dumps(['ns-sk', 'RoleA', self.start_time, time.process_time(), self.loops]))
        self.socket_a.close()
    #end run()
        
    def ns_client(self):
        #print('NS_Client: Initating NS-SK protocol.')
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
        #print('M2:', m2)
        if m2[0] != nonce_a:
            print('NS_Client: Protocol Failure: Nonce returned by key server does not match.')
            return
        if m2[2] != ('B', self.host_b, self.port_b):
            print('NS_Client: Protocol Failure: Remote client identity returned by key server does not match.')
            return
        key_AB = m2[1]
        #Send M3
        self.socket_a.sendto(b'm3' + m2[3], (self.host_b, self.port_b))
        m4_raw, recv_address = self.socket_a.recvfrom(4096)
        if m4_raw[:2] != b'm4':
            print('NS_Client: Protocol Failure: Client does not recognize message:', m4_raw)
            return
        #Receive M4
        m4_enc = m4_raw[2:]
        cipher_AB = AES.new(key_AB, AES.MODE_CBC, m4_enc[:AES.block_size])
        m4 = pickle.loads(Padder().pkcs7_unpad(cipher_AB.decrypt(m4_enc[AES.block_size:]), AES.block_size))
        #print('M4:', m4)
        nonce_ab = m4 - 1
        IV_AB = Random.new().read(AES.block_size)
        cipher_AB = AES.new(key_AB, AES.MODE_CBC, IV_AB)
        #Send M5
        self.socket_a.sendto(b'm5' + IV_AB + cipher_AB.encrypt(
            Padder().pkcs7_pad(pickle.dumps(nonce_ab), AES.block_size)), recv_address)
        #print('NS_Client: Finished NS-SK protocol')
        return
    #end def ns_initiate()
#end class NS_Client

class NS_Recv(multiprocessing.Process):
    def __init__(self, h, p, kbs, l):
        multiprocessing.Process.__init__(self)
        self.host_b = h
        self.port_b = p
        self.key_BS = kbs
        self.loops = l
        self.start_time = 0
    #end __init__()

    def run(self):
        self.socket_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket_b.bind((self.host_b, self.port_b))
        Random.atfork()
        threads = []
        #print('Starting NS_Recv')
        #Receive M3
        self.start_time = time.process_time()
        for i in range(self.loops):
            m3_raw = self.socket_b.recv(4096)
            threads.append(threading.Thread(target = self.ns_recv, args=(m3_raw,)))
            threads[-1].start()
        threads[-1].join()
        print(json.dumps(['ns-sk', 'RoleB', self.start_time, time.process_time(), self.loops]))
        self.socket_b.close()
    #end run()

    def ns_recv(self, m3_raw):
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        #Check tag on incoming message
        if m3_raw[:2] != b'm3':
            print('NS_Recv: M3: Protocol Failure: Receiver does not recognize message:', m3_raw)
            return
        cipher_BS = AES.new(self.key_BS, AES.MODE_CBC, m3_raw[2:(AES.block_size + 2)])
        m3 = pickle.loads(Padder().pkcs7_unpad(cipher_BS.decrypt(m3_raw[(AES.block_size + 2):]), AES.block_size))
        #print('M3:', m3) 
        key_AB = m3[0]
        nonce_b = getrandbits(NONCE_SIZE)
        IV_AB = Random.new().read(AES.block_size)
        cipher_AB = AES.new(key_AB, AES.MODE_CBC, IV_AB)
        #send M4
        recv_socket.sendto(b'm4' + IV_AB + cipher_AB.encrypt(
            Padder().pkcs7_pad(pickle.dumps(nonce_b), AES.block_size)), (m3[1][1], m3[1][2]))
        #Receive M5
        m5_raw = recv_socket.recv(4096)
        if m5_raw[:2] != b'm5':
            print('NS_Recv: M5: Protocol Failure: Receiver does not recognize message:', m5_raw)
            return
        cipher_AB = AES.new(key_AB, AES.MODE_CBC, m5_raw[2:(AES.block_size + 2)])
        m5 = pickle.loads(Padder().pkcs7_unpad(cipher_AB.decrypt(m5_raw[(AES.block_size + 2):]), AES.block_size))
        if m5 != (nonce_b - 1):
            print('NS_Recv_Handler: Protocol Failure: Decremented nonce returned by',
                  'initiating client does not match.')
            return
        #print('M5:', m5)
        #print('NS_Recv_Handler: Protocol Success: Key exchange complete.')
        recv_socket.close()
    #end ns_recv()
#end class NS_Recv

class NS_KS_Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.counter += 1
        #Check tag on incoming message
        if self.request[0][:2] != b'm1':
            print('NS_KS_Handler: Protocol Failure: Key server does not recognize message:', self.request[0])
            return
        #Receive M1
        m1 = pickle.loads(self.request[0][2:])
        #print('M1:', m1)
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
        if self.server.counter == self.server.loops:
            print(json.dumps(['ns-sk', 'RoleS', self.server.start_time,
                              time.process_time(), self.server.loops]))            
    #end def handle()
#end class NS_KS_Handler
    
class NS_KS(socketserver.ThreadingUDPServer):
    def __init__(self, h, p, kas, kbs, l):
        socketserver.ThreadingUDPServer.__init__(self, (h, p), NS_KS_Handler)
        self.host_ks = h
        self.port_ks = p
        self.key_AS = kas
        self.key_BS = kbs
        self.loops = l
        self.counter = 0
        self.thread_ks = threading.Thread(target=self.serve_forever)
        self.start_time = 0
        #self.thread_ks.daemon = True
    #end def __init__()

    def begin(self):
        Random.atfork()
        #print('Starting NS_KeyServer')
        self.start_time = time.process_time()
        self.thread_ks.start()
    #end def begin()

    def finish(self):
        self.shutdown()
        self.server_close()
        #print('Closed NS_KeyServer')
    #end finish()

def main():
    loops = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    key_AS = Random.new().read(AES_KEY_SIZE)
    key_BS = Random.new().read(AES_KEY_SIZE)
    ns_ks = NS_KS(HOST_KS, PORT_KS, key_AS, key_BS, loops)
    ns_b = NS_Recv(HOST_B, PORT_B, key_BS, loops)
    ns_a = NS_Client(HOST_A, PORT_A, HOST_KS, PORT_KS, key_AS, HOST_B, PORT_B, loops)
    ns_ks.begin()
    ns_b.start()
    ns_a.start()
    ns_a.join()
    ns_b.join()
    ns_ks.finish()

if __name__ == "__main__":
    main()
