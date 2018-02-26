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
        self.pid_a = ("A", self.host_a, self.port_a)
        self.host_ks = hks
        self.port_ks = pks
        self.pid_ks = ("KS", self.host_ks, self.port_ks)
        self.key_AS = kas
        self.host_b = hb
        self.port_b = pb
        self.pid_b = ("B", self.host_b, self.port_b)
        self.loops = l
        self.start_time = 0
        self.socket_a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket_a.bind((self.host_a, self.port_a))
    # end def __init__()

    def run(self):
        Random.atfork()
        #self.start_time = time.process_time()
        for i in range(self.loops):
            self.ns_client()
        #print(json.dumps(['ns-sk', 'RoleA', self.start_time, time.process_time(), self.loops]))
        self.socket_a.close()
    # end run()
        
    def ns_client(self):
        #print('NS_Client: Initating NS-SK protocol.')
        # Send M1: A -> B : A
        self.socket_a.sendto(b'm1' + pickle.dumps(self.pid_a), (self.host_b, self.port_b))

        # Receive M2: B -> A : {A, N1_B}_K_BS
        m2_raw, recv_address = self.socket_a.recvfrom(4096)
        if m2_raw[:2] != b'm2':
            print('NS_Client: Protocol Failure: M2: Client does not recognize message:\n', m2_raw)
            return
        
        nonce_a = getrandbits(NONCE_SIZE)
        # Send M3: A -> KS : A, B, N_A, {A, N1_B}_K_BS
        self.socket_a.sendto(b'm3' + pickle.dumps([self.pid_a, self.pid_b, nonce_a, m2_raw[2:]]),
                             (self.host_ks, self.port_ks))

        # Receive M4: KS -> A : {N_A, K_AB, B, {K_AB, N1_B, A}_K_BS}_K_AS
        m4_raw = self.socket_a.recv(4096)
        if m4_raw[:2] != b'm4':
            print('NS_Client: Protocol Failure: Client does not recognize message:', m4_raw)
            return

        m4_enc = m4_raw[2:]
        cipher_AS = AES.new(self.key_AS, AES.MODE_CBC, m4_enc[:AES.block_size])

        m4 = pickle.loads(Padder().pkcs7_unpad(cipher_AS.decrypt(m4_enc[AES.block_size:]), AES.block_size))
        # print('M4:', m4)

        if m4[0] != nonce_a:
            print('NS_Client: Protocol Failure: Nonce returned by key server does not match.')
            return

        if m4[2] != ('B', self.host_b, self.port_b):
            print('NS_Client: Protocol Failure: Remote client identity returned by key server does not match.')
            return

        key_AB = m4[1]

        # Send M5: A -> B : {K_AB, N1_B, A}_K_BS
        self.socket_a.sendto(b'm5' + m4[3], recv_address)

        # Receive M6: B -> A : {N2_B}_K_AB
        m6_raw = self.socket_a.recv(4096)
        if m6_raw[:2] != b'm6':
            print('NS_Client: Protocol Failure: Client does not recognize message:', m4_raw)
            return
        
        m6_enc = m6_raw[2:]
        cipher_AB = AES.new(key_AB, AES.MODE_CBC, m6_enc[:AES.block_size])

        m6 = pickle.loads(Padder().pkcs7_unpad(cipher_AB.decrypt(m6_enc[AES.block_size:]), AES.block_size))
        # print('M6:', m4)

        # Send M7: A -> B : {(N2_B - 1)}_K_AB
        nonce_ab = m6 - 1
        IV_AB = Random.new().read(AES.block_size)
        cipher_AB = AES.new(key_AB, AES.MODE_CBC, IV_AB)
        
        self.socket_a.sendto(b'm7' + IV_AB + cipher_AB.encrypt(
            Padder().pkcs7_pad(pickle.dumps(nonce_ab), AES.block_size)), recv_address)

        # print('NS_Client: Finished NS-SK protocol')
    # end def ns_initiate()
# end class NS_Client

class NS_Recv(multiprocessing.Process):
    def __init__(self, h, p, kbs, l):
        multiprocessing.Process.__init__(self)
        self.host_b = h
        self.port_b = p
        self.pid_b = ("B", self.host_b, self.port_b)
        self.key_BS = kbs
        self.loops = l
        #self.start_time = 0
    # end __init__()

    def run(self):
        self.socket_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket_b.bind((self.host_b, self.port_b))
        Random.atfork()
        threads = []
        # print('Starting NS_Recv')
        # Receive M1, pass to thread to run protocol with current client
        #self.start_time = time.process_time()
        for i in range(self.loops):
            m1_raw, client_address = self.socket_b.recvfrom(4096)
            threads.append(threading.Thread(target = self.ns_recv, args=(m1_raw, client_address, i)))
            threads[-1].start()
        threads[-1].join()
        self.socket_b.close()
    # end run()

    def ns_recv(self, m1_raw, client_address, counter):
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Handle M1: A -> B : A
        # Check tag on incoming message
        if m1_raw[:2] != b'm1':
            print('NS_Recv: Protocol Failure: M1: Receiver does not recognize message:', m1_raw)
            return

        # Get A's process id out of M1
        pid_a = pickle.loads(m1_raw[2:])

        # Send M2: B -> A : {A, N1_B}_K_BS
        nonce_b1 = getrandbits(NONCE_SIZE)
        IV_BS = Random.new().read(AES.block_size)
        cipher_BS = AES.new(self.key_BS, AES.MODE_CBC, IV_BS)
        recv_socket.sendto(b'm2' + IV_BS + cipher_BS.encrypt(
            Padder().pkcs7_pad(pickle.dumps([pid_a, nonce_b1]), AES.block_size)), client_address)

        # Receive M5: A -> B : {K_AB, N1_B, A}_K_BS
        m5_raw = recv_socket.recv(4096)
        cipher_BS = AES.new(self.key_BS, AES.MODE_CBC, m5_raw[2:(AES.block_size + 2)])
        m5 = pickle.loads(Padder().pkcs7_unpad(cipher_BS.decrypt(m5_raw[(AES.block_size + 2):]), AES.block_size))
        if m5[1] != nonce_b1:
            print('NS_Recv: M5: Protocol Failure: Nonce returned by keyserver does not match',
                  'nonce sent by receiver; possible replay attack.')
            return
        if m5[2] != pid_a:
            print('NS_Recv: M5: Protocol Failure: Process id of client does not match that of the',
                  'client process id returned from the server.')
            return
        key_AB = m5[0]
        # print('M5:', m5)        

        # send M6: B -> A : {N2_B}_K_AB
        nonce_b2 = getrandbits(NONCE_SIZE)
        IV_AB = Random.new().read(AES.block_size)
        cipher_AB = AES.new(key_AB, AES.MODE_CBC, IV_AB)
        recv_socket.sendto(b'm6' + IV_AB + cipher_AB.encrypt(
            Padder().pkcs7_pad(pickle.dumps(nonce_b2), AES.block_size)), client_address)

        # Receive M7
        m7_raw = recv_socket.recv(4096)
        if m7_raw[:2] != b'm7':
            print('NS_Recv: Protocol Failure: M7: Receiver does not recognize message:', m7_raw)
            return
        cipher_AB = AES.new(key_AB, AES.MODE_CBC, m7_raw[2:(AES.block_size + 2)])
        m7 = pickle.loads(Padder().pkcs7_unpad(cipher_AB.decrypt(m7_raw[(AES.block_size + 2):]), AES.block_size))
        if m7 != (nonce_b2 - 1):
            print('NS_Recv_Handler: Protocol Failure: M7: Decremented nonce returned by',
                  'initiating client does not match.')
            return
        # print('M7:', m7)
        #if counter + 1 == self.loops:
        #    print(json.dumps(['ns-sk', 'RoleB', self.start_time, time.process_time(), self.loops]))
        #print('NS_Recv_Handler: Protocol Success: Key exchange complete.')
        recv_socket.close()
    # end ns_recv()
# end class NS_Recv

class NS_KS_Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.counter += 1
        # Receive M3
        # Check tag on incoming message
        if self.request[0][:2] != b'm3':
            print('NS_KS_Handler: Protocol Failure: M3: Key server does not recognize message:', self.request[0])
            return
        m3 = pickle.loads(self.request[0][2:])
        # print('M3:', m1)
        # Decrypt package from receiver, check client process id
        cipher_BS = AES.new(self.server.key_BS, AES.MODE_CBC, m3[3][:AES.block_size])
        pid_a, N1_b = pickle.loads(Padder().pkcs7_unpad(cipher_BS.decrypt(m3[3][AES.block_size:]), AES.block_size))
        if m3[0] != pid_a:
            print("NS_KS_HANDLER: Protocol Failure: M3: Client process id provided by client",
                  "does not match client process id provided by receiver.")
            return
        # Generate fresh session key to distribute to client and receiver
        session_key = Random.new().read(AES_KEY_SIZE)

        # Encrypt package for receiver, including nonce it sent
        IV_BS = Random.new().read(AES.block_size)
        cipher_BS = AES.new(self.server.key_BS, AES.MODE_CBC, IV_BS)
        pkg_B = IV_BS + cipher_BS.encrypt(Padder().pkcs7_pad(
            pickle.dumps([session_key, N1_b, pid_a]), AES.block_size))

        # Encrypt message for client
        IV_AS = Random.new().read(AES.block_size)
        cipher_AS = AES.new(self.server.key_AS, AES.MODE_CBC, IV_AS)
        pkg_A = IV_AS + cipher_AS.encrypt(Padder().pkcs7_pad(
            pickle.dumps([m3[2], session_key, m3[1], pkg_B]), AES.block_size))
        
        #Send M4: S -> A : {Na, B, K_AB, {K_AB, N1_b, A}_K_BS}_K_AS
        self.request[1].sendto(b'm4' + pkg_A, self.client_address)
        #if self.server.counter == self.server.loops:
        #    print(json.dumps(['ns-sk', 'RoleS', self.server.start_time,
        #                      time.process_time(), self.server.loops]))            
    #end def handle()
#end class NS_KS_Handler
    
class NS_KS(socketserver.ThreadingUDPServer):
    def __init__(self, h, p, kas, kbs, l):
        socketserver.ThreadingUDPServer.__init__(self, (h, p), NS_KS_Handler)
        self.host_ks = h
        self.port_ks = p
        self.pid_ks = ("S", self.host_ks, self.port_ks)
        self.key_AS = kas
        self.key_BS = kbs
        self.loops = l
        self.counter = 0
        self.thread_ks = threading.Thread(target=self.serve_forever)
        #self.start_time = 0
        #self.thread_ks.daemon = True
    #end def __init__()

    def begin(self):
        Random.atfork()
        #print('Starting NS_KeyServer')
        #self.start_time = time.process_time()
        self.thread_ks.start()
    #end def begin()

    def finish(self):
        self.shutdown()
        self.server_close()
        #print('Closed NS_KeyServer')
    #end finish()

def main():
    loops = int(sys.argv[1]) if len(sys.argv) > 1 else 1
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
