

import sys
import time
import socket
import socketserver
import json
import pickle
import threading
import multiprocessing
import gc
from sa.secalgoB import *
from sa.timers import dec_proto_run_timer

HOST_A = '127.0.0.1'
HOST_B = '127.0.0.1'
HOST_KS = '127.0.0.1'
PORT_A = 1981
PORT_B = 1970
PORT_KS = 1977

class NS_Client(multiprocessing.Process):
    def __init__(self, h, p, hks, pks, kas, hb, pb):
        gc.disable()
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
        self.socket_a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket_a.bind((self.host_a, self.port_a))
    # end def __init__()
    
    def run(self):
        at_fork()
        self.ns_client()
        self.socket_a.close()
    # end run()

    @dec_proto_run_timer
    def ns_client(self):
        #print('NS_Client: Initating NS-SK protocol.')
        # Send M1: A -> B : A
        self.socket_a.sendto(b'm1' + pickle.dumps(self.pid_a),
                             (self.host_b, self.port_b))

        # Receive M2: B -> A : {A, N1_B}_K_BS
        m2_raw, recv_address = self.socket_a.recvfrom(4096)
        if m2_raw[:2] != b'm2':
            print('NS_Client: Protocol Failure: M2: Client does not' +
                  ' recognize message:\n', m2_raw)
            return
        #print('M2:', m2_raw)
        
        nonce_a = nonce()
        # Send M3: A -> KS : A, B, N_A, {A, N1_B}_K_BS
        self.socket_a.sendto(b'm3' +
                             pickle.dumps([self.pid_a,self.pid_b,
                                           nonce_a, m2_raw[2:]]),
                             (self.host_ks, self.port_ks))

        # Receive M4: KS -> A : {N_A, K_AB, B, {K_AB, N1_B, A}_K_BS}_K_AS
        m4_raw = self.socket_a.recv(4096)
        if m4_raw[:2] != b'm4':
            print('NS_Client: Protocol Failure: Client does not recognize' +
                  ' message:', m4_raw)
            return

        m4_enc = m4_raw[2:]
        m4 = decrypt(m4_enc, key = self.key_AS)
        #print('M4:', m4)

        if m4[0] != nonce_a:
            print('NS_Client: Protocol Failure: Nonce returned by key' +
                  ' server does not match.')
            return

        if m4[2] != ('B', self.host_b, self.port_b):
            print('NS_Client: Protocol Failure: Remote client identity' +
                  ' returned by key server does not match.')
            return

        key_AB = m4[1]

        # Send M5: A -> B : {K_AB, N1_B, A}_K_BS
        self.socket_a.sendto(b'm5' + m4[3], recv_address)

        # Receive M6: B -> A : {N2_B}_K_AB
        m6_raw = self.socket_a.recv(4096)
        if m6_raw[:2] != b'm6':
            print('NS_Client: Protocol Failure: Client does not recognize' +
                  ' message:', m4_raw)
            return
        
        m6_enc = m6_raw[2:]
        m6 = decrypt(m6_enc, key = key_AB)
        #print('M6:', m6)

        # Send M7: A -> B : {(N2_B - 1)}_K_AB
        nonce_ab = m6 - 1
        
        self.socket_a.sendto(b'm7' + encrypt(nonce_ab, key = key_AB), recv_address)
        #print('NS_Client: Key exchange complete')
    # end def ns_initiate()
# end class NS_Client

class NS_Recv(multiprocessing.Process):
    def __init__(self, h, p, kbs):
        gc.disable()
        multiprocessing.Process.__init__(self)
        self.host_b = h
        self.port_b = p
        self.pid_b = ("B", self.host_b, self.port_b)
        self.key_BS = kbs
        self.socket_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket_b.bind((self.host_b, self.port_b))
        self.terminate = False
    # end __init__()

    def run(self):
        at_fork()
        self.ns_responder()
        self.socket_b.close()
    # end def run()

    @dec_proto_run_timer
    def ns_responder(self):
        self.terminate = False
        #print('Starting NS_Recv')
        while not self.terminate:
            m1_raw, client_address = self.socket_b.recvfrom(4096)
            self.ns_responder_handle(m1_raw, client_address)
    # end def ns_responder()

    def ns_responder_handle(self, m1_raw, client_address):
        # Handle M1: A -> B : A
        # Check tag on incoming message
        if m1_raw[:2] != b'm1':
            print('NS_Recv: Protocol Failure: M1: Receiver does not' +
                  ' recognize message:', m1_raw)
            return
        
        # Get A's process id out of M1
        pid_a = pickle.loads(m1_raw[2:])
        #print('M1:', m1_raw)
        
        # Send M2: B -> A : {A, N1_B}_K_BS
        nonce_b1 = nonce()
        self.socket_b.sendto(b'm2' + encrypt([pid_a, nonce_b1], key = self.key_BS), client_address)

        # Receive M5: A -> B : {K_AB, N1_B, A}_K_BS
        m5_raw = self.socket_b.recv(4096)
        if m5_raw[:2] != b'm5':
            print('NS_Recv: Protocol Failure: M5: Receiver does not' +
                  ' recognize message:', m1_raw)
            return

        m5_enc = m5_raw[2:]
        m5 = decrypt(m5_enc, key = self.key_BS) 
        if m5[1] != nonce_b1:
            print('NS_Recv: M5: Protocol Failure: Nonce returned by' +
                  ' keyserver does not match nonce sent by receiver;' +
                  ' possible replay attack.')
            return
        if m5[2] != pid_a:
            print('NS_Recv: M5: Protocol Failure: Process id of client' +
                  ' does not match that of the client process id returned' +
                  ' from the server.')
            return
        key_AB = m5[0]
        #print('M5:', m5)        

        # send M6: B -> A : {N2_B}_K_AB
        nonce_b2 = nonce()
        self.socket_b.sendto(b'm6' + encrypt(nonce_b2, key = key_AB), client_address)

        # Receive M7
        m7_raw = self.socket_b.recv(4096)
        if m7_raw[:2] != b'm7':
            print('NS_Recv: Protocol Failure: M7: Receiver does not' +
                  ' recognize message:', m7_raw)
            return

        m7 = decrypt(m7_raw[2:], key = key_AB)
        if m7 != (nonce_b2 - 1):
            print('NS_Recv_Handler: Protocol Failure: M7: Decremented' +
                  ' nonce returned by initiating client does not match.')
            return
        #print('M7:', m7)
        #print('NS_Responder: Key exchange complete')
        self.terminate = True
    # end def ns_responder_handle()
# end class NS_Recv

class NS_KS(multiprocessing.Process):
    def __init__(self, h, p, kas, kbs):
        gc.disable()
        multiprocessing.Process.__init__(self)
        self.host_ks = h
        self.port_ks = p
        self.pid_ks = ("S", self.host_ks, self.port_ks)
        self.key_AS = kas
        self.key_BS = kbs
        self.socket_ks = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket_ks.bind((self.host_ks, self.port_ks))
        self.terminate = False
    #end def __init__()

    def run(self):
        at_fork()
        self.ns_keyserver()
        self.socket_ks.close()
    # end def run()

    @dec_proto_run_timer
    def ns_keyserver(self):
        self.terminate = False
        #print('Starting NS_KeyServer')
        while not self.terminate:
            m3_raw, client_address = self.socket_ks.recvfrom(4096)
            self.ns_keyserver_handle(m3_raw, client_address)
    #end def ns_keyserver()

    def ns_keyserver_handle(self, m3_raw, client_address):
        # Receive M3
        # Check tag on incoming message
        if m3_raw[:2] != b'm3':
            print('NS_KS_Handler: Protocol Failure: M3: Key server does' +
                  ' not recognize message:', m3_raw)
            return
        m3 = pickle.loads(m3_raw[2:])
        #print('M3:', m3)
        pid_a, N1_b = decrypt(m3[3], key = self.key_BS)
        # Decrypt package from receiver, check client process id
        if m3[0] != pid_a:
            print('NS_KS_HANDLER: Protocol Failure: M3: Client process id' + 
                  ' provided by client does not match client process id' +
                  ' provided by receiver.')
            return
        # Generate fresh session key to distribute to client and receiver
        session_key = keygen('shared')

        # Encrypt package for receiver, including nonce it sent
        pkg_B = encrypt([session_key, N1_b, pid_a], key = self.key_BS)

        # Encrypt message for client
        pkg_A = encrypt([m3[2], session_key, m3[1], pkg_B], key = self.key_AS)
        
        #Send M4: S -> A : {Na, B, K_AB, {K_AB, N1_b, A}_K_BS}_K_AS
        self.socket_ks.sendto(b'm4' + pkg_A, client_address)
        self.terminate = True

def main():
    gc.disable()
    key_AS = keygen('shared')
    key_BS = keygen('shared')
    ns_ks = NS_KS(HOST_KS, PORT_KS, key_AS, key_BS)
    ns_b = NS_Recv(HOST_B, PORT_B, key_BS)
    ns_a = NS_Client(HOST_A, PORT_A, HOST_KS, PORT_KS, key_AS, HOST_B, PORT_B)
    ns_ks.start()
    ns_b.start()
    ns_a.start()
    ns_ks.join()
    ns_b.join()
    ns_a.join()

if __name__ == "__main__":
    main()