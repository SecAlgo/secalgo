import sys
import socket
import socketserver
import pickle
import threading

from padding import Padder #provides PKCS7 padding
from Crypto.Random.random import getrandbits #for nonces
from Crypto import Random #for keys and IVs
from Crypto.Cipher import AES #encryption primitive

AES_KEY_SIZE = 16
NONCE_SIZE = 128
A_PORT = 1981
B_PORT = 1970
KS_PORT = 1977

class NS_Client():
    def __init__(self, h, p, ks_h, ks_p, kas):
        self.c_host = h
        self.c_port = p
        self.ks_host = ks_h
        self.ks_port = ks_p
        self.key_AS = kas
        self.c_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.c_socket.bind((self.c_host, self.c_port))
    #end def __init__()

    def ns_initiate(self, b_host, b_port):
        print('NS_Client: Initating NS-SK protocol.')
        nonce_a = getrandbits(NONCE_SIZE)
        #Send M1
        self.c_socket.sendto(b'm1' + pickle.dumps([('A', self.c_host, self.c_port),
                                           ('B', b_host, b_port), nonce_a]),
                             (self.ks_host, self.ks_port))
        #Receive M2
        m2_raw = self.c_socket.recv(4096)
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
        if m2[2] != ('B', b_host, b_port):
            print('NS_Client: Protocol Failure: Remote client identity returned by key server does not match.')
            return
        key_AB = m2[1]
        #Send M3
        self.c_socket.sendto(b'm3' + m2[3], (b_host, b_port))
        m4_raw = self.c_socket.recv(4096)
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
        self.c_socket.sendto(b'm5' + IV_AB + cipher_AB.encrypt(
            Padder().pkcs7_pad(pickle.dumps(nonce_ab), AES.block_size)), (b_host, b_port))
        print('NS_Client: Finished NS-SK protocol')
        self.c_socket.close()
    #end def ns_initiate()
#end class NS_Client

class NS_Recv():

    def __init__(self, h, p, kbs):
        self.r_host = h
        self.r_port = p
        self.key_BS = kbs
        self.b_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.b_socket.bind((h, p))
    #end __init__()

    def receive(self):
        print('Starting NS_Recv')
        #Receive M3
        m3_raw = self.b_socket.recv(4096)
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
        self.b_socket.sendto(b'm4' + IV_AB + cipher_AB.encrypt(
            Padder().pkcs7_pad(pickle.dumps(nonce_b), AES.block_size)), (m3[1][1], m3[1][2]))
        #Receive M5
        m5_raw = self.b_socket.recv(4096)
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
        self.b_socket.close()
    #end receive()

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
    #end def handle()
#end class NS_KS_Handler
    
class NS_KS(socketserver.ThreadingUDPServer):
    def __init__(self, h, p, kas, kbs):
        socketserver.ThreadingUDPServer.__init__(self, (h, p), NS_KS_Handler)
        self.ks_host = h
        self.ks_port = p
        self.key_AS = kas
        self.key_BS = kbs
        self.ks_thread = threading.Thread(target=self.serve_forever)
        self.ks_thread.daemon = True
    #end def __init__()

    def begin(self):
        print('Starting NS_KS')
        self.ks_thread.start()
    #end def begin()

    def finish(self):
        self.shutdown()
        self.server_close()
        print('Closed NS_KS')
    #end def finish()

if __name__ == '__main__':
    key_AS = Random.new().read(AES_KEY_SIZE)
    key_BS = Random.new().read(AES_KEY_SIZE)
    ns_ks = NS_KS('127.0.0.1', KS_PORT, key_AS, key_BS)
    ns_ks.begin()
    ns_b = NS_Recv('127.0.0.1', B_PORT, key_BS)
    thread_b = threading.Thread(target=ns_b.receive)
    thread_b.start()
    ns_a = NS_Client('127.0.0.1', A_PORT, '127.0.0.1', 1977, key_AS)
    ns_a.ns_initiate('127.0.0.1', B_PORT)
    ns_ks.finish()
    thread_b.join()
