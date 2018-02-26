import sys
import socket
import socketserver
import pickle
import threading
from Crypto.Random.random import getrandbits #for nonces
from Crypto import Random #for keys and IVs
from Crypto.PublicKey import RSA #for key pair generation
from Crypto.Cipher import PKCS1_OAEP #public key encryption primitive
from Crypto.Signature import PKCS1_v1_5 #public key signing primitive
from Crypto.Hash import SHA256 #secure hash primitive for digests
RSA_KEY_SIZE = 2048
NONCE_SIZE = 128
A_HOST = '127.0.0.1'
B_HOST = '127.0.0.1'
AS_HOST = '127.0.0.1'
A_PORT = 1981
B_PORT = 1970
AS_PORT = 1977
class NS_Client():
    def __init__(self, h, p, ska, as_h, as_p, pkas):
        self.c_host = h
        self.c_port = p
        self.SK_A = ska
        self.as_host = as_h
        self.as_port = as_p
        self.PK_AS = pkas
        self.c_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.c_socket.bind((self.c_host, self.c_port))
    def ns_initiate(self, b_host, b_port):
        print('NS_Client: Initating NS-PK protocol.')
        self.c_socket.sendto(b'm1' + pickle.dumps([('A', self.c_host, self.c_port), ('B', b_host, b_port)]), (self.as_host, self.as_port))
        m2_raw = self.c_socket.recv(4096)
        if m2_raw[:2] != b'm2':
            print('NS_Client: Protocol Failure: Client does not recognize message:', m2_raw)
            return
        m2 = pickle.loads(m2_raw[2:])
        print('M2:', m2)
        verifier = PKCS1_v1_5.new(self.PK_AS)
        if not verifier.verify(SHA256.new(pickle.dumps([m2[0], m2[1]])), m2[2]):
            print('NS_Client: Protocol Failure: Could not verify signature on message from authentication server.')
            return
        if m2[1] != ('B', b_host, b_port):
            print('NS_Client: Protocol Failure: Remote client identity returned by key server does not match.')
            return
        PK_B = RSA.importKey(m2[0])
        nonce_a = getrandbits(NONCE_SIZE)
        cipher_B = PKCS1_OAEP.new(PK_B)
        self.c_socket.sendto(b'm3' + cipher_B.encrypt(pickle.dumps([nonce_a, ('A', self.c_host, self.c_port)])), (b_host, b_port))
        m6_raw = self.c_socket.recv(4096)
        if m6_raw[:2] != b'm6':
            print('NS_Client: Protocol Failure: Client does not recognize message:', m6_raw)
            return
        cipher_A = PKCS1_OAEP.new(self.SK_A)
        m6 = pickle.loads(cipher_A.decrypt(m6_raw[2:]))
        print('M6:', m6)
        if m6[0] != nonce_a:
            print('NS_Client: Protocol Failure: Initiator nonce returned by remote client does not match.')
            return
        self.c_socket.sendto(b'm7' + cipher_B.encrypt(pickle.dumps(m6[1])), (b_host, b_port))
        self.c_socket.close()
        print('NS_Client: Finished NS-PK protocol')
class NS_Recv():
    def __init__(self, h, p, skb, h_as, p_as, pkas):
        self.host_b = h
        self.port_b = p
        self.socket_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket_b.bind((self.host_b, self.port_b))
        self.SK_B = skb
        self.host_as = h_as
        self.port_as = p_as
        self.PK_AS = pkas
    def receive(self):
        print('Starting NS_Recv')
        m3_raw = self.socket_b.recv(4096)
        if m3_raw[:2] != b'm3':
            print('NS_Recv: Protocol Failure: Receiver does not recognize message:', m3_raw)
            return
        cipher_B = PKCS1_OAEP.new(self.SK_B)
        m3 = pickle.loads(cipher_B.decrypt(m3_raw[2:]))
        print('M3:', m3)
        self.socket_b.sendto(b'm4' + pickle.dumps([('B', self.host_b, self.port_b), m3[1]]), (self.host_as, self.port_as))
        m5_raw = self.socket_b.recv(4096)
        if m5_raw[:2] != b'm5':
            print('NS_Recv: Protocol Failure: Receiver does not recognize message:', m5_raw)
            return
        m5 = pickle.loads(m5_raw[2:])
        print('M5:', m5)
        verifier = PKCS1_v1_5.new(self.PK_AS)
        if not verifier.verify(SHA256.new(pickle.dumps([m5[0], m5[1]])), m5[2]):
            print('NS_Recv: Protocol Failure: Could not verify signature on message from authentication server.')
            return
        if m5[1] != m3[1]:
            print('NS_Recv: Protocol Failure: Intiator identity returned by authentication server does not match.')
            return
        pk_A = RSA.importKey(m5[0])
        nonce_b = getrandbits(NONCE_SIZE)
        cipher_A = PKCS1_OAEP.new(pk_A)
        self.socket_b.sendto(b'm6' + cipher_A.encrypt(pickle.dumps([m3[0], nonce_b])), (m3[1][1], m3[1][2]))
        m7_raw = self.socket_b.recv(4096)
        if m7_raw[:2] != b'm7':
            print('NS_Recv: Protocol Failure: Receiver does not recognize message:', m7_raw)
            return
        m7 = pickle.loads(cipher_B.decrypt(m7_raw[2:]))
        print('M7:', m7)
        if m7 != nonce_b:
            print('NS_Recv: Protocol Failure: Initiator nonce returned by remote client does not match.')
            return
        print('NS_Recv_Handler: Protocol Success: Mutual authentication complete.')
        self.socket_b.close()
class NS_AS_Handler(socketserver.BaseRequestHandler):
    def handle(self):
        if self.request[0][:2] not in {b'm1', b'm4'}:
            print('NS_KS_Handler: Protocol Failure: Key server does not recognize message:', self.request[0])
            return
        m1or4 = pickle.loads(self.request[0][2:])
        m_label = 'M1:' if self.request[0][:2] == b'm1' else 'M4:'
        print(m_label, m1or4)
        pk_x = self.server.client_keys[self.server.client_list.index(m1or4[1])].exportKey()
        signer = PKCS1_v1_5.new(self.server.SK_AS)
        sig = signer.sign(SHA256.new(pickle.dumps([pk_x, m1or4[1]])))
        m_tag = b'm2' if self.request[0][:2] == b'm1' else b'm5'
        self.request[1].sendto(m_tag + pickle.dumps([pk_x, m1or4[1], sig]), self.client_address)    
class NS_AS(socketserver.ThreadingUDPServer):
    def __init__(self, h, p, skas, a, b, pka, pkb):
        socketserver.ThreadingUDPServer.__init__(self, (h, p), NS_AS_Handler)
        self.as_host = h
        self.as_port = p
        self.SK_AS = skas
        self.client_list = [a, b]
        self.client_keys = [pka, pkb]
        self.as_thread = threading.Thread(target=self.serve_forever)
        self.as_thread.daemon = True
    def begin(self):
        print('Starting NS_KS')
        self.as_thread.start()
    def finish(self):
        self.shutdown()
        self.server_close()
        print('Closed NS_KS')
if __name__ == '__main__':
    SK_A = RSA.generate(RSA_KEY_SIZE)
    SK_B = RSA.generate(RSA_KEY_SIZE)
    SK_AS = RSA.generate(RSA_KEY_SIZE)
    ns_as = NS_AS(AS_HOST, AS_PORT, SK_AS, ('A', A_HOST, A_PORT), ('B', B_HOST, B_PORT), SK_A.publickey(), SK_B.publickey())
    ns_as.begin()
    ns_b = NS_Recv(B_HOST, B_PORT, SK_B, AS_HOST, AS_PORT, SK_AS.publickey())
    b_thread = threading.Thread(target=ns_b.receive)
    b_thread.start()
    ns_a = NS_Client(A_HOST, A_PORT, SK_A, AS_HOST, AS_PORT, SK_AS.publickey())
    ns_a.ns_initiate(B_HOST, B_PORT)
    b_thread.join()
    ns_as.finish()
