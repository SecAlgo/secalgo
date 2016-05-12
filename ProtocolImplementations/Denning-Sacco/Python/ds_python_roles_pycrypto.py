import sys
import socket
import random
import json
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto import Random

MIN_TCP_PORT = 1025
MAX_TCP_PORT = 65500


class pk_server():
    def __init__(address):
        self.pk = dict()
        self.port = None:
        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        while self.port == None:
            self.port = random.randint(MIN_TCP_PORT, MAX_TCP_PORT)
            try:
                self.list_socket.bind(self.address, self.port)
            except socket.error:
                self.port = None
        #end while port assignment
    # end __init__()

    def start():
        
    
#end class pk_server
