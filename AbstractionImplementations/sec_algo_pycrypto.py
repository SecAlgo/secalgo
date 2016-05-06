import sys
import random
import pickle
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import _RSAobj
from Crypto.Hash import SHA256
from Crypto import Random
#Definition of High-Level Encryption/Authentication Methods

def gen_k():
    return RSA.generate(2048)

def gen_pk(k):
    return k.publickey()

def gen_symk():
    return Random.new().read(32)

def encrypt(data, key):
    if isinstance(key, _RSAobj):
        if len(data) > 256:
            blergh = (key.encrypt(data[0:256], '')[0] + key.encrypt(data[256:], '')[0], )
            return blergh
        return key.encrypt(data, '')
    pre = Random.new().read(8)
    ctr = Counter.new(64, prefix = pre)
    crypter = AES.new(key, AES.MODE_CTR, counter = ctr)
    return pre + crypter.encrypt(data)

def decrypt(data, key):
    if isinstance(key, _RSAobj):
        if len(data[0]) > 256:
            blergh = key.decrypt((data[0][0:256], )) + key.decrypt((data[0][256:], ))            
            return blergh
        return key.decrypt(data)
    pre = data[0:8]
    ctr = Counter.new(64, prefix = pre)
    crypter = AES.new(key, AES.MODE_CTR, counter = ctr)
    return crypter.decrypt(data[8:])

def sign(data, key):
    sig = key.sign(SHA256.new(data).digest(), '')
    result = (data, sig[0].to_bytes(((sig[0].bit_length() // 8) + 1), 
                                    byteorder = 'little'))
    return pickle.dumps(result)

#returns None when verfication fails
def checksign(data, key):
    unp_data = pickle.loads(data)
    sig = (int.from_bytes(unp_data[1], byteorder = 'little'), )
    verdict = key.verify(SHA256.new(unp_data[0]).digest(), sig)
    if verdict:
        return unp_data[0]
    else:
        return None
               
#End of High-Level Encryption Definitions
