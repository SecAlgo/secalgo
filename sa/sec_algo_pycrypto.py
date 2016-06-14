import sys
import random
import pickle
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import _RSAobj
from Crypto.Hash import SHA256
from Crypto import Random

RKEY_SIZE_BITS = 1024
RKEY_SIZE_BYTES = 128

def gen_key_pair():
    return RSA.generate(1024)
#end gen_key_pair()

def get_public_key(k):
    return k.publickey()
#end get_public_key()

def gen_sym_key():
    return Random.new().read(32)
#end gen_sym_key

def sym_encrypt(plaintext, key):
    pre = Random.new().read(8)
    ctr = Counter.new(64, prefix = pre)
    encrypter = AES.new(key, AES.MODE_CTR, counter = ctr)
    return pre + encrypter.encrypt(plaintext)
#end sym_encrypt()

def sym_decrypt(ciphertext, key):
    pre = ciphertext[0:8]
    ctr = Counter.new(64, prefix = pre)
    decrypter = AES.new(key, AES.MODE_CTR, counter = ctr)
    return decrypter.decrypt(ciphertext[8:])
#end sym_decrypt()

def asym_encrypt(plaintext, public_key):
    frag_counter = (len(plaintext) // RKEY_SIZE_BYTES) + 1
    ct_list = []
    for i in range(frag_counter):
        ciphertext = public_key.encrypt(plaintext[(i * RKEY_SIZE_BYTES):
                                                  ((i + 1) * RKEY_SIZE_BYTES)], '')
        ct_list.append(ciphertext)
    #end for
    return ct_list
#end asym_encrypt()

def asym_decrypt(ct_list, key):
    pt = b''
    for ciphertext in ct_list:
        pt += key.decrypt(ciphertext)
    #end for
    return pt
#end asym_decrypt()

def encrypt(plaintext, key):
    if isinstance(key, _RSAobj):
        return asym_encrypt(plaintext, key)
    else:
        return sym_encrypt(plaintext, key)
#end encrypt

def decrypt(ciphertext, key):
    if isinstance(key, _RSAobj):
        return asym_decrypt(ciphertext, key)
    else:
        return sym_decrypt(ciphertext, key)
#end decrypt()

def sign(data, key):
    sig = key.sign(SHA256.new(data).digest(), '')
    result = (data, sig[0].to_bytes(((sig[0].bit_length() // 8) + 1), 
                                    byteorder = 'little'))
    return pickle.dumps(result)
#end sign()

#returns None when verfication fails
def verify(data, key):
    unp_data = pickle.loads(data)
    sig = (int.from_bytes(unp_data[1], byteorder = 'little'), )
    verdict = key.verify(SHA256.new(unp_data[0]).digest(), sig)
    if verdict:
        return unp_data[0]
    else:
        return None
#end def verify()
