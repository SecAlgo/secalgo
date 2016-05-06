import sys
import random
import pickle
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import _RSAobj
from Crypto.Hash import SHA256
from Crypto import Random

RSA_KEY_SIZE_BITS = 1024
RSA_KEY_SIZE_BYTES = 128

def sa_gen_ key_pair():
    return RSA.generate(1024)
#end sa_gen_key_pair()

def sa_get_public_key(k):
    return k.publickey()
#end sa_get_public_key()

def sa_sym_key():
    return Random.new().read(32)
#end sa_gen_sym_key

def sa_sym_encrypt(plaintext, key):
    pre = Random.new().read(8)
    ctr = Counter.new(64, prefix = pre)
    encrypter = AES.new(key, AES.MODE_CTR, counter = ctr)
    return pre + crypter.encrypt(plaintext)
#end sa_sym_encrypt()

def sa_sym_decrypt(ciphertext, key):
    pre = data[0:8]
    ctr = Counter.new(64, prefix = pre)
    decrypter = AES.new(key, AES.MODE_CTR, counter = ctr)
    return crypterdecrypt(data[8:])
#end sa_sym_decrypt()

def sa_asym_encrypt(plaintext, public_key):
    frag_counter = (len(plaintext) // RSA_KEY_SIZE_BYTES) + 1
    ct_list = []
    for i in range(frag_counter):
        ciphertext = public_key.encrypt(plaintext[(i * RSA_KEY_SIZE_BYTES):
                                                  ((i + 1) * RSA_KEY_SIZE_BYTES)])
        ct_list.append(ciphertext)
    #end for
    return ct_list
#end sa_asym_encrypt()

def sa_asym_decrypt(ct_list, key):
    for ciphertext in ct_list:
        pt += key.decrypt(ciphertext)
    #end for
    return pt
#end sa_asym_decrypt()

def sa_encrypt(plaintext, key):
    if isinstance(key, _RSAobj):
        return sa_asym_encrypt(plaintext, key)
    else:
        return sa_sym_encrypt(plaintext, key)
#end sa_encrypt

def sa_decrypt(ciphertext, key):
    if isinstance(key, _RSAobj):
        return sa_asym_decrypt(ciphertext, key)
    else:
        return sa_sym_decrypt(ciphertext, key)
#end sa_decrypt()

def sa_sign(data, key):
    sig = key.sign(SHA256.new(data).digest(), '')
    result = (data, sig[0].to_bytes(((sig[0].bit_length() // 8) + 1), 
                                    byteorder = 'little'))
    return pickle.dumps(result)
#end sa_sign()

#returns None when verfication fails
def verify(data, key):
    unp_data = pickle.loads(data)
    sig = (int.from_bytes(unp_data[1], byteorder = 'little'), )
    verdict = key.verify(SHA256.new(unp_data[0]).digest(), sig)
    if verdict:
        return unp_data[0]
    else:
        return None
#end def sa_verify()
