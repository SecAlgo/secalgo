import sys
import random
import pickle
import inspect
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import _RSAobj
from Crypto.Hash import SHA256
from Crypto import Random
from sa.Misc.Padding import pkcs7_pad, pkcs7_unpad

KEY_PAIR_DEFAULT_SIZE_BITS = 2048
KEY_PAIR_DEFAULT__SIZE_BYTES = 256
SYM_KEY_DEFAULT_SIZE_BITS = 256
SYM_KEY_DEFAULT_SIZE_BYTES = 32

def gen_key_pair():
    return RSA.generate(KEY_PAIR_DEFAULT_SIZE_BITS)
#end gen_key_pair()

def get_pub_key(k):
    return k.publickey()
#end get_public_key()

def gen_sym_key():
    size = SYM_KEY_DEFAULT_SIZE_BYTES
    configs = get_configs()
    if 'keysize' in configs:
        size = (configs['keysize'] // 8)
    return Random.new().read(size)
#end gen_sym_key

def encrypt(*plaintext, key):
    configs = get_configs()
    print('###############:', configs)
    if isinstance(key, _RSAobj):
        return asym_encrypt(plaintext, key)
    else:
        if 'mode' in configs:
            return sym_encrypt(plaintext, key, mode=configs['mode'])
        else:
            return sym_encrypt(plaintext, key)
#end encrypt

def sym_encrypt(plaintext, key, alg = 'AES', mode = 'CTR'):
    serial_pt = pickle.dumps(plaintext)
    if mode == 'CTR':
        print('$$$$$$$$$$: USING CTR')
        pre = Random.new().read(8)
        ctr = Counter.new(64, prefix = pre)
        encrypter = AES.new(key, AES.MODE_CTR, counter = ctr)
        ciphertext =  pre + encrypter.encrypt(serial_pt)
    elif mode == 'CBC':
        print('$$$$$$$$$$: USING CBC')
        padded_pt = pkcs7_pad(serial_pt)
        iv = Random.new().read(16)
        encrypter = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = iv + encrypter.encrypt(padded_pt)
    return ciphertext
#end sym_encrypt()

def decrypt(ciphertext, key):
    configs = get_configs()
    print('###############:', configs)
    if isinstance(key, _RSAobj):
        return asym_decrypt(ciphertext, key)
    else:
        if 'mode' in configs:
            return sym_decrypt(ciphertext, key, mode=configs['mode'])
        else:
            return sym_decrypt(ciphertext, key)
#end decrypt()

def sym_decrypt(ciphertext, key, alg = 'AES', mode = 'CTR'):
    if mode == 'CTR':
        pre = ciphertext[0:8]
        ctr = Counter.new(64, prefix = pre)
        decrypter = AES.new(key, AES.MODE_CTR, counter = ctr)
        serial_pt = decrypter.decrypt(ciphertext[8:])
    elif mode == 'CBC':
        iv = ciphertext[0:16]
        decrypter = AES.new(key, AES.MODE_CBC, iv)
        padded_pt = decrypter.decrypt(ciphertext[16:])
        serial_pt = pkcs7_unpad(padded_pt)
    return pickle.loads(serial_pt)
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

#utility functions
def get_configs():
    stack = inspect.stack()
    frame = stack[2]
    module_name = inspect.getmodulename(frame.filename)
    configs = sys.modules[module_name]._config_object
    return configs
#end get_configs()
