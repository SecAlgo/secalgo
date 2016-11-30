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
KEY_PAIR_DEFAULT_SIZE_BYTES = 256
SYM_KEY_DEFAULT_SIZE_BITS = 256
SYM_KEY_DEFAULT_SIZE_BYTES = 32

def genkey(key_type, key_size = None):
    if key_type == 'shared':
        if key_size != None:
            return gen_sym_key(key_size)
        else:
            return gen_sym_key()
    elif key_type == 'public':
        if key_size != None:
            private_key = gen_key_pair(key_size)
            return private_key, get_pub_key(private_key)
        else:
            private_key = gen_key_pair()
            return private_key, get_pub_key(private_key)
#end genkey()

def gen_key_pair(key_size = KEY_PAIR_DEFAULT_SIZE_BITS):
    return RSA.generate(key_size)
#end gen_key_pair()

def get_pub_key(k):
    return k.publickey()
#end get_public_key()

def gen_sym_key(key_size = SYM_KEY_DEFAULT_SIZE_BYTES):
    size = key_size
    configs = get_configs()
    if 'keysize' in configs:
        size = (configs['keysize'] // 8)
    return Random.new().read(size)
#end gen_sym_key

def encrypt(*plaintext, key):
    configs = get_configs()
    #print('###############:', configs)
    #may want to consider a segment_size configuration option for CFB mode
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
        print('$$$$$$$$$$: Encrypt: USING CTR')
        pre = Random.new().read(8)
        ctr = Counter.new(64, prefix = pre)
        encrypter = AES.new(key, AES.MODE_CTR, counter = ctr)
        ciphertext =  pre + encrypter.encrypt(serial_pt)
    elif mode == 'CBC':
        print('$$$$$$$$$$: Encrypt: USING CBC')
        padded_pt = pkcs7_pad(serial_pt)
        iv = Random.new().read(16)
        encrypter = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = iv + encrypter.encrypt(padded_pt)
    elif mode == 'ECB':
        print('$$$$$$$$$$: Encrypt: USING ECB')
        padded_pt = pkcs7_pad(serial_pt)
        encrypter = AES.new(key, AES.MODE_ECB)
        ciphertext = encrypter.encrypt(padded_pt)
    elif mode == 'CFB':
        print('$$$$$$$$$$: Encrypt: USING CFB')
        seg_size = 8
        padded_pt = pkcs7_pad(serial_pt, seg_size)
        iv = Random.new().read(16)
        encrypter = AES.new(key, AES.MODE_CFB, iv, segment_size=seg_size)
        ciphertext = iv + encrypter.encrypt(padded_pt)
    return ciphertext
#end sym_encrypt()

def asym_encrypt(plaintext, public_key):
    serial_pt = pickle.dumps(plaintext)
    frag_counter = (len(serial_pt) // KEY_PAIR_DEFAULT_SIZE_BYTES) + 1
    ct_list = []
    for i in range(frag_counter):
        ciphertext = public_key.encrypt(serial_pt[(i * KEY_PAIR_DEFAULT_SIZE_BYTES):((i + 1) * KEY_PAIR_DEFAULT_SIZE_BYTES)], '')
        ct_list.append(ciphertext)
    #end for
    return ct_list
#end asym_encrypt()

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
        print('$$$$$$$$$$: Decrypt: USING CTR')
        pre = ciphertext[0:8]
        ctr = Counter.new(64, prefix = pre)
        decrypter = AES.new(key, AES.MODE_CTR, counter = ctr)
        serial_pt = decrypter.decrypt(ciphertext[8:])
    elif mode == 'CBC':
        print('$$$$$$$$$$: Decrypt: USING CBC')
        iv = ciphertext[0:16]
        decrypter = AES.new(key, AES.MODE_CBC, iv)
        padded_pt = decrypter.decrypt(ciphertext[16:])
        serial_pt = pkcs7_unpad(padded_pt)
    elif mode == 'ECB':
        print('$$$$$$$$$$: Decrypt: USING ECB')
        decrypter = AES.new(key, AES.MODE_ECB)
        padded_pt = decrypter.decrypt(ciphertext)
        serial_pt = pkcs7_unpad(padded_pt)
    elif mode == 'CFB':
        print('$$$$$$$$$$: Encrypt: USING CFB')
        seg_size = 8
        iv = ciphertext[0:16]
        decrypter = AES.new(key, AES.MODE_CFB, iv, segment_size = seg_size)
        padded_pt = decrypter.decrypt(ciphertext[16:])
        serial_pt = pkcs7_unpad(padded_pt, seg_size)
    return pickle.loads(serial_pt)
#end sym_decrypt()

def asym_decrypt(ct_list, private_key):
    serial_pt = b''
    for ciphertext in ct_list:
        serial_pt += private_key.decrypt(ciphertext)
    #end for
    plaintext = pickle.loads(serial_pt)
    return plaintext
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
    frame = stack[3]
    module_name = inspect.getmodulename(frame.filename)
    configs = sys.modules[module_name]._config_object
    return configs
#end get_configs()
