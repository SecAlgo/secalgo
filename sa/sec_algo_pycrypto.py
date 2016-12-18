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
from Crypto.Random.random import getrandbits
from sa.Misc.Padding import pkcs7_pad, pkcs7_unpad
from Crypto.Util.number import getPrime, isPrime, GCD

KEY_PAIR_DEFAULT_SIZE_BITS = 2048
KEY_PAIR_DEFAULT_SIZE_BYTES = 256
SYM_KEY_DEFAULT_SIZE_BITS = 256
SYM_KEY_DEFAULT_SIZE_BYTES = 32
NONCE_DEFAULT_SIZE_BITS = 128
DH_DEFAULT_SIZE_BITS = 2048

def gen_nonce(size = NONCE_DEFAULT_SIZE_BITS):
    Random.atfork()
    return getrandbits(size)
#end gen_nonce

def genkey(key_type, key_size = None, dh_p, dh_g):
    Random.atfork()
    if key_type == 'shared':
        if key_size != None:
            return gen_sym_key(key_size)
        else:
            return gen_sym_key()
    elif key_type == 'public':
        if key_size != None:
            private_key = gen_key_pair(key_size)
            return private_key.exportKey(), get_pub_key(private_key).exportKey()
        else:
            private_key = gen_key_pair()
            return private_key.exportKey(), get_pub_key(private_key).exportKey()
    elif key_type == 'diffie-hellman' or key_type == 'dh':
        if key_size == None:
            key_size = DH_DEFAULT_KEY_SIZE
        return gen_dh_key(key_size, dh_p, dh_g)
#end genkey()

def gen_key_pair(key_size = KEY_PAIR_DEFAULT_SIZE_BITS):
    return RSA.generate(key_size)
#end gen_key_pair()

def get_pub_key(k):
    return k.publickey()
#end get_public_key()

def gen_sym_key(key_size = SYM_KEY_DEFAULT_SIZE_BYTES):
    size = key_size
    #configs = get_configs()
    #if 'keysize' in configs:
    #    size = (configs['keysize'] // 8)
    return Random.new().read(size)
#end gen_sym_key

def gen_dh_key(key_size, dh_p, dh_g):
    if dh_p == None:
        while not isPrime(dh_p) and GCD(dh_g, : 
            q = getPrime(key_size - 1)
            dh_p = (2 * q) + 1
            dh_g = 2
        
        

def encrypt(*plaintext, key):
    Random.atfork()
    if len(plaintext) == 1:
        plaintext = plaintext[0]
    #configs = get_configs()
    #may want to consider a segment_size configuration option for CFB mode
    #print('KEYKEYKEY:', key)
    if b'BEGIN' in key:
        return asym_encrypt(plaintext, RSA.importKey(key))
    else:
        #if 'mode' in configs:
        #    return sym_encrypt(plaintext, key, mode=configs['mode'])
        #else:
        return sym_encrypt(plaintext, key)
#end encrypt

def sym_encrypt(plaintext, key, alg = 'AES', mode = 'CTR'):
    serial_pt = pickle.dumps(plaintext)
    if mode == 'CTR':
        #print('$$$$$$$$$$: Encrypt: USING CTR')
        pre = Random.new().read(8)
        ctr = Counter.new(64, prefix = pre)
        encrypter = AES.new(key, AES.MODE_CTR, counter = ctr)
        ciphertext =  pre + encrypter.encrypt(serial_pt)
    elif mode == 'CBC':
        #print('$$$$$$$$$$: Encrypt: USING CBC')
        padded_pt = pkcs7_pad(serial_pt)
        iv = Random.new().read(16)
        encrypter = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = iv + encrypter.encrypt(padded_pt)
    elif mode == 'ECB':
        #print('$$$$$$$$$$: Encrypt: USING ECB')
        padded_pt = pkcs7_pad(serial_pt)
        encrypter = AES.new(key, AES.MODE_ECB)
        ciphertext = encrypter.encrypt(padded_pt)
    elif mode == 'CFB':
        #print('$$$$$$$$$$: Encrypt: USING CFB')
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
    Random.atfork()
    #configs = get_configs()
    if b'BEGIN' in key:
        return asym_decrypt(ciphertext, RSA.importKey(key))
    else:
        #if 'mode' in configs:
        #    return sym_decrypt(ciphertext, key, mode=configs['mode'])
        #else:
        return sym_decrypt(ciphertext, key)
#end decrypt()

def sym_decrypt(ciphertext, key, alg = 'AES', mode = 'CTR'):
    if mode == 'CTR':
        #print('$$$$$$$$$$: Decrypt: USING CTR')
        pre = ciphertext[0:8]
        ctr = Counter.new(64, prefix = pre)
        decrypter = AES.new(key, AES.MODE_CTR, counter = ctr)
        serial_pt = decrypter.decrypt(ciphertext[8:])
    elif mode == 'CBC':
        #print('$$$$$$$$$$: Decrypt: USING CBC')
        iv = ciphertext[0:16]
        decrypter = AES.new(key, AES.MODE_CBC, iv)
        padded_pt = decrypter.decrypt(ciphertext[16:])
        serial_pt = pkcs7_unpad(padded_pt)
    elif mode == 'ECB':
        #print('$$$$$$$$$$: Decrypt: USING ECB')
        decrypter = AES.new(key, AES.MODE_ECB)
        padded_pt = decrypter.decrypt(ciphertext)
        serial_pt = pkcs7_unpad(padded_pt)
    elif mode == 'CFB':
        #print('$$$$$$$$$$: Encrypt: USING CFB')
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
    Random.atfork()
    serial_data = pickle.dumps(data)
    im_key = RSA.importKey(key)
    sig = im_key.sign(SHA256.new(serial_data).digest(), '')
    result = (serial_data, sig[0].to_bytes(((sig[0].bit_length() // 8) + 1), 
                                    byteorder = 'little'))
    s_result = pickle.dumps(result)
    return s_result
#end sign()

#returns None when verfication fails
def verify(data, key):
    Random.atfork()
    im_key = RSA.importKey(key)
    unp_data = pickle.loads(data)
    sig = (int.from_bytes(unp_data[1], byteorder = 'little'), )
    verdict = im_key.verify(SHA256.new(unp_data[0]).digest(), sig)
    if verdict:
        return pickle.loads(unp_data[0])
    else:
        return None
#end def verify()

#utility functions
#def get_configs():
#    configs = dict()
#    stack = inspect.stack()
#    #frame = stack[3]
#    for frame in stack:
#        print('$$$$$$$$$$:', frame.filename)
#        module_name = inspect.getmodulename(frame.filename)
#        print('##########:', module_name)
#    #configs = sys.modules[module_name]._config_object
#    return configs
#end get_configs()
