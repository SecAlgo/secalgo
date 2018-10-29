import sys
import sa.sec_algo_pycrypto as SA_PyCrypto
#import sa.sec_algo_pycrytodome as SA_PyCryptodome
#import sa.sec_algo_charm as SA_Charm
from Crypto.Random import atfork as raf
from sa.timers import dec_timer

PUBLIC_KEY_DEFAULT_SIZE_BITS = {'rsa' : 2048}
PUBLIC_KEY_DEFAULT_SIZE_BYTES = {'rsa': 256}

SHARED_KEY_DEFAULT_SIZE_BITS = {'aes' : 256,
                                'des3' : 192,
                                'blowfish' : 448}

SHARED_KEY_DEFAULT_SIZE_BYTES = {'aes' : 32,
                                 'des3' : 24,
                                 'blowfish' : 56}                            

MAC_KEY_DEFAULT_SIZE_BITS = {'hmac' : 256}
MAC_KEY_DEFAULT_SIZE_BYTES = {'hmac' : 32}
NONCE_DEFAULT_SIZE_BITS = 128
DH_DEFAULT_MOD_SIZE_BITS = 2048
DH_DEFAULT_EXP_SIZE_BITS = 512
DH_DEFAULT_MODP_GROUP = 14

PUBLIC_KEY_CIPHERS = {'rsa', 'public'}
PUBLIC_KEY_SIGNING_ALGORITHMS = {'rsa', 'dsa', 'ecc', 'public'}
SHARED_KEY_BLOCK_CIPHERS = {'aes', 'des3', 'blowfish', 'shared'}
SHARED_KEY_STREAM_CIPHERS = {'salsa', 'chacha'}
SHARED_KEY_CIPHERS = SHARED_KEY_BLOCK_CIPHERS | SHARED_KEY_STREAM_CIPHERS
BLOCK_CIPHER_MODES = {'cbc', 'ctr', 'cfb', 'ofb'}
MAC_ALGORITHMS = {'hmac', 'mac'}
HASH_FUNCTIONS = {'sha224', 'sha256', 'sha384', 'sha512'}
KEY_SIZES = {'aes' : {128, 129, 256},
             'des3' : {192},
             'blowfish' : set(range(4, 57)),
             'rsa' : set(range(1024, ))
}

# This dict is initialized with the default values for all configuration
# options. Calls to the config function will change this dictionary, which
# will change the configuration for all processes running in the current
# session.
configuration = {'key_type'          : 'shared',
                 'key_type_shared'   : 'aes',
                 'block_cipher_mode' : 'ctr',
                 'key_size_shared'   : SHARED_KEY_DEFAULT_SIZE_BITS,
                 'key_type_mac'      : 'hmac',
                 'key_size_mac'      : MAC_KEY_DEFAULT_SIZE_BITS,
                 'key_type_public'   : 'rsa',
                 'key_size_public'   : PUBLIC_KEY_DEFAULT_SIZE_BITS,
                 'signing_hash'      : 'sha256',
                 'nonce_size'        : NONCE_DEFAULT_SIZE_BITS,
                 'dh_grp'            : DH_DEFAULT_MODP_GROUP,
                 'dh_mod_size'       : DH_DEFAULT_MOD_SIZE_BITS,
                 'dh_exp_size'       : DH_DEFAULT_EXP_SIZE_BITS,
                 'sign_return_pair'  : False,
                 'backend_library'   : 'SA_PyCrypto'}

backend_modules = {'SA_PyCrypto' : SA_PyCrypto}

def configure(**configs):
    global configuration
    for k, v in configs.items():
        if configuration[k] != None:
            configuration[k] = v
#end configure()

def at_fork():
    if configuration['backend_library'] == 'SA_PyCrypto':
        raf()
#end def atfork()

#@dec_timer
def nonce(size = None):
    backend = backend_modules[configuration['backend_library']]
    if size == None:
        size = configuration['nonce_size']
    if backend != None:
        return backend.nonce(size)
#end nonce()

#@dec_timer
def keygen(key_type = None, key_size = None, block_mode = None, hash_alg = None,
           key_mat = None, use_dh_group = True, curve = None,
           dh_group = None, dh_mod_size = None, dh_p = None, dh_g = None):
    backend = backend_modules[configuration['backend_library']]
    if key_type == None:
        key_type = configuration['key_type']
    if key_type == 'random':
        return backend.keygen_random(key_size)
    elif key_type in MAC_ALGORITHMS:
        if key_type == 'mac':
            key_type = configuration['key_type_mac']
        if key_size == None:
            key_size = (configuration['key_size_mac']['key_type_mac'] // 8)
        if hash_alg == None:
            hash_alg = configuration['signing_hash']
        return backend.keygen_mac(key_size, key_type, hash_alg, key_mat)
    elif key_type in SHARED_KEY_CIPHERS:
        if key_type == 'shared':
            key_type = configuration['key_type_shared']
        if key_size == None:
            key_size = configuration['key_size_shared'][key_type]
        if key_type in SHARED_KEY_BLOCK_CIPHERS and block_mode == None:
            block_mode = configuration['block_cipher_mode']
        return backend.keygen_shared(key_size, key_type, block_mode, key_mat)
    elif key_type in PUBLIC_KEY_CIPHERS:
        if key_type == 'public':
            key_type = configuration['key_type_public']
        if key_size == None:
            key_size = configuration['key_size_public'][key_type]
        if hash_alg == None:
            hash_alg = configuration['signing_hash']
        return backend.keygen_public(key_size, key_type, hash_alg, curve)
    elif key_type == 'diffie-hellman' or key_type == 'dh':
        if key_size == None:
            key_size = configuration['dh_exp_size']
        if use_dh_group:
            if dh_group == None:
                dh_group = configuration['dh_grp']
        else:
            if dh_p == None and dh_mod_size == None:
                dh_mod_size = configuration['dh_mod_size']
        return backend.keygen_dh(key_size, use_dh_group, dh_group,
                                 dh_mod_size, dh_p, dh_g)
#end keygen()

#@dec_timer
def encrypt(plaintext, key, iv = None):
    backend = backend_modules[configuration['backend_library']]
    if key['alg'] in PUBLIC_KEY_CIPHERS:
        return backend.public_key_encrypt(plaintext, key)
    elif key['alg'] in SHARED_KEY_CIPHERS:
        if key['alg'] in SHARED_KEY_BLOCK_CIPHERS and key['mode'] not in BLOCK_CIPHER_MODES:
            raise SecAlgoError("Unrecognized shared key block cipher mode " +
                               "of operation: " + key['mode'])
        return backend.shared_key_encrypt(plaintext, key, iv)
    else:
        raise SecAlgoError("Unrecognized encryption algorithm: " + key['alg']) 
#end encrypt()

#@dec_timer
def decrypt(ciphertext, key):
    backend = backend_modules[configuration['backend_library']]
    if key['alg'] in PUBLIC_KEY_CIPHERS:
        return backend.public_key_decrypt(ciphertext, key)
    elif key['alg'] in SHARED_KEY_CIPHERS:
        if key['alg'] in SHARED_KEY_BLOCK_CIPHERS and key['mode'] not in BLOCK_CIPHER_MODES:
            raise SecAlgoError("Unrecognized shared key block cipher mode " +
                               "of operation: " + key['mode'])
        return backend.shared_key_decrypt(ciphertext, key)
    else:
        raise SecAlgoError("Unrecognized decryption algorithm: " + key['alg']) 
#end decrypt()

#@dec_timer
def sign(data, key):
    backend = backend_modules[configuration['backend_library']]
    if key['alg'] in PUBLIC_KEY_SIGNING_ALGORITHMS:
        sig = backend.public_key_sign(data, key)
    elif key['alg'] in MAC_ALGORITHMS:
        sig = backend.shared_key_sign(data, key)
    else:
        raise SecAlgoError("Unrecognized signing algorithm: " + key['alg'])
    if configuration['sign_return_pair']:
        return (data, sig)
    else:
        return sig
#end sign()

#@dec_timer
def verify(data, sig, key = None):
    backend = backend_modules[configuration['backend_library']]
    if configuration['sign_return_pair'] and key == None:
        key = sig
        sig = data[1]
        data = data[0]
    if key['alg'] in PUBLIC_KEY_SIGNING_ALGORITHMS:
        return backend.public_key_verify(data, sig, key)
    elif key['alg'] in MAC_ALGORITHMS:
        return backend.shared_key_verify(data, sig, key)
#end verify()

class SecAlgoError(Exception):
    def __init__(self, msg):
        self.message = msg
    #end __init__()
#end class SecAlgoError
