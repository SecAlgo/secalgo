import json, time, pickle, sys
import sa.sec_algo_pycrypto as SA_PyCrypto
#import sa.sec_algo_charm as SA_Charm
from Crypto.Random import atfork as raf

KEY_PAIR_DEFAULT_SIZE_BITS = 2048
KEY_PAIR_DEFAULT_SIZE_BYTES = 256

SYM_KEY_DEFAULT_SIZE_BITS = {'AES' : 256,
                             'DES' : 64,
                             'DES3' : 192,
                             'Blowfish' : 448}

SYM_KEY_DEFAULT_SIZE_BYTES = {'AES' : 32,
                              'DES' : 8,
                              'DES3' : 24,
                              'Blowfish' : 56}                            

MAC_KEY_DEFAULT_SIZE_BITS = 256
MAC_KEY_DEFAULT_SIZE_BYTES = 32
NONCE_DEFAULT_SIZE_BITS = 128
DH_DEFAULT_MOD_SIZE_BITS = 2048
DH_DEFAULT_EXP_SIZE_BITS = 512
DH_DEFAULT_MODP_GROUP = 14

PUBLIC_CIPHERS = {'RSA', 'DSA', 'ECC', 'public'}
SYM_CIPHERS = {'AES', 'DES3', 'Blowfish', 'shared'}
MAC_ALGORITHMS = {'HMAC', 'mac'}
HASH_FUNCTIONS = {'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512'}

# This dict is initialized with the default values for all configuration
# options. Calls to the config function will change this dictionary, which
# will change the configuration for all processes running in the current
# session.
configuration = {'sym_cipher'        : 'AES',
                 'block_mode'        : 'CBC',
                 'sym_key_size'      : SYM_KEY_DEFAULT_SIZE_BITS,
                 'mac_alg'           : 'HMAC',
                 'mac_key_size'      : MAC_KEY_DEFAULT_SIZE_BITS,
                 'pub_cipher'        : 'RSA',
                 'pub_key_size'      : KEY_PAIR_DEFAULT_SIZE_BITS,
                 'verify_returns'    : 'data',
                 'hash_alg'          : 'SHA-256',
                 'nonce_size'        : NONCE_DEFAULT_SIZE_BITS,
                 'dh_grp'            : DH_DEFAULT_MODP_GROUP,
                 'dh_mod_size'       : DH_DEFAULT_MOD_SIZE_BITS,
                 'dh_exp_size'       : DH_DEFAULT_EXP_SIZE_BITS,
                 'benchmark'         : False,
                 'backend'           : 'SA_PyCrypto'}

backend_modules = {'SA_PyCrypto' : SA_PyCrypto}#,
#'SA_Charm' : SA_Charm}

def configure(**configs):
    global configuration
    for k, v in configs.items():
        if configuration[k] != None:
            configuration[k] = v
#end configure()

def at_fork():
    if configuration['backend'] == 'SA_PyCrypto':
        raf()
#end def atfork()

def nonce(size = None):
    backend = backend_modules[configuration['backend']]
    if size == None:
        size = configuration['nonce_size']
    if backend != None:
        return backend.nonce(size)
#end nonce()

def keygen(key_type, key_size = None, block_mode = None, hash_alg = None,
           key_mat = None, use_dh_group = True, curve = None,
           dh_group = None, dh_mod_size = None, dh_p = None, dh_g = None):
    backend = backend_modules[configuration['backend']]
    if key_type == 'random':
        return backend.keygen_random(key_size)
    elif key_type in MAC_ALGORITHMS:
        if key_type == 'mac':
            key_type = configuration['mac_alg']
        if key_size == None:
            key_size = (configuration['mac_key_size'] // 8)
        if hash_alg == None:
            hash_alg = configuration['hash_alg']
        return backend.keygen_mac(key_size, key_type, hash_alg, key_mat)
    elif key_type in SYM_CIPHERS:
        if key_type == 'shared':
            key_type = configuration['sym_cipher']
        if key_size == None:
            key_size = (configuration['sym_key_size'][key_type])
        if block_mode == None:
            block_mode = configuration['block_mode']
        return backend.keygen_shared(key_size, key_type, block_mode, key_mat)
    elif key_type in PUBLIC_CIPHERS:
        if key_type == 'public':
            key_type = configuration['pub_cipher']
        if key_size == None:
            key_size = configuration['pub_key_size']
        if hash_alg == None:
            hash_alg = configuration['hash_alg']
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

def encrypt(plaintext, *, key, iv = None):
    backend = backend_modules[configuration['backend']]
    if key['alg'] in PUBLIC_CIPHERS:
        return backend.asym_encrypt(plaintext, key)
    else:
        return backend.sym_encrypt(plaintext, key, iv)
#end encrypt()

def decrypt(ciphertext, *, key):
    backend = backend_modules[configuration['backend']]
    if key['alg'] in PUBLIC_CIPHERS:
        return backend.asym_decrypt(ciphertext, key)
    else:
        return backend.sym_decrypt(ciphertext, key)
#end decrypt()

def sign(data, *, key):
    backend = backend_modules[configuration['backend']]
    if key['alg'] in PUBLIC_CIPHERS:
        return backend.pubkey_sign(data, key)
    else:
        return backend.mac_sign(data, key)
#end sign()

def verify(data, *, key):
    backend = backend_modules[configuration['backend']]
    if key['alg'] in PUBLIC_CIPHERS:
        if configuration['verify_returns'] == 'data':
            return backend.pubkey_verify(data, key)
        if configuration['verify_returns'] == 'bool':
            return backend.pubkey_verify1(data[0], data[1], key)
    else:
        if configuration['verify_returns'] == 'data':
            return backend.mac_verify(data, key)
        if configuration['verify_returns'] == 'bool':
            return backend.mac_verify1(data[0], data[1], key)
#end verify()
