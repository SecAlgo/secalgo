import json, time, pickle
import sa.sec_algo_pycrypto as SA_PyCrypto
#import sa.sec_algo_charm as SA_Charm
from Crypto.Random import atfork as raf


# Constants for testing and measurements
KEYGEN  = 0
ENCRYPT = 1
DECRYPT = 2
SIGN    = 3
VERIFY  = 4
NONCE   = 5

proto_loops = {'ds'          : 400,
               'ds-pk'       : 300,
               'ns-sk'       : 1000,
               'ns-skA'      : 1000,
               'ns-skB'      : 1000,
               'ns-skC'      : 1000,
               'ns-sk_fixed' : 1000,
               'ns-sk_fixedA' : 1000,
               'ns-sk_fixedB' : 1000,
               'ns-sk_fixedC' : 1000,
               'ns-pk'       : 300,
               'ns-pkA'       : 300,
               'ns-pkB'       : 300,
               'ns-pkC'       : 300,
               'or'          : 1000,
               'wl'          : 500,
               'ya'          : 1000,
               'dhke-1'      : 100,
               'sdh'         : 50,
               'kerberos5'   : 300,
               'tls1_2'      : 50}

keyed_methods = {'encrypt', 'decrypt', 'sign', 'verify'}

public_method_loops = {'keygen'  : 4,
                       'encrypt' : 4000,
                       'decrypt' : 300,
                       'sign'    : 300,
                       'verify'  : 4000}

shared_method_loops = {'keygen'  : 10000,
                       'encrypt' : 10000,
                       'decrypt' : 15000,
                       'sign'    : 15000,
                       'verify'  : 15000,
                       'nonce'   : 15000}

# End Constants for testing and measurements

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
PUBLIC_CIPHERS = {'RSA', 'DSA', 'public'}
SYM_CIPHERS = {'AES', 'DES', 'DES3', 'Blowfish', 'shared'}
MAC_ALGORITHMS = {'HMAC', 'mac'}
HASH_FUNCTIONS = {'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512'}

config_fn = 'config.sac'

default_cfg = {'sym_cipher'        : 'AES',
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

with open(config_fn, 'w') as f:
    json.dump(default_cfg, f)

def configure(**configs):
    with open(config_fn, 'r') as f1:
        current_cfg = json.load(f1)
    for k, v in configs.items():
        if current_cfg[k] != None:
            current_cfg[k] = v
    with open(config_fn, 'w') as f2:
        json.dump(current_cfg, f2)
#end security_declarations()

# This decorator is applied to the run function of process classes in protocols
# we wish to time.
def dec_proto_run_timer(func):
    def proto_run_timer(*args, **kwargs):
        start_time = time.process_time()
        for i in range(proto_loops[func.__module__]):
            func(*args, **kwargs)
        print(json.dumps([func.__module__, func.__qualname__, start_time,
                          time.process_time(), (i + 1)]))
    #end proto_timer()
    return proto_run_timer
#end dec_proto_timer()

def dec_proto_await_timer(func):
    def proto_await_timer(*args, **kwargs):
        start_time = time.process_time()
        func(*args, **kwargs)
        print(json.dumps([func.__module__, func.__qualname__, start_time,
                          time.process_time(), proto_loops[func.__module__]]))
    #end proto_await_timer()
    return proto_await_timer
#end dec_proto_await_timer()

def dec_timer(func):
    def timer(*args, **kwargs):
        start_time = time.process_time()
        #end_time = 0
        #i = 0
        #while ((end_time - start_time) < 2):
        #print('ARGS:', args)
        #print('KWARGS:', kwargs)
        if ((func.__name__ in keyed_methods and kwargs['key']['alg'] in PUBLIC_CIPHERS) or
            (func.__name__ is 'keygen' and args[0] in PUBLIC_CIPHERS)):
            loops = public_method_loops[func.__name__]
        else:
            loops = shared_method_loops[func.__name__]
        for i in range(loops):
            result = func(*args, **kwargs)
            #if i == 0:
                #result = func(*args, **kwargs)
            #else:
            #    trash = func(*args, **kwargs)
            #end_time = time.process_time()
            #i += 1
        print(json.dumps([func.__name__, start_time, time.process_time(), (i + 1)]))
        return result
    #end timer()
    return timer
#end dec_timer()

def get_backend(cfg_backend):
    backend = None
    if cfg_backend == 'SA_PyCrypto':
        backend =  SA_PyCrypto
    elif cfg_backend == 'SA_Charm':
        backend = SA_Charm
    else:
        print('SA_ERROR: Backend library, ' + current_cfg['backend'] +
              ', not recognized.', flush = True)
    return backend

def at_fork():
    with open(config_fn, 'r') as f:
        current_cfg = json.load(f)
    if current_cfg['backend'] == 'SA_PyCrypto':
        raf()
#end def atfork()

@dec_timer
def nonce(size = None):
    with open(config_fn, 'r') as f:
        current_cfg = json.load(f)
    backend = get_backend(current_cfg['backend'])
    if size == None:
        size = current_cfg['nonce_size']
    if backend != None:
        return backend.nonce(size)
#end nonce()

@dec_timer
def keygen(key_type, key_size = None, block_mode = None, hash_alg = None,
           key_mat = None, use_dh_group = True,
           dh_group = None, dh_mod_size = None, dh_p = None, dh_g = None):
    with open(config_fn, 'r') as f:
        current_cfg = json.load(f)
    backend = get_backend(current_cfg['backend'])
    if key_type == 'random':
        return backend.keygen_random(key_size)
    elif key_type in MAC_ALGORITHMS:
        if key_type == 'mac':
            key_type = current_cfg['mac_alg']
        if key_size == None:
            key_size = (current_cfg['mac_key_size'] // 8)
        if hash_alg == None:
            hash_alg = current_cfg['hash_alg']
        return backend.keygen_mac(key_size, key_type, hash_alg, key_mat)
    elif key_type in SYM_CIPHERS:
        if key_type == 'shared':
            key_type = current_cfg['sym_cipher']
        if key_size == None:
            key_size = (current_cfg['sym_key_size'][key_type])
        if block_mode == None:
            block_mode = current_cfg['block_mode']
        return backend.keygen_shared(key_size, key_type, block_mode, key_mat)
    elif key_type in PUBLIC_CIPHERS:
        if key_type == 'public':
            key_type = current_cfg['pub_cipher']
        if key_size == None:
            key_size = current_cfg['pub_key_size']
        if hash_alg == None:
            hash_alg = current_cfg['hash_alg']
        return backend.keygen_public(key_size, key_type, hash_alg)
    elif key_type == 'diffie-hellman' or key_type == 'dh':
        if key_size == None:
            key_size = current_cfg['dh_exp_size']
        if use_dh_group:
            if dh_group == None:
                dh_group = current_cfg['dh_grp']
        else:
            if dh_p == None and dh_mod_size == None:
                dh_mod_size = current_cfg['dh_mod_size']
        return backend.keygen_dh(key_size, use_dh_group, dh_group,
                                 dh_mod_size, dh_p, dh_g)
#end keygen()

@dec_timer
def encrypt(plaintext, *, key):
    with open(config_fn, 'r') as f:
        current_cfg = json.load(f)
    backend = get_backend(current_cfg['backend'])
    if key['alg'] in PUBLIC_CIPHERS:
        return backend.asym_encrypt(plaintext, key)
    else:
        return backend.sym_encrypt(plaintext, key)
#end encrypt()

@dec_timer
def decrypt(ciphertext, *, key):
    with open(config_fn, 'r') as f:
        current_cfg = json.load(f)
    backend = get_backend(current_cfg['backend'])
    if key['alg'] in PUBLIC_CIPHERS:
        return backend.asym_decrypt(ciphertext, key)
    else:
        return backend.sym_decrypt(ciphertext, key)
#end decrypt()

@dec_timer
def sign(data, *, key):
    with open(config_fn, 'r') as f:
        current_cfg = json.load(f)
    backend = get_backend(current_cfg['backend'])
    if key['alg'] in PUBLIC_CIPHERS:
        return backend.pubkey_sign(data, key)
    else:
        return backend.mac_sign(data, key)
#end sign()

@dec_timer
def verify(data, *, key):
    with open(config_fn, 'r') as f:
        current_cfg = json.load(f)
    backend = get_backend(current_cfg['backend'])
    if key['alg'] in PUBLIC_CIPHERS:
        if current_cfg['verify_returns'] == 'data':
            return backend.pubkey_verify(data, key)
        if current_cfg['verify_returns'] == 'bool':
            return backend.pubkey_verify1(data[0], data[1], key)
    else:
        if current_cfg['verify_returns'] == 'data':
            return backend.mac_verify(data, key)
        if current_cfg['verify_returns'] == 'bool':
            return backend.mac_verify1(data[0], data[1], key)
#end verify()

# Public/Private key access functions hack
# setup code
#public_fn = 'public_keys.sac' #name for file storing public keys
#private_fn = 'private_keys.sac' #name for file storing private keys

# These two blocks overwrite any existing public and private key files with
# new files containing empty dictionaries. This ensures that the files are
# always present when register or the access functions try to open them, and
# that keys used by any previous protcol executions are eliminated.
#with open(public_fn, 'wb') as f:
#    pickle.dump(dict(), f)
#with open(private_fn, 'wb') as f:
#    pickle.dump(dict(), f)

# Works exactly the same as my persistent configurations. Opens the file
# corresponding to the type of the key, loads the dictionary holding the
# keys into a local reference. Then adds the new key to the dictionary
# using the process id of the owner of the key as the key. The modified
# dictionary is then written to the key file.
#def register_key(type, id, key):
#    if type == 'public':
#        with open(public_fn, 'rb') as f:
#            public_keys = pickle.load(f)
#        public_keys[id] = key
#        with open(public_fn, 'wb') as f:
#            pickle.dump(public_keys, f)
#    elif type == 'private':
#        with open(private_fn, 'rb') as f:
#            private_keys = pickle.load(f)
#        private_keys[id] = key
#        with open(private_fn, 'wb') as f:
#            pickle.dump(private_keys, f)
#end register_key()

# Reads the public key file and returns the key owned by id
#def pk(id):
#    with open(public_fn, 'rb') as f:
#        public_keys = pickle.load(f)
#    return public_keys[id]
#end pk()

# Reads the private key file and returns the key owned by id
#def sk(id):
#    with open(private_fn, 'rb') as f:
#        private_keys = pickle.load(f)
#    return private_keys[id]
#end sk()

# end Public/Private key access functions hack
