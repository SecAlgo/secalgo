import json, time 
import sa.sec_algo_pycrypto as SA_Pycrypto
#import sa.sec_algo_charm as SA_Charm

KEY_PAIR_DEFAULT_SIZE_BITS = 2048
KEY_PAIR_DEFAULT_SIZE_BYTES = 256
SYM_KEY_DEFAULT_SIZE_BITS = 256
SYM_KEY_DEFAULT_SIZE_BYTES = 32
MAC_KEY_DEFAULT_SIZE_BITS = 256
MAC_KEY_DEFAULT_SIZE_BYTES = 32
NONCE_DEFAULT_SIZE_BITS = 128
DH_DEFAULT_MOD_SIZE_BITS = 2048
DH_DEFAULT_EXP_SIZE_BITS = 512
DH_DEFAULT_MODP_GROUP = 14
PUBLIC_CIPHERS = {'RSA', 'DSA', 'public'}
SYM_CIPHERS = {'AES', 'DES', '3DES', 'Blowfish', 'shared'}

config_fn = 'config.sac'

default_cfg = {'sym_cipher'        : 'AES',
               'sym_mode'          : 'CBC',
               'sym_key_size'      : SYM_KEY_DEFAULT_SIZE_BITS,
               'mac_alg'           : 'HMAC',
               'mac_key_size'      : MAC_KEY_DEFAULT_SIZE_BITS,
               'pub_cipher'        : 'RSA',
               'pub_key_size'      : KEY_PAIR_DEFAULT_SIZE_BITS,
               'verify_returns'    : 'data', 
               'nonce_size'        : NONCE_DEFAULT_SIZE_BITS,
               'dh_grp'            : DH_DEFAULT_MODP_GROUP,
               'dh_mod_size'       : DH_DEFAULT_MOD_SIZE_BITS,
               'dh_exp_size'       : DH_DEFAULT_EXP_SIZE_BITS,
               'benchmark'         : False,
               'backend'           : 'SA_Pycrypto'}

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

def dec_timer(func):
    with open(config_fn, 'r') as f:
        current_cfg = json.load(f)
    def timer(*args, **kwargs):
        start_time = time.process_time()
        result = func(*args, **kwargs)
        print(json.dumps([func.__name__, start_time, time.process_time()]), flush = True)
        return result
    #end timer()
    if current_cfg['benchmark']:
        return timer
    else:
        return func
#end dec_timer()

def get_backend(cfg_backend):
    backend = None
    if cfg_backend == 'SA_Pycrypto':
        backend =  SA_Pycrypto
    elif cfg_backend == 'SA_Charm':
        backend = SA_Charm
    else:
        print('SA_ERROR: Backend library, ' + current_cfg['backend'] +
              ', not recognized.', flush = True)
    return backend

#@dec_timer
def nonce(size = None):
    with open(config_fn, 'r') as f:
        current_cfg = json.load(f)
    backend = get_backend(current_cfg['backend'])
    if size == None:
        size = current_cfg['nonce_size']
    if backend != None:
        return backend.nonce(size)
#end nonce()

#@dec_timer
def keygen(key_type, key_size = None, use_dh_group = True, dh_group = None,
           dh_mod_size = None, dh_p = None, dh_g = None):
    with open(config_fn, 'r') as f:
        current_cfg = json.load(f)
    backend = get_backend(current_cfg['backend'])
    if key_type == 'random':
        return backend.keygen_random(key_size)
    elif key_type == 'mac':
        if key_size == None:
            key_size = (current_cfg['mac_key_size'] // 8)
        return backend.keygen_mac(key_size, current_cfg['mac_alg'])
    elif key_type in SYM_CIPHERS:
        if key_type == 'shared':
            key_type = current_cfg['sym_cipher']
        if key_size == None:
            key_size = (current_cfg['sym_key_size'] // 8)
        return backend.keygen_shared(key_size, key_type, current_cfg['sym_mode'])
    elif key_type in PUBLIC_CIPHERS:
        if key_type == 'public':
            key_type = current_cfg['pub_cipher']
        if key_size == None:
            key_size = current_cfg['pub_key_size']
        return backend.keygen_public(key_size, key_type)
    elif key_type == 'diffie-hellman' or key_type == 'dh':
        if key_size == None:
            key_size = current_cfg['dh_exp_size']
        if use_dh_group == True:
            if dh_group == None:
                dh_group = current_cfg['dh_grp']
        else:
            if dh_p == None:
                dh_mod_size = current_cfg['dh_mod_size']
        return backend.keygen_dh(key_size, use_dh_group, dh_group, dh_mod_size, dh_p,
                         dh_g)
#end keygen()

#@dec_timer
def encrypt(plaintext, key):
    with open(config_fn, 'r') as f:
        current_cfg = json.load(f)
    backend = get_backend(current_cfg['backend'])
    if key['alg'] in PUBLIC_CIPHERS:
        return backend.asym_encrypt(plaintext, key)
    else:
        return backend.sym_encrypt(plaintext, key)
#end encrypt()

#@dec_timer
def decrypt(ciphertext, key):
    with open(config_fn, 'r') as f:
        current_cfg = json.load(f)
    backend = get_backend(current_cfg['backend'])
    if key['alg'] in PUBLIC_CIPHERS:
        return backend.asym_decrypt(ciphertext, key)
    else:
        return backend.sym_decrypt(ciphertext, key)
#end decrypt()

#@dec_timer
def sign(data, key):
    with open(config_fn, 'r') as f:
        current_cfg = json.load(f)
    backend = get_backend(current_cfg['backend'])
    if key['alg'] in PUBLIC_CIPHERS:
        return backend.pubkey_sign(data, key)
    else:
        return backend.mac_sign(data, key)
#end sign()

#@dec_timer
def verify(data, key):
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
