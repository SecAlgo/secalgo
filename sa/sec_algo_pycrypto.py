import sys
import random
import pickle
import json
import resource
import time
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Hash import HMAC
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import _RSAobj
from Crypto.Hash import SHA256
from Crypto import Random
from Crypto.Random.random import getrandbits
from sa.Misc.Padding import pkcs7_pad, pkcs7_unpad
from Crypto.Util.number import getPrime, isPrime, size, getRandomNBitInteger

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
PUBLIC_CIPHERS = {'RSA', 'DSA'}

#benchmark = False

config_fn = 'config.sac'

default_configuration = {'sym_cipher' : 'AES',
                         'sym_mode' : 'CBC',
                         'sym_key_size' : SYM_KEY_DEFAULT_SIZE_BITS,
                         'mac_alg' : 'HMAC',
                         'mac_key_size' : MAC_KEY_DEFAULT_SIZE_BITS,
                         'pub_cipher' : 'RSA',
                         'pub_key_size' : KEY_PAIR_DEFAULT_SIZE_BITS,
                         'nonce_size' : NONCE_DEFAULT_SIZE_BITS,
                         'dh_grp' : DH_DEFAULT_MODP_GROUP,
                         'dh_mod_size' : DH_DEFAULT_MOD_SIZE_BITS,
                         'dh_exp_size' : DH_DEFAULT_EXP_SIZE_BITS}

with open(config_fn, 'w') as f:
    json.dump(default_configuration, f)

def configure(**configs):
    with open(config_fn, 'r') as f1:
        current_cfg = json.load(f1)
        for k, v in configs.items():
            if current_cfg[k] != None:
                current_cfg[k] = v
    with open(config_fn, 'w') as f2:
        json.dump(current_cfg, f2)
#end security_declarations()

'''
def dec_timer(func):
    def timer(*args, **kwargs):
        start_time = time.process_time()
        result = func(*args, **kwargs)
        print(json.dumps([func.__name__, start_time, time.process_time()]), flush = True)
        return result
    if benchmark:
        return timer
    else:
        return func
#end timer()
'''

#@dec_timer
def nonce(size = NONCE_DEFAULT_SIZE_BITS):
    Random.atfork()
    return getrandbits(size)
#end gen_nonce

#@dec_timer
def keygen(key_type, key_size = None, use_dh_group = True, dh_group = None,
           dh_mod_size = None, dh_p = None, dh_g = None):
    Random.atfork()
    if key_type == 'random':
        if key_size == None:
            print('SA_ERROR: \'random\' option for keygen requires a size argument.')
        return Random.new().read(key_size)
    elif key_type == 'mac':
        return keygen_mac(key_size)   
    elif key_type == 'shared':
        return keygen_shared(key_size)
    elif key_type == 'public':
        return keygen_public(key_size)
    elif key_type == 'diffie-hellman' or key_type == 'dh':
        return keygen_dh(key_size, use_dh_group, dh_group, dh_mod_size, dh_p,
                         dh_g)
#end genkey()

def keygen_mac(key_size):
    with open(config_fn, 'r') as f:
        current_cfg = json.load(f)
    if key_size == None:
        key_size = current_cfg['mac_key_size']
    new_key = Random.new().read(key_size)
    new_key_dict = {'alg' : current_cfg['mac_alg'],
                    'key' : new_key}
    return new_key_dict
#end keygen_mac()

def keygen_public(key_size):
    with open(config_fn, 'r') as f:
        current_cfg = json.load(f)
    if key_size == None:
        key_size = current_cfg['pub_key_size']
    if current_cfg['pub_cipher'] == 'RSA':
        key_pair = RSA.generate(key_size)
        priv_key = key_pair.exportKey()
        pub_key = key_pair.publickey().exportKey()
        priv_key_dict = {'alg' : 'RSA', 'type' : 'private', 'key' : priv_key}
        pub_key_dict = {'alg' : 'RSA', 'type' : 'public', 'key' : pub_key}
        return priv_key_dict, pub_key_dict
    else:
        print('SA_ERROR:', alg, 'not yet implemented.', flush = True)
#end gen_key_pair()

def keygen_shared(key_size):
    with open(config_fn, 'r') as f:
        current_cfg = json.load(f)
    if key_size == None:
        key_size = (current_cfg['sym_key_size'] // 8)
    new_key =  Random.new().read(key_size)
    key_dict = {'alg' : current_cfg['sym_cipher'],
                'mode' : current_cfg['sym_mode'],
                'key' : new_key}
    return key_dict
#end gen_sym_key

def keygen_dh(key_size, use_group, dh_group, dh_mod_size, dh_p, dh_g):
    with open(config_fn, 'r') as f:
        current_cfg = json.load(f)
    if key_size == None:
        key_size = current_cfg['dh_exp_size']
    if use_group == True:        
        if dh_group == None:
            dh_group = current_cfg['dh_grp']
        dh_p = modp_groups[dh_group]['p']
        dh_g = modp_groups[dh_group]['g']
        dh_mod_size = size(dh_p)
    else:
        # check parameters, assign defaults if necessary
        if dh_p != None:
            dh_mod_size = size(dh_p)
        else:
            dh_mod_size = current_cfg['dh_mod_size']

        # print('###########:', key_size, dh_mod_size, flush = True)
        # generate new safe prime to define finite field
        # This is pretty efficient
        if dh_p == None:
            dh_p = 0
            count = 0
            while not isPrime(dh_p):
                count += 1
                q = getPrime(dh_mod_size - 1)
                dh_p = (2 * q) + 1
            #print('Fresh q:', count, q, flush = True)
            #print('Fresh p:', count, dh_p, flush = True) 

        #define new generator for the finite field
        if dh_g == None:
            dh_g = 2
            generator_found = False
            count2 = 0
            while (generator_found == False) and (dh_g < dh_p):
                count2 += 1
                generator_found = True
                #print('&&&&&&&&&&:', count2, 1)
                if pow(dh_g, 2, dh_p) == 1:
                    generator_found = False
                    #print('&&&&&&&&&&:', count2, 2)
                if generator_found == True and pow(dh_g, q, dh_p) == 1:
                    generator_found = False
                    #print('&&&&&&&&&&:', count2, 3)
                if generator_found == False:
                    dh_g += 1
                    #print('&&&&&&&&&&:', count2, 4)
            #print('Fresh g:', count2, dh_g)
    #DH Group Parameters have now been established
    
    #generate new exponent (secret key derivation value)
    dh_x = getRandomNBitInteger(key_size)

    #generate dh_X = dh_g ** dh_x (mod dh_p) (public key derivation value)
    dh_X = pow(dh_g, dh_x, dh_p)

    #first value must remain secret, the rest is public
    return (dh_x, dh_X, dh_g, dh_p)
#end gen_dh_key()

#@dec_timer
def encrypt(plaintext, key):
    Random.atfork()
    if key['alg'] in PUBLIC_CIPHERS:
        return asym_encrypt(plaintext, key)
    else:
        return sym_encrypt(plaintext, key)
#end encrypt

def sym_encrypt(plaintext, key):
    serial_pt = pickle.dumps(plaintext)
    alg = key['alg']
    mode = key['mode']
    k = key['key']
    ciphertext = None
    if alg == 'AES':
        #print('$$$$$$$$$$: Encrypt: USING AES')
        if mode == 'CTR':
            #print('$$$$$$$$$$: Encrypt: USING CTR')
            pre = Random.new().read(8)
            ctr = Counter.new(64, prefix = pre)
            encrypter = AES.new(k, AES.MODE_CTR, counter = ctr)
            ciphertext =  pre + encrypter.encrypt(serial_pt)
        elif mode == 'CBC':
            #print('$$$$$$$$$$: Encrypt: USING CBC')
            padded_pt = pkcs7_pad(serial_pt)
            iv = Random.new().read(16)
            encrypter = AES.new(k, AES.MODE_CBC, iv)
            ciphertext = iv + encrypter.encrypt(padded_pt)
        elif mode == 'ECB':
            #print('$$$$$$$$$$: Encrypt: USING ECB')
            padded_pt = pkcs7_pad(serial_pt)
            encrypter = AES.new(k, AES.MODE_ECB)
            ciphertext = encrypter.encrypt(padded_pt)
        elif mode == 'CFB':
            #print('$$$$$$$$$$: Encrypt: USING CFB')
            seg_size = 8
            padded_pt = pkcs7_pad(serial_pt, seg_size)
            iv = Random.new().read(16)
            encrypter = AES.new(k, AES.MODE_CFB, iv, segment_size=seg_size)
            ciphertext = iv + encrypter.encrypt(padded_pt)
    return ciphertext
#end sym_encrypt()

def asym_encrypt(plaintext, key):
    alg = key['alg']
    k = key['key']
    serial_pt = pickle.dumps(plaintext)
    ct_list = None
    if alg == 'RSA':
        pubk = RSA.importKey(k)
        kpdsb = KEY_PAIR_DEFAULT_SIZE_BYTES
        frag_counter = (len(serial_pt) // kpdsb) + 1
        ct_list = []
        for i in range(frag_counter):
            frag = serial_pt[(i * kpdsb):((i + 1) * kpdsb)]
            ciphertext = pubk.encrypt(frag, '')
            ct_list.append(ciphertext)
        #end for
        return ct_list
    else:
        print('SA_ERROR:', alg, 'not yet implemented.', flush = True) 
#end asym_encrypt()

#@dec_timer
def decrypt(ciphertext, key):
    Random.atfork()
    if key['alg'] in PUBLIC_CIPHERS:
        return asym_decrypt(ciphertext, key)
    else:
        return sym_decrypt(ciphertext, key)
#end decrypt()

def sym_decrypt(ciphertext, key):
    alg = key['alg']
    mode = key['mode']
    k = key['key']
    if alg == 'AES':
        #print('$$$$$$$$$$: Decrypt: USING AES')
        if mode == 'CTR':
            #print('$$$$$$$$$$: Decrypt: USING CTR')
            pre = ciphertext[0:8]
            ctr = Counter.new(64, prefix = pre)
            decrypter = AES.new(k, AES.MODE_CTR, counter = ctr)
            serial_pt = decrypter.decrypt(ciphertext[8:])
        elif mode == 'CBC':
            #print('$$$$$$$$$$: Decrypt: USING CBC')
            iv = ciphertext[0:16]
            decrypter = AES.new(k, AES.MODE_CBC, iv)
            padded_pt = decrypter.decrypt(ciphertext[16:])
            serial_pt = pkcs7_unpad(padded_pt)
        elif mode == 'ECB':
            #print('$$$$$$$$$$: Decrypt: USING ECB')
            decrypter = AES.new(k, AES.MODE_ECB)
            padded_pt = decrypter.decrypt(ciphertext)
            serial_pt = pkcs7_unpad(padded_pt)
        elif mode == 'CFB':
            #print('$$$$$$$$$$: Encrypt: USING CFB')
            seg_size = 8
            iv = ciphertext[0:16]
            decrypter = AES.new(k, AES.MODE_CFB, iv, segment_size = seg_size)
            padded_pt = decrypter.decrypt(ciphertext[16:])
            serial_pt = pkcs7_unpad(padded_pt, seg_size)
    return pickle.loads(serial_pt)
#end sym_decrypt()

def asym_decrypt(ct_list, key):
    serial_pt = b''
    alg = key['alg']
    k = key['key']
    privk = None
    if alg == 'RSA':
        privk = RSA.importKey(k)
        for ciphertext in ct_list:
            serial_pt += privk.decrypt(ciphertext)
        #end for
        plaintext = pickle.loads(serial_pt)
        return plaintext
    else:
        print('SA_ERROR:', alg, 'not yet implemented.', flush = True)
#end asym_decrypt()

#@dec_timer
def sign(data, key):
    Random.atfork()
    if key['alg'] in PUBLIC_CIPHERS:
        return pubkey_sign(data, key)
    else:
        return mac_sign(data, key)
#end sign()

def mac_sign(data, key):
    Random.atfork()
    serial_data = pickle.dumps(data)
    alg = key['alg']
    k = key['key']
    if alg == 'HMAC':
        h = HMAC.new(k, serial_data, SHA256)
        sig = h.digest()
        result = (serial_data, sig)
        s_result = pickle.dumps(result)
        return s_result
    else:
        print('SA_ERROR:', alg, 'not yet implemented.', flush = True)
#end mac_sign()    
        
def pubkey_sign(data, key):
    Random.atfork()
    serial_data = pickle.dumps(data)
    alg = key['alg']
    k = key['key']
    if alg == 'RSA':
        pubk = RSA.importKey(k)
        sig = pubk.sign(SHA256.new(serial_data).digest(), '')
        result = (serial_data, sig[0].to_bytes(((sig[0].bit_length() // 8) + 1), 
                                               byteorder = 'little'))
        s_result = pickle.dumps(result)
        return s_result
    else:
        print('SA_ERROR:', alg, 'not yet implemented.', flush = True) 
#end pubkey_sign()

#returns signed data if verification succeeds
#returns None if verification fails
#@dec_timer
def verify(data, key):
    Random.atfork()
    if key['alg'] in PUBLIC_CIPHERS:
        return pubkey_verify(data, key)
    else:
        return mac_verify(data, key)
#end verify()

#returns True if verification succeeds
#returns False if verification fails
#@dec_timer
def verify1(data, signed_data, key):
    Random.atfork()
    if key['alg'] in PUBLIC_CIPHERS:
        return pubkey_verify1(data, signed_data, key)
    else:
        return mac_verify1(data, signed_data, key)
#end verify1()

def mac_verify(data, key):
    Random.atfork()
    alg = key['alg']
    k = key['key']
    if alg == 'HMAC':
        serial_data, sig = pickle.loads(data)
        verdict = (sig == HMAC.new(k, serial_data, SHA256).digest())
        if verdict:
            return pickle.loads(serial_data)
        else:
            return none
    else:
        print('SA_ERROR:', alg, 'not yet implemented.', flush = True)
#end mac_verify()

def mac_verify1(data, signed_data, key):
    Random.atfork()
    alg = key['alg']
    k = key['key']
    if alg == 'HMAC':
        serial_data, sig = pickle.loads(signed_data)
        verdict = (sig == HMAC.new(k, pickle.dumps(data), SHA256).digest())
        return verdict
    else:
        print('SA_ERROR:', alg, 'not yet implemented.', flush = True)
#end mac_verify1()
    
#returns None when verfication fails
def pubkey_verify(data, key):
    Random.atfork()
    unp_data = pickle.loads(data)
    alg = key['alg']
    k = key['key']
    if alg == 'RSA':
        privk = RSA.importKey(k)
        sig = (int.from_bytes(unp_data[1], byteorder = 'little'), )
        verdict = privk.verify(SHA256.new(unp_data[0]).digest(), sig)
        if verdict:
            return pickle.loads(unp_data[0])
        else:
            return None
    else:
        print('SA_ERROR:', alg, 'not yet implemented.', flush = True)
#end pubkey_verify()

def pubkey_verify1(data, signed_data, key):
    Random.atfork()
    unp_data = pickle.loads(signed_data)
    alg = key['alg']
    k = key['key']
    if alg == 'RSA':
        privk = RSA.importKey(k)
        sig = (int.from_bytes(unp_data[1], byteorder = 'little'), )
        verdict = privk.verify(SHA256.new(pickle.dumps(data)).digest(), sig)
        return verdict
    else:
        print('SA_ERROR:', alg, 'not yet implemented.', flush = True)
#end verify1()

modp_groups = {
    5 :
    { 'p' : 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF,
      'g' : 2 },
    14 :
    { 'p' : 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF,
      'g' : 2 },
    15 :
    { 'p' : 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF,
      'g' : 2 },
    16 :
    { 'p' : 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF,
      'g' : 2 },
    17 :
    { 'p' : 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF,
      'g' : 2},
    18 :
    { 'p' : 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF,
      'g' : 2 }
}
