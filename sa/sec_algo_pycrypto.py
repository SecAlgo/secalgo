import sys
import random
import pickle
import json
import time
from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.Cipher import DES3
from Crypto.Cipher import Blowfish
from Crypto.Util import Counter
from Crypto.Hash import HMAC
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA224
from Crypto.Hash import SHA256
from Crypto.Hash import SHA384
from Crypto.Hash import SHA512
from Crypto import Random
from Crypto.Random.random import getrandbits
from sa.Misc.Padding import pkcs7_pad, pkcs7_unpad
from Crypto.Util.number import getPrime, isPrime, size, getRandomNBitInteger

usePickleTimer = {'pickle' : False, 'pickle_loop' : False}
#usePickleTimer = {'pickle' : True, 'pickle_loop' : True}
pickle_loops = 2000000

PAD_MODES = {'ECB', 'CBC'}
IV_MODES = {'CBC', 'CFB'}
BLOCK_CIPHERS = {'AES' : AES,
                 'DES' : DES,
                 'DES3' : DES3,
                 'Blowfish' : Blowfish}
BLOCK_SIZES = {'AES' : AES.block_size,
               'DES' : DES.block_size,
               'DES3': DES3.block_size,
               'Blowfish' : Blowfish.block_size}
BLOCK_MODES = {'AES' : {'ECB' : AES.MODE_ECB,
                        'CBC' : AES.MODE_CBC,
                        'CFB' : AES.MODE_CFB,
                        'CTR' : AES.MODE_CTR},
               'DES' : {'ECB' : DES.MODE_ECB,
                        'CBC' : DES.MODE_CBC,
                        'CFB' : DES.MODE_CFB,
                        'CTR' : DES.MODE_CTR},
               'DES3' : {'ECB' : DES3.MODE_ECB,
                         'CBC' : DES3.MODE_CBC,
                         'CFB' : DES3.MODE_CFB,
                         'CTR' : DES3.MODE_CTR},
               'Blowfish' : {'ECB' : Blowfish.MODE_ECB,
                             'CBC' : Blowfish.MODE_CBC,
                             'CFB' : Blowfish.MODE_CFB,
                             'CTR' : Blowfish.MODE_CTR}}

def timedPickleDumps(pt, f):
    if usePickleTimer['pickle_loop']:
        start_time = time.process_time()
        for i in range(pickle_loops):
            serial_pt = pickle.dumps(pt)
        print(json.dumps(['pickle.dumps', f, start_time,
                          time.process_time(), pickle_loops]), flush = True)
    else:
        start_time = time.process_time()
        serial_pt = pickle.dumps(pt)
        print(json.dumps(['pickle.dumps', f, start_time,
                          time.process_time()]), flush = True)
    return serial_pt
#end def timedPickleDumps()

def timedPickleLoads(serial_pt, f):
    if usePickleTimer['pickle_loop']:
        start_time = time.process_time()
        for i in range(pickle_loops):
            pt = pickle.loads(serial_pt)
        print(json.dumps(['pickle.loads', f, start_time,
                          time.process_time(), pickle_loops]), flush = True)
    else:
        start_time = time.process_time()
        pt = pickle.loads(serial_pt)
        print(json.dumps(['pickle.loads', f, start_time,
                          time.process_time()]), flush = True)
    return pt
#end def timedPickleloads()

def nonce(size):
    return getrandbits(size)
#end nonce

def keygen_random(key_size):
    if key_size == None:
        print('SA_ERROR: \'random\' option for keygen requires a size argument.')
        return None
    else:
        return Random.new().read(key_size)
#end keygen_random()

def keygen_mac(key_size, alg, hash_alg, key_mat):
    if key_mat == None:
        new_key = Random.new().read(key_size)
    else:
        new_key = key_mat
    new_key_dict = {'alg' : alg,
                    'size' : key_size, 
                    'hash' : hash_alg,
                    'key' : new_key}
    return new_key_dict
#end keygen_mac()

def keygen_shared(key_size, alg, mode, key_mat = None):
    if key_mat == None:
        new_key =  Random.new().read(key_size // 8)
    else:
        new_key = key_mat
    key_dict = {'alg' : alg,
                'size': key_size,
                'mode' : mode,
                'key' : new_key}
    return key_dict
#end keygen_shared()

def keygen_public(key_size, alg, hash_alg):
    if alg == 'RSA':
        key_pair = RSA.generate(key_size)
        priv_key = key_pair.exportKey()
        pub_key = key_pair.publickey().exportKey()
        priv_key_dict = {'alg' : 'RSA', 'type' : 'private',
                         'size': key_size, 'hash' : hash_alg, 'key' : priv_key}
        pub_key_dict = {'alg' : 'RSA', 'type' : 'public',
                        'size': key_size, 'hash' : hash_alg, 'key' : pub_key}
        return priv_key_dict, pub_key_dict
    else:
        print('SA_ERROR:', alg, 'not yet implemented.', flush = True)
#end keygen_public()

def keygen_dh(key_size, use_group, dh_group, dh_mod_size, dh_p, dh_g):
    #print(key_size)
    #print(use_group)
    #print(dh_group)
    #print(dh_mod_size)
    #print(dh_p)
    #print(dh_g)
    if use_group == True:        
        dh_p = modp_groups[dh_group]['p']
        dh_g = modp_groups[dh_group]['g']
        dh_mod_size = size(dh_p)
    else:
        # check parameters, assign defaults if necessary
        if dh_p != None:
            dh_mod_size = size(dh_p)
        
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

def sym_encrypt(plaintext, key):
    if not isinstance(plaintext, bytes):
        if usePickleTimer['pickle']:
            serial_pt = timedPickleDumps(plaintext, 'sym_encrypt')
        else:
            #print('pickle')
            serial_pt = pickle.dumps(plaintext)
    else:
        serial_pt = plaintext
    alg = key['alg']
    mode = key['mode']
    k = key['key']
    ciphertext = None
    ctr = None
    iv = b''
    #seg_size = None
    ctr_pre = b''
    preamble = b''
    encrypt_kwargs = {'mode' : BLOCK_MODES[alg][mode]}
    if mode in PAD_MODES:
        #print('SYM_ENCRYPT: Padding Plaintext', flush = True)
        serial_pt = pkcs7_pad(serial_pt)
    if mode in IV_MODES:
        #print("SYM_ENCRYPT: Generating an IV", flush = True)
        iv = Random.new().read(BLOCK_SIZES[alg])
        encrypt_kwargs['IV'] = iv
        preamble = iv
    elif mode == 'CTR':
        #print('SYM_ENCRYPT: Generating a Counter', flush = True)
        ctr_pre = Random.new().read(BLOCK_SIZES[alg] // 2)
        ctr = Counter.new(((BLOCK_SIZES[alg]*8)//2), prefix = ctr_pre)
        encrypt_kwargs['counter'] = ctr
        preamble = ctr_pre
    #print(encrypt_kwargs, flush = True)
    if alg == 'AES':
        #print('SYM_ENCRYPT: USING AES')
        encrypter = AES.new(k, **encrypt_kwargs)
    elif alg == 'DES':
        #print('SYM_ENCRYPT: USING DES')
        encrypter = DES.new(k, **encrypt_kwargs)
    elif alg == 'DES3':
        #print('SYM_ENCRYPT: USING DES3')
        encrypter = DES3.new(k, **encrypt_kwargs)
    elif alg == 'Blowfish':
        #print('SYM_ENCRYPT: USING Blowfish')
        encrypter = Blowfish.new(k, **encrypt_kwargs)        
    return preamble + encrypter.encrypt(serial_pt)
#end sym_encrypt()

def asym_encrypt(plaintext, key):
    if not isinstance(plaintext, bytes):
        if usePickleTimer['pickle']:
            serial_pt = timedPickleDumps(plaintext, 'asym_encrypt1')
        else:
            #print('pickle')
            serial_pt = pickle.dumps(plaintext)
    else:
        serial_pt = plaintext
    alg = key['alg']
    k = key['key']
    if alg == 'RSA':
        pubk = RSA.importKey(k)
        oaep_cipher = PKCS1_OAEP.new(pubk)
        try:
            ciphertext =  oaep_cipher.encrypt(serial_pt)
        except ValueError: #Use Hybrid Encryption
            #print('**********: Using Hybrid Encryption!')
            shared_key = Random.new().read(32)
            iv = Random.new().read(16)
            sym_cipher = AES.new(shared_key, AES.MODE_CBC, iv)
            data_ct = sym_cipher.encrypt(pkcs7_pad(serial_pt))
            #shared_key = keygen_shared(256, 'AES', 'CBC')
            #data_ct = sym_encrypt(serial_pt, shared_key)
            #if usePickleTimer['pickle']:
            #    serial_key = timedPickleDumps(shared_key, 'asym_encrypt2')
            #else:
            #    serial_key = pickle.dumps(shared_key)
            #key_ct = oaep_cipher.encrypt(serial_key)
            key_ct = oaep_cipher.encrypt(shared_key)
            ciphertext = key_ct + iv + data_ct
        return ciphertext
    else:
        print('SA_ERROR:', alg, 'not yet implemented.', flush = True) 
#end asym_encrypt()

def sym_decrypt(ciphertext, key):
    alg = key['alg']
    mode = key['mode']
    k = key['key']
    preamble_length = None
    decrypt_kwargs = {'mode' : BLOCK_MODES[alg][mode]}
    if mode in IV_MODES:
        #print("SYM_DECRYPT: Generating an IV", flush = True)
        preamble_length = BLOCK_SIZES[alg]
        iv = ciphertext[0:preamble_length]
        decrypt_kwargs['IV'] = iv
    elif mode == 'CTR':
        #print('SYM_DECRYPT: Generating a Counter', flush = True)
        preamble_length = BLOCK_SIZES[alg] // 2
        ctr_pre = ciphertext[0:preamble_length]
        ctr = Counter.new(((BLOCK_SIZES[alg]*8)//2), prefix = ctr_pre)
        decrypt_kwargs['counter'] = ctr
    #print(decrypt_kwargs, flush = True)    
    if alg == 'AES':
        #print('SYM_DECRYPT: USING AES')
        decrypter = AES.new(k, **decrypt_kwargs)
    elif alg == 'DES':
        #print('SYM_DECRYPT: USING DES')
        decrypter = DES.new(k, **decrypt_kwargs)
    elif alg == 'DES3':
        #print('SYM_DECRYPT: USING DES3')
        decrypter = DES3.new(k, **decrypt_kwargs)
    elif alg == 'Blowfish':
        #print('SYM_DECRYPT: USING Blowfish')
        decrypter = Blowfish.new(k, **decrypt_kwargs)
    serial_pt = decrypter.decrypt(ciphertext[preamble_length:])
    if mode in PAD_MODES:
        serial_pt = pkcs7_unpad(serial_pt)
    if usePickleTimer['pickle']:
        pt = timedPickleLoads(serial_pt, 'sym_decrypt')
    else:
        try:
            pt = pickle.loads(serial_pt)
        except (pickle.PickleError, TypeError):
            #print('not pickle')
            return serial_pt
    return pt
#end sym_decrypt()

def asym_decrypt(ciphertext, key):
    serial_pt = b''
    alg = key['alg']
    size = key['size']
    k = key['key']
    privk = None
    if alg == 'RSA':
        privk = RSA.importKey(k)
        oaep_cipher = PKCS1_OAEP.new(privk)
        if len(ciphertext) > (size // 8): #Hybrid Encryption Used!
            #serial_key = oaep_cipher.decrypt(ciphertext[:256])
            #if usePickleTimer['pickle']:
            #    session_key = timedPickleLoads(serial_key, 'asym_decrypt2')
            #else:
            #    session_key = pickle.loads(serial_key)
            #serial_pt = sym_decrypt(ciphertext[256:], key = session_key)
            shared_key = oaep_cipher.decrypt(ciphertext[:256])
            iv = ciphertext[256:272]
            sym_cipher = AES.new(shared_key, AES.MODE_CBC, iv)
            serial_pt = pkcs7_unpad(sym_cipher.decrypt(ciphertext[272:]))
        else:
            serial_pt = oaep_cipher.decrypt(ciphertext)
        if usePickleTimer['pickle']:
            plaintext = timedPickleLoads(serial_pt, 'asym_decrypt1')
        else:
            try:
                plaintext = pickle.loads(serial_pt)
            except (pickle.PickleError, TypeError) as e:
                #print(e)
                #print('not pickle')
                #print(serial_pt)
                return serial_pt
        return plaintext
    else:
        print('SA_ERROR:', alg, 'not yet implemented.', flush = True)
#end asym_decrypt()

hash_modules = {'SHA-224' : SHA224,
                'SHA-256' : SHA256,
                'SHA-384' : SHA384,
                'SHA-512' : SHA512}

#def get_hash_alg(hash_name):
#    if hash_name == 'SHA-224':
#        h = SHA224
#    elif hash_name == 'SHA-256':
#        h = SHA256
#    elif hash_name == 'SHA-384':
#        h = SHA384
#    elif hash_name == 'SHA-512':
#        h = SHA512
#    else:
#        print('SA_ERROR:', hash_name, 'is not a recognized hash function.', flush = True)
#    return h
#end def get_hash()
        
def mac_sign(data, key):
    if not isinstance(data, bytes):
        if usePickleTimer['pickle']:
            serial_data = timedPickleDumps(data, 'mac_sign1')
        else:
            #print('pickle')
            serial_data = pickle.dumps(data)
    else:
        serial_data = data
    alg = key['alg']
    k = key['key']
    #hash_alg = get_hash_alg(key['hash'])
    hash_alg = hash_modules[key['hash']]
    if alg == 'HMAC':
        h = HMAC.new(k, serial_data, hash_alg)
        sig = h.digest()
        result = (serial_data, sig)
        return result
    else:
        print('SA_ERROR:', alg, 'not yet implemented.', flush = True)
#end mac_sign()    
        
def pubkey_sign(data, key):
    if not isinstance(data, bytes):
        if usePickleTimer['pickle']:
            serial_data = timedPickleDumps(data, 'pubkey_sign1')
        else:
            #print('pickle')
            serial_data = pickle.dumps(data)
    else:
        serial_data = data
    alg = key['alg']
    k = key['key']
    hash_alg = hash_modules[key['hash']]
    if alg == 'RSA':
        privk = RSA.importKey(k)
        h = hash_alg.new(serial_data)
        signer = PKCS1_v1_5.new(privk)
        sig = signer.sign(h)
        result = (serial_data, sig)
        return result
    else:
        print('SA_ERROR:', alg, 'not yet implemented.', flush = True) 
#end pubkey_sign()

def mac_verify(data, key):
    alg = key['alg']
    k = key['key']
    hash_alg = hash_modules[key['hash']]
    if alg == 'HMAC':
        serial_data, sig = data
        verdict = (sig == HMAC.new(k, serial_data, hash_alg).digest())
        if verdict:
            if usePickleTimer['pickle']:
                result = timedPickleLoads(serial_data, 'mac_verify2')
            else:
                try:
                    result = pickle.loads(serial_data)
                except (pickle.PickleError, TypeError):
                    #print('not pickle')
                    return serial_data
            return result
        else:
            return none
    else:
        print('SA_ERROR:', alg, 'not yet implemented.', flush = True)
#end mac_verify()

def mac_verify1(data, signed_data, key):
    alg = key['alg']
    k = key['key']
    hash_alg = hash_modules[key['hash']]
    if alg == 'HMAC':
        serial_data, sig = signed_data
        if not isinstance(data, bytes):
            if usePickleTimer['pickle']:
                check_data = timedPickleDumps(data, 'mac_verify2')
            else:
                #print('pickle')
                check_data = pickle.dumps(data)
        else:
            check_data = data
        verdict = (sig == HMAC.new(k, check_data, hash_alg).digest())
        return verdict
    else:
        print('SA_ERROR:', alg, 'not yet implemented.', flush = True)
#end mac_verify1()
    
#returns None when verfication fails
def pubkey_verify(data, key):    
    alg = key['alg']
    k = key['key']
    hash_alg = hash_modules[key['hash']]
    if alg == 'RSA':
        pubk = RSA.importKey(k)
        h = hash_alg.new(data[0])
        sig = data[1]
        verifier = PKCS1_v1_5.new(pubk)
        verdict = verifier.verify(h, sig)
        if verdict:
            if usePickleTimer['pickle']:
                result = timedPickleLoads(data[0], 'pubkey_verify2')
            else:
                try:
                    result = pickle.loads(data[0])
                except (pickle.PickleError, TypeError):
                    #print('not pickle')
                    return data[0]
            return result
        else:
            return None
    else:
        print('SA_ERROR:', alg, 'not yet implemented.', flush = True)
#end pubkey_verify()

def pubkey_verify1(data, signed_data, key):
    #print('$$$$$$$$$$: verify1', flush = True)
    alg = key['alg']
    k = key['key']
    hash_alg = hash_modules[key['hash']]
    if alg == 'RSA':
        if not isinstance(data, bytes):
            if usePickleTimer['pickle']:
                check_data = timedPickleDumps(data, 'pubkey_verify2')
            else:
                #print('pickle')
                check_data = pickle.dumps(data)
        else:
            check_data = data
        pubk = RSA.importKey(k)
        h = hash_alg.new(check_data)
        sig = signed_data[1]
        verifier = PKCS1_v1_5.new(pubk)
        verdict = verifier.verify(h, sig)
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
