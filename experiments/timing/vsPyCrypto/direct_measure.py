

import sys, time, resource, json, pickle

TEST_DATA = None
TEST_SYM_KEY = None
TEST_SYM_CT = None
TEST_MAC_KEY = None
TEST_MAC = None
TEST_PUB_KEY = None
TEST_PRIV_KEY = None
TEST_PUB_CT = None
TEST_PUB_SIG = None

with open('test_sym_key.sac', 'rb') as f:
    TEST_SYM_KEY = pickle.load(f)

with open('test_data.sac', 'rb') as f:
    TEST_DATA = pickle.load(f)

with open('test_sym_ct.sac', 'rb') as f:
    TEST_SYM_CT = pickle.load(f)

with open('test_mac_key.sac', 'rb') as f:
    TEST_MAC_KEY = pickle.load(f)

with open('test_mac.sac', 'rb') as f:
    TEST_MAC = pickle.load(f)

with open('test_pub_key.sac', 'rb') as f:
    TEST_PUB_KEY = pickle.load(f)

with open('test_priv_key.sac', 'rb') as f:
    TEST_PRIV_KEY = pickle.load(f)

with open('test_pub_ct.sac', 'rb') as f:
    TEST_PUB_CT = pickle.load(f)

with open('test_pub_sig.sac', 'rb') as f:
    TEST_PUB_SIG = pickle.load(f)
    
def time_SA_sym_encrypt(loops):
    start_wallclock = time.perf_counter()
    start_data = resource.getrusage(resource.RUSAGE_SELF)
    
    import sa.secalgo as SA

    for i in range(loops):
        result = SA.encrypt(TEST_DATA, key = TEST_SYM_KEY)

    end_wallclock = time.perf_counter()
    end_data = resource.getrusage(resource.RUSAGE_SELF)

    output_results('SA_sym_encrypt', (start_wallclock, start_data), (end_wallclock, end_data))
#end def time_SA_sym_encrypt()

def time_PyCrypto_sym_encrypt(loops):
    serial_data = pickle.dumps(TEST_DATA)
    start_wallclock = time.perf_counter()
    start_data = resource.getrusage(resource.RUSAGE_SELF)
    
    from Crypto.Cipher import AES
    from Crypto import Random
    from sa.Misc.Padding import pkcs7_pad as pad

    for i in range(loops):
        IV = Random.new().read(AES.block_size)
        cipher = AES.new(TEST_SYM_KEY['key'], AES.MODE_CBC, IV)
        result = IV + cipher.encrypt(pad(serial_data))

    end_wallclock = time.perf_counter()
    end_data = resource.getrusage(resource.RUSAGE_SELF)

    output_results('PC_sym_encrypt', (start_wallclock, start_data), (end_wallclock, end_data))
#end def time_PyCrypto_sym_encrypt()

def time_SA_sym_decrypt(loops):
    start_wallclock = time.perf_counter()
    start_data = resource.getrusage(resource.RUSAGE_SELF)
    
    import sa.secalgo as SA

    for i in range(loops):
        result = SA.decrypt(TEST_SYM_CT, key = TEST_SYM_KEY)
    
    end_wallclock = time.perf_counter()
    end_data = resource.getrusage(resource.RUSAGE_SELF)

    output_results('SA_sym_decrypt', (start_wallclock, start_data), (end_wallclock, end_data))
#end def time_SA_sym_decrypt()

def time_PyCrypto_sym_decrypt(loops):
    start_wallclock = time.perf_counter()
    start_data = resource.getrusage(resource.RUSAGE_SELF)
    
    from Crypto.Cipher import AES
    from Crypto import Random
    from sa.Misc.Padding import pkcs7_unpad as unpad
    
    for i in range(loops):
        IV = Random.new().read(AES.block_size)
        cipher = AES.new(TEST_SYM_KEY['key'], AES.MODE_CBC, IV)
        result = unpad(cipher.decrypt(TEST_SYM_CT))

    end_data = resource.getrusage(resource.RUSAGE_SELF)
    end_wallclock = time.perf_counter()
    
    output_results('PC_sym_decrypt', (start_wallclock, start_data), (end_wallclock, end_data))
#end def time_PyCrypto_sym_decrypt()

def time_SA_mac_sign(loops):
    start_wallclock = time.perf_counter()
    start_data = resource.getrusage(resource.RUSAGE_SELF)
    
    import sa.secalgo as SA

    for i in range(loops):
        result = SA.sign(TEST_DATA, key = TEST_MAC_KEY)

    end_wallclock = time.perf_counter()
    end_data = resource.getrusage(resource.RUSAGE_SELF)

    output_results('SA_mac_sign', (start_wallclock, start_data), (end_wallclock, end_data))
#end def time_SA_mac_sign()

def time_PyCrypto_mac_sign(loops):
    serial_data = pickle.dumps(TEST_DATA)
    start_wallclock = time.perf_counter()
    start_data = resource.getrusage(resource.RUSAGE_SELF)
    
    from Crypto.Hash import HMAC
    from Crypto.Hash import SHA256

    for i in range(loops):
        h = HMAC.new(TEST_MAC_KEY['key'], serial_data, SHA256)
        sig = h.digest()
        result = (serial_data, sig)
        
    end_wallclock = time.perf_counter()
    end_data = resource.getrusage(resource.RUSAGE_SELF)

    output_results('PC_mac_sign', (start_wallclock, start_data), (end_wallclock, end_data))
#end def time_PyCrypto_mac_sign()

def time_SA_mac_verify(loops):
    start_wallclock = time.perf_counter()
    start_data = resource.getrusage(resource.RUSAGE_SELF)
    
    import sa.secalgo as SA

    for i in range(loops):
        result = SA.verify(TEST_MAC, key = TEST_MAC_KEY)
    assert result != None
        
    end_wallclock = time.perf_counter()
    end_data = resource.getrusage(resource.RUSAGE_SELF)

    output_results('SA_mac_verify', (start_wallclock, start_data), (end_wallclock, end_data))
#end def time_SA_mac_verify()

def time_PyCrypto_mac_verify(loops):
    data, sig = pickle.loads(TEST_MAC)
    start_wallclock = time.perf_counter()
    start_data = resource.getrusage(resource.RUSAGE_SELF)
    
    from Crypto.Hash import HMAC
    from Crypto.Hash import SHA256

    for i in range(loops):
        h = HMAC.new(TEST_MAC_KEY['key'], data, SHA256)
        verdict = (sig == h.digest())
        result = data if verdict else None
        assert result != None
        
    end_wallclock = time.perf_counter()
    end_data = resource.getrusage(resource.RUSAGE_SELF)

    output_results('PC_mac_verify', (start_wallclock, start_data), (end_wallclock, end_data))
#end def time_PyCrypto_mac_verify()

def time_SA_pub_encrypt(loops):
    start_wallclock = time.perf_counter()
    start_data = resource.getrusage(resource.RUSAGE_SELF)
    
    import sa.secalgo as SA

    for i in range(loops):
        result = SA.encrypt(TEST_DATA, key = TEST_PUB_KEY)

    end_wallclock = time.perf_counter()
    end_data = resource.getrusage(resource.RUSAGE_SELF)

    output_results('SA_pub_encrypt', (start_wallclock, start_data), (end_wallclock, end_data))
#end def time_SA_pub_encrypt()

def time_PyCrypto_pub_encrypt(loops):
    serial_data = pickle.dumps(TEST_DATA)
    start_wallclock = time.perf_counter()
    start_data = resource.getrusage(resource.RUSAGE_SELF)
    
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto import Random
    from Crypto.Cipher import AES
    from sa.Misc.Padding import pkcs7_pad as pad

    for i in range(loops):
        pubk = RSA.importKey(TEST_PUB_KEY['key'])
        cipher = PKCS1_OAEP.new(pubk)
        try:
            result = cipher.encrypt(serial_data)
        except ValueError:
            shared_key = Random.new().read(32)
            iv = Random.new().read(AES.block_size)
            sym_cipher = AES.new(shared_key, AES.MODE_CBC, iv)
            data_ct = iv + sym_cipher.encrypt(pad(serial_data))
            key_ct = cipher.encrypt(shared_key)
            result = key_ct + data_ct
    end_wallclock = time.perf_counter()
    end_data = resource.getrusage(resource.RUSAGE_SELF)

    output_results('PC_pub_encrypt', (start_wallclock, start_data), (end_wallclock, end_data))
#end def time_PyCrypto_pub_encrypt()

def time_SA_pub_decrypt(loops):
    start_wallclock = time.perf_counter()
    start_data = resource.getrusage(resource.RUSAGE_SELF)
    
    import sa.secalgo as SA

    for i in range(loops):
        result = SA.decrypt(TEST_PUB_CT, key = TEST_PRIV_KEY)

    end_wallclock = time.perf_counter()
    end_data = resource.getrusage(resource.RUSAGE_SELF)

    output_results('SA_pub_decrypt', (start_wallclock, start_data), (end_wallclock, end_data))
#end def time_SA_pub_decrypt()

def time_SA_pub_sign(loops):
    start_wallclock = time.perf_counter()
    start_data = resource.getrusage(resource.RUSAGE_SELF)
    
    import sa.secalgo as SA

    for i in range(loops):
        result = SA.sign(TEST_DATA, key = TEST_PRIV_KEY)

    end_wallclock = time.perf_counter()
    end_data = resource.getrusage(resource.RUSAGE_SELF)

    output_results('SA_pub_sign', (start_wallclock, start_data), (end_wallclock, end_data))
#end def time_SA_pub_sign()

def time_SA_pub_verify(loops):
    start_wallclock = time.perf_counter()
    start_data = resource.getrusage(resource.RUSAGE_SELF)
    
    import sa.secalgo as SA

    for i in range(loops):
        result = SA.verify(TEST_PUB_SIG, key = TEST_PUB_KEY)
    assert result != None

    end_wallclock = time.perf_counter()
    end_data = resource.getrusage(resource.RUSAGE_SELF)

    output_results('SA_pub_verify', (start_wallclock, start_data), (end_wallclock, end_data))
#end def time_SA_pub_verify()

def output_results(op, start, end):
    print('OP:', op)
    
    print('Wallclock:', end[0], '-', start[0], '=', (end[0] - start[0]))
    ptime_start = getattr(start[1], 'ru_utime') + getattr(start[1], 'ru_stime')
    ptime_end = getattr(end[1], 'ru_utime') + getattr(end[1], 'ru_stime')
    print('Process:', ptime_end, '-', ptime_start, '=', ptime_end - ptime_start)
          

def run_tests(loops):
    print('********** Starting Tests **********')
    print('\n***** SA_sym_encrypt *****')
    time_SA_sym_encrypt(loops)
    print('\n***** PyCrypto_sym_encrypt *****')
    time_PyCrypto_sym_encrypt(loops)
    print('\n***** SA_sym_decrypt *****')
    time_SA_sym_decrypt(loops)
    print('\n***** PyCrypto_sym_decrypt *****')
    time_PyCrypto_sym_decrypt(loops)
    print('\n***** SA_mac_sign *****')
    time_SA_mac_sign(loops)
    print('\n***** PyCrypto_mac_sign *****')
    time_PyCrypto_mac_sign(loops)
    print('\n***** SA_mac_verify *****')
    time_SA_mac_verify(loops)
    print('\n***** PyCrypto_mac_verify *****')
    time_PyCrypto_mac_verify(loops)
    print('\n***** SA_pub_encrypt *****')
    time_SA_pub_encrypt(loops)
    print('\n***** PyCrypto_pub_encrypt *****')
    time_PyCrypto_pub_encrypt(loops)
    print('\n***** SA_pub_decrypt *****')
    time_SA_pub_decrypt(loops)
    print('\n***** SA_pub_sign *****')
    time_SA_pub_sign(loops)
    print('\n***** SA_pub_verify *****')
    time_SA_pub_verify(loops)
    print('\n********** Tests Complete **********\n')

if __name__ == "__main__":
    loops = int(sys.argv[1]) if len(sys.argv) > 1 else 100000
    run_tests(loops)
