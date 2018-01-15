

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
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)

    for i in range(loops):
        import sa.secalgo as SA
        result = SA.encrypt(TEST_DATA, key = TEST_SYM_KEY)

    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)

    output_results('SA_sym_encrypt',
                   (start_wc, start_cpu),
                   (end_wc, end_cpu),
                   loops)
#end def time_SA_sym_encrypt()

def time_PyCrypto_sym_encrypt(loops):
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)

    for i in range(loops):
        from Crypto.Cipher import AES
        from Crypto import Random
        from sa.Misc.Padding import pkcs7_pad as pad
        serial_data = pickle.dumps(TEST_DATA)
        serial_data = pad(serial_data)
        IV = Random.new().read(AES.block_size)
        cipher = AES.new(TEST_SYM_KEY['key'], AES.MODE_CBC, IV)
        result = IV + cipher.encrypt(serial_data)

    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)

    output_results('PC_sym_encrypt',
                   (start_wc, start_cpu),
                   (end_wc, end_cpu),
                   loops)
#end def time_PyCrypto_sym_encrypt()

def time_SA_sym_decrypt(loops):
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)

    for i in range(loops):
        import sa.secalgo as SA
        result = SA.decrypt(TEST_SYM_CT, key = TEST_SYM_KEY)

    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)

    output_results('SA_sym_decrypt',
                   (start_wc, start_cpu),
                   (end_wc, end_cpu),
                   loops)
#end def time_SA_sym_decrypt()

def time_PyCrypto_sym_decrypt(loops):
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)

    for i in range(loops):
        from Crypto.Cipher import AES
        from Crypto import Random
        from sa.Misc.Padding import pkcs7_unpad as unpad
        iv = TEST_SYM_CT[:16]
        cipher = AES.new(TEST_SYM_KEY['key'], AES.MODE_CBC, iv)
        serial_pt = cipher.decrypt(TEST_SYM_CT[16:])
        serial_pt = unpad(serial_pt)
        result = pickle.loads(serial_pt)

    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)
    
    output_results('PC_sym_decrypt',
                   (start_wc, start_cpu),
                   (end_wc, end_cpu),
                   loops)
#end def time_PyCrypto_sym_decrypt()

def time_SA_mac_sign(loops):
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)
    
    for i in range(loops):
        import sa.secalgo as SA
        result = SA.sign(TEST_DATA, key = TEST_MAC_KEY)

    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)

    output_results('SA_mac_sign',
                   (start_wc, start_cpu),
                   (end_wc, end_cpu),
                   loops)
#end def time_SA_mac_sign()

def time_PyCrypto_mac_sign(loops):
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)
    
    for i in range(loops):
        from Crypto.Hash import HMAC
        from Crypto.Hash import SHA256
        serial_data = pickle.dumps(TEST_DATA)
        h = HMAC.new(TEST_MAC_KEY['key'], serial_data, SHA256)
        sig = h.digest()
        result = pickle.dumps((serial_data, sig))
        
    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)
    
    output_results('PC_mac_sign',
                   (start_wc, start_cpu),
                   (end_wc, end_cpu),
                   loops)
#end def time_PyCrypto_mac_sign()

def time_SA_mac_verify(loops):
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)
    
    for i in range(loops):
        import sa.secalgo as SA
        result = SA.verify(TEST_MAC, key = TEST_MAC_KEY)
    assert result != None
        
    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)
    
    output_results('SA_mac_verify',
                   (start_wc, start_cpu),
                   (end_wc, end_cpu),
                   loops)
#end def time_SA_mac_verify()

def time_PyCrypto_mac_verify(loops):
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)
    
    for i in range(loops):
        from Crypto.Hash import HMAC
        from Crypto.Hash import SHA256
        data, sig = pickle.loads(TEST_MAC)
        verdict = (sig == HMAC.new(TEST_MAC_KEY['key'], data, SHA256).digest())
        result = pickle.loads(data) if verdict else None
        assert result != None
        
    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)
    
    output_results('PC_mac_verify',
                   (start_wc, start_cpu),
                   (end_wc, end_cpu),
                   loops)
#end def time_PyCrypto_mac_verify()

def time_SA_pub_encrypt(loops):
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)

    for i in range(loops):
        import sa.secalgo as SA
        result = SA.encrypt(TEST_DATA, key = TEST_PUB_KEY)

    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)

    output_results('SA_pub_encrypt',
                   (start_wc, start_cpu),
                   (end_wc, end_cpu),
                   loops)
#end def time_SA_pub_encrypt()

def time_PyCrypto_pub_encrypt(loops):
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)

    for i in range(loops):
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP
        from Crypto import Random
        from Crypto.Cipher import AES
        from sa.Misc.Padding import pkcs7_pad as pad
        serial_data = pickle.dumps(TEST_DATA)
        pubk = RSA.importKey(TEST_PUB_KEY['key'])
        cipher = PKCS1_OAEP.new(pubk)
        try:
            result = cipher.encrypt(serial_data)
        except ValueError:
            shared_key = Random.new().read(32)
            iv = Random.new().read(AES.block_size)
            sym_cipher = AES.new(shared_key, AES.MODE_CBC, iv)
            data_ct = iv + sym_cipher.encrypt(pad(serial_data))
            serial_key = pickle.dumps(shared_key)
            key_ct = cipher.encrypt(serial_key)
            result = key_ct + data_ct
            
    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)

    output_results('PC_pub_encrypt',
                   (start_wc, start_cpu),
                   (end_wc, end_cpu),
                   loops)
#end def time_PyCrypto_pub_encrypt()

def time_SA_pub_decrypt(loops):
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)

    for i in range(loops):
        import sa.secalgo as SA
        result = SA.decrypt(TEST_PUB_CT, key = TEST_PRIV_KEY)

    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)

    output_results('SA_pub_decrypt',
                   (start_wc, start_cpu),
                   (end_wc, end_cpu),
                   loops)
#end def time_SA_pub_decrypt()

def time_PyCrypto_pub_decrypt(loops):
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)
    
    for i in range(loops):
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP
        from Crypto import Random
        from Crypto.Cipher import AES
        from sa.Misc.Padding import pkcs7_unpad as unpad
        privk = RSA.importKey(TEST_PRIV_KEY['key'])
        cipher = PKCS1_OAEP.new(privk)
        if len(TEST_PUB_CT) > (TEST_PRIV_KEY['size'] // 8):
            key_ct = TEST_PUB_CT[:256]
            data_ct = TEST_PUB_CT[256:]
            serial_key = cipher.decrypt(key_ct)
            shared_key = pickle.loads(serial_key)
            sym_cipher = AES.new(shared_key['key'], AES.MODE_CBC, data_ct[:16])
            serial_result = unpad(sym_cipher.decrypt(data_ct[16:]))
        else:
            serial_result = cipher.decrypt(TEST_PUB_CT)
            result = pickle.loads(serial_result)
        
    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)

    output_results('PC_pub_decrypt',
                   (start_wc, start_cpu),
                   (end_wc, end_cpu),
                   loops)
#end def time_PyCrypto_pub_decrypt()

def time_SA_pub_sign(loops):
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)

    for i in range(loops):
        import sa.secalgo as SA
        result = SA.sign(TEST_DATA, key = TEST_PRIV_KEY)

    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)

    output_results('SA_pub_sign',
                   (start_wc, start_cpu),
                   (end_wc, end_cpu),
                   loops)
#end def time_SA_pub_sign()

def time_PyCrypto_pub_sign(loops):
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)

    for i in range(loops):
        from Crypto.PublicKey import RSA
        from Crypto.Signature import PKCS1_v1_5
        from Crypto.Hash import SHA256
        serial_data = pickle.dumps(TEST_DATA)
        privk = RSA.importKey(TEST_PRIV_KEY['key'])
        h = SHA256.new(serial_data)
        signer = PKCS1_v1_5.new(privk)
        sig = signer.sign(h)
        result = (serial_data, sig)
        s_result = pickle.dumps(result)

    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)

    output_results('PC_pub_sign',
                   (start_wc, start_cpu),
                   (end_wc, end_cpu),
                   loops)
#end def time_PyCrypto_pub_sign()

def time_SA_pub_verify(loops):
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)
    
    for i in range(loops):
        import sa.secalgo as SA
        result = SA.verify(TEST_PUB_SIG, key = TEST_PUB_KEY)
    assert result != None

    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)

    output_results('SA_pub_verify',
                   (start_wc, start_cpu),
                   (end_wc, end_cpu),
                   loops)
#end def time_SA_pub_verify()

def time_PyCrypto_pub_verify(loops):
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)
    
    for i in range(loops):
        from Crypto.PublicKey import RSA
        from Crypto.Signature import PKCS1_v1_5
        from Crypto.Hash import SHA256
        pubk = RSA.importKey(TEST_PUB_KEY['key'])
        data, sig = pickle.loads(TEST_PUB_SIG)
        h = SHA256.new(data)
        verifier = PKCS1_v1_5.new(pubk)
        verdict = verifier.verify(h, sig)
        result = pickle.loads(data) if verdict else None
        assert result != None

    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)

    output_results('PC_pub_verify',
                   (start_wc, start_cpu ),
                   (end_wc, end_cpu),
                   loops)
#end def time_PyCrypto_pub_verify()

def output_results(op, start, end, loops):
    start_wc, start_cpu = start
    end_wc, end_cpu = end

    wtime_total = end_wc - start_wc
    wtime_avg = wtime_total / loops * 1000 #miliseconds

    ptime_start = getattr(start_cpu, 'ru_utime') + getattr(start_cpu, 'ru_stime')
    ptime_end = getattr(end_cpu, 'ru_utime') + getattr(end_cpu, 'ru_stime')
    ptime_total = ptime_end - ptime_start
    ptime_avg = (ptime_total / loops) * 1000 #miliseconds

    print('OP:', op)
    print('WC Total:', end_wc, '-', start_wc, '=', wtime_total)
    print('WC Avg:', wtime_avg)
    print('CPU Total:', ptime_end, '-', ptime_start, '=', ptime_total)
    print('CPU Avg:', ptime_avg)

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
    time_PyCrypto_mac_sign(loops * 10)
    print('\n***** SA_mac_verify *****')
    time_SA_mac_verify(loops)
    print('\n***** PyCrypto_mac_verify *****')
    time_PyCrypto_mac_verify(loops * 10)
    print('\n***** SA_pub_encrypt *****')
    time_SA_pub_encrypt(loops // 10)
    print('\n***** PyCrypto_pub_encrypt *****')
    time_PyCrypto_pub_encrypt(loops // 10)
    print('\n***** SA_pub_decrypt *****')
    time_SA_pub_decrypt(loops // 10)
    print('\n***** PyCrypto_pub_decrypt *****')
    time_PyCrypto_pub_decrypt(loops // 10)
    print('\n***** SA_pub_sign *****')
    time_SA_pub_sign(loops // 10)
    print('\n***** PyCrypto_pub_sign *****')
    time_PyCrypto_pub_sign(loops // 10)
    print('\n***** SA_pub_verify *****')
    time_SA_pub_verify(loops // 10)
    print('\n***** PyCrypto_pub_verify *****')
    time_PyCrypto_pub_verify(loops // 10)
    print('\n********** Tests Complete **********\n')

if __name__ == "__main__":
    loops = int(sys.argv[1]) if len(sys.argv) > 1 else 20000
    run_tests(loops)
