

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

ops = ['SA_sym_keygen', 'PC_sym_keygen', 'SA_sym_encrypt', 'PC_sym_encrypt',
       'SA_sym_decrypt', 'PC_sym_decrypt', 'SA_mac_sign', 'PC_mac_sign',
       'SA_mac_verify', 'PC_mac_verify', 'SA_pub_keygen', 'PC_pub_keygen',
       'SA_pub_encrypt', 'PC_pub_encrypt', 'SA_pub_decrypt', 'PC_pub_decrypt',
       'SA_pub_sign', 'PC_pub_sign', 'SA_pub_verify', 'PC_pub_verify']

raw_data = dict()
for op in ops:
    raw_data[op] = []

result_ops = ['sym_keygen', 'sym_encrypt', 'sym_decrypt', 'mac_sign', 'mac_verify',
              'pun_keygen', 'pub_encryp', 'pub_decrypt', 'pub_sign', 'pub_verify']
results = dict()
for op in result_ops:
    results[op] = dict()

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
    
def time_SA_sym_keygen(loops):

    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)

    for i in range(loops):
        import sa.secalgo as SA
        result = SA.keygen('shared')

    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)

    return collect_raw('SA_sym_keygen',
                       (start_wc, start_cpu),
                       (end_wc, end_cpu),
                       loops)
#end def time_SA_sym_encrypt()

def time_PyCrypto_sym_keygen(loops):
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)

    for i in range(loops):
        from Crypto import Random
        new_key = Random.new().read(256 // 8)
        result = {'alg' : 'AES',
                  'size' : 256,
                  'mode' : 'CBC',
                  'key' : new_key}

    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)

    return collect_raw('PC_sym_keygen',
                       (start_wc, start_cpu),
                       (end_wc, end_cpu),
                       loops)
#end def time_PyCrypto_sym_keygen()    

def time_SA_sym_encrypt(loops):
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)

    for i in range(loops):
        import sa.secalgo as SA
        result = SA.encrypt(TEST_DATA, key = TEST_SYM_KEY)

    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)

    return collect_raw('SA_sym_encrypt',
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

    return collect_raw('PC_sym_encrypt',
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

    return collect_raw('SA_sym_decrypt',
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
    
    return collect_raw('PC_sym_decrypt',
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

    return collect_raw('SA_mac_sign',
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
    
    return collect_raw('PC_mac_sign',
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
    
    return collect_raw('SA_mac_verify',
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
    
    return collect_raw('PC_mac_verify',
                       (start_wc, start_cpu),
                       (end_wc, end_cpu),
                       loops)
#end def time_PyCrypto_mac_verify()

def time_SA_pub_keygen(loops):
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)

    for i in range(loops):
        import sa.secalgo as SA
        result = SA.keygen('public')
        
    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)
    
    return collect_raw('SA_pub_keygen',
                       (start_wc, start_cpu),
                       (end_wc, end_cpu),
                       loops)
#end def time_SA_pub_keygen()

def time_PyCrypto_pub_keygen(loops):
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)

    for i in range(loops):
        from Crypto.PublicKey import RSA
        key_pair = RSA.generate(2048)
        priv_key = key_pair.exportKey()
        pub_key = key_pair.publickey().exportKey()
        priv_key_dict = {'alg' : 'RSA', 'type' : 'private',
                         'size' : 2048, 'hash' : 'SHA-256',
                         'key' : priv_key}
        pub_key_dict = {'alg' : 'RSA', 'type' : 'public',
                        'size' : 2048, 'hash' : 'SHA-256',
                        'key' : pub_key}
        result = (priv_key_dict, pub_key_dict)

    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)
    
    return collect_raw('PC_pub_keygen',
                       (start_wc, start_cpu),
                       (end_wc, end_cpu),
                       loops)
#end def time_PyCrypto_pub_keygen()

def time_SA_pub_encrypt(loops):
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)

    for i in range(loops):
        import sa.secalgo as SA
        result = SA.encrypt(TEST_DATA, key = TEST_PUB_KEY)

    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)

    return collect_raw('SA_pub_encrypt',
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

    return collect_raw('PC_pub_encrypt',
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

    return collect_raw('SA_pub_decrypt',
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

    return collect_raw('PC_pub_decrypt',
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

    return collect_raw('SA_pub_sign',
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

    return collect_raw('PC_pub_sign',
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

    return collect_raw('SA_pub_verify',
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

    return collect_raw('PC_pub_verify',
                       (start_wc, start_cpu ),
                       (end_wc, end_cpu),
                       loops)
#end def time_PyCrypto_pub_verify()

def collect_raw(op, start, end, loops):
    start_wc, start_cpu = start
    end_wc, end_cpu = end

    wtime_total = end_wc - start_wc
    wtime_avg = wtime_total / loops * 1000 #miliseconds

    ptime_start = getattr(start_cpu, 'ru_utime') + getattr(start_cpu, 'ru_stime')
    ptime_end = getattr(end_cpu, 'ru_utime') + getattr(end_cpu, 'ru_stime')
    ptime_total = ptime_end - ptime_start
    ptime_avg = (ptime_total / loops) * 1000 #miliseconds

    data = {'Op' : op, 'start' : ptime_start, 'end' : ptime_end, 'loops' : loops}
    
    print('OP:', op)
    print('Loops:', loops)
    print('WC Total:', end_wc, '-', start_wc, '=', wtime_total)
    print('WC Avg:', wtime_avg)
    print('CPU Total:', ptime_end, '-', ptime_start, '=', ptime_total)
    print('CPU Avg:', ptime_avg)

    return data

def compute_results():
    for op in raw_data:
        per_round_avgs = []
        for round_data in op:
            avg = ((round_data['end'] - round_data['start']) / round_data['loops']) * 1000 #miliseconds
            per_round_avgs.append(avg)
        total_avg = sum(per_round_avgs) / len(per_round_avgs)
        results[op[2:]][op] = total_avg
        
    
def run_tests(rounds):
    for i in range(rounds):
        print('********** Starting Tests **********')
        print('\n***** SA_sym_keygen *****')
        raw_data['SA_sym_keygen'].append(time_SA_sym_keygen(30000))
        
        print('\n***** PyCrypto_sym_keygen *****')
        raw_data['PC_sym_keygen'].append(time_PyCrypto_sym_keygen(60000))
        
        print('\n***** SA_sym_encrypt *****')
        raw_data['SA_sym_encrypt'].append(time_SA_sym_encrypt(20000))
        
        print('\n***** PyCrypto_sym_encrypt *****')
        raw_data['PC_sym_encrypt'].append(time_PyCrypto_sym_encrypt(40000))
        
        print('\n***** SA_sym_decrypt *****')
        raw_data['SA_sym_decrypt'].append(time_SA_sym_decrypt(40000))
        
        print('\n***** PyCrypto_sym_decrypt *****')
        raw_data['PC_sym_decrypt'].append(time_PyCrypto_sym_decrypt(200000))
        
        print('\n***** SA_mac_sign *****')
        raw_data['SA_mac_sign'].append(time_SA_mac_sign(30000))
        
        print('\n***** PyCrypto_mac_sign *****')
        raw_data['PC_mac_sign'].append(time_PyCrypto_mac_sign(200000))
        
        print('\n***** SA_mac_verify *****')
        raw_data['SA_mac_verify'].append(time_SA_mac_verify(30000))
        
        print('\n***** PyCrypto_mac_verify *****')
        raw_data['PC_mac_verify'].append(time_PyCrypto_mac_verify(200000))
        
        print('\n***** SA_pub_keygen *****')
        raw_data['SA_pub_keygen'].append(time_SA_pub_keygen(50))
        
        print('\n***** PyCrypto_pub_keygen *****')
        raw_data['PC_pub_keygen'].append(time_PyCrypto_pub_keygen(50))
        
        print('\n***** SA_pub_encrypt *****')
        raw_data['SA_pub_encrypt'].append(time_SA_pub_encrypt(3000))
        
        print('\n***** PyCrypto_pub_encrypt *****')
        raw_data['PC_pub_encrypt'].append(time_PyCrypto_pub_encrypt(3000))
        
        print('\n***** SA_pub_decrypt *****')
        raw_data['SA_pub_decrypt'].append(time_SA_pub_decrypt(1000))
        
        print('\n***** PyCrypto_pub_decrypt *****')
        raw_data['PC_pub_decrypt'].append(time_PyCrypto_pub_decrypt(1000))
        
        print('\n***** SA_pub_sign *****')
        raw_data['SA_pub_sign'].append(time_SA_pub_sign(1000))
        
        print('\n***** PyCrypto_pub_sign *****')
        raw_data['PC_pub_sign'].append(time_PyCrypto_pub_sign(1000))
        
        print('\n***** SA_pub_verify *****')
        raw_data['SA_pub_verify'].append(time_SA_pub_verify(4000))
        
        print('\n***** PyCrypto_pub_verify *****')
        raw_data['PC_pub_verify'].append(time_PyCrypto_pub_verify(4000))

        print('\n********** Round ' + str(i) + ' Complete **********\n')

    print('\n********** Tests Complete **********\n')
        
if __name__ == "__main__":
    rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    run_tests(rounds)
    print(json.dumps(raw_data))
