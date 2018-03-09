import sys, time, resource, json, pickle
#import sa.secalgoB as SA
#from Crypto import Random
#from Crypto.Cipher import AES
#from Crypto.Hash import HMAC
#from Crypto.Hash import SHA256
#from Crypto.PublicKey import RSA
#from Crypto.Cipher import PKCS1_OAEP
#from Crypto.Signature import PKCS1_v1_5
#from sa.Misc.Padding import pkcs7_pad as pad
#from sa.Misc.Padding import pkcs7_unpad as unpad

ops = ['SA_import_once', 'SA_import',
       'PC_sym_keygen_import_once', 'PC_sym_keygen_import',
       'PC_sym_encrypt_import_once', 'PC_sym_encrypt_import',
       'PC_sym_decrypt_import_once', 'PC_sym_decrypt_import',
       'PC_sym_mac_import_once', 'PC_sym_mac_import',
       'PC_pub_keygen_import_once', 'PC_pub_keygen_import',
       'PC_pub_encrypt_import_once', 'PC_pub_encrypt_import',
       'PC_pub_decrypt_import_once', 'PC_pub_decrypt_import',
       'PC_pub_auth_import_once', 'PC_pub_auth_import',
       'PC_complete_import_once', 'PC_complete_import']

raw_data = dict()
for op in ops:
    raw_data[op] = []

result_ops = ['sym_keygen', 'sym_encrypt', 'sym_decrypt', 'mac_sign', 'mac_verify',
              'pub_keygen', 'pub_encrypt', 'pub_decrypt', 'pub_sign', 'pub_verify']

results = dict()
for op in result_ops:
    results[op] = dict()
    
def time_SA_import_once():
    loops = 1
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)
    
    import sa.secalgoB

    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)

    return collect_raw('SA_import_once',
                       (start_wc, start_cpu),
                       (end_wc, end_cpu),
                       loops)
#end def time_SA_import_once()

def time_SA_import(loops):
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)

    for i in range(loops):
        import sa.secalgoB

    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)

    return collect_raw('SA_import',
                       (start_wc, start_cpu),
                       (end_wc, end_cpu),
                       loops)
#end def time_SA_import()    

def time_PC_sym_keygen_import_once():
    loops = 1
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)

    from Crypto import Random

    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)

    return collect_raw('SA_sym_keygen_once',
                       (start_wc, start_cpu),
                       (end_wc, end_cpu),
                       loops)
#end def time_SA_sym_keygen_import_once()

def time_PC_sym_keygen_import(loops):
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)

    for i in range(loops):
        from Crypto import Random

    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)

    return collect_raw('PC_sym_keygen_import',
                       (start_wc, start_cpu),
                       (end_wc, end_cpu),
                       loops)
#end def time_PyCrypto_sym_keygen_import()

def time_PC_sym_encrypt_import_once():
    loops = 1
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)

    from Crypto import Random
    from Crypto.Cipher import AES
    from sa.Misc.Padding import pkcs7_pad

    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)

    return collect_raw('PC_sym_encrypt_import_once',
                       (start_wc, start_cpu),
                       (end_wc, end_cpu),
                       loops)
#end def time_PyCrypto_sym_encrypt_import_once()

def time_PC_sym_encrypt_import(loops):
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)

    for i in range(loops):
        from Crypto import Random
        from Crypto.Cipher import AES
        from sa.Misc.Padding import pkcs7_pad

    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)

    return collect_raw('PC_sym_encrypt_import',
                       (start_wc, start_cpu),
                       (end_wc, end_cpu),
                       loops)
#end def time_PyCrypto_sym_encrypt_import()

def time_PC_sym_decrypt_import_once():
    loops = 1
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)

    from Crypto.Cipher import AES
    from Crypto import Random
    from sa.Misc.Padding import pkcs7_unpad

    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)

    return collect_raw('PC_sym_decrypt_import_once',
                       (start_wc, start_cpu),
                       (end_wc, end_cpu),
                       loops)
#end def time_PyCrypto_sym_decrypt_import_once()

def time_PC_sym_decrypt_import(loops):
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)

    for i in range(loops):
        from Crypto.Cipher import AES
        from sa.Misc.Padding import pkcs7_unpad

    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)

    return collect_raw('PC_sym_decrypt_import',
                       (start_wc, start_cpu),
                       (end_wc, end_cpu),
                       loops)
#end def time_PyCrypto_sym_decrypt_import()

def time_PC_sym_mac_import_once():
    loops = 1
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)

    from Crypto.Hash import SHA256
    from Crypto.Hash import HMAC

    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)

    return collect_raw('PC_sym_mac_import_once',
                       (start_wc, start_cpu),
                       (end_wc, end_cpu),
                       loops)
#end def time_PyCrypto_sym_mac_import_once()

def time_PC_sym_mac_import(loops):
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)

    for i in range(loops):
        from Crypto.Hash import SHA256
        from Crypto.Hash import HMAC

    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)

    return collect_raw('PC_sym_mac_import',
                       (start_wc, start_cpu),
                       (end_wc, end_cpu),
                       loops)
#end def time_PyCrypto_sym_mac_import()

def time_PC_pub_keygen_import_once():
    loops = 1
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)

    from Crypto.PublicKey import RSA
    
    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)

    return collect_raw('PC_pub_keygen_import_once',
                       (start_wc, start_cpu),
                       (end_wc, end_cpu),
                       loops)
#end def time_PyCrypto_pub_keygen_import_once()

def time_PC_pub_keygen_import(loops):
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)

    for i in range(loops):
        from Crypto.PublicKey import RSA
    
    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)

    return collect_raw('PC_pub_keygen_import',
                       (start_wc, start_cpu),
                       (end_wc, end_cpu),
                       loops)
#end def time_PyCrypto_pub_keygen_import()

def time_PC_pub_encrypt_import_once():
    loops = 1
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)

    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto import Random
    from Crypto.Cipher import AES
    from sa.Misc.Padding import pkcs7_pad
    
    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)

    return collect_raw('PC_pub_encrypt_import_once',
                       (start_wc, start_cpu),
                       (end_wc, end_cpu),
                       loops)
#end def time_PyCrypto_pub_encrypt_import_once()

def time_PC_pub_encrypt_import(loops):
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)

    for i in range(loops):
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP
        from Crypto import Random
        from Crypto.Cipher import AES
        from sa.Misc.Padding import pkcs7_pad
    
    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)

    return collect_raw('PC_pub_encrypt_import',
                       (start_wc, start_cpu),
                       (end_wc, end_cpu),
                       loops)
#end def time_PyCrypto_pub_encrypt_import()

def time_PC_pub_decrypt_import_once():
    loops = 1
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)

    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto import Random
    from Crypto.Cipher import AES
    from sa.Misc.Padding import pkcs7_unpad
    
    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)

    return collect_raw('PC_pub_decrypt_import_once',
                       (start_wc, start_cpu),
                       (end_wc, end_cpu),
                       loops)
#end def time_PyCrypto_pub_decrypt_import_once()

def time_PC_pub_decrypt_import(loops):
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)

    for i in range(loops):
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP
        from Crypto import Random
        from Crypto.Cipher import AES
        from sa.Misc.Padding import pkcs7_unpad
    
    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)

    return collect_raw('PC_pub_decrypt_import',
                       (start_wc, start_cpu),
                       (end_wc, end_cpu),
                       loops)
#end def time_PyCrypto_pub_decrypt_import()

def time_PC_pub_auth_import_once():
    loops = 1
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)

    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_v1_5
    from Crypto.Hash import SHA256
    
    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)

    return collect_raw('PC_pub_auth_import_once',
                       (start_wc, start_cpu),
                       (end_wc, end_cpu),
                       loops)
#end def time_PyCrypto_pub_auth_import_once()

def time_PC_pub_auth_import(loops):
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)

    for i in range(loops):
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_v1_5
        from Crypto.Hash import SHA256
    
    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)

    return collect_raw('PC_pub_auth_import',
                       (start_wc, start_cpu),
                       (end_wc, end_cpu),
                       loops)
#end def time_PyCrypto_pub_auth_import()

def time_PC_complete_import_once():
    loops = 1
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)

    from Crypto import Random
    from Crypto.Cipher import AES
    from Crypto.Hash import HMAC
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Signature import PKCS1_v1_5
    from sa.Misc.Padding import pkcs7_pad, pkcs7_unpad
    
    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)

    return collect_raw('PC_complete_import_once',
                       (start_wc, start_cpu),
                       (end_wc, end_cpu),
                       loops)
#end def time_PyCrypto_complete_import_once()

def time_PC_complete_import(loops):
    start_wc = time.perf_counter()
    start_cpu = resource.getrusage(resource.RUSAGE_SELF)

    for i in range(loops):
        from Crypto import Random
        from Crypto.Cipher import AES
        from Crypto.Hash import HMAC
        from Crypto.Hash import SHA256
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP
        from Crypto.Signature import PKCS1_v1_5
        from sa.Misc.Padding import pkcs7_pad, pkcs7_unpad
    
    end_wc = time.perf_counter()
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)

    return collect_raw('PC_complete_import',
                       (start_wc, start_cpu),
                       (end_wc, end_cpu),
                       loops)
#end def time_PyCrypto_complete_import()

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
    
    print('Op:', op)
    print('Loops:', loops)
    print('WC Total:', end_wc, '-', start_wc, '=', wtime_total)
    print('WC Avg:', wtime_avg)
    print('CPU Total:', ptime_end, '-', ptime_start, '=', ptime_total)
    print('CPU Avg:', ptime_avg)

    return data

def compute_results(rd):
    print('RawD:', rd)
    for op in rd:
        per_round_avgs = []
        for round_data in rd[op]:
            # miliseconds
            print('RndD:', round_data)
            avg = (((round_data['end'] - round_data['start'])
                   / round_data['loops']) * 1000)
            per_round_avgs.append(avg) 
        print('PRA:', per_round_avgs)
        total_avg = sum(per_round_avgs) / len(per_round_avgs)
        results[op[3:]][op] = total_avg

def compute_results2(rd, op, of):
    for round_data in rd[op]:
        #miliseconds
        avg = (((round_data['end'] - round_data['start'])
                   / round_data['loops']) * 1000)
        with open(of, "a") as f:
            f.write(str(avg) + '\n')

def compute_multiplier(rslt):
    for op, avgs in rslt.items():
        multiplier = avgs['SA_' + op] / avgs['PC_' + op]
        results[op]['mult'] = multiplier
        
def run_tests(rounds, op):
    for i in range(rounds):
        print('********** Starting Tests **********')
        
        if op == 'SA_import_once':
            print('\n***** SA_import_once *****')
            raw_data['SA_import_once'].append(time_SA_import_once())

        elif op == 'SA_import':
            print('\n***** SA_import *****')
            raw_data['SA_import'].append(time_SA_import(60000))

        elif op == 'PC_sym_keygen_import_once':
            print('\n***** PyCrypto_sym_keygen_import_once *****')
            raw_data['PC_sym_keygen_import_once'].append(time_PC_sym_keygen_import_once())

        elif op == 'PC_sym_keygen_import':
            print('\n***** PyCrypto_sym_keygen_import *****')
            raw_data['PC_sym_keygen_import'].append(time_PC_sym_keygen_import(60000))

        elif op == 'PC_sym_encrypt_import_once':
            print('\n***** PyCrypto_sym_encrypt_import_once *****')
            raw_data['PC_sym_encrypt_import_once'].append(time_PC_sym_encrypt_import_once())

        elif op == 'PC_sym_encrypt_import':
            print('\n***** PyCrypto_sym_encrypt_import *****')
            raw_data['PC_sym_encrypt_import'].append(time_PC_sym_encrypt_import(40000))

        elif op == 'PC_sym_decrypt_import_once':
            print('\n***** PyCrypto_sym_decrypt_import_once *****')
            raw_data['PC_sym_decrypt_import_once'].append(time_PC_sym_decrypt_import_once())

        elif op == 'PC_sym_decrypt_import':
            print('\n***** PyCrypto_sym_decrypt_import *****')
            raw_data['PC_sym_decrypt_import'].append(time_PC_sym_decrypt_import(200000))

        elif op == 'PC_sym_decrypt_import_once':
            print('\n***** PyCrypto_sym_decrypt_import_once *****')
            raw_data['PC_sym_decrypt_import_once'].append(time_PC_sym_decrypt_import_once())

        elif op == 'PC_sym_mac_import_once':
            print('\n***** PyCrypto_sym_mac_import_once *****')
            raw_data['PC_sym_mac_import_once'].append(time_PC_sym_mac_import_once())

        elif op == 'PC_sym_mac_import':
            print('\n***** PyCrypto_sym_mac_import *****')
            raw_data['PC_sym_mac_import'].append(time_PC_sym_mac_import(200000))

        elif op == 'PC_pub_keygen_import_once':
            print('\n***** PyCrypto_pub_keygen_import_once *****')
            raw_data['PC_pub_keygen_import_once'].append(time_PC_pub_keygen_import_once())

        elif op == 'PC_pub_keygen_import':
            print('\n***** PyCrypto_pub_keygen_import *****')
            raw_data['PC_pub_keygen_import'].append(time_PC_pub_keygen_import(25))

        elif op == 'PC_pub_encrypt_import_once':
            print('\n***** PyCrypto_pub_encrypt_import_once *****')
            raw_data['PC_pub_encrypt_import_once'].append(time_PC_pub_encrypt_import_once())

        elif op == 'PC_pub_encrypt_import':
            print('\n***** PyCrypto_pub_encrypt_import *****')
            raw_data['PC_pub_encrypt_import'].append(time_PC_pub_encrypt_import(3000))

        elif op == 'PC_pub_decrypt_import_once':
            print('\n***** PyCrypto_pub_decrypt_import_once *****')
            raw_data['PC_pub_decrypt_import_once'].append(time_PC_pub_decrypt_import_once())

        elif op == 'PC_pub_decrypt_import':
            print('\n***** PyCrypto_pub_decrypt_import *****')
            raw_data['PC_pub_decrypt_import'].append(time_PC_pub_decrypt_import(1000))

        elif op == 'PC_pub_auth_import_once':
            print('\n***** PyCrypto_pub_auth_import_once *****')
            raw_data['PC_pub_auth_import_once'].append(time_PC_pub_auth_import_once())

        elif op == 'PC_pub_auth_import':
            print('\n***** PyCrypto_pub_auth_import *****')
            raw_data['PC_pub_auth_import'].append(time_PC_pub_auth_import(4000))

        elif op == 'PC_complete_import_once':
            print('\n***** PyCrypto_complete_import_once *****')
            raw_data['PC_complete_import_once'].append(time_PC_complete_import_once())

        elif op == 'PC_complete_import':
            print('\n***** PyCrypto_complete_import *****')
            raw_data['PC_complete_import'].append(time_PC_complete_import(400000))

        print('\n********** Round ' + str(i) + ' Complete **********\n')

    print('\n********** Tests Complete **********\n')

if __name__ == "__main__":
    op = sys.argv[1] if len(sys.argv) > 1 else 'all'
    output_file = sys.argv[2] if len(sys.argv) > 2 else 'out.txt'
    rounds = int(sys.argv[3]) if len(sys.argv) > 3 else 1
    #print('TEST DATA:', type(TEST_DATA), ':', len(TEST_DATA))
    if op == 'all':
        for opitem in ops:
            run_tests(rounds, opitem)
            compute_results2(raw_data, opitem, output_file)
            print('\n' + ('-' * 60) + '\n')
    else:
        run_tests(rounds, op)
        compute_results2(raw_data, op, output_file)
    #compute_multiplier(results)
    #print(json.dumps(raw_data))
    #print(json.dumps(results))

    #print('Average execution times per primitive operation over {} rounds:'.format(rounds))
    #for op in results:
    #    print('{} --'.format(op))
    #    for be_op, val in results[op].items():
    #        print('\t{}: {}'.format(be_op, val))
