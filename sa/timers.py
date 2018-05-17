import json, time, pickle, sys
import sa.sec_algo_pycrypto as SA_PyCrypto
#import sa.sec_algo_charm as SA_Charm

# Constants for testing and measurements
KEYGEN = 0
ENCRYPT = 1
DECRYPT = 2
SIGN = 3
VERIFY = 4
NONCE = 4

useTimers = {'library' : False, 'protocol' : False}
#useTimers = {'library' : False, 'protocol' : True}
#useTimers = {'library' : True, 'protocol' : False}

proto_loops = {'dsT'             : 600,
               'ds-pkT'          : 400,
               'ns-skT'          : 2000,
               'ns-sk_fixedT'    : 2000,
               'pc_ns-sk_fixedT' : 2000,
               'ns-pkT'          : 300,
               'orT'             : 2000,
               'wlT'             : 2000,
               'yaT'             : 2000,
               'dhke-1T'         : 100,
               'sdhT'            : 50,
               'kerberos5T'      : 3000,
               'tls1_2T'         : 300,
               'x3dhT'           : 100,
               '__main__'        : 30000}

keyed_methods = {'encrypt', 'decrypt', 'sign', 'verify'}

public_method_loops = {'keygen'  : 25,
                       'encrypt' : 3400,
                       'decrypt' : 1000,
                       'sign'    : 1000,
                       'verify'  : 4300}

shared_method_loops = {'keygen'  : 60000,
                       'encrypt' : 50000,
                       'decrypt' : 200000,
                       'sign'    : 15000,
                       'verify'  : 15000,
                       'nonce'   : 60000,
                       'BitGen'  : 250,
                       'key_derivation' : 250,
                       'local_pow' : 40,
                       'tls_prf_sha256' : 50000}

# End Constants for testing and measurements

PUBLIC_CIPHERS = {'RSA', 'DSA', 'public'}
SYM_CIPHERS = {'AES', 'DES', 'DES3', 'Blowfish', 'shared'}
MAC_ALGORITHMS = {'HMAC', 'mac'}
HASH_FUNCTIONS = {'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512'}

def dec_proto_run_timer(func):
    #global useTimers
    def proto_run_timer(*args, **kwargs):
        start_time = time.process_time()
        for i in range(proto_loops[func.__module__]):
            func(*args, **kwargs)
        print(json.dumps([func.__module__, func.__qualname__, start_time,
                          time.process_time(), (i + 1)]), flush = True)
    #end proto_timer()
    if not useTimers['protocol']:
        return func
    else:
        return proto_run_timer
#end dec_proto_timer()

"""
def dec_proto_await_timer(func):
    def proto_await_timer(*args, **kwargs):
        start_time = time.process_time()
        func(*args, **kwargs)
        print(json.dumps([func.__module__, func.__qualname__,
                          start_time, time.process_time(),
                          proto_loops[func.__module__]]), flush = True)
    #end proto_await_timer()
    global useTimers
    if not useTimers['protocol']:
        return func
    else:
        return proto_await_timer
#end dec_proto_await_timer()
"""

def dec_timer(func):
    def timer(*args, **kwargs):
        start_time = time.process_time()
        if ((func.__name__ in keyed_methods and
             kwargs['key']['alg'] in PUBLIC_CIPHERS)
            or (func.__name__ is 'keygen' and
                (args[0] in PUBLIC_CIPHERS or args[0] == 'dh'))):
            loops = public_method_loops[func.__name__]
        else:
            loops = shared_method_loops[func.__name__]
        for i in range(loops):
            result = func(*args, **kwargs)
        print(json.dumps([func.__name__, start_time,
                          time.process_time(), (i + 1)]), flush = True)
        return result
    #end timer()
    global useTimers
    if not useTimers['library']:
        return func
    else:
        return timer
#end dec_timer()
