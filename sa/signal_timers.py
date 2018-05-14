import json, time, pickle, sys

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

proto_loops = {'x3dhT'                    : 1500,
               'doubleratchet_dist_testT' : 600,
               'signal_dist_testT'        : 1000,
               '__main__'                 : 6000}

keyed_methods = {'encrypt', 'decrypt', 'sign', 'verify'}

public_method_loops = {'keygen'  : 25,
                       'encrypt' : 3400,
                       'decrypt' : 1000,
                       'sign'    : 1000,
                       'verify'  : 4300}

shared_method_loops = {'keygen'      : 40000,
                       'encode'      : 2000000,
                       'decode'      : 2000000,
                       'dh'          : 10000,
                       'kdf'         : 20000,
                       'encrypt'     : 10000,
                       'decrypt'     : 10000,
                       'sign'        : 20000,
                       'verify'      : 20000,
                       'GENERATE_DH' : 35000,
                       'DH'          : 10000,
                       'KDF_RK'      : 30000,
                       'KDF_CK'      : 80000,
                       'ENCRYPT'     : 20000,
                       'DECRYPT'     : 20000,
                       'HEADER'      : 1000000,
                       'CONCAT'      : 800000}
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
        #if ((func.__name__ in keyed_methods and
        #     kwargs['key']['alg'] in PUBLIC_CIPHERS)
        #    or (func.__name__ is 'keygen' and
        #        (args[0] in PUBLIC_CIPHERS or args[0] == 'dh'))):
        #    loops = public_method_loops[func.__name__]
        #else:
        loops = shared_method_loops[func.__name__]
        for i in range(loops):
            result = func(*args, **kwargs)
        print(json.dumps([func.__name__, start_time,
                          time.process_time(), (i + 1)]), flush = True)
        return result
    #end timer()
    #global useTimers
    if not useTimers['library']:
        return func
    else:
        return timer
#end dec_timer()
