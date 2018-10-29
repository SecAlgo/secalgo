
import random, string, pickle
from sa.secalgo import keygen, encrypt, decrypt, sign, verify

def random_string(length = 1000):
    chars = string.printable
    return ''.join(random.choice(chars) for x in range(length))
#end def random_string()

def init():
    test_data = random_string()
    test_sym_key = keygen('shared')
    test_sym_ct = encrypt(test_data, key = test_sym_key)
    test_mac_key = keygen('mac')
    test_mac = sign(test_data, key = test_mac_key)
    test_priv_key, test_pub_key = keygen('public')
    test_pub_ct = encrypt(test_data, key = test_pub_key)
    test_pub_sig = sign(test_data, key = test_priv_key)

    with open('test_sym_key.sac', 'wb') as f:
        pickle.dump(test_sym_key, f)

    with open('test_data.sac', 'wb') as f:
        pickle.dump(test_data, f)

    with open('test_sym_ct.sac', 'wb') as f:
        pickle.dump(test_sym_ct, f)

    with open('test_mac_key.sac', 'wb') as f:
        pickle.dump(test_mac_key, f)

    with open('test_mac.sac', 'wb') as f:
        pickle.dump(test_mac, f)

    with open('test_priv_key.sac', 'wb') as f:
        pickle.dump(test_priv_key, f)

    with open('test_pub_key.sac', 'wb') as f:
        pickle.dump(test_pub_key, f)

    with open('test_pub_ct.sac', 'wb') as f:
        pickle.dump(test_pub_ct, f)

    with open('test_pub_sig.sac', 'wb') as f:
        pickle.dump(test_pub_sig, f)
#end def init()

if __name__ == '__main__':
    init()
#end main
