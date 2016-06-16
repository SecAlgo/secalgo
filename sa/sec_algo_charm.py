import sys
from charm.core.engine.util import objectToBytes, bytesToObject
from charm.core.math.pairing import pc_element
from charm.core.math.pairing import hashPair as extractor
from charm.toolbox.conversion import Conversion
from charm.toolbox.securerandom import OpenSSLRand
from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.toolbox.integergroup import IntegerGroup
from charm.schemes.pkenc.pkenc_rsa import RSA, RSA_Enc, RSA_Sig
from sa.Misc.da_utils import serialize_endpoint, deserialize_endpoint

RKEY_SIZE_BITS = 1024
RKEY_SIZE_BYTES = 128

def gen_key_pair():
    return RSA().keygen(1024)
#end gen_key_pair()

def get_pub_key(k):
    return k[0]
#end get_public_key()

def gen_sym_key():
    return PairingGroup('SS512').random(GT)
#end gen_sym_key

def sym_encrypt(plaintext, key):
    serial_pt = objectToBytes(plaintext, PairingGroup('SS512'))
    encrypter = SymmetricCryptoAbstraction(extractor(key))
    return encrypter.encrypt(serial_pt)
#end sym_encrypt()

def sym_decrypt(ciphertext, key):
    decrypter = SymmetricCryptoAbstraction(extractor(key))
    serial_pt = decrypter.decrypt(ciphertext)
    return bytesToObject(serial_pt, PairingGroup('SS512'))
#end sym_decrypt()

def asym_encrypt(plaintext, public_key):
    encrypter = RSA_Enc()
    serial_pt = objectToBytes(plaintext, IntegerGroup())
    frag_counter = (len(serial_pt) // RKEY_SIZE_BYTES) + 1
    ct_list = []
    for i in range(frag_counter):
        ciphertext = encrypter.encrypt(public_key, serial_pt[(i * RKEY_SIZE_BYTES):((i + 1) * RKEY_SIZE_BYTES)])
        ct_list.append(ciphertext)
    #end for
    return ct_list
#end asym_encrypt()

def asym_decrypt(ct_list, key):
    public_key, private_key = key
    decrypter = RSA_Enc()
    serial_pt = b''
    for ciphertext in ct_list:
        serial_pt += decrypter.decrypt(public_key, private_key, ciphertext)
    #end for
    return bytesToObject(serial_pt, IntegerGroup())
#end asym_decrypt()

def encrypt(plaintext, key):
    if isinstance(key, pc_element):
        return sym_encrypt(plaintext, key)
    else:
        return asym_encrypt(plaintext, key)
#end encrypt()

def decrypt(plaintext, key):
    if isinstance(key, pc_element):
        return sym_decrypt(plaintext, key)
    else:
        return asym_decrypt(plaintext, key)
#end decrypt()

def sign(data, private_key):
    signer = RSA_Sig()
    sig = signer.sign(private_key[1], data)
    sig = Conversion.OS2IP(sig)
    serial_data_and_sig = objectToBytes([data, sig], IntegerGroup())
    return serial_data_and_sig
#end sign()

#returns None when verification fails
def verify(serial_data_and_sig, public_key):
    verifier = RSA_Sig()
    data_and_sig = bytesToObject(serial_data_and_sig, IntegerGroup())
    data, sig = data_and_sig
    sig = Conversion.IP2OS(sig)
    verdict = verifier.verify(public_key, data, sig)
    if verdict == True:
        return data
    else:
        return None
#verify()
