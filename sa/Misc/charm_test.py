from charm.core.engine.util import objectToBytes, bytesToObject
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.core.math.pairing import hashPair as extractor
from charm.toolbox.securerandom import OpenSSLRand
from charm.toolbox.conversion import Conversion
from charm_da_utils import Null_Group, serialize_endpoint, deserialize_endpoint
from da.endpoint import *

def test1(client, p, nonce, key_client, key_p):
    group_object = PairingGroup('SS512')
    shared_key = group_object.random(GT)
    crypter_a = SymmetricCryptoAbstraction(extractor(bytesToObject(key_client,
                                                                   group_object)))
    crypter_b = SymmetricCryptoAbstraction(extractor(bytesToObject(key_p,
                                                                   group_object)))
    package_b = crypter_b.encrypt(objectToBytes([shared_key,
                                                serialize_endpoint(client)],
                                                group_object))
    package_a = crypter_a.encrypt(objectToBytes([Conversion.OS2IP(nonce),
                                                 shared_key,
                                                 serialize_endpoint(p),
                                                 package_b],
                                                group_object))
    return package_a
#end test1

def test2():
    client = UdpEndPoint()
    p = UdpEndPoint()
    group_object = PairingGroup('SS512')
    key_client = group_object.random(GT)
    key_p = group_object.random(GT)
    nonce = OpenSSLRand().getRandomBits(128)
    server_crypter_a = SymmetricCryptoAbstraction(extractor(key_client))
    server_crypter_b = SymmetricCryptoAbstraction(extractor(key_p))
    c_package_a = test1(client, p, nonce, objectToBytes(key_client,
                                                        group_object),
                        objectToBytes(key_p, group_object))
    print('===========================================================')
    print(c_package_a)
    key_package_a = server_crypter_a.decrypt(c_package_a)
    key_package_a = bytesToObject(key_package_a, group_object)
    key_package_b = server_crypter_b.decrypt(key_package_a[3])
    key_package_b = bytesToObject(key_package_b, group_object)
    print('===========================================================')
    i = 1
    for thing in key_package_a:
        print(str(i) +  '.', thing)
        i += 1
    print('===========================================================')
    j = 1
    for thing in key_package_b:
        print(str(j) + '.', thing)
        j += 1
    print('===========================================================')
#end test2

test2()
