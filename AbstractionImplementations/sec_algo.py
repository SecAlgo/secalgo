from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util import Counter
from Crypto.Hash import SHA256
from Crypto import Random

#Abstracted Encryption Algorithms
class Sec_Algo():
      def __init__(self):
            self.AES = True
            self.DES = False
            self.sym_mode = 'CTR'
            self.RSA = True
            self.DSA = False
            #self.asym_key = None
            #self.sym_key = None
      #end __init__()

      def set_AES(self):
            self.AES = True
            self.DES = False
      #end set_AES()

      def set_DES(self):
            self.DES = True
            self.AES = False
      #end set_DES()

      def set_RSA(self):
            self.RSA = True
            self.DSA = False
      #end set_RSA()

      def set_DSA(self):
            self.DSA = True
            self.RSA = False
      #end set_DSA()

      def set_sym_mode(self, value):
            if (value == 'CBC' or value == 'CTR'):
                  self.sym_mode = value
            elif (value == 'ECB'):
                  self.sym_mode = value
                  print("WARNING: ECB Mode encryption is not secure.")
            else:
                  print('WARNING: Symmetric Encryption Mode \'' +
                        value + '\' not recognized.')
      #end set_sym_mode()

      @staticmethod
      def pkcs7_pad(plaintext):
            pt_bytes = plaintext
            #print("pt_bytes, before: ", pt_bytes)
            if (not isinstance(plaintext, bytes)):
                  pt_bytes = plaintext.encode()
                  pt_bytes = (1).to_bytes(1, byteorder = 'little') + pt_bytes
            else:
                  pt_bytes = (0).to_bytes(1, byteorder = 'little') + pt_bytes
            #print("ptbytes, after: ", pt_bytes)
            pad_length = 16 - (len(pt_bytes) % 16)
            pt_bytes += bytes([pad_length])*pad_length
            return pt_bytes
      #end pkcs7_pad()

      @staticmethod
      def pkcs7_unpad(decrypted_text):
            pt_bytes = decrypted_text[:-decrypted_text[-1]]
            plaintext = pt_bytes
            if (plaintext[0] == (1).to_bytes(1, byteorder = 'little')):
                  plaintext = plaintext[1:].decode()
            else:
                  plaintext = plaintext[1:]
            return plaintext
      #end pkcs7_unpad

      #returns the signature of 'data' in bytes
      def sda_sign(self, asym_key, data):
            data_sig = asym_key.sign(SHA256.new(data).digest(), '')
            return data_sig[0].to_bytes((data_sig[0].bit_length() // 8) + 1, 
                                        byteorder = 'little')
      #end sda_sign()

      def sda_verify(self, asym_key, orig_data, signed_data):
            signed_data_sig = (int.from_bytes(signed_data, byteorder = 'little'), )
            return asym_key.verify(SHA256.new(orig_data).digest(), signed_data_sig)
      #end sda_verify

      def sda_asym_encrypt(self, asym_key, data):
            return asym_key.encrypt(data, '')
      #end sda_asym_encrypt()

      def sda_asym_decrypt(self, asym_key, data):
            return asym_key.decrypt(data)
      #end sda_asym_decrypt()

      def sda_sym_encrypt(self, sym_key, plain):
            theEncrypter = None
            ciphertext = None
            if (self.sym_mode == 'ECB'):
                  theEncrypter = AES.new(sym_key, AES.MODE_ECB)
                  ciphertext = theEncrypter.encrypt(self.pkcs7_pad(plain))
            if (self.sym_mode == 'CBC'):
                  theIV = Random.new().read(16)
                  theEncrypter = AES.new(sym_key, AES.MODE_CBC, theIV)
                  ciphertext = theIV + theEncrypter.encrypt(self.pkcs7_pad(plain))
            if (self.sym_mode == 'CTR'):
                  thePrefix = Random.new().read(8)
                  theCounter = Counter.new(64, prefix = thePrefix)
                  theEncrypter = AES.new(sym_key, AES.MODE_CTR, counter = theCounter)
                  ciphertext = thePrefix + theEncrypter.encrypt(plain)
            return ciphertext
      #end sda_sym_encrypt

      def sda_sym_decrypt(self, sym_key, cipher):
            print('Ciphertext: ', cipher)
            print('Length: ', len(cipher))
            theDecrypter = None
            plaintext = None
            if (self.sym_mode == 'ECB'):
                  theDecrypter = AES.new(sym_key, AES.MODE_ECB)
                  plaintext = self.pkcs7_unpad(theDecrypter.decrypt(cipher))
            if (self.sym_mode == 'CBC'):
                  theIV = cipher[0:16]
                  theDecrypter = AES.new(sym_key, AES.MODE_CBC, theIV)
                  plaintext = self.pkcs7_unpad(theDecrypter.decrypt(cipher[16:]))
            if (self.sym_mode == 'CTR'):
                  thePrefix = cipher[0:8]
                  theCounter = Counter.new(64, prefix = thePrefix)
                  theDecrypter = AES.new(sym_key, AES.MODE_CTR, counter = theCounter)
                  plaintext = theDecrypter.decrypt(cipher[8:])
            return plaintext
      #end sda_sym_decrypt()

#end class Sec_Algo

#End Abstracted Encryption Algorithms
