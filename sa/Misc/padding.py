#This files contains implementations of padding algorithms.

def pkcs7_pad(bytestring, blocksize=16):
    bytestring_length = len(bytestring)
    pad_length = blocksize - (bytestring_length % blocksize)
    return bytestring + bytearray([pad_length] * pad_length)
#end pkcs7_pad()

def pkcs7_unpad(bytestring, blocksize=16):
    pad_length = bytestring[-1]
    if pad_length > blocksize:
        raise ValueError('Input is not padded or the padding is corrupted.')
    real_length = len(bytestring) - pad_length
    return bytestring[:real_length]
#end pkcs7_unpad()
