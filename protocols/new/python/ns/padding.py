
class Padder():
    def __init__(self):
        pass

    def pkcs7_pad(self, msg, block_size = 16):
        assert type(msg) is bytes, "Padding is only applied to bytes."
        length = len(msg)
        pad_length = block_size - (length % block_size)
        return msg + bytearray([pad_length] * (pad_length))

    #end pkcs7_pad()

    def pkcs7_unpad(self, msg, block_size = 16):
        pad_length = msg[-1]
        msg_length = len(msg) - pad_length
        assert type(pad_length) is int, "Extracted pad length must be an int."
        assert (len(msg) % block_size) == 0, "Padded length not a multiple of block size."
        assert pad_length <= block_size, "Pad length must not be greater than block size."
        assert pad_length != 0, "Pad length must not be zero."
        assert pad_length == msg.count(pad_length, msg_length), "Pading bytes corrupted."
        return msg[:msg_length]
    #end pkcs7_unpad()

#Test case encrypts 8 bite message with 16 byte blocksize
#assertion checks that message stripped of padding matches original message.
if __name__ == "__main__":
    #m = 'abcdefgh'
    m = b'abcdefgh'
    print(m)
    p = Padder()
    pm = p.pkcs7_pad(m, 16)
    print(pm)
    um = p.pkcs7_unpad(pm, 16)
    assert m == um, "Message stripped of padding does not match original message."
    print(um)
