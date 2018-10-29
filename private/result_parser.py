import json
import sys

def result_parser(file_name):
    crypto_names = ('genkey', 'gen_nonce', 'encrypt', 'decrypt', 'sign', 'verify', 'verfiy1')
    crypto_time = 0
    protocol_time = 0
    protocol_name = ''
    with open(file_name, 'r') as f:
        for line in f:
            timing_data = json.loads(line)
            if timing_data[0] in crypto_names:
                crypto_time += timing_data[1]
            else:
                protocol_name = timing_data[0]
                protocol_time = timing_data[1]
    ratio = crypto_time / protocol_time
    result_data = {'crypto_time' : crypto_time, 'protocol_time' : protocol_time, 'ratio' : ratio}
    print(json.dumps(result_data))

if __name__ == "__main__":
    file_name = sys.argv[1]
    result_parser(file_name)
