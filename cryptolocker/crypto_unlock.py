import sys
from AESCipher import *
import hashlib
from Crypto.Cipher import AES


def get_sha256_2bytes():
    """ 
        builds a list of all 2 byte sha256 hashes
    """
    hashes = []
    hash_key_map = {}
    for byte0 in range(256):
        for byte1 in range(256):
            key_hash = hashlib.sha256(chr(byte0) + chr(byte1)).digest()
            hashes.append(key_hash)
            hash_key_map[key_hash.encode('hex')] = chr(byte0) + chr(byte1)
    return hashes, hash_key_map
    

if __name__ == "__main__":
    argc = len(sys.argv)
    if argc != 3:
        print "usage: %s input_filename output_filename" % (sys.argv[0])
        exit(0)
    input_filename = sys.argv[1]
    output_filename = sys.argv[2]

    # read ciphertext from input file
    ciphertext = open(input_filename, "r").read()
    
    # build sha256 hash list for all 2 byte combinations
    hashes, key_map = get_sha256_2bytes()

    # each hash is a possible key, attempt decryption and check padding
    decrypted_data = ''
    current_ciphertext = ciphertext
    layer_keys = []
    guess = []
    for layer in range(4):
        print "decrypting layer %d" % (4 - layer)
        for key in hashes:
            cipher = AESCipher(key)
            decrypted_data = cipher.decrypt(current_ciphertext)
            # for the 3 outermost layers, we can expect the padding to be 16 bytes of 0x10
            # this is because the plaintext for every round (other than the very first) is the 
            # ciphertext (multiple of 32 bytes) + iv (16 bytes) combination from the previous round.
            if layer != 3:
                padding_block = decrypted_data[-AES.block_size:]
                is_valid = True
                for ch in padding_block:
                    if ord(ch) != 16:
                        is_valid = False
                        break
                if is_valid:
                    current_ciphertext = AESCipher._unpad(decrypted_data)
                    layer_keys.append(key.encode('hex'))
                    print "solved layer %d with key : %s, padding byte : %d" % (4 - layer, key.encode('hex'), ord(padding_block[-1]))
                    break
            else:
                last_byte = decrypted_data[-1]
                count = ord(last_byte)
                padding_block = decrypted_data[-count:]
                is_valid = True
                for ch in padding_block:
                    if ord(ch) != ord(last_byte):
                        is_valid = False
                        break
                if is_valid:
                    print "padding %d" % (count)
                    guess.append( (count, AESCipher._unpad(decrypted_data), key.encode('hex')) ) 
    _, plaintext, key = sorted(guess, reverse=True)[0]

    layer_keys.append(key)
    password = ""
    for key in layer_keys[::-1]:
        password += key_map[key]
    print "password: %s" % (password)
  
    print "writing decrypted file to %s" % (output_filename)
    with open(output_filename, "wb") as file:
        file.write(plaintext)







