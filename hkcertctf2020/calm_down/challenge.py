import sys

# Challenge written by Mystiz.

import base64
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes


# replicate challenge locally for testing
class RSAKey:
    def __init__(self, e, d, n):
        self.e = e
        self.d = d
        self.n = n

    def encrypt(self, message):
        message = bytes_to_long(message)
        ciphertext = pow(message, self.e, self.n)
        return long_to_bytes(ciphertext)

    def decrypt(self, ciphertext):
        ciphertext = bytes_to_long(ciphertext)
        message = pow(ciphertext, self.d, self.n)
        return long_to_bytes(message)


class Challenge:
    def __init__(self, message):
        self.generate_key()
        self.message = message

    def generate_key(self):
        key = RSA.generate(2048)
        self.key = RSAKey(key.e, key.d, key.n)

    def get_public_key(self):
        n = base64.b64encode(long_to_bytes(self.key.n)).decode()
        print(f'[pkey] {n}')
        return n

    def get_secret_message(self):
        ciphertext = self.key.encrypt(self.message)
        ciphertext = base64.b64encode(ciphertext).decode()
        print(f'[shhh] {ciphertext}')
        return ciphertext

    def send(self, ciphertext):
        ciphertext = base64.b64decode(ciphertext)
        message = self.key.decrypt(ciphertext)
        if message[-1:] != b'.':
            raise Exception('Be polite. Your message should terminate with a full-stop.')
        # print('nice')

def main():
    message = "S0m4 $uperr S4cr4t me$$4ge H#r@".encode('utf-8')
    c = Challenge(message)

    while True:
        command = input('[cmd] ').split(' ')

        try:
            if command[0] == 'send':
                c.send(command[1])
            elif command[0] == 'pkey':
                c.get_public_key()
            elif command[0] == 'read':
                c.get_secret_message()
        except Exception as exc:
            print(f'nope {exc}')

if __name__ == '__main__':
    main()
