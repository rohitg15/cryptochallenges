import sys
from Crypto.Util.number import long_to_bytes, bytes_to_long
import base64
from pwn import *


class Challenge:
    def __init__(self, endpoint: str, port: str) -> None:
        self._sock = remote(endpoint, port)

        data = self._sock.recvuntil(b'[cmd] ')
        self._sock.sendline(b'pkey')
        data = self._sock.recvuntil(b'[cmd] ')
        data = data.replace(b'[pkey] ', b'')

        self._b64_modulus = data.replace(b'\n[cmd] ', b'')

        self._sock.sendline(b'read')
        data = self._sock.recvuntil(b'[cmd] ')
        data = data.replace(b'[shhh] ', b'')

        self._b64_ciphertext = data.replace(b'\n[cmd] ', b'')

    def get_secret_message(self) -> str:
        return self._b64_ciphertext

    def get_public_key(self) -> str:
        return self._b64_modulus
    
    def send(self, c: int) -> bool:
        b64ciphertext = base64.b64encode( long_to_bytes(c) )
        msg = b'send ' + b64ciphertext
        self._sock.sendline(msg)
        data = self._sock.recvuntil(b'[cmd] ') 
        res = data.replace(b'\n[cmd] ', b'')
        return res == b'nice'


if __name__ == "__main__":

    challenge = Challenge('archive.cryptohack.org', '53580')

    # read ciphertext
    c = bytes_to_long(
        base64.b64decode(challenge.get_secret_message())
    )
    e = 65537
    n = bytes_to_long(
        base64.b64decode(challenge.get_public_key())
    )

    oracle_wrapper = lambda s: challenge.send(c * pow(s, e, n))

    # find random int 's0' , 's1' such that
    # s0.m  <  n and s1.m > n
    # to detect this, we find 's' values ending in 0x81
    # since 0x81 . 0x2e % 256 = 0x2e 
    # i.e result ends in a '.' which allows using the oracle to detect
    # when we go over n
    s = ['1', '8']
    while True:
        s_val = int(''.join(reversed(s)), 16)
        if not oracle_wrapper(s_val):
            break
        s.append('f')
    
    s.reverse()
        
    # now value of s*m (> n) returns 'False' from the oracle
    # find smallest 's', such that
    # s * m is > n
    for i in range(len(s) - 2):
        ch = s[i]
        # print (f'running iteration {i} on char {ch}')
        
        # loop invariant
        # print (s)
        assert ( oracle_wrapper(int(''.join(s), 16)) == False )
        
        # for hex character at index 'i', find the smallest
        # value in [F, E, D... 0] such that oracle(s) is False
        for val in range(int(ch, 16), -1, -1):
            s[i] = hex(val)[2:]
            s_val = int(''.join(s), 16)
            if oracle_wrapper(s_val):
                # s * m < n, so value at i must be val + 1
                assert( val < 0xf )
                s[i] = hex(val + 1)[2:]
                break

    # we have 's' that is the smallest value such that
    # s * m > n
    # print (s)
    s = int(''.join(s), 16)
    assert( oracle_wrapper(s) == False )
    print ( long_to_bytes(n // s) )


                
