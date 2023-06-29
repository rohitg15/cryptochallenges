# CALM DOWN (HKCERTCTF 2020)

## Source
['https://hackmd.io/@hoifanrd/SyeYX-HFP']

## Challenge
The given server exposes an RSA decryption oracle. Interacting with the server provides access to the public key and ciphertext. The objective is to decrypt the
ciphertext.


## Solution

The RSA decryption doesn't apply padding but expects the message to end with a '.' character and
returns an error if that is not the case. This effectively exposes an oracle based on the message format, that could be used to decryptthe encrypted ciphertext.
The lack of padding implies we could blind the RSA ciphertext in such a way that it ends with a '.'. By increasing the size of the blinding factor 's',
we try to get as close to 'n' - the public modulus as possible. Since the message is very small compared to n, once we retrieve the smallest 's' 
such that s . m > n, we could obtain the message as n // m.


