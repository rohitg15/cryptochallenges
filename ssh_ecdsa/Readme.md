# Based on the YNOTCTF challenge crypto-sms

### https://duksctf.github.io/2017/11/17/YNOT17-SmS-Secret-Server.html

In this challenge we're given a PRNG, that uses the hardness of the discrete logarithm problem to generate a secret from a seed.

The given generator, clearly has order 673 (brute-force values from 1...p-1 and 673 will result in a 1 upon modular exponentiation). This implies that there are only 673 possible values upon modular exponentiation. We can generate all 673 values, compute the candidate private keys with each of these values as a seed to the given PRNG function, and compare the corresponding public keys.