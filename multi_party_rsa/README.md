# Multi-Party RSA

### Source
[https://ctftime.org/writeup/2869 "multi-party RSA"]

#### Challenge

The given file contains an RSA encrypted string whose public key is provided in the PEM file. The objective is to be able to decrypt the contents of the file

#### Solution

The PEM file reveals an RSA public key with a small modulus (~512 bits) and a public exponent 3. We can easily factorize the RSA modulus from online sources and we observe that it is the product of 3 prime factors p, q, r. The totient is computed as (p-1) * (q-1) * (r-1). computing the gcd of e, totient we can see that it is not relatively prime and thus we can't compute a modular inverse.

 But we can compute ciphertext mod p, ciphertext mod q, ciphertext mod r. All of them are equal to p^3 and we can compute the cube roots modulo p,q,r respectively to arrive at an array of possible solutions for each of them.

Now we have
    pt = cube_root_fromp[i] mod p
    pt = cube_root_fromq[j] mod q
    pt = cube_root_fromr[k] mod r

    This can be solved using the Chinese Remainder Theorem to arrive at a solution for pt in modulo p*q*r (which is the modulus of the given RSA public key). 
