import sys
from Crypto.PublicKey import RSA
from crypto_math import CryptoMath



def get_rsa_key(filename):
    with open(filename, "rb") as file:
        rsa_key = RSA.importKey(file.read())
    return rsa_key


if __name__ == "__main__":
    argc = len(sys.argv)
    if argc != 3:
        print "usage: %s key_file flag_file" % (sys.argv[0])
        exit(0)
    key_file = sys.argv[1]
    flag_file = sys.argv[2]

    rsa_key = get_rsa_key(key_file)
    
    # these are obtained by factorizing n online (since n is small)
    p = 26440615366395242196516853423447
    q = 27038194053540661979045656526063
    r = 32581479300404876772405716877547


    totient = (p-1) * (q-1) * (r-1)

    print "gcd of e, totient is %d" % (CryptoMath.egcd(rsa_key.e, totient)[0])

    # read ciphertext
    with open(flag_file, "rb") as file:
        ciphertext = file.read()
    ciphertext_num = int(ciphertext.encode('hex'), 16)

    # plaintext ** 3 mod p = ciphertext mod p
    # plaintext ** 3 mod q = ciphertext mod q
    # plaintext ** 3 mod r = ciphertext mod r
    # solving cube roots online from wolfram alpha we get the following
    
    proots = [5686385026105901867473638678946, 7379361747422713811654086477766, 13374868592866626517389128266735]
    qroots = [19616973567618515464515107624812]
    rroots = [6149264605288583791069539134541, 13028011585706956936052628027629, 13404203]

    # now we have the following relation
    # pt = proots[i] mod p
    # pt = qroots[j] mod q
    # pt = rroots[k] mod r
    # we can solve for pt using the chinese remainder theorem

    for proot in proots:
        for qroot in qroots:
            for rroot in rroots:            
                n = [p, q, r]
                cubes = [proot, qroot, rroot]
                pt = CryptoMath.solve_crt(cubes, n)
                plaintext = hex(pt)[2:-1]
                if len(plaintext) % 2 == 1:
                    plaintext = "0" + plaintext
                if plaintext.decode('hex').find("ctf") != -1:
                    print plaintext.decode('hex')

