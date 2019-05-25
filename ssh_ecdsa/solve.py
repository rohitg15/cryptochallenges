import sys
from crypto_math import CryptoMath
from ecdsa import VerifyingKey, SigningKey

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils


curve = ec.SECP256R1()
algo = ec.ECDSA(hashes.SHA256())


def read_public_key(filename):
    with open(filename, 'rb') as f:
        data = f.read()
        return serialization.load_ssh_public_key(data,default_backend())

def check_private_key(x, ec_vk):
    try:
        privateKey = ec.derive_private_key(
                x, pubnum.curve,default_backend())
        privx = 111433156259364900962657153211716695705202991454468823799384945634014805414613
        privy = 86341025742165109488493954778459452974853754548471807463760699827395827180375
        if privx == privateKey.public_key().public_numbers():
            return True, privateKey
        else:
            return False, None

        # if ec_vk.public_numbers()==privateKey.public_key().public_numbers():
        #     return True, privateKey
        # else:
        #     return False, None
    except:
        return False, None

def find_subgroup_order(g, p):
    for x in range(0, 1000):
        pub_key = CryptoMath.mod_exp(g, x, p)
        if pub_key == 1 and x != 0:
            return x



def genECDSAPriv(x, q): #To seed with 128 bits of /dev/random
    p = 14219462995139870823732990991847116988782830807352488252401693038616204860083820490505711585808733926271164036927426970740721056798703931112968394409581
    g = 13281265858694166072477793650892572448879887611901579408464846556561213586303026512968250994625746699137042521035053480634512936761634852301612870164047
    keyLength = 32
    ret = 0
    ths = round((p-1)/2)
    #To increase security, throw away first 10000 numbers
    #for j in range(10000):
    #    x = CryptoMath.mod_exp(g,x,p)
    for i in range(keyLength*8):
        x = pow(g, x % q, p)
        if x > ths:
            ret += 2**i
    return ret


def find_subgroup_elements(g, p, q):
    elements = []
    for i in range(q):
        elements.append(pow(g, i, p))
    return elements

def generate_all_private_keys(g, p):

    # since g has order 673 (say q) (g ** q) mod p = 1
    q = find_subgroup_order(g, p)

    print (q)

    subgroup_elements = find_subgroup_elements(g, p, q)
    print (len(subgroup_elements))

    private_keys = []
    # Thus (g ** x) mod p is equivalent to ( g ** (x % q)) mod p
    # So we can brute force all values from [0, q-1] and compute all possible
    # public keys. The value of x that matches the given ecdsa public key is our private key
    i = 0
    for x in range(q):
        private_key = genECDSAPriv(x, q)
        print (i, private_key)
        private_keys.append(private_key)
        i = i + 1
    return private_keys

def get_ecdsa_private_key(g, p, ec_vk):
    private_key_candidates = generate_all_private_keys(g, p)
    print (private_key_candidates)
    for candidate_key in private_key_candidates:
        #ec_sk = SigningKey.from_secret_exponent(candidate_key, SECP256r1, sha256)
        #ec_vk = SigningKey.get_verifying_key()
        #print (ec_vk)
        #break
        res, ec_sk = check_private_key(candidate_key, ec_vk)
        if res:
            print (ec_sk)
            data = ec_sk.private_bytes(encoding=serialization.Encoding.PEM,
                     format=serialization.PrivateFormat.TraditionalOpenSSL,
                     encryption_algorithm=serialization.NoEncryption())
            with open("id_ecdsa.priv","w") as f2:
                f2.write(data)
            print ("Written to id_ecdsa.priv:","\n",data)
            break

if __name__ == "__main__":
    p = 14219462995139870823732990991847116988782830807352488252401693038616204860083820490505711585808733926271164036927426970740721056798703931112968394409581
    g = 13281265858694166072477793650892572448879887611901579408464846556561213586303026512968250994625746699137042521035053480634512936761634852301612870164047
    
    #print find_subgroup_order(g, p)
    filename = sys.argv[1]
    ec_pubkey = read_public_key(filename)
    print (ec_pubkey.public_numbers())
    get_ecdsa_private_key(g, p, ec_pubkey)
