# Cryptolocker

### Source 
[https://ctftime.org/task/2963 "cryptolockers challenge"]

#### Challenge
     The given source code was used to encrypt a file (flag.encrypted) using AES-cbc 4 times successively. A password with 8 characters is divided into 2 characters each and hashed 4 times to obtain 4 symmetric keys that are used to encrypt the file successively.The objective is to retrieve the password used originally to encrypt the file, and consequently be able to decrypt the file.


#### Solution
     The 4 successive encryptions use a sha256 hash of a 2 byte string each. Therefore we can compute a dictionary of all possible 2 byte strings and their corresponding sha256 hashes. The 4 keys will certainly be present somewhere in this dictionary. Now we 
can attempt decryption using each one of the 65536 possible keys and identify a valid decryption based on whether or not the resulting padding was successful. For the last 3 layers of encryptions, the input itself is the iv + ciphertext of AES-cbc from the previous layer.THerefore, the ciphertext will have a size that is a multiple of 32 and the iv will be 16 bytes. So each one of these rounds will have 16 bytes of 16 as padding. The very first layer of encryption could have any valid padding although it is likely to be bigger than 1.
Thus for the innermost layer, we capture all possible decryptions and use the one with the highest padding value. At every step we can keep track of the key corresponding to a successful decryption and map it back to a valid password.


