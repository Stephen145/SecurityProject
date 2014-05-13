import os
from Crypto.Hash import MD5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Random import random
import string

def sign_file(f):
    # TODO: For Part 2, you'll use public key crypto here
    # The existing scheme just ensures the updates start with the line 'Caesar'
    # This is naive -- replace it with something better!
    with open('pastebot.net/priv_key', 'r') as g:
        key = RSA.importKey(g.read())
    text = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))
    hash = SHA256.new(text.encode('utf-8')).digest()
    signature = key.sign(hash, '')
    return bytes(str(signature[0]) + "\n" + text + "\n", "ascii") +  f
    # return bytes("Caesar\n", "ascii") + f


if __name__ == "__main__":
    fn = input("Which file in pastebot.net should be signed? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    signed_f = sign_file(f)
    signed_fn = os.path.join("pastebot.net", fn + ".signed")
    out = open(signed_fn, "wb")
    out.write(signed_f)
    out.close()
    print("Signed file written to", signed_fn)
