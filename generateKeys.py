from Crypto.PublicKey import RSA
from Crypto import Random
random_generator = Random.new().read
key = RSA.generate(1024, random_generator)
public_key = key.publickey()
with open('pastebot.net/priv_key', 'w+b') as f:
    f.write(key.exportKey())
with open('pub_key', 'w+b') as f:
    f.write(public_key.exportKey())

