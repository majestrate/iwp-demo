from hashlib import blake2b, sha256
import base64
import pysodium

rand = pysodium.randombytes

keysize = 64

encode = lambda x : base64.b32encode(x).decode('ascii').lower()
encodeKey = lambda x : encode(x).strip('=')
decode = lambda x : base64.b32decode(x.upper())
decodeKey = lambda x : '=' in x and decode('{}===='.format(x.strip('='))) or decode('{}===='.format(x))

def loadKeys(fd):
    """
    load keys from file descriptor
    """
    sk = None
    while True:
        line = fd.readline()
        if len(line) == 0:
            break
        if line.startswith('seed:'):
            sk = decodeKey(line[5:].strip())
    return sk

seedgen = lambda : blake2b(rand(keysize), digest_size=pysodium.crypto_box_SEEDBYTES).digest()

def genKeys(addrstr, fd):
    """
    generate keypair for address and dump to file descriptor
    """
    seed = seedgen()
    fd.write('seed:')
    fd.write(encodeKey(seed))
    fd.write('\n')

def keypair(seed):
    pk, sk = pysodium.crypto_box_seed_keypair(seed)
    return sk, pk

def genEphemeralKeys():
    return keypair(seedgen())

def keyExchange(us, them, extra):
    """
    do key exchange
    """
    q = pysodium.crypto_scalarmult_curve25519(us, them)
    h = blake2b(digest_size=pysodium.crypto_aead_chacha20poly1305_KEYBYTES)
    h.update(q)
    h.update(us)
    h.update(them)
    h.update(extra)
    return h.digest()

def encrypt(k, data):
    n = rand(pysodium.crypto_aead_chacha20poly1305_NONCEBYTES)
    return n + pysodium.crypto_aead_chacha20poly1305_encrypt(data, None, n, k)

def decrypt(k, data):
    n = data[:pysodium.crypto_aead_chacha20poly1305_NONCEBYTES]
    c = data[len(n):]
    return pysodium.crypto_aead_chacha20poly1305_decrypt(c, None, n, k)

def oneshotEncrypt(sk, pk, data):
    n = rand(pysodium.crypto_box_NONCEBYTES)
    return n + pysodium.crypto_box(data, n, pk, sk)

def oneshotDecrypt(sk, pk, data):
    n = data[:pysodium.crypto_box_NONCEBYTES]
    c = data[len(n):]
    return pysodium.crypto_box_open(c, n, pk, sk)

def sign(sk, data):
    return pysodium.crypto_sign_detached(data, sk)

def genProofOfWork(seed, difficulty=1):
    good = False
    while not good:
        r = rand(32)
        h = sha256(seed+r).digest()
        good = h.startswith(b'\x00' * difficulty)
    return r, h

def verifyProofOfWork(seed, r, h, minDifficulty=1):
    d = sha256(seed + r).digest()
    return d == h and h.startswith(b'\x00' * minDifficulty)


