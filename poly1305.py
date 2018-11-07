#!/usr/bin/python3
# -*- encoding: utf-8 -*-

"""
Poly1305-AES in python.

This is a PEP-compliant implementation of D.J. Berstein's Poly1305-Algorithm.
Some parts of the code are taken from Ken Raeburn's python implementation
from http://cr.yp.to/mac/poly1305aes.py.

"""

## Original release notes by Ken Raeburn:
##
##  # Hack implementation of DJB's Poly1305-AES MAC.
##  # Written 2005-01-18 by Ken Raeburn, and placed in the public domain.
##  # Apologies for the clunkiness, I'm still learning Python


from __future__ import print_function

import binascii
import sys
import warnings

PY3K = int(sys.version[0]) >= 3

try:
    from Crypto.Cipher import AES
except ImportError:
    pycrypto = False
else:
    pycrypto = True

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers.algorithms import AES as AES_C
    from cryptography.hazmat.primitives.ciphers.modes import ECB
    from cryptography.hazmat.primitives.ciphers import Cipher
except ImportError:
    crypto = False
else:
    crypto = True

try:
    import M2Crypto
except ImportError:
    m2crypto = False
else:
    m2crypto = True


if pycrypto:
    def _aes_encrypt(key, val):
        "Encrypt one single data block with AES -- PyCrypto based"
        return AES.new(key, mode=AES.MODE_ECB).encrypt(val)
elif crypto:
    def _aes_encrypt(key, val):
        "Encrypt one single data block with AES -- cryptography based"
        e = Cipher(AES_C(key), ECB(), default_backend()).encryptor()
        return e.update(val)+e.finalize() 
elif m2crypto:
    def _aes_encrypt(key, val):
            "Encrypt one single data block with AES -- M2Crypto based"
            c = M2Crypto.EVP.Cipher(alg='aes_128_ecb', key=key, op=1)
            return c.update(val)+c.final()
else:
    warnings.warn("No AES libary found! Most functions won't work!",
                  ImportWarning)
    def _aes_encrypt(*args):
        "No crypto libary found!"
        raise NotImplementedError("No crypto libary found!")


import hmac
if hasattr(hmac, 'compare_digest'):
    def constant_time_compare(a,b):
        return hmac.compare_digest(a,b)
else:
    def constant_time_compare(a,b):
            if len(a) != len(b):
                return False
            result = 0
            if PY3K and isinstance(a, bytes) and isinstance(b, bytes):
                for x, y in zip(a, b):
                    result |= x ^ y
            else:
                for x, y in zip(a, b):
                    result |= ord(x) ^ ord(y)
            return result == 0

constant_time_compare.__doc__ = """
Returns True if the two strings are equal, False otherwise.
    
The time taken is independent of the number of characters that match.
For the sake of simplicity, this function executes in constant time only
when the two strings have the same length. It short-circuits when an error
occurs they have different lengths. Since Poly1305 MAC's have a constant
length, this is acceptable.

:param a: The first parameter
:type a: byte or ascii string
:param b: The second parameter
:type b: byte or ascii string
"""

def new(*args, **kwargs):
    """
    Returns a Poly1305-object with given parameters.

    See the Poly1305-class for details.
    """

class Poly1305:
    """
    The main class.

    :param key_aes: your cipher key, the length
        depends on your cipher (16, 24 or 32 for AES)
    :type key_aes: bytes
    
    :param r: your poly1305 key with a length of 16
    :type r: bytes
    
    :param nonce: your *random* nonce with a length of 16
    :type nonce: bytes
    
    :param string: the message you want to sign
    :type string: bytes

    :param method: the encryption method with the syntax encrypt(key, val).
        Defaults to AES from cryptography, pycypto or m2crypto.
    :type method: method with args (key, msg)
    """
    digest_size = 16
    
    def __init__(self, key_aes, r, nonce , string=b"", method=_aes_encrypt):
        self.__key_aes = key_aes
        self.__r = r
        self.__nonce = nonce
        self.__string = string
        self.__aes = method

    def update(self, msg):
        """
        Update the hmac object with msg.
        Repeated calls are equivalent to a single call with the concatenation
        of all the arguments: m.update(a); m.update(b) is equivalent
        to m.update(a + b).

        :type msg: bytes
        """
        
        self.__string += msg

    def digest(self):
        """
        Return the digest of the bytes passed to the update()
        method so far. This bytes object will be the same
        length of 16 constructor. It may contain non-ASCII bytes,
        including NUL bytes.
        """

        k, r, n, msg = (self.__key_aes, self.__r,
                        self.__nonce, self.__string)
        mod1305 = (1 << 130) - 5
        rval = str2num_littleend(r)
        rval &= 0x0ffffffc0ffffffc0ffffffc0fffffff
        q = (len(msg) + 15) / 16
        tot = 0
        for i in range(int(q)):
            sub = msg[i*16 : i*16+16] + b"\x01"
            sub += (17 - len(sub)) * b"\x00"
            num = str2num_littleend(sub)
            tot = (tot + num) * rval
        tot = tot % mod1305
        enc = self.__aes(k, n)
        enc = str2num_littleend(enc)
        result = (tot + enc) % (1 << 128)
        # Convert to a 16-byte string, little-endian order.
        result = ''.join(map(lambda i: chr(0xff & (result >> 8*i)), range(16)))
        if PY3K:
            result = result.encode("latin-1")
        
        return result

    def hexdigest(self):
        """
        Like digest() except the digest is returned as a string twice the
        length containing only hexadecimal digits. This may be used to
        exchange the value safely in email or other non-binary environments.
        """
        return binascii.hexlify(self.digest()).decode()

    def copy(self):
        """
        Return a copy (“clone”) of the Poly1305 object. This can be used to
        efficiently compute the digests of strings that share a common
        initial substring.

        .. warning::

            Using two Poly1305-objects with the same key & nonce is insecure.
            The nonce must only be used one time per key.
        """
        return Poly1305(self.__key_aes, self.__r,
                        self.__nonce, self.__string,
                        self.__aes)


def poly1305aes(k, r, n, m):
    """\
    Poly1305-AES computation function.
    This function grants interoperability with the old version
    which was written by Ken Raeburn.

    :param k: your cipher key, the length depends on your cipher
    :type k: bytes
    
    :param r: your poly1305 key with a length of 16
    :type r: bytes
    
    :param n: your *random* nonce with a length of 16
    :type n: bytes
    
    :param m: the message you want to sign
    :type m: bytes

    
    """
    return Poly1305(k, r, n, m, _aes_encrypt).digest()


####################################

def str2num_littleend(val):
    "Helper function to make a byte string to a number (int or long)."
    return int(binascii.hexlify(val[::-1]), 16)

if sys.version[0] == "3":
    def hexify(s):
        b = []
        for i in s: # bytes...
            if type(i) == int:
                i = chr(i).encode()
            elif type(i) == bytes:
                pass
            elif type(i) == str:
                i = i.encode()
            b.append(i)
        return b' '.join(map(binascii.hexlify, b))
elif sys.version[0] == "2":
    def hexify(s):
        return b" ".join(map(binascii.hexlify, s))

hexify.__doc__ = ("Helper function to turn a binary "
                  "string into a human readable hex-encoded "
                  "form.")

####################################

testvec = [
    { "k" : b"\xec\x07\x4c\x83\x55\x80\x74\x17\x01\x42\x5b\x62\x32\x35\xad\xd6",
      "m" : b"\xf3\xf6",
      "r" : b"\x85\x1f\xc4\x0c\x34\x67\xac\x0b\xe0\x5c\xc2\x04\x04\xf3\xf7\x00",
      "n" : b"\xfb\x44\x73\x50\xc4\xe8\x68\xc5\x2a\xc3\x27\x5c\xf9\xd4\x32\x7e",
      "x" : b"\xf4\xc6\x33\xc3\x04\x4f\xc1\x45\xf8\x4f\x33\x5c\xb8\x19\x53\xde"
    },
    { "k" : b"\x75\xde\xaa\x25\xc0\x9f\x20\x8e\x1d\xc4\xce\x6b\x5c\xad\x3f\xbf",
      "m" : b"",
      "r" : b"\xa0\xf3\x08\x00\x00\xf4\x64\x00\xd0\xc7\xe9\x07\x6c\x83\x44\x03",
      "n" : b"\x61\xee\x09\x21\x8d\x29\xb0\xaa\xed\x7e\x15\x4a\x2c\x55\x09\xcc",
      "x" : b"\xdd\x3f\xab\x22\x51\xf1\x1a\xc7\x59\xf0\x88\x71\x29\xcc\x2e\xe7"
    },
    { "k" : b"\x6a\xcb\x5f\x61\xa7\x17\x6d\xd3\x20\xc5\xc1\xeb\x2e\xdc\xdc\x74",
      "m" : b"\x66\x3c\xea\x19\x0f\xfb\x83\xd8\x95\x93\xf3\xf4\x76\xb6\xbc\x24"
          + b"\xd7\xe6\x79\x10\x7e\xa2\x6a\xdb\x8c\xaf\x66\x52\xd0\x65\x61\x36",
      "r" : b"\x48\x44\x3d\x0b\xb0\xd2\x11\x09\xc8\x9a\x10\x0b\x5c\xe2\xc2\x08",
      "n" : b"\xae\x21\x2a\x55\x39\x97\x29\x59\x5d\xea\x45\x8b\xc6\x21\xff\x0e",
      "x" : b"\x0e\xe1\xc1\x6b\xb7\x3f\x0f\x4f\xd1\x98\x81\x75\x3c\x01\xcd\xbe"
    },
    { "k" : b"\xe1\xa5\x66\x8a\x4d\x5b\x66\xa5\xf6\x8c\xc5\x42\x4e\xd5\x98\x2d",
      "m" : b"\xab\x08\x12\x72\x4a\x7f\x1e\x34\x27\x42\xcb\xed\x37\x4d\x94\xd1"
	  + b"\x36\xc6\xb8\x79\x5d\x45\xb3\x81\x98\x30\xf2\xc0\x44\x91\xfa\xf0"
	  + b"\x99\x0c\x62\xe4\x8b\x80\x18\xb2\xc3\xe4\xa0\xfa\x31\x34\xcb\x67"
	  + b"\xfa\x83\xe1\x58\xc9\x94\xd9\x61\xc4\xcb\x21\x09\x5c\x1b\xf9",
      "r" : b"\x12\x97\x6a\x08\xc4\x42\x6d\x0c\xe8\xa8\x24\x07\xc4\xf4\x82\x07",
      "n" : b"\x9a\xe8\x31\xe7\x43\x97\x8d\x3a\x23\x52\x7c\x71\x28\x14\x9e\x3a",
      "x" : b"\x51\x54\xad\x0d\x2c\xb2\x6e\x01\x27\x4f\xc5\x11\x48\x49\x1f\x1b"
    } ];


def runtests():
    "Runs the poly1305aes selftest."
    f = 0
    for d in testvec:
        res = poly1305aes(d["k"], d["r"], d["n"], d["m"])
        if res != d["x"]:
            print ("COMPUTED RESULT DOESN'T MATCH EXPECTED OUTPUT!", file=sys.stderr)
            print ("expected = ", hexify(d["x"]).decode())
            print ("returned = ", hexify(res).decode())
            print(res == d["x"])
            f += 1
    if not f:
        print("\nAll tests successfully!")
        return True
    else:
        print("\nError!", file=sys.stderr)
        return False

if __name__ == "__main__":
    runtests()
    print('Extra test:', (Poly1305(testvec[0]["k"], testvec[0]["r"],
                                 testvec[0]["n"], testvec[0]["m"]).digest()
                          ==testvec[0]["x"])
          )
