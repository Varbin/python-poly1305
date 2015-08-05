#!/usr/bin/python3
"""
Poly1305
----------------

A package providing DJK's Poly1305 algorithms, on the top of PyCrypto,
cryptography or m2crypto (it may not work correctly).

Example
---------------

Basic usage::

    >>> from poly1305 import poly1305aes
    >>> import os
    >>> nonce = os.urandom(16)
    >>> poly1305aes(b" "*16, b" "*16, nonce, b"secret"*7)

If AES should insecure in the future, you could easily switch to another
blockcipher::

    >>> from Crypto.Cipher import CAST5
    >>> import os
    >>> nonce = os.urandom(16)
    >>> def cast5_ecb(key, data):
    ...     return CAST5.new(key, mode=CAST5.MODE_ECB).encrypt(val)
    >>> p = Poly1305(b" "*16, b" "*16, nonce, b"secret"*7, cast5_ecb)
    >>> p.digest() # binary out
    ...
    >>> p.hexdigest() # normal out
    ... 

"""
#-------------------------------------------------------------------------------
# Name:        setup.py
# Purpose:     Programm installer
#
# Author:      Simon Biewald
#
# Created:     03.08.2014
# Copyright:   (c) Simon 2014
# Licence:     Public domain without warranty of any kind
#-------------------------------------------------------------------------------

try:
    from setuptools import setup
except ImportError: # Distutils fallback
    from distutils.core import setup


setup_data = dict(name="python-poly1305",
                  version="0.9",
                  author="Simon Biewald",
                  author_email="simon.biewald@hotmail.de",
                  description="Poly1305 in python!",
                  long_description=__doc__,
                  license="MIT",
                  zip_safe=True,
                  platforms="any",
                  py_modules=['poly1305'])

########### Check for any crypto lib

try:
    from Crypto.Cipher import AES
except ImportError:
    pycrypto = False
else:
    pycrypto = True

try:
    import cryptography
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

if not True in [pycrypto, crypto, m2crypto]:
    setup_data["install_requires"]="cryptography"

########### 


setup(**setup_data)
    
