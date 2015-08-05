
4. Examples
===========

Basic usage:

.. code:: python

    >>> from poly1305 import poly1305aes
    >>> import os
    >>> nonce = os.urandom(16)
    >>> poly1305aes(b" "*16, b" "*16, nonce, b"secret"*7)

If AES should be insecure in the future, you could easily switch to another
blockcipher:

.. code:: python

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
