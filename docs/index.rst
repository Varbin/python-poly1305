Welcome to python-poly1305's documentation!
===========================================

python-poly1305 is a package providing DJK's Poly1305 algorithms, on the top 
of PyCrypto, cryptography or m2crypto.


The usage is as easy as:

.. code:: python

   >>> from poly1305 import poly1305aes
   >>> message = b"secret"*8
   >>> key1 = key2 = nonce = b" "*16  # nonce must be random
   >>> poly1305aes(key1, key2, nonce, message)
   b'\xec&\xe3kHP\xe9\t*\xaf\xd75a\x8b\xe9B'


Content
-------

.. toctree::
   :maxdepth: 2

   install
   api
   random_numbers
   examples

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

