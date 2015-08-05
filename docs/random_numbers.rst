3. Generating random numbers
============================

Why?
----

It is important to create unique nonces (numbers used onced)

Generating secure numbers with python
-------------------------------------

To generate a secure random number you could use following wich refers to the 
operating system's CSPRNG (/dev/urandom on \*nix, CryptGenRandom on Windows):

.. code:: python

    >>> import os
    >>> os.urandom(16)

.. warning::

   *Never* use the random module from python.
