1. Installation
===============

Dependencies
------------

python-poly1305 depends on PyCrypto, cryptography *or* m2crypto.
If none of them is installed, it will automaticly install the
cryptography package. You may need a C-Compiler.

Install with pip
----------------

You can install the latest version of python-poly1305 with pip:

.. code:: shell

   $ pip install git+https://github.com/varbin/python-poly1305


Manual way
----------

Dowload the source. You can use git to clone the repository with git:

.. code:: shell

   $ git clone git://github.com/varbin/python-poly1305

After that change to this directory and run the installation routine:

.. code:: shell

   $ cd python-poly1305
   $ python3 setup.py build
   $ (sudo) python3 setup.py install
