2. Library reference
====================


.. automodule:: poly1305
   :members: new

The Poly1305 class
---------------------

.. autoclass:: Poly1305
    :members:

The poly1305aes function
------------------------

.. autofunction:: poly1305aes

The constant_time_compare function
----------------------------------

.. warning::

   Never compare two digests with a==b. Use constant-time function for that.

.. autofunction:: constant_time_compare

Test
----

.. autofunction:: runtests

Utility functions
---------------------
.. autofunction:: str2num_littleend
.. autofunction:: hexify
