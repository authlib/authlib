.. _install:

Installation
============

.. meta::
    :description: How to install Authlib with pip, source code, etc.

This part of the documentation covers the installation of Authlib, just
like any other software package needs to be installed first.


$ pip install Authlib
---------------------


Installing Authlib is simple with `pip <https://pip.pypa.io/>`_:

.. code-block:: console

    $ pip install Authlib

It will also install the dependencies:

- cryptography
- joserfc

.. note::
    You may enter problems when installing cryptography, check its official
    document at https://cryptography.io/en/latest/installation/

Using Authlib with requests:

.. code-block:: console

    $ pip install Authlib requests

Using Authlib with httpx2:

.. code-block:: console

    $ pip install Authlib httpx2

Using Authlib with Flask:

.. code-block:: console

    $ pip install Authlib Flask

Using Authlib with Django:

.. code-block:: console

    $ pip install Authlib Django

Using Authlib with Starlette:

.. code-block:: console

    $ pip install Authlib httpx2 Starlette


Get the Source Code
-------------------

Authlib is actively developed on GitHub, where the code is
`always available <https://github.com/authlib/authlib>`_.

You can either clone the public repository:

.. code-block:: console

    $ git clone https://github.com/authlib/authlib.git

Download the `tarball <https://github.com/authlib/authlib/tarball/main>`_:

.. code-block:: console

    $ curl -OL https://github.com/authlib/authlib/tarball/main

Or, download the `zipball <https://github.com/authlib/authlib/zipball/main>`_:

.. code-block:: console

    $ curl -OL https://github.com/authlib/authlib/zipball/main


Once you have a copy of the source, you can embed it in your Python package,
or install it into your site-packages easily:

.. code-block:: console

    $ cd authlib
    $ pip install .
