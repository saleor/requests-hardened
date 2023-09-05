=================
requests-hardened
=================

|pypi-latest-version| |pypi-python-versions| |pypi-implementations|


``requests-hardened`` is a library that overrides the default behaviors of the ``requests``
library, and adds new security features.

Installation
============

The project is available on PyPI_:

.. code-block::

  pip install requests-hardened

Features
========

Overrides of Defaults
---------------------

This library allows to override some default values from the ``requests`` library
that can have a security impact:

- ``Config.never_redirect = False`` always reject HTTP redirects
- ``Config.default_timeout = (2, 10)`` sets the default timeout value when no value or ``None`` is passed


SSRF Filters
------------

A SSRF IP filter can be used to reject HTTP(S) requests targeting private and loopback
IP addresses.

Settings:

- ``Config.ip_filter_enable`` whether or not to filter the IP addresses
- ``ip_filter_allow_localhost`` whether or not to allow loopback IP addresses


Example Usage
=============

.. code-block:: python

  from requests_hardened import Config, Manager

  # Creates a global "manager" that can be used to create ``requests.Session``
  # objects with hardening in place.
  DefaultManager = Manager(
      Config(
          default_timeout=(2, 10),
          never_redirect=False,
          ip_filter_enable=True,
          ip_filter_allow_localhost=False,
      )
  )

  # Sends an HTTP request without re-using ``requests.Session``:
  resp = DefaultManager.send_request("GET", "https://example.com")
  print(resp)

  # Sends HTTP requests with reusable ``requests.Session``:
  with DefaultManager.get_session() as sess:
      sess.request("GET", "https://example.com")
      sess.request("POST", "https://example.com", json={"foo": "bar"})


.. _PyPI: https://pypi.org/project/requests-hardened

.. |pypi-latest-version| image:: https://img.shields.io/pypi/v/requests-hardened.svg
  :alt: Latest Version
  :target: `PyPI`_

.. |pypi-python-versions| image:: https://img.shields.io/pypi/pyversions/requests-hardened.svg
  :alt: Supported Python Versions
  :target: `PyPI`_

.. |pypi-implementations| image:: https://img.shields.io/pypi/implementation/requests-hardened.svg
  :alt: Supported Implementations
  :target: `PyPI`_
