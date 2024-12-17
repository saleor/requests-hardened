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

- `SSRF Filters`_: blocks private and loopback IP ranges.
- HTTP Redirects: can be used safely alongside the SSRF filter feature.
- `Proxy Support`_: proxies can be used in combination with SSRF Filters for a defense in depth.
- Handy `Overrides of Defaults`_: allows to enforce secure defaults globally, such as to
  mitigate DoS attacks.

Overrides of Defaults
---------------------

This library allows to override some default values from the ``requests`` library
that can have a security impact:

- ``Config.never_redirect = False`` always reject HTTP redirects
- ``Config.default_timeout = (2, 10)`` sets the default timeout value when no value or ``None`` is passed
- ``Config.user_agent_override = None`` optional config to override ``User-Agent`` header. When set to ``None``, ``requests`` library will set its `default user-agent <https://github.com/psf/requests/blob/ee93fac6b2f715151f1aa9a1a06ddba9f7dcc59a/src/requests/utils.py#L886-L892>`_.

SSRF Filters
------------

A SSRF IP filter can be used to reject HTTP(S) requests targeting private and loopback
IP addresses.

Settings:

- ``Config.ip_filter_enable`` whether or not to filter the IP addresses
- ``ip_filter_allow_loopback_ips`` whether or not to allow loopback IP addresses

Proxy Support
^^^^^^^^^^^^^

The SSRF IP filter's behavior with proxies are as follows:

- **Proxy's IP Address:** does not block private and loopback IP addresses (no filtering).
  Instead, the filter assumes that the proxy URL is never tainted with untrusted
  user input.
- **Target IP Address (Tunneled HTTP Requests):** by default, the tunneled requests are
  filtered for potential SSRF attacks.
- **Protocols Supported:** SOCKS4, SOCKS5, HTTP, and HTTPS proxy server protocols are supported.

  .. note::

    We rely on the ``requests`` and ``urllib3`` thus the list may change over time.

  .. warning::

    For SOCKS4 and SOCKS5, you need to run ``pip install requests[socks]``

Example Usage:

.. code-block:: python

  from requests_hardened import Config, Manager

  http_manager = Manager(
      Config(
          default_timeout=(2, 10),
          never_redirect=False,
          # Enable SSRF IP filter
          ip_filter_enable=True,
          ip_filter_allow_loopback_ips=False,
      )
  )

  # List of proxies
  proxies = {
    "https": "socks5://127.0.0.1:8888",
    "http": "socks5://127.0.0.1:8888",
  }

  # Sends the HTTP request using the proxy
  resp = http_manager.send_request("GET", "https://example.com", proxies=proxies)
  print(resp)


.. note::

  For more details on using proxies with the ``requests`` library, see the `official
  documentation <https://docs.python-requests.org/en/latest/user/advanced/#proxies>`_.


Full Example
============

.. code-block:: python

  from requests_hardened import Config, Manager

  # Creates a global "manager" that can be used to create ``requests.Session``
  # objects with hardening in place.
  http_manager = Manager(
      Config(
          default_timeout=(2, 10),
          never_redirect=False,
          ip_filter_enable=True,
          ip_filter_allow_loopback_ips=False,
          user_agent_override=None
      )
  )

  # Sends an HTTP request without re-using ``requests.Session``:
  resp = http_manager.send_request("GET", "https://example.com")
  print(resp)

  # Sends HTTP requests with reusable ``requests.Session``:
  with http_manager.get_session() as sess:
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
