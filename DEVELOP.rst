=================
Development Guide
=================

The purpose of this document is to share knowledge surrounding the development of this
library in order to make the development process easier for new comers.

Using Proxies
=============

The library supports using proxies, such as in the IP filtering feature,
this section describes how to start a proxy server and how to use it.

Running a Proxy Server
----------------------

You can start a proxy using one of these options:

Using pproxy
^^^^^^^^^^^^

The `pproxy`_ command comes pre-installed as part of the development dependencies
(``poetry install --with dev``).

.. note::

  In these examples, we will use ``127.0.0.1:8888`` as the proxy address.

To start a server with the multiple protocols (HTTP, SOCKS4, SOCKS5), run:

.. code-block:: bash

  pproxy -l 'http+socks4+socks5://127.0.0.1:8888/'

Alternatively, you can select a single protocol. For example, if you only want SOCKS5:

.. code-block:: bash

  pproxy -l 'socks5://127.0.0.1:8888/'

Using SSH
^^^^^^^^^

You can start a SOCKS4 and SOCKS5 proxy using the following SSH command:

.. code-block:: bash

  ssh user@example.com -D 127.0.0.1:8888

Using the Proxy Server
----------------------

.. note::

  You will find more details inside the ``requests`` `documentation <https://docs.python-requests.org/en/latest/user/advanced/#proxies>`_

Once you have a `proxy running in the background <Running a Proxy Server_>`_,
you can tell requests-hardened to use it using either of these methods:

Using Environment Variables
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Using ``HTTP_PROXY`` and ``HTTPS_PROXY``:

.. code-block:: bash

  $ export HTTP_PROXY="socks5://127.0.0.1:8888"
  $ export HTTPS_PROXY="socks5://127.0.0.1:8888"
  $ python3 my-script.py

Alternatively, using ``ALL_PROXY``:

.. code-block:: bash

  $ export ALL_PROXY="socks5://127.0.0.1:8888"
  $ python3 my-script.py

Using the ``proxies={...}`` Keyword (Python Code)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``requests`` libraries allows to define proxies servers to be used via the ``proxies``
parameter.

Example:

.. code-block:: python

  from requests_hardened import Config, Manager

  http_manager = Manager(
      Config(
          ip_filter_enable=True,
          ip_filter_allow_loopback_ips=True,
          never_redirect=False,
          default_timeout=2,
      )
  )

  proxies = {
    "http": "socks5://127.0.0.1:8888",
    "https": "socks5://127.0.0.1:8888",
  }

  http_manager.send_request("GET", "https://example.com", proxies=proxies)


.. _pproxy: https://github.com/qwj/python-proxy/
