=========
Releasing
=========

This document describes how to release changes.

Publishing to Production PyPI
=============================

This section describes how to publish to the default version of PyPI (production/live).

Steps:

1. Edit the ``version`` field from `<./pyproject.toml>`_ and open a pull request
   with the changes

   .. note::

     This follows `PEP 440`_, for example these are valid:

     - 0.9.0
     - 1.0.0a1
     - 1.0.0a2
     - 1.0.0b1
     - 1.0.0rc1
     - 1.0.0
     - 1.1.0a1

     Poetry will also detect non-compliance by running the command ``poetry check``.

2. Merge the pull request
3. Create a GitHub release, and include ``v`` as the version prefix, e.g., ``v1.0.0b5``
4. The `Publish to PyPI`_ workflow will then trigger
   You need to request for other maintainers to approve the deployment to PyPI
   (self-reviews are not allowed).
5. Once the workflow run is approved, a new version will be published on the `PyPI project`_.

Publishing to TestPyPI
======================

This section describes how to deploy to `TestPyPI`_, which is useful whenever one needs
to check whether the build works properly without affecting any user
(e.g., when doing major changes to the `Publish to PyPI`_ pipeline,
or major changes in the way the project is built).

Steps:

1. (Optional but recommended), change the version number in `<./pyproject.toml>`_
2. Push the changes on a branch
3. Go under the `Publish to PyPI`_ workflow, and click "Run workflow"

   1. Select the correct branch
   2. Make sure "testpypi" is selected as the PyPI repository
   3. Click the submit button

4. Request workflow run approval from one of the maintainers.
5. Once approved, it will be available under the `TestPyPI project`_.

.. _PEP 440: https://peps.python.org/pep-0440/
.. _Publish to PyPI: https://github.com/saleor/requests-hardened/actions/workflows/publish-pypi.yaml
.. _PyPI project: https://pypi.org/project/requests-hardened/
.. _TestPyPI project: https://test.pypi.org/project/requests-hardened/
.. _TestPyPI: https://test.pypi.org/
