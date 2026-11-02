Contribution
============

Thanks for reading this section, you have a good intention. Since you are
interested in contributing to Authlib, there are few things you need to know:

1. **Contributions are welcome**, as long as everyone involved is treated
   with respect.
2. Your contribution may be rejected, but don't despair. It's just that this
   certain pull request doesn't fit Authlib. Be brave for a next contribution.
3. Some issues will be labeled as **good first issue**, if you're new to
   Authlib, you may find these issues are a good start for contribution.

AI-Assisted Contributions
-------------------------

You may use AI tools to help you contribute. You are responsible for what you
submit. You must understand it and answer review questions yourself.

Autonomous agents must not interact with the project. A human must review
every issue, pull request, comment and security report before it is submitted.
Maintainers may close contributions from autonomous agents without review or
reply, and block the accounts that submit them.

Bug Reports
-----------

It's welcome for everyone to submit a bug report. However, before you submit a
report on GitHub issues, please check the old issues both open and closed, to
ensure that you are not submitting a duplicate issue.

Please don't ask for help on GitHub issues. Ask them on :ref:`stackoverflow`.

Documentation Contributions
---------------------------

Documentation improvements are welcome, both on grammar and the sentences. I'm
not a native English speaker, you may find errors in this documentation, don't
hesitated to submit an improvement.

Our documentation is generated with Sphinx. All documentation should be written
in reStructuredText, if you are not familiar reStructuredText, please read its
documentation.

We keep a soft limit of 79 characters wide in text files. Yet, if you have to
exceed this limit, it's OK, but no more than 110 characters.

Make a Pull Request
-------------------

Thank you. Now that you have a fix for Authlib, please describe it clearly in
your pull request. There are some requirements for a pull request to be
accepted:

* You can use ruff to check your code style.
* Tests for the code changes are required.
* Please add documentation for it, if it requires.
* Add a changelog fragment if the change is visible to users.

Add a Changelog Fragment
------------------------

Authlib uses `scriv <https://scriv.readthedocs.io>`_ to build the changelog.
Each pull request adds a fragment file in the ``changelog.d`` directory. The
fragments are collected into :doc:`../upgrades/changelog` at release time.

1. Create a fragment::

       uv run scriv create

2. Open the new file in ``changelog.d``. Uncomment the category that fits the
   change: ``Breaking changes``, ``Added``, ``Changed``, ``Deprecated``,
   ``Fixed`` or ``Security``.
3. Replace the example bullet with a short description of what users get.
   Add the issue and pull request references::

       Fixed
       ~~~~~

       - The token endpoint returns ``invalid_grant`` for expired assertions.
         :issue:`123` :pr:`456`

4. Commit the fragment with the rest of the pull request.

.. note::
    By making a pull request, you consent that the copyright of your pull
    request source code belongs to Authlib's author.

Become a Backer
---------------

Finance support is also welcome. A better finance can make Authlib
:ref:`sustainable`. Here I offer two options:

1. **Recurring Pledges**

   Recurring pledges come with exclusive benefits, e.g. having your name
   listed in the Authlib GitHub repository, or have your company logo placed
   on this website.

   * `Become a backer or sponsor via Patreon <https://patreon.com/lepture>`_
   * `Become a backer or sponsor via GitHub <https://github.com/sponsors/lepture>`_

2. **One Time Donation**

   I accept one time donation via Stripe, Alipay and Wechat. Donate via

   `Support Hsiaoming Yang <https://lepture.com/donate>`_
