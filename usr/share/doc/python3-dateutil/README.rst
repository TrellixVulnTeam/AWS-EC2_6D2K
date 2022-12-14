dateutil - powerful extensions to datetime
==========================================

.. image:: https://img.shields.io/travis/dateutil/dateutil/master.svg?style=flat-square
    :target: https://travis-ci.org/dateutil/dateutil
    :alt: travis build status

.. image:: https://img.shields.io/appveyor/ci/dateutil/dateutil/master.svg?style=flat-square
    :target: https://ci.appveyor.com/project/dateutil/dateutil
    :alt: appveyor build status

.. image:: https://codecov.io/github/dateutil/dateutil/coverage.svg?branch=master
    :target: https://codecov.io/github/dateutil/dateutil?branch=master
    :alt: Code coverage

.. image:: https://img.shields.io/pypi/dd/python-dateutil.svg?style=flat-square
    :target: https://pypi.python.org/pypi/python-dateutil/
    :alt: pypi downloads per day

.. image:: https://img.shields.io/pypi/v/python-dateutil.svg?style=flat-square
    :target: https://pypi.python.org/pypi/python-dateutil/
    :alt: pypi version


The `dateutil` module provides powerful extensions to
the standard `datetime` module, available in Python.


Download
========
dateutil is available on PyPI
https://pypi.python.org/pypi/python-dateutil/

The documentation is hosted at:
https://dateutil.readthedocs.io/

Code
====
https://github.com/dateutil/dateutil/

Features
========

* Computing of relative deltas (next month, next year,
  next monday, last week of month, etc);
* Computing of relative deltas between two given
  date and/or datetime objects;
* Computing of dates based on very flexible recurrence rules,
  using a superset of the `iCalendar <https://www.ietf.org/rfc/rfc2445.txt>`_
  specification. Parsing of RFC strings is supported as well.
* Generic parsing of dates in almost any string format;
* Timezone (tzinfo) implementations for tzfile(5) format
  files (/etc/localtime, /usr/share/zoneinfo, etc), TZ
  environment string (in all known formats), iCalendar
  format files, given ranges (with help from relative deltas),
  local machine timezone, fixed offset timezone, UTC timezone,
  and Windows registry-based time zones.
* Internal up-to-date world timezone information based on
  Olson's database.
* Computing of Easter Sunday dates for any given year,
  using Western, Orthodox or Julian algorithms;
* A comprehensive test suite.

Quick example
=============
Here's a snapshot, just to give an idea about the power of the
package. For more examples, look at the documentation.

Suppose you want to know how much time is left, in
years/months/days/etc, before the next easter happening on a
year with a Friday 13th in August, and you want to get today's
date out of the "date" unix system command. Here is the code:

.. doctest:: readmeexample

    >>> from dateutil.relativedelta import *
    >>> from dateutil.easter import *
    >>> from dateutil.rrule import *
    >>> from dateutil.parser import *
    >>> from datetime import *
    >>> now = parse("Sat Oct 11 17:13:46 UTC 2003")
    >>> today = now.date()
    >>> year = rrule(YEARLY,dtstart=now,bymonth=8,bymonthday=13,byweekday=FR)[0].year
    >>> rdelta = relativedelta(easter(year), today)
    >>> print("Today is: %s" % today)
    Today is: 2003-10-11
    >>> print("Year with next Aug 13th on a Friday is: %s" % year)
    Year with next Aug 13th on a Friday is: 2004
    >>> print("How far is the Easter of that year: %s" % rdelta)
    How far is the Easter of that year: relativedelta(months=+6)
    >>> print("And the Easter of that year is: %s" % (today+rdelta))
    And the Easter of that year is: 2004-04-11

Being exactly 6 months ahead was **really** a coincidence :)


Author
======
The dateutil module was written by Gustavo Niemeyer <gustavo@niemeyer.net>
in 2003.

It is maintained by:

* Gustavo Niemeyer <gustavo@niemeyer.net> 2003-2011
* Tomi Pievil??inen <tomi.pievilainen@iki.fi> 2012-2014
* Yaron de Leeuw <me@jarondl.net> 2014-2016
* Paul Ganssle <paul@ganssle.io> 2015-

Our mailing list is available at `dateutil@python.org <https://mail.python.org/mailman/listinfo/dateutil>`_. As it is hosted by the PSF, it is subject to the `PSF code of
conduct <https://www.python.org/psf/codeofconduct/>`_.

Building and releasing
======================
When you get the source, it does not contain the internal zoneinfo
database. To get (and update) the database, run the updatezinfo.py script. Make sure
that the zic command is in your path, and that you have network connectivity
to get the latest timezone information from IANA, or from `our mirror of the
IANA database <https://dateutil.github.io/tzdata/>`_.

Starting with version 2.4.1, all source and binary distributions will be signed
by a PGP key that has, at the very least, been signed by the key which made the
previous release. A table of release signing keys can be found below:

===========  ============================
Releases     Signing key fingerprint
===========  ============================
2.4.1-       `6B49 ACBA DCF6 BD1C A206 67AB CD54 FCE3 D964 BEFB`_
===========  ============================

Testing
=======
dateutil has a comprehensive test suite, which can be run simply by running
`python setup.py test [-q]` in the project root. Note that if you don't have the internal
zoneinfo database, some tests will fail. Apart from that, all tests should pass.

To easily test dateutil against all supported Python versions, you can use
`tox <https://tox.readthedocs.io/en/latest/>`_.

All github pull requests are automatically tested using travis and appveyor.


.. _6B49 ACBA DCF6 BD1C A206 67AB CD54 FCE3 D964 BEFB:
   https://pgp.mit.edu/pks/lookup?op=vindex&search=0xCD54FCE3D964BEFB
