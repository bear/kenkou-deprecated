# -*- coding: utf-8 -*-
"""
:copyright: (c) 2012-2015 by Mike Taylor
:license: MIT, see LICENSE for more details.
"""

__author__       = 'Mike Taylor'
__email__        = 'bear@bear.im'
__copyright__    = 'Copyright (c) 2012-2015 by Mike Taylor'
__license__      = 'MIT'
__version__      = '0.5.2'
__url__          = 'https://github.com/bear/kenkou'
__download_url__ = 'https://pypi.python.org/pypi/kenkou'
__description__  = 'A python based tool to check that a given resource (URL, Certificate and DNS entry) is alive and valid.'

from .dnscheck import checkDNS
from .urlcheck import checkURL
from .certcheck import checkCert
