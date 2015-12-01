#!/usr/bin/env python

import unittest
import certifi

from kenkou import checkCert

cafile = certifi.where()

class TestGoodCert(unittest.TestCase):
    def runTest(self):
      assert True == checkCert('test', 'https://bear.im', cafile, False)

