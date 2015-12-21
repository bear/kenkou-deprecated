#!/usr/bin/env python

import unittest

from kenkou import checkCert

class TestGoodCert(unittest.TestCase):
  def runTest(self):
    r = checkCert('bear.im')
    assert len(r) == 0

class TestExpiredCert(unittest.TestCase):
  def runTest(self):
    r = checkCert('expired.badssl.com')
    assert len(r) == 1
    assert 'get_peer_certificate attempt: Certificate COMODO RSA Domain Validation Secure Server CA has expired!' in r[0]

class TestSelfSignedCert(unittest.TestCase):
  def runTest(self):
    r = checkCert('self-signed.badssl.com')
    assert len(r) == 1
    assert 'certificate verify failed' in r[0]

class TestWrongHostCert(unittest.TestCase):
  def runTest(self):
    r = checkCert('wrong.host.badssl.com')
    assert len(r) == 1
    assert 'Hostname does not match' in r[0]


class TestMsgSizeCert(unittest.TestCase):
  def runTest(self):
    r = checkCert('10000-sans.badssl.com')
    assert len(r) == 1
    assert 'excessive message size' in r[0]
