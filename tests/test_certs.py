#!/usr/bin/env python

import unittest

from kenkou import checkCert

class TestGoodCert(unittest.TestCase):
  def runTest(self):
    r = checkCert('test', 'bear.im')
    assert 'check' in r.keys()
    assert r['check']    == 'cert'
    assert len(r.keys()) == 1

class TestExpiredCert(unittest.TestCase):
  def runTest(self):
    s = 'get_peer_certificate attempt: Certificate COMODO RSA Domain Validation Secure Server CA has expired!'
    r = checkCert('test', 'expired.badssl.com')
    assert 'check' in r.keys()
    assert r['check']     == 'cert'
    assert len(r.keys())  == 5
    assert r['domain']    == 'expired.badssl.com'
    assert r['namespace'] == 'test'
    assert r['errors']    == s

class TestSelfSignedCert(unittest.TestCase):
  def runTest(self):
    r = checkCert('test', 'self-signed.badssl.com')
    assert 'check' in r.keys()
    assert r['check']     == 'cert'
    assert len(r.keys())  == 5
    assert r['domain']    == 'self-signed.badssl.com'
    assert r['namespace'] == 'test'
    assert 'certificate verify failed' in r['errors']

class TestWrongHostCert(unittest.TestCase):
  def runTest(self):
    s = 'Hostname does not match'
    r = checkCert('test', 'wrong.host.badssl.com')
    assert 'check' in r.keys()
    assert r['check']     == 'cert'
    assert len(r.keys())  == 5
    assert r['domain']    == 'wrong.host.badssl.com'
    assert r['namespace'] == 'test'
    assert r['errors']    == s

class TestMsgSizeCert(unittest.TestCase):
  def runTest(self):
    r = checkCert('test', '10000-sans.badssl.com')
    assert 'check' in r.keys()
    assert r['check']     == 'cert'
    assert len(r.keys())  == 5
    assert r['domain']    == '10000-sans.badssl.com'
    assert r['namespace'] == 'test'
    assert 'excessive message size' in r['errors']
