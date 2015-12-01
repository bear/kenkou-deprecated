#!/usr/bin/env python

import unittest

from kenkou import checkCert

class TestGoodCert(unittest.TestCase):
  def runTest(self):
    assert [] == checkCert('test', 'bear.im')

class TestExpiredCert(unittest.TestCase):
	def runTest(self):
		s = 'get_peer_certificate attempt: Certificate COMODO RSA Domain Validation Secure Server CA has expired!'
		r = checkCert('test', 'expired.badssl.com')

		assert r[0]['domain']    == 'expired.badssl.com'
		assert r[0]['namespace'] == 'test'
		assert r[0]['errors']    == s

class TestSelfSignedCert(unittest.TestCase):
	def runTest(self):
		s = "get_peer_certificate attempt: [('SSL routines', 'ssl3_get_server_certificate', 'certificate verify failed')]"
		r = checkCert('test', 'self-signed.badssl.com')

		assert r[0]['domain']    == 'self-signed.badssl.com'
		assert r[0]['namespace'] == 'test'
		assert r[0]['errors']    == s

class TestWrongHostCert(unittest.TestCase):
	def runTest(self):
		s = 'Hostname does not match'
		r = checkCert('test', 'wrong.host.badssl.com')

		assert r[0]['domain']    == 'wrong.host.badssl.com'
		assert r[0]['namespace'] == 'test'
		assert r[0]['errors']    == s

class TestMsgSizeCert(unittest.TestCase):
	def runTest(self):
		s = "get_peer_certificate attempt: [('SSL routines', 'ssl3_get_server_certificate', 'certificate verify failed')]"
		r = checkCert('test', 'incomplete-chain.badssl.com')

		assert r[0]['domain']    == 'incomplete-chain.badssl.com'
		assert r[0]['namespace'] == 'test'
		assert r[0]['errors']    == s

class TestMsgSizeCert(unittest.TestCase):
	def runTest(self):
		s = "get_peer_certificate attempt: [('SSL routines', 'ssl3_get_message', 'excessive message size')]"
		r = checkCert('test', '10000-sans.badssl.com')

		assert r[0]['domain']    == '10000-sans.badssl.com'
		assert r[0]['namespace'] == 'test'
		assert r[0]['errors']    == s
