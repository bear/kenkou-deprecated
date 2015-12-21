#!/usr/bin/env python

import unittest

from kenkou.urlcheck import checkURL


class TestSimpleURL(unittest.TestCase):
  def runTest(self):
    r = checkURL('http://bear.im')
    assert len(r) == 0

class TestSecureURL(unittest.TestCase):
  def runTest(self):
    r = checkURL('https://bear.im')
    assert len(r) == 0

class TestBadSecureURL(unittest.TestCase):
  def runTest(self):
    r = checkURL('https://expired.badssl.com')
    assert len(r) == 1
    assert 'certificate verify failed' in r[0]

class TestBadURL(unittest.TestCase):
  def runTest(self):
    r = checkURL('http://bear.im/42')
    assert len(r) == 1
    assert 'bear.im/42' in r[0]
