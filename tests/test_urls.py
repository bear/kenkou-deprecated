#!/usr/bin/env python

import unittest

from kenkou.urlcheck import checkURL


class TestSimpleURL(unittest.TestCase):
  def runTest(self):
    r = checkURL('test', 'http://bear.im')
    assert 'check' in r.keys()
    assert r['check']    == 'url'
    assert len(r.keys()) == 1

class TestSecureURL(unittest.TestCase):
  def runTest(self):
    r = checkURL('test', 'https://bear.im')
    assert 'check' in r.keys()
    assert r['check']    == 'url'
    assert len(r.keys()) == 1

class TestBadSecureURL(unittest.TestCase):
  def runTest(self):
    r = checkURL('test', 'https://expired.badssl.com')
    assert 'check' in r.keys()
    assert len(r.keys())    == 6
    assert r['check']       == 'url'
    assert r['status_code'] == 0
    assert r['url']         == 'https://expired.badssl.com'
    assert r['namespace']   == 'test'

class TestBadURL(unittest.TestCase):
  def runTest(self):
    r = checkURL('test', 'http://bear.im/42')
    assert 'check' in r.keys()
    assert len(r.keys())    == 6
    assert r['check']       == 'url'
    assert r['status_code'] == 404
    assert r['url']         == 'http://bear.im/42'
    assert r['namespace']   == 'test'
    assert r['errors']      == 'The given URL http://bear.im/42 returned a status code of 404'
