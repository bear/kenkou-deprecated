#!/usr/bin/env python

import unittest

from kenkou.urlcheck import checkURL


class TestSimpleURL(unittest.TestCase):
    def runTest(self):
      assert [] == checkURL('test', 'http://bear.im', False)

class TestSecureURL(unittest.TestCase):
    def runTest(self):
      assert [] == checkURL('test', 'https://bear.im', False)

class TestBadSecureURL(unittest.TestCase):
    def runTest(self):
      r = checkURL('test', 'https://expired.badssl.com', False)
      assert r[0]['status_code'] == 0
      assert r[0]['url']         == 'https://expired.badssl.com'
      assert r[0]['namespace']   == 'test'

class TestBadURL(unittest.TestCase):
    def runTest(self):
      body = """Kenkou has discovered an issue with the site test URL http://bear.im/42
The request for the site returned 404
The body from the request was:
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server.  If you entered the URL manually please check your spelling and try again.</p>

"""
      r = checkURL('test', 'http://bear.im/42', False)
      assert r[0]['status_code'] == 404
      assert r[0]['url']         == 'http://bear.im/42'
      assert r[0]['namespace']   == 'test'
      assert r[0]['body']        == body
