#!/usr/bin/env python

import unittest

from kenkou.dnscheck import checkDNS

domain = 'bear.im'
ip     = '91.121.16.171'
ns     = [ 'ns1.dnsimple.com', 'ns2.dnsimple.com',
           'ns3.dnsimple.com', 'ns4.dnsimple.com' ]

class TestIPLookup(unittest.TestCase):
  def runTest(self):
    assert [] == checkDNS('test', ( domain, ip, ns))

class TestWrongIP(unittest.TestCase):
  def runTest(self):
    r = checkDNS('test', ( domain, '127.0.0.1', ns ))

    assert r[0]['found'][0] != '127.0.0.1'

class TestWrongNS(unittest.TestCase):
  def runTest(self):
    r = checkDNS('test', ( domain, ip, ['ns.wrong.com']))
    assert len(r[0]['found']) == len(ns)
    for s in ns:
      assert s in r[0]['found']