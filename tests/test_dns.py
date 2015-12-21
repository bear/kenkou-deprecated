#!/usr/bin/env python

import unittest

from kenkou.dnscheck import checkDNS

domain = 'bear.im'
ip     = '91.121.16.171'
ns     = [ 'ns1.dnsimple.com', 'ns2.dnsimple.com',
           'ns3.dnsimple.com', 'ns4.dnsimple.com' ]

class TestIPLookup(unittest.TestCase):
  def runTest(self):
    r = checkDNS(domain, ip, ns)
    assert len(r) == 0

class TestWrongIP(unittest.TestCase):
  def runTest(self):
    r = checkDNS(domain, '127.0.0.1', ns)
    assert len(r) == 1
    assert 'was not found in the DNS response' in r[0]

class TestWrongNS(unittest.TestCase):
  def runTest(self):
    r = checkDNS(domain, ip, ['ns.wrong.com'])
    assert len(r) == 1
    assert 'The given list of nameservers does not match the DNS response: ns1.dnsimple.com,ns2.dnsimple.com,ns3.dnsimple.com,ns4.dnsimple.com' in r[0]
