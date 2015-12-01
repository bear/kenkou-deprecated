#!/usr/bin/env python

import unittest

from kenkou.dnscheck import checkDNS

domain = 'bear.im'
ip     = '91.121.16.171'
ns     = [ 'ns1.dnsimple.com', 'ns2.dnsimple.com',
           'ns3.dnsimple.com', 'ns4.dnsimple.com' ]

class TestIPLookup(unittest.TestCase):
  def runTest(self):
    r = checkDNS('test', ( domain, ip, ns))
    assert 'check' in r.keys()
    assert r['check']    == 'dns'
    assert len(r.keys()) == 1

class TestWrongIP(unittest.TestCase):
  def runTest(self):
    r = checkDNS('test', ( domain, '127.0.0.1', ns ))
    assert 'check' in r.keys()
    assert r['check']    == 'dns'
    assert len(r.keys()) == 7
    assert r['errors']   == "The given ip address 127.0.0.1 was not found in the DNS response: ['91.121.16.171']"


class TestWrongNS(unittest.TestCase):
  def runTest(self):
    r = checkDNS('test', ( domain, ip, ['ns.wrong.com']))
    assert 'check' in r.keys()
    assert r['check']    == 'dns'
    assert len(r.keys()) == 7
    assert r['errors']   == 'The given list of nameservers does not match the DNS response: ns1.dnsimple.com,ns2.dnsimple.com,ns3.dnsimple.com,ns4.dnsimple.com'