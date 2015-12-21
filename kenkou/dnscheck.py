# -*- coding: utf-8 -*-
"""
:copyright: (c) 2012-2015 by Mike Taylor
:license: MIT, see LICENSE for more details.
"""

import dns.resolver
import dns.message
import dns.query


def checkDNS(domain, ip, nameservers):
  ips    = []
  ns     = []
  errors = []
  try:
    for a in dns.resolver.query(domain):
      ips.append(a.to_text())

    q = dns.message.make_query(domain, dns.rdatatype.NS)
    m = dns.query.udp(q, '8.8.8.8')
    for k in m.index.keys():
      s = m.index[k].to_text()
      for t in s.split('\n'):
        # bear.im. 1704 IN NS ns1.dnsimple.com.
        # bear.im. IN NS
        l = t.split()
        if len(l) == 5 and l[3] == 'NS':
          ns.append(t.split()[-1][:-1])

    if ip not in ips:
      errors.append('The given ip address %s was not found in the DNS response: %s' % (ip, ips))

    for s in nameservers:
      for t in ns:
        if t == s:
          ns.remove(t)

    if len(ns) > 0:
      errors.append('The given list of nameservers does not match the DNS response: %s' % ','.join(ns))

  except Exception as e:
    errors.append('An exception was raised during the DNS check: %s' % e.message)

  return errors
