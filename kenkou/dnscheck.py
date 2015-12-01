# -*- coding: utf-8 -*-
from __future__ import print_function

"""
:copyright: (c) 2012-2015 by Mike Taylor
:license: MIT, see LICENSE for more details.
"""

import os, sys

import dns.resolver
import dns.message
import dns.query


_exception = """Kenkou has run into a problem checking the DNS for %(namespace)s.
The exception raised during the attempt to reach the site was:
%(msg)s
"""
_IPerror =  """Kenkou has discovered an issue with the %(namespace)s IP returned for %(domain)s.
The IP address should be %(ip)s but the DNS Query returned %(found)s
"""
_NSerror =  """Kenkou has discovered an issue with the %(namespace)s name server list for %(namespace)s.
The nameserver list should be:
%(nameservers)s
but the DNS lookup returned
%(found)s
"""

def handleEvent(namespace, domain, ip, nameservers, found):
  event = { 'namespace': namespace,
            'domain': domain,
            'ip': ip,
            'nameservers': nameservers,
            'found': found,
            'body': ''
          }

  if ip is None:
    event['body'] = _NSerror % event
  else:
    event['body'] = _IPerror % event

  return event

def checkDNS(namespace, data, debug=False):
  events = []
  try:
    domain, ip, nameservers = data
    if debug:
      print('checking DNS for %s: %s %s' % (namespace, domain, ip))

    ips = []
    ns  = []

    for a in dns.resolver.query(domain):
      ips.append(a.to_text())

    q = dns.message.make_query(domain, dns.rdatatype.NS)
    m = dns.query.udp(q, '8.8.8.8')

    k = m.index.keys()[0]
    for i in m.index[k]:
      ns.append(i.to_text())

    if ip not in ips:
      events.append(handleEvent(namespace, domain, ip, None, ips))

    for s in nameservers:
      for t in ns:
        if t.startswith(s):
          ns.remove(t)

    if len(ns) > 0:
      events.append(handleEvent(namespace, domain, None, nameservers, ns))

  except Exception as e:
    print('Exception during DNS check for %s' % namespace, e, file=sys.stderr)

  return events
