# -*- coding: utf-8 -*-
"""
:copyright: (c) 2012-2015 by Mike Taylor
:license: MIT, see LICENSE for more details.
"""

import os, sys
import re
import time
import uuid
import email
import types
import socket
import datetime

from OpenSSL import SSL
from pyasn1.codec.der.decoder import decode
from pyasn1.type.char import IA5String
from pyasn1.type.univ import ObjectIdentifier
from pyasn1_modules.rfc2459 import GeneralNames

try:
  from certifi import where
except ImportError:
  def where():
    return '/etc/ssl/certs/ca-certificates.crt'


_error =  """Kenkou has discovered an issue with the %(namespace)s Certificate check for the domain %(domain)s
The errors that were found are:
%(errors)s
"""

def handleEvent(namespace, domain, errors):
  event = { 'check': 'cert',
            'namespace': namespace,
            'domain': domain,
            'errors': '\n'.join(errors),
            'body': ''
          }
  event['body'] = _error % event
  return event

# _dnsname_match() and match_hostname() are from Python 3
# code and modified to work with pyOpenSSL objects

class CertificateError(ValueError):
  pass

def _dnsname_match(domain, hostname, max_wildcards=1):
  """Matching according to RFC 6125, section 6.4.3

  http://tools.ietf.org/html/rfc6125#section-6.4.3
  """
  patterns = []
  if not domain:
      return False

  # Ported from python3-syntax:
  # leftmost, *remainder = domain.split(r'.')
  parts     = domain.split(r'.')
  leftmost  = parts[0]
  remainder = parts[1:]
  wildcards = leftmost.count('*')
  if wildcards > max_wildcards:
    # Issue #17980: avoid denials of service by refusing more
    # than one wildcard per fragment.  A survey of established
    # policy among SSL implementations showed it to be a
    # reasonable choice.
    raise CertificateError(
        "too many wildcards in certificate DNS name: " + repr(domain))

  # speed up common case w/o wildcards
  if not wildcards:
    return domain.lower() == hostname.lower()

  # RFC 6125, section 6.4.3, subitem 1.
  # The client SHOULD NOT attempt to match a presented identifier in which
  # the wildcard character comprises a label other than the left-most label.
  if leftmost == '*':
    # When '*' is a fragment by itself, it matches a non-empty dotless
    # fragment.
    patterns.append('[^.]+')
  elif leftmost.startswith('xn--') or hostname.startswith('xn--'):
    # RFC 6125, section 6.4.3, subitem 3.
    # The client SHOULD NOT attempt to match a presented identifier
    # where the wildcard character is embedded within an A-label or
    # U-label of an internationalized domain name.
    patterns.append(re.escape(leftmost))
  else:
    # Otherwise, '*' matches any dotless string, e.g. www*
    patterns.append(re.escape(leftmost).replace(r'\*', '[^.]*'))

  # add the remaining fragments, ignore any wildcards
  for fragment in remainder:
    patterns.append(re.escape(fragment))

  pattern = re.compile(r'^%s' % r'\.'.join(patterns), re.IGNORECASE)
  return pattern.match(hostname)

def match_hostname(cert, hostname):
  """Verify that *cert* (in decoded format as returned by
  SSLSocket.getpeercert()) matches the *hostname*.  RFC 2818 and RFC 6125
  rules are followed, but IP addresses are not accepted for *hostname*.

  CertificateError is raised on failure. On success, the function
  returns nothing.
  """
  if not cert:
    raise ValueError("empty or no certificate")
  dnsnames = []
  for n in range(cert.get_extension_count()):
    ext     = cert.get_extension(n)
    extName = ext.get_short_name()
    if extName == b"subjectAltName":
        names, _ = decode(ext.get_data(), asn1Spec=GeneralNames())
        for item in names:
            name  = item.getName()
            value = bytes(item.getComponent())
            if name == "dNSName":
                if _dnsname_match(value, hostname):
                    return
                dnsnames.append(value)
  if not dnsnames:
    # The subject is only checked when there is no dNSName entry
    # in subjectAltName
    value = cert.get_subject().commonName
    if _dnsname_match(value, hostname):
        return
    dnsnames.append(value)
  if len(dnsnames) > 1:
    raise CertificateError("hostname %r doesn't match either of %s"
                           % (hostname, ', '.join(map(repr, dnsnames))))
  elif len(dnsnames) == 1:
    raise CertificateError("hostname %r doesn't match %r" % (hostname, dnsnames[0]))
  else:
    raise CertificateError("no appropriate commonName or subjectAltName fields were found")

def pyopenssl_check_callback(connection, x509, errnum, errdepth, ok):
  """callback for pyopenssl ssl check
  """
  if x509.has_expired():
    raise CertificateError('Certificate %s has expired!' % x509.get_issuer().commonName)
  if not ok:
    return False
  return ok

def checkCert(namespace, domain, cafile=None):
  result = { 'check': 'cert' }
  errors = []
  try:
    domain = domain.replace('https://', '').replace('http://', '')

    if cafile is None:
      cafile = where()
    try:
      socket.getaddrinfo(domain, 443)[0][4][0]
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      try:
        sock.connect((domain, 443))
        try:
          ctx = SSL.Context(SSL.TLSv1_METHOD)
            # prevent fallback to insecure SSLv2
          ctx.set_options(SSL.OP_NO_SSLv2)
          ctx.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
                         pyopenssl_check_callback)
          ctx.load_verify_locations(cafile)

          ssl_sock = SSL.Connection(ctx, sock)
          try:
            ssl_sock.set_connect_state()
            ssl_sock.set_tlsext_host_name(domain)
            ssl_sock.do_handshake()

            x509 = ssl_sock.get_peer_certificate()
            try:
              match_hostname(x509, domain)
            except CertificateError:
              errors.append('Hostname does not match')
            try:
              expire_date = datetime.datetime.strptime(x509.get_notAfter(), "%Y%m%d%H%M%SZ")
              expire_td   = expire_date - datetime.datetime.now()
              if expire_td.days < 15:
                errors.append('Expires in %s days' % expire_td.days)
            except:
              errors.append('Certificate %s has an unknown date format' % x509.get_issuer().commonName)
          except Exception as e:
            errors.append('get_peer_certificate attempt: %s' % e)
          finally:
            ssl_sock.shutdown()
        except SSL.Error as e:
          errors.append('SSL.Error: %s' % e.message)
        finally:
          sock.close()
      except socket.error as e:
        errors.append('Socket Error: %s' % e.message)
    except socket.gaierror as e:
        errors.append('Socket GAIError: %s' % e.message)
  except Exception as e:
    errors.append('Exception during Certificate check: %s' % e.message)

  if len(errors) > 0:
    result = handleEvent(namespace, domain, errors)

  return result
