#!/usr/bin/env python

""" HTTP resource check

    Check that a web site or HTTP resource is alive

    :copyright: (c) 2012-2013 by Mike Taylor
    :license: BSD 2-Clause

    Assumes Python v2.7+

    Authors:
        bear    Mike Taylor <bear@bear.im>
"""

import os, sys
import re
import json
import time
import uuid
import email
import types
import socket
import logging
import datetime
import urlparse
import argparse

from OpenSSL import SSL
from pyasn1.codec.der.decoder import decode
from pyasn1.type.char import IA5String
from pyasn1.type.univ import ObjectIdentifier
from pyasn1_modules.rfc2459 import GeneralNames
from bs4 import BeautifulSoup, SoupStrainer

import requests
import dns.resolver
import dns.message
import dns.query


_version_   = u'0.4.6'
_copyright_ = u'Copyright (c) 2012-2014 Mike Taylor'
_license_   = u'BSD 2-Clause'

_ourPath = os.getcwd()
_ourName = os.path.splitext(os.path.basename(sys.argv[0]))[0]
_usage   = """
Usage
    -c --config  Configuration file (json format)
"""

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(_ourName)


def normalizeFilename(filename):
    result = os.path.expanduser(filename)
    result = os.path.abspath(result)
    return result

def loadConfig(cfgFilename):
    result = {}
    if not os.path.exists(cfgFilename):
        for cfgpath in configPaths:
            possibleFile = normalizeFilename(os.path.join(cfgpath, configName))
            if os.path.exists(possibleFile):
                result = json.load(open(possibleFile, 'r'))
                break
    else:
        possibleFile = normalizeFilename(cfgFilename)
        if os.path.exists(possibleFile):
            result = json.load(open(possibleFile, 'r'))
    return result

def flatten(source):
    result     = {}
    namespaces = []
    for ns in source:
        namespaces.append(ns)
        for site in source[ns]:
            key = '%s.%s' % (ns, site)
            result[key] = source[ns][site]
    return result, namespaces

def pagerDuty(event):
    if 'method' in config['pagerduty']:
        method = config['pagerduty']['method']
    else:
        method = 'POST'
    if 'params' in config['pagerduty']:
        params = config['pagerduty']['params']

    log.info('sending trigger request')

    try:
        if '%s' in params['incident_key']:
            params['incident_key'] = params['incident_key'] % event['sitename']

        params['description'] = event['subject'][:1000]
 
        resp = requests.post(config['pagerduty']['url'], data=json.dumps(params))

        if resp.status_code == requests.codes.ok:
            log.info('trigger successfully sent')
        else:
            log.error('trigger failed: %s %s' % (resp.status_code, resp.text))
    except:
        log.exception('Error during failure reporting, exiting')

def postageApp(subject, body):
    payload = { "api_key":   config['postageapp']['api_key'],
                "uid":       str(uuid.uuid4()),
                "arguments": { "recipients": config['postageapp']['recipients'],
                               "headers":    { "subject": subject,
                                               "from":    "kenkou <ops@andyet.net>",
                                             },
                               "content":    { "text/plain": body }
                             }
              }

    s = json.dumps(payload)
    r = requests.post('https://api.postageapp.com/v.1.0/send_message.json', data=s, headers={'Content-Type': 'application/json'})
    return r.status_code

_exception = """Kenkou has discovered an issue with the site %(url)s
The result from the attempt to reach the site is:
%(message)s
"""
_error    =  """Kenkou has discovered an issue with the site %(url)s
The result from the attempt to reach the site is: %(status)s
The body of the request is:
%(message)s
"""
_IPerror =  """Kenkou has discovered an issue with the DNS for %(sitename)s.
The IP address should be %(ip)s but the DNS Query returned %(found)s
"""
_NSerror =  """Kenkou has discovered an issue with the DNS for %(sitename)s.
The nameserver list should be:
%(nameservers)s
but the DNS lookup returned
%(found)s
"""

def handleEvent(sitename, sitedata, target, status, message):
    log.error('Check event for %s (%s) %s: %s' % (sitename, target, status, message))

    subject = "Kenkou Site Check Failed for %s" % sitename
    data    = { 'sitename': sitename,
                'url':      target,
                'status':   status,
                'message':  message,
                'subject':  subject
              }
    if status is None:
        body = _exception % data
    else:
        body = _error % data

    for item in config['onevent']:
        if item == 'postageapp':
            log.debug('event sent to PostageApp: %s' % postageApp(subject, body))
        elif item == 'pagerduty':
            log.debug('event sent to pagerDuty: %s' % pagerDuty(data))

def handleDNSEvent(sitename, ip, nameservers, found):
    log.error('Check event for %s' % sitename)

    subject = "Kenkou DNS Check Failed for %s" % sitename
    data    = { 'sitename':    sitename,
                'ip':          ip,
                'nameservers': nameservers,
                'found':       found,
                'subject':     subject
              }
    if ip is None:
        body = _NSerror % data
    else:
        body = _IPerror % data

    for item in config['onevent']:
        if item == 'postageapp':
            log.debug('event sent to PostageApp: %s' % postageApp(subject, body))
        elif item == 'pagerduty':
            log.debug('event sent to pagerDuty: %s' % pagerDuty(data))

def hasURL(tag):
    for item in ('href', 'cite', 'background', 'action', 'profile', 'src', 
                 'longdesc', 'data', 'usemap', 'codebase', 'classid',
                 'formaction', 'icon', 'manifest', 'poster'):
        if tag.has_attr(item):
            return True, item
    return False, None

def checkMixedContent(response):
    """Search the html content for a URL for all URLs that would trigger
       a mixed content warning. 

       All anchor tags and link tags with rel="alternate" are skipped.

        HTML4:
            <applet codebase=url>
            <area href=url>
            <base href=url>
            <blockquote cite=url>
            <body background=url>
            <del cite=url>
            <form action=url>
            <frame longdesc=url> and <frame src=url>
            <head profile=url>
            <iframe longdesc=url> and <iframe src=url>
            <img longdesc=url> and <img src=url> and <img usemap=url>
            <input src=url> and <input usemap=url>
            <ins cite=url>
            <link href=url>
            <object classid=url> and <object codebase=url> and <object data=url> and <object usemap=url>
            <q cite=url>
            <script src=url>

        HTML5:
            <audio src=url>
            <button formaction=url>
            <command icon=url>
            <embed src=url>
            <html manifest=url>
            <input formaction=url>
            <source src=url>
            <video poster=url> and <video src=url>
    """
    mixed   = []
    urlData = urlparse.urlparse(response.url)
    scheme  = urlData.scheme.lower()

    if scheme == 'https':
        bsoup = BeautifulSoup(response.text, 'html5lib')
        for tag in bsoup.find_all(True):
            f, item = hasURL(tag)

            if f:
                tagUrl  = tag.attrs[item]
                urlData = urlparse.urlparse(tagUrl)

                if tag.name == 'a':
                    continue
                if (tag.name == 'link') and ('rel' in tag.attrs) and ('alternate' in tag.attrs['rel']):
                    log.debug('skipping link tag with url %s' % tagUrl)
                    continue
                if len(urlData.scheme) == 0:
                    tagScheme = scheme
                else:
                    tagScheme = urlData.scheme.lower()
                if tagScheme.startswith('http') and (tagScheme != scheme):
                    mixed.append(tagUrl)
    return mixed

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
    '''callback for pyopenssl ssl check'''
    log.debug('callback: %d %s' % (errdepth, x509.get_issuer().commonName))
    if x509.has_expired():
        raise CertificateError('Certificate %s has expired!' % x509.get_issuer().commonName)
    if not ok:
        return False
    return ok

def checkCertificate(sitename, sitedata):
    domain = bytes(sitedata['cert'])
    errors = []

    log.debug('checking Certificates for %s [%s]' % (sitename, domain))
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
                ctx.load_verify_locations(config['cafile'])

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
                    errors.append('%s' % e)
                finally:
                    ssl_sock.shutdown()
            except SSL.Error as e:
                errors.append('%s' % e)
            finally:
                sock.close()
        except socket.error as e:
            errors.append('%s' % e)
    except socket.gaierror as e:
        errors.append('%s' % e)

    if len(errors) > 0:
        msg = 'Certificate verification for the site has failed with the following errors:'
        msg += '\n    '.join(errors)
        handleEvent(sitename, sitedata, domain, None, msg)

# talky.static {u'url': u'http://static.talky.io/readme'}
def checkURLS(sitename, sitedata, verifyHTTPS=False):
    log.debug('checking URL for %s' % sitename)
    if 'url' in sitedata:
        url = sitedata['url']

        try:
            r = requests.get(url, verify=verifyHTTPS)
            if url != r.url:
                log.debug('URL was redirected, processing last URL handled')
            log.debug('%s responded with %s' % (r.url, r.status_code))

            if r.status_code != 200:
                handleEvent(sitename, sitedata, url, r.status_code, r.text)
            else:
                mixed = checkMixedContent(r)
                if len(mixed) > 0:
                    s = 'Mixed Content URLs found within the site\n'
                    for url in mixed:
                        s += '    %s\n' % url
                    handleEvent(sitename, sitedata, url, r.status_code, s)

        except (requests.exceptions.RequestException, 
                requests.exceptions.ConnectionError,
                requests.exceptions.HTTPError,
                requests.exceptions.URLRequired,
                requests.exceptions.TooManyRedirects) as e:
            handleEvent(sitename, sitedata, url, None, e.message)

def checkDNS(sitename, sitedata):
    log.debug('checking DNS for %s' % sitename)
    if 'dns' in sitedata:
        domain, ip, nameservers = sitedata['dns']

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
            handleDNSEvent(sitename, ip, None, ips)

        for s in nameservers:
            for t in ns:
                if t.startswith(s):
                    ns.remove(t)

        if len(ns) > 0:
            handleDNSEvent(sitename, None, nameservers, ns)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', default='%s.cfg' % _ourName)
    parser.add_argument('--cafile', default='/etc/ssl/certs/ca-certificates.crt')

    args   = parser.parse_args()
    config = loadConfig(args.config)

    if config['debug']:
        log.setLevel(logging.DEBUG)

    if 'cafile' not in config:
        config['cafile'] = args.cafile

    log.info('Starting')

    if config['urls'] is None:
        log.error('URLs configuration item is required, exiting')
        sys.exit(2)

    urls       = {}
    namespaces = []
    for k in config['urls']:
        if k == 'file':
            try:
                fUrls = json.loads(' '.join(open(config['urls'][k], 'r').readlines()))
                for key in fUrls:
                    urls[key] = fUrls[key]
            except:
                log.exception('unable to load url list from %s' % config['urls'][k])
        elif k == 'redis':
            log.warning('redis is not handled currently')
        else:
            log.error('Unknown URL entry [%s]' % k)

    urls, namespaces = flatten(urls)
    for key in urls.keys():
        if 'cert' in urls[key]:
            checkCertificate(key, urls[key])
        else:
            if 'verify_https' in config:
                verify = config['verify_https']
            else:
                verify = False
            checkURLS(key, urls[key], verify)

    dnsitems   = {}
    namespaces = []
    for k in config['dns']:
        if k == 'file':
            try:
                fDNS = json.loads(' '.join(open(config['dns'][k], 'r').readlines()))
                for key in fDNS:
                    dnsitems[key] = fDNS[key]
            except:
                log.exception('unable to load dns list from %s' % config['dns'][k])
        else:
            log.error('Unknown URL entry [%s]' % k)

    dnsitems, namespaces = flatten(dnsitems)
    for key in dnsitems.keys():
        checkDNS(key, dnsitems[key])
