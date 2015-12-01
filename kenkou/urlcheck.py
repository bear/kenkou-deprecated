# -*- coding: utf-8 -*-
from __future__ import print_function

"""
:copyright: (c) 2012-2015 by Mike Taylor
:license: MIT, see LICENSE for more details.
"""

import os, sys
import urlparse

import requests
from bs4 import BeautifulSoup, SoupStrainer



_exception = """Kenkou has run into a problem checking the %(namespace)s URL %(url)s
The exception raised during the attempt to reach the site was:
%(msg)s
"""
_error =  """Kenkou has discovered an issue with the site %(namespace)s URL %(url)s
The request for the site returned %(status_code)s
The body from the request was:
%(msg)s
"""

def handleEvent(namespace, url, status_code, msg):
  event = { 'namespace': namespace,
            'url': url,
            'status_code': status_code,
            'msg': msg,
            'body': ''
          }
  if status_code == 0:
    event['body'] = _exception % event
  else:
    event['body'] = _error % event
  return event

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
    bs = BeautifulSoup(response.text, 'html5lib')
    for tag in bs.find_all(True):
      f, item = hasURL(tag)

      if f:
        tagUrl  = tag.attrs[item]
        urlData = urlparse.urlparse(tagUrl)

        if tag.name == 'a':
          continue
        if (tag.name == 'link') and ('rel' in tag.attrs) and ('alternate' in tag.attrs['rel']):
          continue
        if len(urlData.scheme) == 0:
          tagScheme = scheme
        else:
          tagScheme = urlData.scheme.lower()
        if tagScheme.startswith('http') and (tagScheme != scheme):
          mixed.append(tagUrl)

  return mixed

def checkURL(namespace, url, debug=False):
  events = []
  try:
    if debug:
      print('%s: checking URL %s' % (namespace, url))

    try:
        r = requests.get(url, verify=True)
        if debug:
          if url != r.url:
            print('%s: URL was redirected, processing last URL handled' % namespace)
          print('%s: %s %s' % (namespace, r.status_code, r.url))

        if r.status_code != 200:
            events.append(handleEvent(namespace, url, r.status_code, r.text ))
        else:
            mixed = checkMixedContent(r)
            if len(mixed) > 0:
                s = 'Mixed Content URLs found.\n'
                for url in mixed:
                    s += '    %s\n' % url
                events.append(handleEvent(namespace, url, r.status_code, s ))

    except (requests.exceptions.RequestException, 
            requests.exceptions.ConnectionError,
            requests.exceptions.HTTPError,
            requests.exceptions.URLRequired,
            requests.exceptions.TooManyRedirects) as e:
        events.append(handleEvent(namespace, url, 0, e.message ))
  except Exception as e:
    print('Exception during URL check for %s' % namespace, e, file=sys.stderr)

  print(events)

  return events
