# -*- coding: utf-8 -*-
"""
:copyright: (c) 2012-2015 by Mike Taylor
:license: MIT, see LICENSE for more details.
"""

import os, sys
import urlparse

import requests
from bs4 import BeautifulSoup, SoupStrainer


_error =  """Kenkou has discovered an issue with the site %(namespace)s URL %(url)s
The errors that were found are:
%(errors)s
"""

def handleEvent(namespace, url, status_code, errors):
  event = { 'check': 'url',
            'namespace': namespace,
            'url': url,
            'status_code': status_code,
            'errors': '\n'.join(errors),
            'body': ''
          }
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

def checkURL(namespace, url):
  result = { 'check': 'url' }
  errors = []
  status_code = 0
  try:
      r = requests.get(url, verify=True)
      status_code = r.status_code
      if r.status_code != 200:
          errors.append('The given URL %s returned a status code of %s' % (url, r.status_code))
      else:
          mixed = checkMixedContent(r)
          if len(mixed) > 0:
              s = 'The given URL %s contains the following Mixed Content URLs: '
              for u in mixed:
                  s += '%s,' % u
              errors.append(s[:-1])

  except (requests.exceptions.RequestException, 
          requests.exceptions.ConnectionError,
          requests.exceptions.HTTPError,
          requests.exceptions.URLRequired,
          requests.exceptions.TooManyRedirects) as e:
      errors.append('The given URL %s generated an exception: %s' % (url, e.message ))

  if len(errors) > 0:
    result = handleEvent(namespace, url, status_code, errors)

  return result
