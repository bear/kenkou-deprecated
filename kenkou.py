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
import json
import time
import uuid
import email
import types
import logging
import datetime

from bearlib import bConfig, bLogs
import requests


_version_   = u'0.4.0'
_copyright_ = u'Copyright (c) 2012-2013 Mike Taylor'
_license_   = u'BSD 2-Clause'

_ourPath = os.getcwd()
_ourName = os.path.splitext(os.path.basename(sys.argv[0]))[0]
_usage   = """
Usage
    -c --config         Configuration file (json format)
    -d --debug          Turn on debug logging
                        default: False
    -l --logfile        Filename to write the log output
                        default: None
"""


log = logging.getLogger(_ourName)

def flatten(source):
    result     = {}
    namespaces = []
    for ns in source:
        namespaces.append(ns)
        for site in source[ns]:
            key = '%s.%s' % (ns, site)
            result[key] = source[ns][site]
    return result, namespaces

def pagerDuty(payload):
    if 'method' in config.options.pagerduty:
        method = config.options.pagerduty['method']
    else:
        method = 'POST'
    if 'params' in config.options.pagerduty:
        params = config.options.pagerduty['params']
    else:
        params = {}

    log.info('sending trigger request')
    try:
        req = urllib2.Request(config.options.pagerduty['url'])
        req.add_data(json.dumps(params))
        req.add_header('Content-Type', 'application/json')
        res = urllib2.urlopen(req)
        result = json.loads(res.read())

        if 'status' in result and result['status'] == 'success':
            log.info('trigger successfully sent')
        else:
            log.error('trigger failed: %s' % result['message'])
    except:
        log.exception('Error during failure reporting, exiting')

def postageApp(subject, body):
    payload = { "api_key":   config.options.postageapp['api_key'],
                "uid":       str(uuid.uuid4()),
                "arguments": { "recipients": config.options.postageapp['recipients'],
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

def handleEvent(sitename, sitedata, status, message):
    data = { 'sitename': sitename,
             'url':      sitedata['url'],
             'status':   status,
             'message':  message
           }
    if status is None:
        body = _exception % data
    else:
        body = _error % data

    subject = "Kenkou Site Check Failed for %s" % sitename

    for item in config.options.onfail:
        if item == 'postageapp':
            log.info('event sent to PostageApp: %s' % postageApp(subject, body))
        elif item == 'pagerduty':
            pagerDuty(body)

def check(sitename, sitedata):
    log.debug('checking %s' % sitename)
    if 'url' in sitedata:
        url = sitedata['url']

        try:
            r = requests.get(url, verify=False)
            log.info('site %s (%s) responded with %s' % (sitename, url, r.status_code))

            if r.status_code != 200:
                handleEvent(sitename, sitedata, r.status_code, r.text)

        except (requests.exceptions.RequestException, 
                requests.exceptions.ConnectionError,
                requests.exceptions.HTTPError,
                requests.exceptions.URLRequired,
                requests.exceptions.TooManyRedirects) as e:
            log.exception('ERROR for %s (%s): %s' % (sitename, url, e.message))
            handleEvent(sitename, sitedata, None, e.message)


if __name__ == '__main__':
    config = bConfig(filename='%s.cfg' % _ourName)
    bLogs(_ourName, echo=config.options.echo, debug=config.options.debug, logfile=config.options.logfile)

    log.info('Starting')

    if config.options.urls is None:
        log.error('URLs configuration item is required, exiting')
        sys.exit(2)

    urls       = {}
    namespaces = []
    for k in config.options.urls:
        if k == 'file':
            try:
                fUrls = json.loads(' '.join(open(config.options.urls[k], 'r').readlines()))
                for key in fUrls:
                    urls[key] = fUrls[key]
            except:
                log.exception('unable to load url list from %s' % config.options.urls[k])
        elif k == 'redis':
            log.info('need to do something here')
        else:
            log.error('Unknown URL entry [%s]' % k)

    urls, namespaces = flatten(urls)

    if len(config.args) > 0:
        keys = []
        for s in config.args:
            if s in urls:
                keys.append(s)
            else:
                if s in namespaces: 
                    for k in urls.keys():
                        if k.startswith(s):
                            keys.append(k)
    else:
        keys = urls.keys()

    for key in keys:
        check(key, urls[key])
