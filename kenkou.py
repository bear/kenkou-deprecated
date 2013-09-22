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
    -l --logpath        Path where the log file output is written
                        default: None
"""


log = logging.getLogger(_ourName)


def pagerDuty(cfg, payload):
    if 'method' in options.onfail:
        method = options.onfail['method']
    else:
        method = 'POST'
    if 'params' in options.onfail:
        params = options.onfail['params']
    else:
        params = {}

    log.info('sending trigger request')
    try:
        req = urllib2.Request(options.onfail['url'])
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

def postageApp(body):
    payload = { "api_key":   "HRo8SuktnubH4XErey2l0zUEMQXGrYCH",
                "uid":       str(uuid.uuid4()),
                "arguments": { "recipients": ["ops@andyet.net"],
                               "headers":    { "subject": msg.get('Subject'),
                                               "from":    msg.get('From'),
                                             },
                               "content":    { "text/plain": payload }
                             }
              }

    s = json.dumps(body)
    r = requests.post('https://api.postageapp.com/v.1.0/send_message.json', data=s, headers={'Content-Type': 'application/json'})

    return r.status

def check(urls):
    log.debug('checking %d urls' % len(urls))
    for url in urls:
        log.info('checking %s' % url)
        r = requests.get(url)
        print r

if __name__ == '__main__':
    config = bConfig(filename='%s.cfg' % _ourName)
    bLogs(_ourName, echo=config.options.echo, debug=config.options.debug, logpath=config.options.logpath)

    log.info('Starting')

    if config.options.urls is None:
        log.error('URLs configuration item is required, exiting')
        sys.exit(2)

    for k in config.options.urls:
        if k == 'file':
            try:
                urls = json.loads(' '.join(open(config.options.urls[k], 'r').readlines()))
                for ns in urls:
                    check(urls[ns])
            except:
                log.exception('unable to load url list from %s' % config.options.urls[k])
        else:
            log.error('Unknown URL entry [%s]' % k)
