#!/usr/bin/env python

""" HTTP resource check

    Check that a web site or HTTP resource is alive

    :copyright: (c) 2012 by Mike Taylor
    :license: BSD 2-Clause

    Assumes Python v2.7+

    Usage
        -c --config         Configuration file (json format)
                            default: None
        -u --url            HTTP URL to check
        -p --period         How often to check
        -d --debug          Turn on debug logging
                            default: False
        -l --logpath        Path where the log file output is written
                            default: None
        -b --background     Fork to a daemon process
                            default: False

    Authors:
        bear    Mike Taylor <bear@code-bear.com>
"""

import os, sys
import json
import time
import types
import signal
import urllib2
import logging
import datetime

from optparse import OptionParser


_version_   = u'0.4.0'
_copyright_ = u'Copyright (c) 2012 Mike Taylor'
_license_   = u'BSD 2-Clause'

_ourPath = os.getcwd()
_ourName = os.path.splitext(os.path.basename(sys.argv[0]))[0]

log = logging.getLogger(_ourName)


def handleSIGTERM(signum, frame):
    raise KeyboardInterrupt

signal.signal(signal.SIGTERM, handleSIGTERM)

def loadConfig(filename):
    result = {}
    if os.path.isfile(filename):
        try:
            result = json.loads(' '.join(open(filename, 'r').readlines()))
        except:
            log.error('error during loading of config file [%s]' % filename, exc_info=True)
    return result

def initOptions(defaults=None, params=None):
    """Parse command line parameters and populate the options object.
    """
    parser = OptionParser()

    defaultOptions = { 'config':  ('-c', '--config',  '',    'Configuration file'),
                       'debug':   ('-d', '--debug',   False, 'Enable Debug'),
                       'logpath': ('-l', '--logpath', '',    'Path where log file is to be written'),
                       'verbose': ('-v', '--verbose', False, 'show extra output from remote commands'),
                     }

    if params is not None:
        for key in params:
            defaultOptions[key] = params[key]

    if defaults is not None:
        for key in defaults:
            defaultOptions[key] = defaultOptions[key][0:2] + (defaults[key],) + defaultOptions[key][3:]

    for key in defaultOptions:
        items = defaultOptions[key]

        (shortCmd, longCmd, defaultValue, helpText) = items

        if type(defaultValue) is types.BooleanType:
            parser.add_option(shortCmd, longCmd, dest=key, action='store_true', default=defaultValue, help=helpText)
        else:
            parser.add_option(shortCmd, longCmd, dest=key, default=defaultValue, help=helpText)

    (options, args) = parser.parse_args()
    options.args    = args
    options.appPath = _ourPath

    if options.config is None:
        s = os.path.join(_ourPath, '%s.cfg' % _ourName)
        if os.path.isfile(s):
            options.config = s

    if options.config is not None:
        options.config = os.path.abspath(options.config)

        if not os.path.isfile(options.config):
            options.config = os.path.join(_ourPath, '%s.cfg' % options.config)

        if not os.path.isfile(options.config):
            options.config = os.path.abspath(os.path.join(_ourPath, '%s.cfg' % _ourName))

        jsonConfig = loadConfig(options.config)

        for key in jsonConfig:
            setattr(options, key, jsonConfig[key])

    if options.logpath is not None:
        options.logpath = os.path.abspath(options.logpath)

        if os.path.isdir(options.logpath):
            options.logfile = os.path.join(options.logpath, '%s.log'% _ourName)
        else:
            options.logfile = None

    if 'background' not in defaultOptions:
        options.background = False

    return options

def initLogs(options, chatty=True, loglevel=logging.INFO):
    if options.logpath is not None:
        fileHandler   = RotatingFileHandler(os.path.join(options.logpath, '%s.log' % _ourName), maxBytes=1000000, backupCount=99)
        fileFormatter = logging.Formatter('%(asctime)s %(levelname)-7s %(processName)s: %(message)s')

        fileHandler.setFormatter(fileFormatter)

        log.addHandler(fileHandler)
        log.fileHandler = fileHandler

    echoHandler = logging.StreamHandler()

    if chatty:
        echoFormatter = logging.Formatter('%(levelname)-7s %(processName)s[%(process)d]: %(message)s')
    else:
        echoFormatter = logging.Formatter('%(levelname)-7s %(message)s')

    echoHandler.setFormatter(echoFormatter)

    log.addHandler(echoHandler)

    if options.debug:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(loglevel)


def parsePeriod(period):
    # TODO do something real here
    td = datetime.timedelta(minutes=15)
    return (td.days * 3600 * 24) + td.seconds

def pollURL(options):
    period = parsePeriod(options.period)

    while True:
        polled = False
        try:
            req = urllib2.Request(options.url)
            try:
                res = urllib2.urlopen(req)
                
                if res.getcode() == 200:
                    polled = True
                    log.info("URL check successful")
                else:
                    log.error('URL check returned %d' % res.getcode())

            except urllib2.URLError as e:
                log.error('URLError raised during check: %s' % e.args)
        except:
            log.exception('Exception raised during URL check, exiting')

        if not polled:
            if 'url' in options.onfail:
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
                    break

        if options.background:
            log.debug('sleeping for %d seconds' % period)
            time.sleep(period)
        else:
            break


_defaultOptions = { 'config':     ('-c', '--config',     None,  'Configuration file'),
                    'debug':      ('-d', '--debug',      True,  'Enable Debug'),
                    'background': ('-b', '--background', False, 'daemonize ourselves'),
                    'logpath':    ('-l', '--logpath',    None,  'Path where log file is to be written'),
                    'url':        ('-u', '--url',        None,  'HTTP URL to check'),
                    'period':     ('-p', '--period',     '15m', 'Period to use for checking. Default is 15 minutes'),
                  }


if __name__ == '__main__':
    options = initOptions(params=_defaultOptions)
    initLogs(options)

    log.info('Starting')

    if options.url is None:
        log.error('URL parameter is required, exiting')
        sys.exit(2)

    pollURL(options)
