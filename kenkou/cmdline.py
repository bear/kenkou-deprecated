# -*- coding: utf-8 -*-
from __future__ import print_function

"""
:copyright: (c) 2012-2015 by Mike Taylor
:license: MIT, see LICENSE for more details.
"""

import os, sys
import log
import argparse

from kenkou.dnscheck import checkDNS
from kenkou.urlcheck import checkURLS
from kenkou.certcheck import checkCerts


_usage   = """
Usage
    -c --config  Configuration file (JSON format)

Returns a JSON blob of results emitted to STDOUT
"""

def loadConfig(cfgFilename=None, possibleConfigFiles):
  result = {}

  if cfgFilename is None:
    for possibleFile in possibleConfigFiles:
      possibleFile = os.path.expanduser(possibleFile)
      if os.path.exists(possibleFile):
        result = json.load(open(possibleFile, 'r'))
        break
  else:
    possibleFile = os.path.expanduser(cfgFilename)
    if os.path.exists(possibleFile):
      result = json.load(open(possibleFile, 'r'))

  return result

def main(config=None, checks=None):
  if config is None:
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', default=None)
    parser.add_argument('--cafile', default=None)
    args = parser.parse_args()

    cfgFilenames = ('kenkou.cfg', '.kenkou.cfg')
    cfgFilepaths = (os.getcwd(), '~/', '~/.kenkou/')

    possibleConfigFiles = []

    for p in cfgFilepaths:
      for f in cfgFilenames:
        possibleConfigFiles.append(os.path.join(p, f))

    config = loadConfig(args.config, possibleConfigFiles)

  # set debug level for any modules that honour it
  if config['debug']:
    log.setLevel(logging.DEBUG)

  if 'cafile' not in config:
    config['cafile'] = args.cafile

  if checks is None:
    checks = json.loads(' '.join(open(config['checks'], 'r').readlines()))

  if checks is None:
    print('The items to check is a required, exiting', file=sys.stderr)
    sys.exit(2)

  for namespace in checks.keys():
    data = checks[namespace]
    if 'cert' in data:
      checkCert(namespace, data['cert'], config['cafile'], config['debug'])
    elif 'dns' in data:
      checkDNS(namespace, data['dns'], config['debug'])
    elif 'url' in data:
      checkURL(namespace, data['url'], config['debug'])
