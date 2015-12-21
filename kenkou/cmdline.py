# -*- coding: utf-8 -*-
from __future__ import print_function

"""
:copyright: (c) 2012-2015 by Mike Taylor
:license: MIT, see LICENSE for more details.
"""

import os
import sys
import json
import argparse

from .urlcheck import checkURL
from .certcheck import checkCert
from .dnscheck import checkDNS


_usage = """
Usage
    -c --config  Configuration file (JSON format)

Returns a JSON blob of results emitted to STDOUT
"""

def loadConfig(cfgFilename, possibleConfigFiles):
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
    parser.add_argument('--config', default=None)
    parser.add_argument('--checks', default=None)
    parser.add_argument('--cafile', default=None)
    parser.add_argument('args', nargs=argparse.REMAINDER)
    args = parser.parse_args()

    cfgFilenames = ('kenkou.cfg', '.kenkou.cfg')
    cfgFilepaths = (os.getcwd(), '~/', '~/.kenkou/')

    possibleConfigFiles = []

    for p in cfgFilepaths:
      for f in cfgFilenames:
        possibleConfigFiles.append(os.path.join(p, f))

    config = loadConfig(args.config, possibleConfigFiles)

  if 'cafile' not in config:
    config['cafile'] = None
  if 'onevent' not in config:
    config['onevent'] = ['json']
  if 'checks' in config:
    checks = json.loads(' '.join(open(config['checks'], 'r').readlines()))
  else:
    checks = {}
  
  checkItems = []
  if len(args.args) > 0:
    for item in args.args:
      checkItems.append(item.lower())
  else:
    checkItems = checks.keys()

  if len(checkItems) == 0:
    print('No items have been given to check, exiting', file=sys.stderr)
    sys.exit(2)

  results = []
  
  for namespace in checkItems:
    if namespace in checks:
      data = checks[namespace]
      r = []
      if 'cert' in data:
        r.append(checkCert(data['cert'], config['cafile']))
      if 'dns' in data:
        r.append(checkDNS(**data['dns']))
      if 'url' in data:
        r.append(checkURL(data['url']))

      results.append({ namespace: r })

  if 'json' in config['onevent']:
    print(json.dumps(results, indent=2))

  if len(results) > 0:
    sys.exit(1)
