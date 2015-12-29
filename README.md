健康 - kenkou - health

[![Downloads](https://img.shields.io/pypi/v/kenkou.svg)](https://img.shields.io/pypi/v/kenkou.svg)
[![Build Status](https://circleci.com/gh/bear/kenkou.svg?style=shield&circle-token=427220e3ebc3fae25d8edc0683c53d1504e1bc35)](https://circleci.com/gh/:owner/kenkou.svg?style=shield&circle-token=427220e3ebc3fae25d8edc0683c53d1504e1bc35)
[![Requirements Status](https://requires.io/github/bear/kenkou/requirements.svg?branch=master)](https://requires.io/github/bear/kenkou/requirements/?branch=master)
[![Code Coverage](http://codecov.io/github/bear/kenkou/coverage.svg?branch=master)](http://codecov.io/github/bear/kenkou/coverage.svg?branch=master)

A python based tool to check that a given resource is alive and valid.

It can check on URLs, Certificates and also DNS entries.

All redirects are followed and once the final URL is discovered it is tested for a 2XX result. If a 2XX is returned it is also scanned for mixed-content items if the url is HTTPS. Certificates are verified for any HTTPS site.

Currently it assumes port 443 for TLS and also that the given domain resolves to an IP address.

Designed to be run from a cronjob as often as you want to check the sites.

Note: Kenkou will check to see if the [Certifi](https://certifi.io/en/latest/) Python package is installed, and if so, it will use the CA Bundle from that. If not it will check to see if ```/etc/ssl/certs/ca-certificates.crt``` exists. If neither is found it will exit with an error if a certificate check was requested.

Usage
-----

```
python kenkou.py [--config FILE] [--checks FILE] [--cafile FILE] [list,of,namespaces]

Where:
    --config  Configuration file (JSON format)
    --checks  Checks to run (JSON format)
    --cafile  ca-certificates file

    [list,of,namespaces] optional list of which namespaces to process

The output is a based on the value of the "onevent" configuration key:
  "json" (default if not present)
  "pagerduty"
  "postageapp"
```

Requirements
------------
See requirements.txt for details about what Python modules to install.

Configuration
-------------
Example kenkou.cfg file:

```json
{ "pagerduty": {
    "url":    "https://events.pagerduty.com/generic/2010-04-15/create_event.json",
    "method": "POST",
    "params": { "service_key":  "secret",
                "incident_key": "incident_secret",
                "event_type":   "trigger",
                "description":  "FAILURE for production/HTTP"
              }
  },
  "postageapp": {
    "api_key":    "secret",
    "recipients": [ "email@example.com" ]
  },
  "onevent": [ "postageapp" ],
  "checks": "kenkou_check.cfg"
}
```

kenkou_check.cfg:

```json
{ "web": { "url":  "https://example.com",
           "dns":  { "domain": "example.com",
                     "ip": "127.0.0.1",
                     "namespaces": [ "ns1.dnsimple.com", "ns2.dnsimple.com" ]
                   },
           "cert": "example.com"
         },
  "lb": { "url":  "http://lb.example.com",
          "dns":  { "domain": "lb.example.com",
                    "ip": "127.0.0.1", 
                    "namespaces": [ "ns1.dnsimple.com", "ns2.dnsimple.com" ]
                  },
          "cert": "lb.example.com"
         }
}
```
