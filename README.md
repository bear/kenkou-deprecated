kenkou
======
健康 - kenkou - health

A python based tool to check that a given resource is alive and valid.

It can check on URLs, Certificates and also DNS entries.

All redirects are followed and once the final URL is discovered it is tested for a 2XX result. If a 2XX is returned it is also scanned for mixed-content items if the url is HTTPS. The certificate for an HTTPS site is verified if ```verify_https``` is True in the config.

Currently it assumes port 443 for TLS and also that the given domain resolves to an IP address.

Designed to be run from a cronjob as often as you want to check the sites.

Note: Kenkou will check to see if the [Certifi](https://certifi.io/en/latest/) Python package is installed, and if so, it will use the CA Bundle from that. If not it will check to see if ```/etc/ssl/certs/ca-certificates.crt``` exists. If neither is found it will exit with an error if a certificate check was requested.

Usage
-----

```
python kenkou.py [-c|--config FILENAME] [--cafile PATH]

Where:
    -c --config  Configuration file (json format)
```

Requirements
------------
See requirements.txt for details about what versions to install.
* requests
* certifi
* beautifulsoup4
* html5lib
* dnspython
* pyOpenSSL

Configuration
-------------
Example kenkou.cfg file:

```json
{ "debug": true,
  "pagerduty": {
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
  "checks": "things_to_check.cfg"
}
```

urls_to_check.cfg:

```json
{ "web": { "url":  "http://example.com",
           "dns":  [ "example.com", "127.0.0.1", 
                     [ "ns1.dnsimple.com", "ns2.dnsimple.com" ]
                   ],
           "cert": "example.com"
         },
  "lb": { "url":  "http://lb.example.com",
          "dns":  [ "lb.example.com", "127.0.0.1", 
                    [ "ns1.dnsimple.com", "ns2.dnsimple.com" ]
                  ],
          "cert": "lb.example.com"
         }
}
```
