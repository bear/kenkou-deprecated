kenkou
======
健康 - kenkou - health

A python based tool to check that a given resource is alive and valid.

It can check on URLs, Certificates and also DNS entries.

All redirects are followed and once the final URL is discovered it is tested for a 2XX result. If a 2XX is returned it is also scanned for mixed-content items if the url is HTTPS. The certificate for an HTTPS site is verified if ```verify_https``` is True in the config.

Currently it assumes port 443 for TLS and also that the given domain resolves to an IP address.

Designed to be run from a cronjob as often as you want to check the sites.

Note: if you are running kenkou on OS X you will need to export your root certificates using the Keychain Access tool. See https://www.madboa.com/geek/pine-macosx/#openssl for a great write-up on how to do this.

Usage
-----

```
python kenkou.py [-c|--config FILENAME] [--cafile PATH]

Where:
    -c --config  Configuration file (json format)
    --cafile     Path to your OS root certificate file
```

On OS X computers the root certificate file is located at ```/System/Library/OpenSSL/cert.pem``` if you have followed the export instructions given above.

On modern Linux systems it can be found at ```/etc/ssl/certs/ca-certificates.crt```.

Requirements
------------
See requirements.txt for details about what versions to install.
* requests
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
    "url": "https://events.pagerduty.com/generic/2010-04-15/create_event.json",
    "method": "POST",
    "params": { "service_key": "secrets",
                "incident_key": "incident_secret",
                "event_type": "trigger",
                "description": "FAILURE for production/HTTP"
    }
  },
  "postageapp": {
    "api_key": "secrets",
    "recipients": ["email@example.com"]
  },
  "onevent": [ "postageapp" ],
  "verify_https": true,
  "urls": {
    "file": "urls_to_check.cfg"
  },
  "dns": {
    "file": "dns_to_check.cfg"
  }
}
```

The file option allows for multiple sites to be grouped.

urls_to_check.cfg:

```json
{
  "production": {
    "main":    { "url": "http://127.0.0.1" },
    "example": { "url": "http://example.com" },
    "certchk": { "cert": "example.com" }
  }
}
```

dns_to_check.cfg:

```json
{
  "production": {
    "main": { "dns": [ "example.com", 
                       "127.0.0.1", 
                       [ "ns1.dnsimple.com", "ns2.dnsimple.com" ]
                     ]
    }
  }
}
```

The namespace for the Redis option is used to build both the key used to retrieve the
list of urls and also the keys used to store the last results.

```
  kenkou:urls_to_check            [ "production" ]
  kenkou:url.production           [ "main" ]
  kenkou:url.production.main      { "url": "http://127.0.0.1" }
  kenkou:result.production.main   200
```
