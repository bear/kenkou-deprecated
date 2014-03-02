kenkou
======
健康 - kenkou - health

A python based tool to check that an http resource is alive.

All redirects are followed and once the final URL is discovered it is tested
for a 2XX result. If 2XX is returned it is also scanned for mixed-content items.

Designed to be run from a cronjob as often as you want to check the sites.

Usage
-----

```
python kenkou.py [-c|--config FILENAME]

Where:
    -c --config  Configuration file (json format)
```

Requirements
------------
requests
beautifulsoup4
html5lib

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
  "urls": {
    "file": "urls_to_check.cfg"
  }
}
```

The file option allows for multiple sites to be grouped, for example:

```json
{
  "production": {
    "main":    { "url": "http://127.0.0.1" },
    "example": { "url": "http://example.com" }
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
