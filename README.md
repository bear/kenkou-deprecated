kenkou
======

A python tool to check that an http resource is alive.

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
  "echo": true,
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
  "onfail": [ "postageapp" ],
  "redis": { "host": "127.0.0.1",
             "port": 6379,
             "db": 0,
             "namespace": "kenkou"
  }
  "urls": {
    "file": "urls_to_check.cfg",
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

The file option allows for multiple sites to be grouped, for example:

```json
{
  "production": {
    "main":    { "url": "http://127.0.0.1" },
    "example": { "url": "http://example.com" }
  }
}
```
