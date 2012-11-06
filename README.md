kenkou
======

A small python tool to check that an http resource is alive

While you can run it from the command line, currently I have made
it so that the options for posting an failure event come from the
configuration file.

Example kenkou.cfg file:

{ "debug": true,
  "url":  "http://127.0.0.1:8080",
  "period":  "5m",
  "onfail": { "url": "https://events.pagerduty.com/generic/2010-04-15/create_event.json",
              "method": "POST",
              "params": { "service_key": "92029390290923939",
                          "incident_key": "server01/HTTP",
                          "event_type": "trigger",
                          "description": "FAILURE for production/HTTP"
                        }
            }
}

TODO
  * make the config file handle multiple sites
  * copy some parsing code from parsedatetime so the period value can be more free form, e.g.
    5m, 5 min, 5 minutes, 3 days 2 min and so on
  * make the success determination more data driven such that it could be any result code or
    even a regex compare with something in the response body