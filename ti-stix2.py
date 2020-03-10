#!/usr/bin/env python

import argparse
import configparser
import datetime
import json
import os
import sys

import requests
from stix2 import Bundle, Indicator


def severity_map(sev_quant):
    if sev_quant == 1:
        return "MINIMAL"
    elif sev_quant == 2:
        return "LOW"
    elif sev_quant == 3:
        return "MED"
    elif sev_quant == 4:
        return "HIGH"
    elif sev_quant == 5:
        return "EXTREME"
    else:
        return ""


def confidence_map(con_quant):
    if con_quant >= 75:
        return "HIGH"
    elif con_quant >= 50:
        return "MED"
    elif con_quant >= 25:
        return "LOW"
    elif con_quant >= 0:
        return "NONE"
    else:
        return ""


def outputstix2(results):
    indicators = []
    for result in results:
        if result['type'] == 'url':
            indicator = Indicator(valid_from=result['last_seen'],
                                  labels=str(result['last_seen_as']),
                                  description=str(result['threat_types']),
                                  pattern="[url:value='%s']" % result['key'])
        elif result['type'] == 'domain':
            indicator = Indicator(valid_from=result['last_seen'],
                                  labels=str(result['last_seen_as']),
                                  description=str(result['threat_types']),
                                  pattern="[domain-name:value = '%s']" % result['key'])
        elif result['type'] == 'ip':
            indicator = Indicator(valid_from=result['last_seen'],
                                  labels=str(result['last_seen_as']),
                                  description=str(result['threat_types']),
                                  pattern="[domain-name:value = '%s']" % result['key'])
        indicators.append(indicator)
    bundle = Bundle(indicators)
    return bundle


class Config(object):
    """configuration object for TI"""

    def __init__(self, args, filename='ti.cfg'):
        super(Config, self).__init__()

        self.configp = configparser.ConfigParser()
        self.configp.read(filename)

        # Initial basics
        self.token = os.getenv('IDEF_TOKEN') or self.configp.get('ti', 'token')
        if not self.token:
            sys.exit('Must specify API token in config file or environment variable')

        if args.output:
            self.out_f = args.output
        else:
            self.out_f = self.configp.get('ti', 'out')
        self.confidence = args.confidence or self.configp.get('ti', 'confidence')
        self.severity = args.severity or self.configp.get('ti', 'severity')
        self.url = self.configp.get('ti', 'url')
        self.types = args.types
        self.debug = args.debug

        # Calculate the start date for TI data retrieval
        if args.number is not None:
            days = args.number
        else:
            days = self.configp.getint('ti', 'days')
        timestr = datetime.datetime.now() - datetime.timedelta(days=days)
        self.last_import = timestr.strftime("%Y-%m-%dT%H") + ":00:00.000Z"

        # set up column headings
        self.fieldnames = ['type', 'format', 'value', 'role', 'sample-md5', 'last-observed', 'comment', 'ref-id', 'confidence', 'severity']
        self.headers = {"Content-Type": "application/json", "auth-token": self.token}


def main():
    parser = argparse.ArgumentParser(description='Produce CSV output of iDefense TI feed')
    parser.add_argument('-o', '--output', help='Name of output file')
    parser.add_argument('-n', '--number', help='Number of days of data to fetch', type=int)
    parser.add_argument('-s', '--severity', help='Minimum severity', choices=['high', 'medium'])
    parser.add_argument('-c', '--confidence', help='Minimum confidence', choices=['high', 'medium'])
    parser.add_argument('-C', '--config', help='Name of configuration file', default='ti.cfg')
    parser.add_argument('-t', '--types', help='Types of indicators to fetch', choices=['url', 'domain', 'ip'], nargs='*')
    parser.add_argument('--debug', action="store_true", help='Print additional debug output')
    args = parser.parse_args()

    config = Config(args)

    # Set the datetime of the last import
    page = 1
    more_data = True
    results = []
    while more_data:
        # build search request
        request_payload = {"start_date": config.last_import, "page_size": 200, "page": page}
        if config.severity == 'high':
            request_payload['severity'] = {'from': 4}
        elif config.severity == 'medium':
            request_payload['severity'] = {'from': 3}

        if config.confidence == 'high':
            request_payload['confidence'] = {'from': 75}
        elif config.confidence == 'medium':
            request_payload['confidence'] = {'from': 50}

        if config.types:
            request_payload['type'] = {'values': config.types}

        if config.debug:
            print("Requesting:")
            print(json.dumps(request_payload))

        # Fetch next page of data
        try:
            r = requests.post(config.url, headers=config.headers, data=json.dumps(request_payload))
        except requests.exceptions.ConnectionError as e:
            sys.exit("Check your network connection\n%s" % str(e))
        except requests.exceptions.HTTPError as e:
            sys.exit("Bad HTTP response\n%s" % str(e))

        if r.status_code == requests.codes.ok:
            try:
                # Read in response as json
                response = r.json()
            except (ValueError, KeyError):
                sys.exit("Response couldn't be decoded")

            more_data = response['more']
            print("Page %d ==> %s (%s)" % (page, response['more'], response['total_size']))
            page += 1

            if 'results' not in response:
                sys.exit("No results for request")
            else:
                results.extend(response['results'])

        else:
            res = r.json()
            sys.stderr.write('%s @ %s\n' % (res['message'], res['timestamp']))
            sys.exit("API request couldn't be fulfilled (%d)\n" % r.status_code)

    bundle = outputstix2(results)
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(bundle, f)
    else:
        print(bundle)


if __name__ == "__main__":
    main()
