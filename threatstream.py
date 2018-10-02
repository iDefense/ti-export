import datetime
import json
import os
import sys

import anomali_feedsdk.feed as feed
import requests


DEBUG = True

sev_map = {1: "low", 2: "low", 3: "medium", 4: "high", 5: "very-high"}

# get all the data since DELTA days ago, this can be changed in the next line
DELTA = 1
timestr = datetime.datetime.now() - datetime.timedelta(days=DELTA)
last_import = timestr.strftime("%Y-%m-%dT%H") + ":00:00.000Z"

url = "https://api.intelgraph.idefense.com/rest/threatindicator/v0"
token = os.getenv('IDEF_TOKEN')
headers = {"Content-Type": "application/json", "auth-token": token}

page = 1
more = True
indicators = []

# fetch indicators 200 at a time (max allowed by IG)
while more:
    request_payload = {"start_date": last_import, "page_size": 200, "page": page}
    try:
        if DEBUG:
            sys.stderr.write("Requesting %s page %d starting from %s\n" % (url, page, last_import))
        r = requests.post(url, headers=headers, data=json.dumps(request_payload))
    except requests.exceptions.ConnectionError as e:
        sys.exit("Check your network connection\n%s" % str(e))
    except requests.exceptions.HTTPError as e:
        sys.exit("Bad HTTP response\n%s" % str(e))

    try:
        response = r.json()
    except (ValueError, KeyError) as e:
        sys.exit("Response couldn't be decoded\n")

    if r.status_code != requests.codes.ok:
        sys.stderr.write('%s @ %s\n' % (response['message'], response['timestamp']))
        sys.exit("API request couldn't be fulfilled (%d)\n" % r.status_code)

    # this will be False when the API says no more results are available
    more = response['more']
    page += 1

    if 'results' not in response:
        sys.exit("No results for request\n")

    for indicator in response['results']:
        indicators.append(indicator)

# map our data to the ThreatStream data model and build the list
ts_iocs = []
for indicator in indicators:
    # ioc is a placeholder to build up the map
    ioc = {}
    ioc['value'] = indicator['key']
    if DEBUG:
        sys.stderr.write("Processing indicator %s\n" % indicator['key'])

    # use a default of 50 because of a bug in iDefense TI
    ioc['confidence'] = indicator.get('confidence', 50)
    ioc['severity'] = sev_map[indicator['severity']]

    if "Cyber Espionage" in indicator['threat_types']:
        ioc['threat_type'] = "apt"
        # examples: "apt_ip", "c2_url"
        ioc['itype'] = "apt_" + indicator['type']
    elif "MALWARE_C2" in indicator['last_seen_as']:
        ioc['threat_type'] = "c2"
        ioc['itype'] = "c2_" + indicator['type']
    else:  # generally MALWARE_DOWNLOAD
        ioc['threat_type'] = "malware"
        ioc['itype'] = "mal_" + indicator['type']

    # every malware family and threat campaign should be a tag for the indicator
    ioc['tags'] = []
    for mf in indicator.get('malware_family', ''):
        ioc['tags'].append(mf)
    for tc in indicator.get('threat_campaigns', ''):
        ioc['tags'].append(tc['key'])

    # set expiration to 2 years for espionage (defaults to 90 days otherwise)
    if ioc['threat_type'] == "apt":
        ioc['expiration'] = 730
    else:
        ioc['expiration'] = 90

    ts_ioc = feed.Indicator(ioc['value'], confidence=ioc['confidence'], severity=ioc['severity'],
                            threat_type=ioc['threat_type'], itype=ioc['itype'], tags=ioc['tags'],
                            expiration=ioc['expiration'])
    ts_iocs.append(ts_ioc)

ts_feed = feed.Feed()
ts_feed.ingest_indicators(ts_iocs)
