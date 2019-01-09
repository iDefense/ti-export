#!/usr/bin/env python3
#
# Really simple reference set and table creation
# for threat intelligence integration. This script
# will create the standard reference collections
# as described at https://ibm.biz/rfisi_threat_intel
#
# This is meant to be used as a sample starting
# point only. The sample lacks key features of a
# production-ready solution such as certificate
# validation on SSL/TLS connections and robust
# exception handling.

import json

import requests

# do as I say, not as I do
requests.packages.urllib3.disable_warnings()

config = {}
exec(open('threat_reference_config').read(), config)

# QRadar specific.
global qradarIpAddress
global qradarSecToken

qradarIpAddress = config.get('qradarIP')
qradarSecToken = config.get('qradarAPIToken')


def addIndicator(indicator):
    referenceSetName = 'iDefense Threat Indicators'

    headers = {'SEC': qradarSecToken, 'Version': '4.0', 'Accept': 'application/json'}

    set_url = 'https://' + qradarIpAddress + '/api/reference_data/sets/' + referenceSetName
    set_data = {'name': referenceSetName, 'value': indicator['value'], 'source': 'iDefense'}

    table_name = referenceSetName + ' Data'
    table_url = 'https://' + qradarIpAddress + '/api/reference_data/tables/' + table_name
    fields = [{'name': 'Threat Type', 'value': indicator['type']},
              {'name': 'Confidence', 'value': indicator['confidence']},
              {'name': 'Severity', 'value': indicator['severity']},
              {'name': 'Role', 'value': indicator['role']},
              {'name': 'Comment', 'value': indicator['comment']},
              {'name': 'Last Seen Date', 'value': indicator['last-observed']}]

    try:
        response = requests.post(set_url, headers=headers, data=set_data, verify=False)
        for i in fields:
            data = {'name': table_name, 'outer_key': indicator['value'], 'inner_key': i['name'], 'value': i['value'], 'source': 'iDefense IntelGraph'}
            response = requests.post(table_url, headers=headers, data=data, verify=False)
        print(('Indicator ' + str(indicator['value']) + ' insertion HTTP status: ' + str(response.status_code)))
    except requests.exceptions.RequestException as exception:
        print((str(exception) + ', exiting.\n'))


def main():
    with open('ti.json') as f:
        feed = json.load(f)
        for indicator in feed:
            addIndicator(indicator)

if __name__ == '__main__':
    main()
