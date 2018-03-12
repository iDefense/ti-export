# Use Python 2.7.x for this version
#
# Automatically ingest iDefense Threat Indicators data feed.
# Output to STIX 1.2
#
# Requires python-stix-1.2.0.0+ and python-cybox-2.1.0.12+

import csv
import json
import os
import sys
from itertools import islice

import requests
from cybox.object.http_session_object import HTTPClientRequest
from cybox.object.http_session_object import HTTPRequestHeader
from cybox.object.http_session_object import HTTPRequestHeaderFields
from cybox.object.http_session_object import HTTPRequestResponse
from cybox.object.http_session_object import HTTPSession
from cybox.objects.address_object import Address
from cybox.objects.domain_name_object import DomainName
from cybox.objects.uri_object import URI
from stix.common import Confidence
from stix.common.vocabs import VocabString
from stix.core import STIXHeader
from stix.core import STIXPackage
from stix.indicator import Indicator
from stix.ttp import TTP
from stix.utils import set_id_namespace


def main():

    # Define constants

    # iDefense API base URL
    BASE_URL = 'https://intelgraph.idefense.com/rest/customer/'

    # Threat Indicators URL
    TI_URL = 'threatindicator/v0'

    # iDefense API Key
    # To avoid hard-coding creds, I'm using environment variables
    # Encoded base64 for obfuscation (not perfect, but better than nothing)

    if os.environ.get('IDEF_TOKEN') is None:
        print "error: please store your iDefense IntelGraph API key in the IDEF_TOKEN environment variable"
        sys.exit(1)

    API_KEY = os.environ.get('IDEF_TOKEN')

    fullUrl = BASE_URL + TI_URL

    # XXX this should be set by the user
    LAST_IMPORT = '2015-01-01T00:00:00.000Z'

    # Set custom headers
    headers = {'Content-Type': 'application/json', 'auth-token': API_KEY}

    try:
        payload = {'start_date': LAST_IMPORT}

        r = requests.post(fullUrl, headers=headers, data=json.dumps(payload))
        if r.status_code == requests.codes.ok:
            try:
                # Read in response as JSON
                response = r.json()

                # Iterate the response
                for indicatorD in response['results']:

                    # Indicator value such as the value of the IP/Domain/URL
                    indicator = indicatorD.get('key')

                    # The type of the indicator (IP/Domain/URL)
                    indicator_type = indicatorD.get('type')

                    # Integer value of the severity ratings, 1 representing the least severe and 5 the most severe
                    # 'LOW' -> 2, 'MEDIUM' -> 3, 'HIGH' -> 4
                    severity = indicatorD.get('severity')

                    # Classification of the indicator (Cyber Crime, Cyber Espionage, Hacktivism)
                    threat_types = indicatorD.get('threat_types')

                    # Classification of how the indicator is being used ('MALWARE_C2', 'MALWARE_DOWNLOAD', 'EXPLOIT')
                    type_of_use = indicatorD.get('last_seen_as')

                    # Associated host based indicators
                    if 'files' in indicatorD:
                        for hashD in indicatorD['files']:
                            md5 = hashD.get('key')
                            # Malware Family classification of the hash if available
                            malware_family = hashD.get('malware_family')

                    # Associated intelligence alert providing the added context and narrative for the indicator
                    if 'mentioned_by' in indicatorD:
                        for intel in indicatorD['mentioned_by']:
                            # Classification of the type of report (Intelligence Report, Intelligence Alert)
                            report_type = intel.get('type')
                            # Identifier for the report
                            report_identifier = intel.get('key')

                    print indicator, indicator_type, severity, threat_types, type_of_use, md5, malware_family, report_type, report_identifier

            except (ValueError, KeyError) as e:
                print "Response couldn't be decoded :("

        else:
            print "API request couldn't be fulfilled due status code: %d" % r.status_code

    except requests.exceptions.ConnectionError as e:
        print "Check your network connection\n %s" % str(e)
        pass

    except requests.exceptions.HTTPError as e:
        print "Bad HTTP response\n %s" % str(e)
        pass

    except Exception as e:
        print "Uncaught exception\n %s" % str(e)
        pass

    exit(0)

    # Convert string to list of lines
    modContent = r.text.splitlines()

    # Convert each line into comma separated list content
    data = csv.reader(modContent)

    # TI field description
    # type = {IPV4, DOMAIN, URL, USER_AGENT, REGISTRY_ENTRY, MUTEX} [0]
    # format = {STRING, REGEX} [1]
    # value = actual indicator value [2]
    # role = {MALWARE_C2, MALWARE_DOWNLOAD, EXPLOIT, MALWARE_INFECTION} [3]
    # sample-md5 = MD5 hash of malware sample [4]
    # last-observed = date/time indicator observed [5]
    # comment = Free text comment [6]
    # ref-id = IR# for iDefense report for add'l context [7]
    # confidence = {LOW, MEDIUM, HIGH} [8]
    # severity = {LOW, MEDIUM, HIGH} [9]
    # sample-sha1 = SHA1 hash of malware sample [10]
    # sample-sha256 = SHA256 hash of malware sample [11]

    # Set namespace
    NAMESPACE = {"http://idefense.com": "idefense"}
    set_id_namespace(NAMESPACE)

    # Create STIX Package
    stix_package = STIXPackage()
    stix_header = STIXHeader()
    stix_header.description = "iDefense Threat Indicators Feed"
    stix_package.stix_header = stix_header

    ttps = {}

    # Iterate over results, ignoring first 8 header lines
    for i in islice(data, 8, None):
        if i[0] == "IPV4":
            # Identify TTP
            if i[3] not in ttps:
                ttps[i[3]] = TTP(title=i[3])
                stix_package.add_ttp(ttps[i[3]])

            # Create indicator
            indicator = Indicator(title=i[6], timestamp=i[5])
            indicator.add_indicator_type("IP Watchlist")

            # Populate IP address
            addr = Address(address_value=i[2], category=Address.CAT_IPV4)
            addr.condition = "Equals"
            indicator.add_observable(addr)
            # Link TTP
            indicator.add_indicated_ttp(TTP(idref=ttps[i[3]].id_))
            # Indicate confidence score
            indicator.confidence = Confidence(value=VocabString(i[8]))
            # Add to package
            stix_package.add_indicator(indicator)
        elif i[0] == "URL":
            # Identify TTP
            if i[3] not in ttps:
                ttps[i[3]] = TTP(title=i[3])
                stix_package.add_ttp(ttps[i[3]])

            # Create indicator
            indicator = Indicator(title=i[6], timestamp=i[5])
            indicator.add_indicator_type("URL Watchlist")

            # Populate URL
            url = URI()
            url.value = i[2]
            url.type_ = URI.TYPE_URL
            url.value.condition = "Equals"

            indicator.add_observable(url)
            # Link TTP
            indicator.add_indicated_ttp(TTP(idref=ttps[i[3]].id_))
            # Indicate confidence score
            indicator.confidence = Confidence(value=VocabString(i[8]))
            # Add to package
            stix_package.add_indicator(indicator)
        elif i[0] == "DOMAIN":
            # Identify TTP
            if i[3] not in ttps:
                ttps[i[3]] = TTP(title=i[3])
                stix_package.add_ttp(ttps[i[3]])

            # Populate domain name
            indicator = Indicator(title=i[6], timestamp=i[5])
            indicator.add_indicator_type("Domain Watchlist")

            domain = DomainName()
            domain.value = i[2]
            domain.value.condition = "Equals"

            indicator.add_observable(domain)
            # Link TTP
            indicator.add_indicated_ttp(TTP(idref=ttps[i[3]].id_))
            # Indicate confidence score
            indicator.confidence = Confidence(value=VocabString(i[8]))
            # Add to package
            stix_package.add_indicator(indicator)
        elif i[0] == "USER_AGENT":
            # Identify TTP
            if i[3] not in ttps:
                ttps[i[3]] = TTP(title=i[3])
                stix_package.add_ttp(ttps[i[3]])

            # Populate user-agent-string
            indicator = Indicator(title=i[6], timestamp=i[5])
            indicator.add_indicator_type("URL Watchlist")

            fields = HTTPRequestHeaderFields()
            fields.user_agent = i[2]
            header = HTTPRequestHeader()
            header.parsed_header = fields
            request = HTTPClientRequest()
            request.http_request_header = header
            req_res = HTTPRequestResponse()
            req_res.http_client_request = request
            session = HTTPSession()
            session.http_request_response = [req_res]

            indicator.add_observable(session)
            # Link TTP
            indicator.add_indicated_ttp(TTP(idref=ttps[i[3]].id_))
            # Indicate confidence
            indicator.confidence = Confidence(value=VocabString(i[8]))
            # Add to package
            stix_package.add_indicator(indicator)

    # Output to XML
    print stix_package.to_xml()

if __name__ == '__main__':
    main()
