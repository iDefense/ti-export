# Automatically ingest iDefense Threat Indicators API data feed.
# Output to STIX 1.2.1
#
# Requires python-stix-1.2.0.8

import datetime
import json
import os
import sys

import requests
from cybox.common import Hash
from cybox.objects.address_object import Address
from cybox.objects.domain_name_object import DomainName
from cybox.objects.file_object import File
from cybox.objects.uri_object import URI
from mixbox.idgen import set_id_namespace
from mixbox.namespaces import Namespace
from stix.common import Confidence
from stix.common.vocabs import VocabString
from stix.core import STIXHeader
from stix.core import STIXPackage
from stix.indicator import Indicator
from stix.ttp import TTP
from stix.ttp.behavior import Behavior
from stix.ttp.malware_instance import MalwareInstance


def add_malware(hashVal, TTPTitle, malware_uuid):
    malware_instance = MalwareInstance()
    malware_instance.add_name(TTPTitle)
    # malware_instance.add_type("Malware")

    ttp = TTP(title=TTPTitle)
    ttp.behavior = Behavior()
    ttp.behavior.add_malware_instance(malware_instance)

    file_object = File()
    file_object.add_hash(Hash(hashVal))
    file_object.hashes[0].simple_hash_value.condition = "Equals"

    indicator = Indicator(id_="indicator-{0}".format(malware_uuid), title="File hash")
    indicator.add_indicator_type("File Hash Watchlist")
    indicator.add_observable(file_object)
    indicator.add_indicated_ttp(TTP(idref=ttp.id_))
    return(indicator)


def main():
    # define constants
    TI_REQUEST_URL = "https://api.intelgraph.idefense.com/rest/threatindicator/v0"
    # iDefense API Key
    # To avoid hard-coding creds, I'm using environment variables

    if os.environ.get('IDEF_TOKEN') is None:
        print("error: please store your iDefense IntelGraph API key in the IDEF_TOKEN environment")
        sys.exit(1)

    API_KEY = os.environ.get('IDEF_TOKEN')
    API_SECRET = ''

    # TODO: use command-line parameter
    timestr = datetime.datetime.utcnow() - datetime.timedelta(days=1)
    LAST_IMPORT = timestr.strftime("%Y-%m-%dT%H:%M:%S") + ".000Z"

    # TODO: use context manager
    file = open('stix-1.2.1.xml', 'w')

    HEADERS = {
        "Content-Type": "application/json",
        "auth-token": API_KEY,
        "X-Api-Key-Proof": API_SECRET
    }

    print(HEADERS)

    page = 1
    more_data = True
    count = 0

    # Set namespace
    NAMESPACE = Namespace("https://intelgraph.idefense.com", "idefense")
    set_id_namespace(NAMESPACE)

    # Create STIX Package
    stix_package = STIXPackage()
    stix_header = STIXHeader()
    stix_header.description = "iDefense Threat Indicators Feed"
    stix_package.stix_header = stix_header

    ttps = {}
    malware = {}

    try:

        while more_data:
            request_payload = {"start_date": LAST_IMPORT, "page_size": 200, "page": page}
            r = requests.post(TI_REQUEST_URL, headers=HEADERS, data=json.dumps(request_payload))
            print(r)
            response = []
            if r.status_code == requests.codes.ok:
                try:
                    # Read in response as json
                    response = r.json()

                except (ValueError, KeyError):
                    print("Response couldn't be decoded :(")
                    more_data = False
                    continue

                more_data = response.get('more', 'False')
                print("Page %d ==> %s (%s)" % (page, response['more'], response['total_size']))
                page += 1

                # Iterate the response
                for indicatorD in response['results']:
                    count += 1
                    # Indicator value such as the value of the IP/Domain/URL
                    indicator = indicatorD.get('key')
                    print(indicator, indicatorD.get('type'))
                    if indicatorD.get('last_seen_as') is None:
                        last_seen_as = 'UNKNOWN'
                    else:
                        last_seen_as = ''.join(indicatorD.get('last_seen_as'))

                    # Identify TTP
                    if last_seen_as not in ttps:
                        ttps[last_seen_as] = TTP(title=last_seen_as)
                        stix_package.add_ttp(ttps[last_seen_as])

                    # Identify malware source
                    if 'files' in indicatorD:
                        for hashD in indicatorD['files']:
                            md5 = hashD.get('key')
                            # Malware Family classification of the hash if available
                            if hashD.get('malware_family') is None:
                                malware_family = "Unknown"
                            else:
                                malware_family = ''.join(hashD.get('malware_family'))
                            if md5 not in malware:
                                malware[md5] = add_malware(md5, malware_family, hashD.get('uuid'))

                    if indicatorD.get('type') == "url":
                        # Create indicator
                        indicator = Indicator(id_="indicator-{0}".format(indicatorD.get('uuid')), title=''.join(indicatorD.get('malware_family')), timestamp=indicatorD.get('last_seen'))
                        indicator.add_indicator_type("URL Watchlist")

                        # Populate URL
                        url = URI()
                        url.value = indicatorD.get('key')
                        url.type_ = URI.TYPE_URL
                        url.value.condition = "Equals"

                        indicator.add_observable(url)

                    elif indicatorD.get('type') == "domain":
                        # Populate domain name
                        indicator = Indicator(id_="indicator-{0}".format(indicatorD.get('uuid')), title=''.join(indicatorD.get('malware_family')), timestamp=indicatorD.get('last_seen'))
                        indicator.add_indicator_type("Domain Watchlist")
                        domain = DomainName()
                        domain.value = indicatorD.get('key')
                        domain.value.condition = "Equals"
                        indicator.add_observable(domain)

                    elif indicatorD.get('type') == "ip":
                        # Create indicator
                        indicator = Indicator(id_="indicator-{0}".format(indicatorD.get('uuid')), title=indicatorD.get('malware_family'), timestamp=indicatorD.get('last_seen'))
                        indicator.add_indicator_type("IP Watchlist")
                        # Populate IP address
                        addr = Address(address_value=indicatorD.get('key'), category=Address.CAT_IPV4)
                        addr.condition = "Equals"
                        indicator.add_observable(addr)

                    # Link TTP
                    indicator.add_indicated_ttp(TTP(idref=ttps[last_seen_as].id_))
                    # Indicate confidence score
                    indicator.confidence = Confidence(value=VocabString(indicatorD.get('confidence')))
                    # Add related indicator to malware
                    indicator.add_related_indicator(malware[md5])
                    # Add to package
                    stix_package.add_indicator(indicator)

            else:
                print("API request couldn't be fulfilled due status code: %d" % r.status_code)
                more_data = False

        # Output to XML
        # print stix_package.to_xml()
        file.write(stix_package.to_xml())
        file.close()

    except requests.exceptions.ConnectionError as e:
        print("Check your network connection\n %s" % str(e))

    except requests.exceptions.HTTPError as e:
        print("Bad HTTP response\n %s" % str(e))

    except Exception as e:
        print("Uncaught exception\n %s" % str(e))


if __name__ == '__main__':
    main()
