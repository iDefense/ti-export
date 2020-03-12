# ti-export

This README documents the usage of the `ti-export.py` script for accessing the iDefense IntelGraph Threat Indicator API. The script processes the rich JSON data returned by the API and optionally renders it in a CSV format that should be compatible with our legacy IP feed.

## Usage

The script requires an API authentication token as documented at the [IntelGraph documentation site](https://intelgraph.idefense.com/#/docs/view#page-section-2-0) (the "API code"). For security reasons, the script looks for your IG API token in the environment variable `IDEF_TOKEN` rather than specifying directly on the command line. Alternately, the file `ti.cfg` has a variable for the token.

The syntax is as follows:

```
usage: ti-export.py [-h] [-o OUTPUT] [-n NUMBER] [-s {high,medium}]
                    [-c {high,medium}]
                    [-t [{url,domain,ip,file} [{url,domain,ip,file} ...]]]
                    [-v {1,2}] [--debug]
```

- `-h`: Help message
- `-o`: Specify output file. Default is `ti.csv` if none specified.
- `-n`: Specify number of days of data. Default is 7 days if none specified.
- `-s`: Specify severity minimum for indicators. Choices are `medium` or `high`. Choosing either of these will filter all indicators for which no severity is listed.
- `-c`: Specify confidence minimum for indicators. Choices are `medium` or `high`. Choosing either of these will filter all indicators for which no confidence is listed.
- `-t`: Specify types of (primary) indicators to fetch. Choices are `url`, `domain`, or `ip`. Multiple choices can be specified, separated by a space (e.g. `-t url domain`). Note that this choice is unrelated to the MD5 hash of related files included with the primary indicator.
- `-v`: Specify version of legacy TI feed. Version 2 (the default) includes `confidence` and `severity` fields. The versions are otherwise identical.
- `-f`: Specify format for output. Choices are `json` or `csv` (the latter is primarily used by legacy clients).
- `--debug`: Produce additional output for debugging. This is normally not needed unless working with iDefense support.

Most of these parameters can also be set in the `ti.cfg` file.

Note that this script requires the use of the [requests](http://docs.python-requests.org/en/master/) library.

## STIX 2.x script
This script uses most of the same options as the core `ti-export.py` tool. It requires the use of the [cti-python-stix2](https://github.com/oasis-open/cti-python-stix2) library (`pip install stix2`) and tqdm (`pip install tqdm`)

## STIX 1.2.1 script
This script is not updated with all the features from `ti-export.py` and is included here for legacy purposes only. STIX 2.x support is forthcoming and will be fully supported.

## QRadar integration

After downloading a JSON file, the script `ti-qradar.py` can be used to upload the indicators to an IBM QRadar instance. Please note that this *proof of concept* script is based on the [rfisi-threat-import](https://github.com/ibm-security-intelligence/data-import/tree/master/rfisi-threat-import) tool provided by IBM and is used here in accordance with the terms of the Apache 2 license.

## Known issues

See known issues at [our GitHub page](https://github.com/iDefense/ti-export).
