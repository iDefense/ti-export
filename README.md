# ti-export

This README documents the usage of the `ti-export.py` module for accessing the iDefense IntelGraph Threat Indicator API. The script processes the rich JSON data returned by the API and renders it in a number of formats useful in different environments.

## Usage

The script requires an API authentication token as documented at the [IntelGraph documentation site](https://intelgraph.idefense.com/#/docs/view#page-section-2-0) (the "API code"). For security reasons, the script looks for your IG API token in the environment variable `IDEF_TOKEN` rather than specifying directly on the command line. Alternately, you can specify the token in the `ti.cfg` configuration file using the variable `token`.

The syntax is as follows:

```
usage: ti-export.py [-h] [-o OUTPUT] [--hours NUMBER] [-s {high,medium}]
                    [-c {high,medium}]
                    [-t [{url,domain,ip,file} [{url,domain,ip,file} ...]]]
                    [-v {1,2}] [--debug]
```

- `-h`: Help message
- `-o`: Output file. Default is stdout if none specified.
- `-s`: Severity minimum for indicators. Choices are `medium` or `high`. Choosing either of these will filter all indicators for which no severity is listed. Default is medium.
- `-c`: Confidence minimum for indicators. Choices are `medium` or `high`. Choosing either of these will filter all indicators for which no confidence is listed. Note that `high` will only retrieve indicators manually entered by analysts. Default is medium.
- `-t`: Types of (primary) indicators to fetch. Choices are `url`, `domain`, or `ip`. Multiple choices can be specified, separated by a space (e.g. `-t url domain`). Default is all types.
- `-f`: Format for output. Choices are `json` (raw output from the API), `csv` for legacy clients, `stix1` (STIX v1.2.1 XML), or `stix2` (STIX v2.x JSON)
- `--hours`: Hours of data to fetch. If not specified, then the default will be 24 hours.
- `--quiet`: Quiet mode to minimize non-error output. Appropriate for use in scheduled tasks like cron jobs.
- `--debug`: Produce additional output for debugging. This is normally not needed unless working with iDefense support.

Most of these parameters can also be set in the `ti.cfg` file.

## Requirements

At its core, this is a Python 3 application and thus requires Python 3.X or higher.

This module requires `requests` in all cases.

Optional dependencies include the `stix` library (for STIX v1.2.1 support) or `stix2` library (for STIX v2.x support). These can be installed using `setup.py` (see the Installation section).

## Installation

Run `python3 setup.py install`.

## Known issues

See known issues at [our GitHub page](https://github.com/iDefense/ti-export).
