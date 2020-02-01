Headcheck
=========

![GPL License](https://img.shields.io/github/license/mmartins000/headcheck)

## Overview

Headcheck is a standalone script that verifies the implementation of security controls related to HTTP Methods and HTTP Headers.

The reports in JSON and HTML provide the evaluation and the raw data.
They also provide a recommendation that shall be tested in QA prior to implementation. 

Headcheck was tested with Python 3.8 on macOS 10.14.6 and 10.15.3.

Dependencies are: requests, urllib3, packaging
Install with: $ pip install requests urllib3 packaging

#### Advantages
- It can be run in internal networks, and doesn't depend on DNS servers.
- HTML report can be generated from the previously generated JSON answer file.
- Doesn't need to connect to any host (except the one being evaluated) to perform its job.

#### Disadvantages
- Python SSL/TLS and X.509 modules have a hard time working with broken certificates
- There is no threading in this version, so the SRI check and recommendation may take several seconds in each website, depending on the number of JS scripts they load. SRI checks can always be disabled with --no-check-sri

#### To learn more about HTTP security checks:
- [https://infosec.mozilla.org/guidelines/web_security](https://infosec.mozilla.org/guidelines/web_security)
- [https://developers.google.com/web/fundamentals/security/csp/](https://developers.google.com/web/fundamentals/security/csp/)
- [https://www.owasp.org/index.php/OWASP_Secure_Headers_Project](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project)

## Running Headcheck

### Usage

```
usage: headcheck.py [-h] [-s HOSTSCAN | -i INPUTSCAN | -l LOADFILE] [-v] [-q] [-j JSON] [-r REPORT] [-o] [--no-browser]
                    [--no-check-headers] [--no-check-tls] [--no-check-httpredir] [--no-check-methods] [--no-check-metatags]
                    [--no-check-sri] [--no-check-version] [--no-check-certificate] [--no-check-optional]
                    [--no-check-connection] [--no-recommendation] [--no-warning]

optional arguments:
  -h, --help            show this help message and exit
  -s HOSTSCAN, --site HOSTSCAN
                        Website to be evaluated
  -i INPUTSCAN, --input INPUTSCAN
                        File with list of websites for evaluation
  -l LOADFILE, --load LOADFILE
                        Load JSON from previous scan to generate HTML report
  -v, --version         Prints version and exists
  -q, --quiet           Do not print error messages
  -j JSON, --json JSON  Filename for JSON output
  -r REPORT, --report REPORT
                        Filename for HTML output
  -o, --overwrite       Overwrite existing JSON and HTML reports
  --no-browser          Do not open the report in the default web browser
  --no-check-headers    Skip headers check
  --no-check-tls        Skip TLS check
  --no-check-httpredir  Skip HTTP Redir check
  --no-check-methods    Skip HTTP Methods check
  --no-check-metatags   Skip HTML Meta Tags check
  --no-check-sri        Skip Subresource Integrity check
  --no-check-version    Skip Version check
  --no-check-certificate
                        Skip Digital Certificate check
  --no-check-optional   Skip Optional checks
  --no-check-connection
                        Skip Connection check
  --no-recommendation   Skip Recommendation
  --no-warning          Skip Warning message
```

### Example

```
$ /usr/local/bin/python3.8 /Users/username/Documents/headcheck/headcheck.py -i sitelist.txt -j headcheck.json -r headcheck.html -o --no-browser
Evaluating youtube.com
Done in 7 seconds.
```

### Report

For the example above, the script will evaluate all sites listed in sitelist.txt (except the ones commented out).
A file headcheck.json will be created with all the information collected and recommendations.
A HTML page headcheck.html will also be created. Both files will be in the root directory of the script.
You can check the screenshots folder for images of HTML report when the script was executed poiting to youtube.com.
