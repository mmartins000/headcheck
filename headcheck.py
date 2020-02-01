#!/usr/local/bin/python3

# HeadCheck
# Source: https://github.com/mmartins000/headcheck
# Author: Marcelo Martins

import requests
import argparse
import re
from pathlib import Path
from urllib.parse import urlparse, urljoin, urlsplit
import json
import ssl
import socket
import sys
from packaging import version
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager
from urllib3.util import ssl_
from datetime import datetime, timezone, timedelta
import fnmatch
import os.path
import html
from html.parser import HTMLParser
# import threading


parser = argparse.ArgumentParser()  # add_help=False)
target_group = parser.add_mutually_exclusive_group()
target_group.add_argument("-s", "--site", help="Website to be evaluated", dest='hostScan')
target_group.add_argument("-i", "--input", help="File with list of websites for evaluation", dest='inputScan')
target_group.add_argument("-l", "--load", help="Load JSON from previous scan to generate HTML report", dest='loadFile')
parser.add_argument("-v", "--version", help="Prints version and exists", action='store_true', dest='version')
parser.add_argument("-q", "--quiet", help="Do not print error messages", action='store_true', dest='quiet')
parser.add_argument("-j", "--json", help="Filename for JSON output", dest='json')
parser.add_argument("-r", "--report", help="Filename for HTML output", dest='report')
parser.add_argument("-o", "--overwrite", help="Overwrite existing JSON and HTML reports",
                    action='store_true', dest='overwrite')
parser.add_argument("--no-browser", help="Do not open the report in the default web browser",
                    action='store_true', dest='no_browser')
parser.add_argument("--no-check-headers", help="Skip headers check",
                    action='store_true', dest='no_check_headers')
parser.add_argument("--no-check-tls", help="Skip TLS check",
                    action='store_true', dest='no_check_tls')
parser.add_argument("--no-check-httpredir", help="Skip HTTP Redir check",
                    action='store_true', dest='no_check_httpredir')
parser.add_argument("--no-check-methods", help="Skip HTTP Methods check",
                    action='store_true', dest='no_check_methods')
parser.add_argument("--no-check-metatags", help="Skip HTML Meta Tags check",
                    action='store_true', dest='no_check_metatags')
parser.add_argument("--no-check-sri", help="Skip Subresource Integrity check",
                    action='store_true', dest='no_check_sri')
parser.add_argument("--no-check-version", help="Skip Version check",
                    action='store_true', dest='no_check_version')
parser.add_argument("--no-check-certificate", help="Skip Digital Certificate check",
                    action='store_true', dest='no_check_certificate')
parser.add_argument("--no-check-optional", help="Skip Optional checks",
                    action='store_true', dest='no_check_optional')
parser.add_argument("--no-check-connection", help="Skip Connection check",
                    action='store_true', dest='no_check_connection')
parser.add_argument("--no-recommendation", help="Skip Recommendation",
                    action='store_true', dest='no_recommendation')
parser.add_argument("--no-warning", help="Skip Warning message",
                    action='store_true', dest='no_warning')

args = parser.parse_args()

__version__ = '0.1'

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_FILE_EXISTS = 2
EXIT_FILE_NOT_FOUND = 3
EXIT_INVALID_OPT = 4
EXIT_TCP_PORT = 5
EXIT_FILE_FORMAT = 6

# To learn more about HTTP security checks:
# https://infosec.mozilla.org/guidelines/web_security
# https://developers.google.com/web/fundamentals/security/csp/
# https://www.owasp.org/index.php/OWASP_Secure_Headers_Project
# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
# https://securityintelligence.com/an-introduction-to-http-response-headers-for-security/
# https://nullsweep.com/http-security-headers-a-complete-guide/
# https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods

# Variable used in check_server_version()
http_server_sources = {
    'apache': {
        'regex': r'Apache/([\d.]+)',
        'source': 'http://www.apache.org/dist/httpd/CHANGES_2.4',
        'latest_regex': r'Changes with Apache ([\d.]+)'
    },
    'nginx': {
        'regex': r'^nginx/([\d.]+)$',
        'source': 'https://nginx.org/en/CHANGES',
        'latest_regex': r'Changes with nginx ([\d.]+)'
    },
    'microsoft': {
        'regex': r'^Microsoft-IIS/([\d.]+)$',
        'source': ''
    },
    'php': {
        'regex': r'PHP/([\d.]+)$',
        'source': 'https://www.php.net/downloads.php',
        'latest_regex': r'Current Stable PHP ([\d.]+)'
    }
}


class MyAdapter(HTTPAdapter):
    """Transport adapter that allows us to use SSLv3, TLSv1, TLSv1.1 and TLSv1.2."""

    def __init__(self, ssl_options=0, **kwargs):
        self.ssl_options = ssl_options
        super(MyAdapter, self).__init__(**kwargs)

    def init_poolmanager(self, *pool_args, **pool_kwargs):
        ctx = ssl_.create_urllib3_context(ssl.PROTOCOL_TLS)
        # extend the default context options, which is to disable ssl2, ssl3
        # and ssl compression, see:
        # https://github.com/shazow/urllib3/blob/6a6cfe9/urllib3/util/ssl_.py#L241
        ctx.options |= self.ssl_options
        self.poolmanager = PoolManager(*pool_args, ssl_context=ctx, **pool_kwargs)


def print_version():
    """
    Called by main()
    :return: True, always
    """
    args.quiet or print("HeadCheck v{}".format(__version__))
    return True


def check_port(p):
    """
    Called by main()
    :param p: Port number
    :return: True, if the 0 < p < 65535
    """
    if re.search('^[0-9]{1,5}', p) and 0 < int(p) < 65536:
        return True
    else:
        print("Error: TCP port number invalid: ", p)
        sys.exit(EXIT_TCP_PORT)


def check_input_output(file):
    """
    Called by check_sanity()
    :param file: filename from args
    :return: True if filename exists, False if doesn't
    """
    if Path(file).is_file():
        return True
    return False


def input_list(input_file):
    if input_file:
        with open(input_file) as f:
            dest_list = [line.rstrip('\n') for line in f]
    return dest_list


def check_ip(t):
    """
    Called by main()
    :param t: IP string
    :return: True if string matches IP format
    """
    ipaddr = '^([0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})(-[0-9]{1,3})?$'
    if re.search(ipaddr, t):
        return True
    return False


def check_cidr(t):
    """
    Called by main()
    :param t: CIDR string
    :return: True if string matches CIDR format
    """
    cidr = '^([0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})(/[0-9]{1,2})$'
    if re.search(cidr, t):
        return True
    return False


def check_domain(t):
    """
    Called by main()
    :param t: domain name string
    :return: True if string matches domain name format
    """
    domain = '^((?!-))(xn--)?[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]{0,1}.(xn--)?([a-z0-9-]{1,61}|[a-z0-9-]{1,30}.[a-z]{2,})$'
    if re.search(domain, t):
        return True
    return False


def check_protocol(t):
    """
    Called by main()
    :param t: URL address string
    :return: True if string starts with http or https
    """
    return re.search('^http|https$', t)


def check_connection(address):
    """
    Called by main()
    :param address: URL address string
    :return: True if successfully connected to address
    """
    try:
        res = requests.get(address, timeout=1)
    except requests.exceptions.ConnectionError:
        pass
        args.quiet or print("Connection error while trying to connect to {}.".format(address))
        return False
    else:
        return True


def split_protocol_host_port(address):
    o = urlparse(address)
    try:
        protocol = o.scheme
    except IndexError:
        protocol = "http"

    host = o.netloc.split(":")[0]
    try:
        port = o.netloc.split(":")[1]
    except IndexError:
        if protocol == "https":
            port = str(443)
        else:
            port = str(80)
    return [protocol, host, port]


def check_sanity():
    if args.json:
        if check_input_output(args.json) and not args.overwrite:
            print("Error: File {} already exists.".format(args.json))
            sys.exit(EXIT_FILE_EXISTS)
    if args.report:
        if check_input_output(args.report) and not args.overwrite:
            print("Error: File {} already exists.".format(args.report))
            sys.exit(EXIT_FILE_EXISTS)
    if args.inputScan:
        if not check_input_output(args.inputScan):
            print("Error: File {} does not exist.".format(args.inputScan))
            sys.exit(EXIT_FILE_NOT_FOUND)
    if args.loadFile:
        if not check_input_output(args.loadFile):
            print("Error: File {} does not exist.".format(args.loadFile))
            sys.exit(EXIT_FILE_NOT_FOUND)


def check_xxss(header):
    if isinstance(header, list):
        header = header[1]

    data = dict()
    data['display'] = "X-XSS-Protection"
    data['source'] = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection"
    data['expected'] = "1; mode=block"  # This is only important for Internet Explorer. Other will use CSP
    if header:
        data['result'] = "Found '" + header + "', but it only works for Internet Explorer"
        counter = 0
        if '1;' in str(header) or re.search('mode=block', str(header)):
            counter += 1
        data['score'] = counter
    else:
        data['score'] = 0
        data['result'] = "Not implemented, but it's only for Internet Explorer. Other will use CSP."
        # Who uses Internet Explorer anyway?

    if int(data['score']) >= 0:
        data['pass'] = "pass"
    else:
        data['pass'] = "fail"
    return data


def check_cookie(cookiejar):
    data = dict()
    data['display'] = "Set-Cookie"
    data['source'] = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Secure_and_HttpOnly_cookies"
    data['expected'] = "Secure; httponly; SameSite=Strict"

    if cookiejar:
        cookielist = list()
        import time
        for cookie in cookiejar:
            cookiestr = cookie.name + "=" + cookie.value + "; domain=" + cookie.domain + "; path=" + cookie.path
            cookiestr += "; Expires: " + time.strftime('%a, %d-%m-%Y %H:%M:%S GMT', time.localtime(cookie.expires))
            if cookie.secure:
                cookiestr += "; Secure"
            if cookie.has_nonstandard_attr('httponly') or \
                    cookie.has_nonstandard_attr('HttpOnly') or cookie.has_nonstandard_attr('httpOnly'):
                cookiestr += "; httponly"
            if cookie.get_nonstandard_attr('SameSite') is not None:
                cookiestr += "; SameSite=" + cookie.get_nonstandard_attr('SameSite')
            cookielist.append(cookiestr)

        data['result'] = cookielist
        counter = 0
        for cookie in cookielist:
            if 'secure' in cookie.lower():
                counter += 1
            else:
                counter -= 1
            if 'httponly' in cookie.lower():            # httponly flag may break a few websites
                counter += 1
            if 'samesite=strict' in cookie.lower():     # SameSite is relatively new and not widely supported
                counter += 1
        data['score'] = counter
    else:
        data['score'] = 0
        data['result'] = "Not implemented"

    if int(data['score']) >= 0:
        data['pass'] = "pass"
    else:
        data['pass'] = "fail"
    return data


def check_origin(header, address):
    if isinstance(header, list):
        header = header[1]

    data = dict()
    data['display'] = "Access-Control-Allow-Origin"
    data['source'] = "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"
    [protocol, host, port] = split_protocol_host_port(address)
    data['expected'] = "https://" + host
    if header:
        data['result'] = header
        if header.lower() == address:
            data['score'] = 0
        else:
            data['score'] = -1
    else:
        data['score'] = -1
        data['result'] = "Not implemented"

    if int(data['score']) >= 0:
        data['pass'] = "pass"
    else:
        data['pass'] = "fail"
    return data


def check_xframe(header):
    if isinstance(header, list):
        header = header[1]

    data = dict()
    data['display'] = "X-Frame-Options"
    data['source'] = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
    data['expected'] = "deny"
    if header:
        data['result'] = header
        counter = 0
        if 'deny' in str(header).lower():
            counter = 2
        elif 'sameorigin' in str(header).lower():
            counter = 1
        data['score'] = counter
    else:
        data['score'] = -1
        data['result'] = "Not implemented"

    if int(data['score']) >= 0:
        data['pass'] = "pass"
    else:
        data['pass'] = "fail"
    return data


def check_xcont(header):
    if isinstance(header, list):
        header = header[1]

    data = dict()
    data['display'] = "X-Content-Options"
    data['source'] = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
    data['expected'] = "nosniff"
    if header:
        data['result'] = header
        if 'nosniff' in header.lower():
            data['score'] = 0
        else:
            data['score'] = -1
    else:
        data['score'] = -1
        data['result'] = "Not implemented"

    if int(data['score']) >= 0:
        data['pass'] = "pass"
    else:
        data['pass'] = "fail"
    return data


def check_referrer(header):
    if isinstance(header, list):
        header = header[1]

    policy_range = {
        'no-referrer': 1,
        'no-referrer-when-downgrade': 0,
        'origin': -1,
        'origin-when-cross-origin': -1,
        'same-origin': -1,
        'strict-origin': -1,
        'strict-origin-when-cross-origin': -1,
        'unsafe-url': -3
    }

    data = dict()
    data['display'] = "Referrer-Policy"
    data['source'] = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
    data['expected'] = "no-referrer"
    # There may be more that one parameter, like 'no-referrer, strict-origin-when-cross-origin'
    # This function will consider only the first
    header = header.split(',')[0]
    if header:
        for k, v in policy_range.items():
            if header.lower() == k:
                data['score'] = v
        if header in 'no-referrer-when-downgrade':
            data['result'] = "Found '" + header + "', but this is the default behaviour anyway"
        elif header in data['expected']:
            data['result'] = "Found '", header + "', but expected to find '" + data['expected'] + "'"
        else:
            data['result'] = "Found '", header + "'"
    else:
        # When it's missing, defaults to 'no-referrer-when-downgrade'
        data['score'] = policy_range['no-referrer-when-downgrade']
        data['result'] = "Not implemented. Defaults to 'no-referrer-when-downgrade', which is ok."

    if int(data['score']) >= 0:
        data['pass'] = "pass"
    else:
        data['pass'] = "fail"
    return data


def check_sts(header):
    if isinstance(header, list):
        header = header[1]

    data = dict()
    data['display'] = "Strict-Transport-Security"
    data['source'] = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
    data['expected'] = "max-age=([0-9]{1,8}); (includeSubDomains)"
    if header:
        data['result'] = header
        counter = 0
        if re.search('max-age=([0-9]{1,8})', header):
            counter += 1
        if 'includeSubDomains' in header:
            counter += 1
        data['score'] = counter
    else:
        data['result'] = "Not implemented"
        data['score'] = -1

    if int(data['score']) >= 0:
        data['pass'] = "pass"
    else:
        data['pass'] = "fail"
    return data


def check_csp(header):
    if isinstance(header, list):
        header = header[1]

    csp_fetch_directives = ['child-src', 'connect-src', 'default-src', 'font-src', 'frame-src', 'img-src',
                            'manifest-src', 'media-src', 'object-src', 'script-src', 'style-src', 'worker-src']
    # csp_document_directives = ['base-uri', 'plugin-types', 'sandbox']
    # csp_navigation_directives = ['form-action', 'frame-ancestors']
    # csp_report_directives = ['report-to']
    # csp_other_directives = ['block-all-mixed-content', 'trusted-types', 'upgrade-insecure-requests']

    good_params = ['https:', '\'self\'', '\'sha256-', 'none']
    bad_params = ['http:', '*']

    data = dict()
    data['display'] = "Content-Security-Policy"
    data['source'] = "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
    data['source2'] = "https://developers.google.com/web/fundamentals/security/csp/"
    data['expected'] = "default-src 'self'"     # It's not that simple though
    result = dict()
    positive = list()
    negative = list()
    if header:
        counter = 0
        header_slice = header.split(';')
        # For every directive and parameters
        for dir_param in header_slice:
            if dir_param == '':
                # Happens when there is a last ';'
                header_slice.remove('')
                continue

            # Directive is param 0
            dir_param_split = dir_param.split()
            if dir_param_split[0] in ('default-src', 'script-src', 'style-src'):
                # These are critical
                positive.append(dir_param_split[0])
                for param in dir_param_split:
                    if dir_param_split.index(param) == 0:
                        continue
                    for good_param in good_params:
                        if param.startswith(good_param):
                            counter += 1
                    for bad_param in bad_params:
                        if param.startswith(bad_param):
                            counter -= 1
                    if param in ('\'unsafe-eval\'', '\'unsafe-inline\''):
                        negative.append(dir_param_split[0] + ' with ' + param)
                        counter -= 2
            elif dir_param_split[0] == 'trusted-types':
                # https://developers.google.com/web/updates/2019/02/trusted-types
                # I won't evaluate the policy. I'll assume it was tested.
                counter += 1
        result['positive'] = positive
        result['negative'] = negative
        data['score'] = counter
        data['result'] = result
    else:
        data['score'] = -4
        data['result'] = "Not implemented"

    if int(data['score']) >= 0:
        data['pass'] = "pass"
    else:
        data['pass'] = "fail"
    return data


def check_pkp(header):
    if isinstance(header, list):
        header = header[1]

    data = dict()
    data['display'] = "Public-Key-Pins"
    data['source'] = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Public_Key_Pinning"
    data['expected'] = \
        'pin-sha256="(.*?)"; max-age=([0-9]{1,8}); (includeSubDomains);'
    if header:
        counter = 0
        header_slice = header.split(';')
        for head_slice in header_slice:
            if 'pin-sha256' in head_slice:
                m = re.search('pin-sha256="(.*?)"', head_slice)
                # https://tools.ietf.org/html/rfc7469#section-2.1.2
                n = re.search('max-age=([0-9]{1,8})', head_slice)
                if m and n:
                    counter += 1
                    # https://tools.ietf.org/html/rfc7469#section-2.1.3
                    if 'includeSubDomains' in head_slice:
                        counter += 1
        data['score'] = counter
        data['result'] = ""
    else:
        data['score'] = 0
        data['result'] = "Not implemented, but it's optional."

    if int(data['score']) >= 0:
        data['pass'] = "pass"
    else:
        data['pass'] = "fail"
    return data


def check_securitytxt(address):
    data = dict()
    data['display'] = "Securitytxt"
    data['source'] = ""
    try:
        sectxt = requests.get(address + '/security.txt')
        if sectxt.status_code == 200:
            return sectxt.text
    except requests.exceptions.ConnectionError:
        return "Connection error"
    return "Not found"


def check_contribute(address):
    data = dict()
    data['display'] = "Contribute.json"
    data['source'] = ""
    try:
        contrib = requests.get(address + '/contribute.json')
        if contrib.status_code == 200:
            return contrib.text
    except requests.exceptions.ConnectionError:
        return "Connection error"
    return "Not found"


def check_http_redir(host):
    data = dict()
    data['display'] = "HTTP Redirect"
    data['source'] = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
    data['expected'] = "301 or 302"
    try:
        redir = requests.get(url='http://' + host, allow_redirects=False)
        if redir.status_code == 301 or redir.status_code == 302:
            data['status_code'] = redir.status_code
            data['score'] = 0
            data['result'] = "Redirected to {} with status code {}.".format(redir.headers['Location'],
                                                                            redir.status_code)
        elif redir.status_code == 200:
            data['status_code'] = redir.status_code
            data['score'] = -1
            data['result'] = "HTTP connection accepted with status code {}.".format(redir.status_code)
    except requests.exceptions.ConnectionError:
        pass
        data['score'] = 0
        data['result'] = "Connection error."

    if int(data['score']) >= 0:
        data['pass'] = "pass"
    else:
        data['pass'] = "fail"
    return data


def check_server_version(header):
    if isinstance(header, list):
        header = header[1]

    data = dict()
    data['display'] = "Server"
    data['source'] = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server"
    if header:
        data['result'] = header
        data['score'] = "Skipped"
        found_version = re.search('', header)[0]
        for server in http_server_sources:
            if re.search(http_server_sources[server]['regex'], header):
                r = requests.get(url=http_server_sources[server]['source'])
                if r.status_code == 200:
                    last_found_version = re.search('', r.content)[0]
                    if version.parse(found_version) < version.parse(last_found_version):
                        data['score'] = -1
                    else:
                        data['score'] = 1
    else:
        data['result'] = "Not implemented"
        data['score'] = -1

    if data['score'] == "Skipped":
        data['pass'] = "skipped"
    elif int(data['score']) >= 0:
        data['pass'] = "pass"
    elif int(data['score']) < 0:
        data['pass'] = "fail"
    else:
        data['pass'] = "info"
    return data


def check_html_meta_tags(full_text):
    data = dict()
    data['display'] = "HTML Meta Tags"
    data['source'] = "https://developer.mozilla.org/en-US/docs/Web/HTML/Element/meta#attr-http-equiv"

    # HPKP shall be ignored in meta tags
    # https://tools.ietf.org/html/rfc7469#section-2.3.4
    m = re.search('meta http-equiv="Content-Security-Policy".*content="(.*)">', full_text, re.IGNORECASE)
    if m:
        data['result'] = m.group(1)
        data['score'] = 0
        if int(data['score']) >= 0:
            data['pass'] = "pass"
        else:
            data['pass'] = "fail"
    return data


def check_sri(full_text, address):
    from html.parser import HTMLParser

    class MyHTMLParser(HTMLParser):
        lsSrcIntegrityTags = list()
        lsSrcTags = list()

        def handle_starttag(self, tag, attrs):
            if str(tag).lower() in ("script", "link"):
                found_src, found_integrity = False, False
                for tuple_item in attrs:
                    if 'src' in tuple_item:
                        found_src = tuple_item[1]
                    if 'integrity' in tuple_item:
                        found_integrity = tuple_item[1]

                if found_src and found_integrity:
                    d = dict()
                    d['src'] = found_src
                    d['integrity'] = found_integrity
                    self.lsSrcIntegrityTags.append(d)
                elif found_src:
                    d = dict()
                    d['src'] = found_src
                    self.lsSrcTags.append(d)

    data = dict()
    data['display'] = "Subresource Integrity"
    data['source'] = "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"
    valid = list()
    invalid = list()
    missing = list()
    counter = 0

    htmlparser = MyHTMLParser()
    htmlparser.feed(full_text)
    for item in htmlparser.lsSrcIntegrityTags:
        if str(item['src']).startswith('.'):
            item['src'] = urljoin(address, item['src'])
        if get_sri_hash(item['src']) == item['integrity']:
            valid.append(item['src'])
        else:
            invalid.append(item['src'])
            counter -= 2

    for item in htmlparser.lsSrcTags:
        # CDNs may hide the protocol to allow http and https
        if re.search('^(://)', item['src']):
            item = "https" + item
        # If the item starts with / or .. we assume the site is loading a local file, which doesn't need SRI
        if not re.search('^(/.*|..)', item['src']):
            missing.append(item['src'])
            counter -= 1

    result = dict()
    result['valid'] = valid
    result['invalid'] = invalid
    result['missing'] = missing
    data['score'] = max(int(counter), -3)
    data['result'] = result

    if not full_text == "":     # One of the reasons is expired TLS certificate
        if int(data['score']) >= 0:
            data['pass'] = "pass"
        else:
            data['pass'] = "fail"
    else:
        data['score'] = "Skipped"
        data['pass'] = "skipped"

    return data


def get_sri_hash(file_link, sha=384):
    """
    https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
    An integrity value begins with at least one string, with each string including a prefix indicating
    a particular hash algorithm (currently the allowed prefixes are sha256, sha384, and sha512),
    followed by a dash, and ending with the actual base64-encoded hash.
    """

    import hashlib
    import base64
    r = requests.get(file_link)
    if sha == 256:
        h = hashlib.sha256(r.content).digest()
    elif sha == 512:
        h = hashlib.sha512(r.content).digest()
    else:
        sha = 384
        h = hashlib.sha384(r.content).digest()
    b = base64.b64encode(h)
    s = bytes(b).decode('utf-8')
    return 'sha' + str(sha) + '-{}'.format(s)


def create_recommendation(full_text, full_header, address, cookielist):
    # Warning: These are reasonable default values.
    # Evaluate every HTTP Header and SRI in QA before use in production environment.
    # Note: Trusted-types are not being evaluated in this version.

    data = dict()
    data['disclaimer'] = "These are reasonable default values. " \
                         "Evaluate every HTTP Header and SRI in QA before use in production environment."

    methods = dict()
    methods['display'] = "HTTP Methods"
    methods['source'] = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods"
    methods['setting'] = ['GET', 'HEAD', 'POST']
    data['methods'] = methods

    headers = dict()
    headers['display'] = "HTTP Headers"
    headers['source'] = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers"

    expect_ct = dict()
    expect_ct['display'] = "Expect-CT"
    expect_ct['source'] = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT"
    expect_ct['setting'] = "Expect-CT: max-age=86400, enforce"
    headers['expect-ct'] = expect_ct

    referrer = dict()
    referrer['display'] = "Referrer-Policy"
    referrer['source'] = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
    referrer['setting'] = "Referrer-Policy: no-referrer, no-referrer-when-downgrade"
    headers['referrer'] = referrer

    x_frame = dict()
    x_frame['display'] = "X-Frame-Options"
    x_frame['source'] = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
    x_frame['setting'] = "X-Frame-Options: deny"
    headers['x-frame'] = x_frame

    hsts = dict()
    hsts['display'] = "Strict-Transport-Security"
    hsts['source'] = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
    hsts['setting'] = "Strict-Transport-Security: max-age=657000; includeSubDomains"
    headers['hsts'] = hsts

    xxss = dict()
    xxss['display'] = "X-XSS-Protection"
    xxss['source'] = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection"
    xxss['setting'] = "X-XSS-Protection: 1; mode=block"     # Useful for IE only
    headers['xxss'] = xxss

    # Cookies
    cookielist_rec = list()
    for cookie in cookielist:
        if cookie == "Set-Cookie":
            continue
        if "secure" not in cookie.lower():
            cookie += "; Secure"
        if "httponly" not in cookie.lower():
            cookie += "; HttpOnly"
        if "samesite" not in cookie.lower():
            cookie += "; SameSite=Strict"
        elif "samesite=strict" not in cookie.lower():
            cookie = re.sub(r"SameSite=Lax", "SameSite=Strict", cookie, re.IGNORECASE)
        cookielist_rec.append(cookie)

    cookie_head = dict()
    cookie_head['display'] = "Set-Cookie"
    cookie_head['source'] = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Secure_and_HttpOnly_cookies"
    cookie_head['setting'] = cookielist_rec
    headers['set-cookie'] = cookie_head

    # CSP and SRI
    # Items starting with '/' and '..' are local and represented by 'self' in CSP
    # Null items (None) are inline scripts missing 'src' attribute
    csp_scriptlinks = list()
    sri_scriptfiles = list()  # Used in the end of this function
    for item in get_list_src_from_tag(full_text, 'script'):
        # CDNs may hide the protocol to allow http and https
        if item is not None:
            if re.search('^(://)', item):
                item = "https" + item
        # If the item starts with / or .. we assume the site is loading a local file, which doesn't need SRI
        if item is None or re.search('^(/.*|\.\.)', item):
            continue
        sri_scriptfiles.append(item)
        csp_scriptlinks.append(get_protocolhostdir_from_url(item))

    csp_imagelinks = list()
    for item in get_list_src_from_tag(full_text, 'img'):
        # CDNs may hide the protocol to allow http and https
        if item is not None:
            if re.search('^(://)', item):
                item = "https" + item
        # If the item starts with / or .. we assume the site is loading a local file, which doesn't need SRI
        if item is None or re.search('^(/.*|\.\.)', item):
            continue
        csp_imagelinks.append(get_protocolhost_from_url(item))

    csp_stylelinks = list()
    sri_stylefiles = list()  # Used in the end of this function
    for item in get_list_src_from_tag(full_text, 'style'):
        # CDNs may hide the protocol to allow http and https
        if item is not None:
            if re.search('^(://)', item):
                item = "https" + item
        # If the item starts with / or .. we assume the site is loading a local file, which doesn't need SRI
        if item is None or re.search('^(/.*|\.\.)', item):
            continue
        sri_stylefiles.append(item)
        csp_stylelinks.append(get_protocolhostdir_from_url(item))

    csp_fontlinks = list()
    for item in get_list_src_from_tag(full_text, 'font'):
        # CDNs may hide the protocol to allow http and https
        if item is not None:
            if re.search('^(://)', item):
                item = "https" + item
        # If the item starts with / or .. we assume the site is loading a local file, which doesn't need SRI
        if item is None or re.search('^(/.*|\.\.)', item):
            continue
        csp_fontlinks.append(get_protocolhostdir_from_url(item))

    # Build CSP header
    # For security reasons, 'unsafe-eval' and 'unsafe-inline' won't be used.
    csp_header = dict()
    csp_header['display'] = "Content-Security-Policy"
    csp_header['source'] = "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
    csp_header['setting'] = "Content-Security-Policy: "
    csp_header['setting'] += "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

    csp_header['setting'] += "; img-src 'self'"
    if csp_imagelinks:
        csp_imagelinks = sorted(set(csp_imagelinks))
        for imagelink in csp_imagelinks:
            csp_header['setting'] += " " + imagelink

    csp_header['setting'] += "; script-src 'self'"
    if csp_scriptlinks:
        csp_scriptlinks = sorted(set(csp_scriptlinks))
        for scriptlink in csp_scriptlinks:
            csp_header['setting'] += " " + scriptlink

    csp_header['setting'] += "; style-src 'self'"
    if csp_stylelinks:
        csp_stylelinks = sorted(set(csp_stylelinks))
        for stylelink in csp_stylelinks:
            csp_header['setting'] += " " + stylelink

    csp_header['setting'] += "; font-src 'self'"
    if csp_fontlinks:
        csp_fontlinks = sorted(set(csp_fontlinks))
        for fontlink in csp_fontlinks:
            csp_header['setting'] += " " + fontlink

    headers['csp'] = csp_header

    # Subresource Integrity
    sri_header = dict()
    sri_header['display'] = "Subresource Integrity"
    sri_header['source'] = "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"
    sri = list()
    if sri_scriptfiles:
        for file in sri_scriptfiles:
            sri_obj = "<script src=\"" + file + "\" " \
                      + "integrity=\"" + get_sri_hash(file) + "\" crossorigin=\"anonymous\"></script>"
            sri.append(sri_obj)

    if sri_stylefiles:
        for file in sri_stylefiles:
            sri_obj = "<link rel=\"stylesheet\" href=\"" + file + "\" " \
                      + "integrity=\"" + get_sri_hash(file) + "\" crossorigin=\"anonymous\">"
            sri.append(sri_obj)

    sri_header['setting'] = sri
    data['headers'] = headers
    data['sri'] = sri_header
    return data


def get_protocolhostdir_from_url(url):
    return os.path.dirname("{0.scheme}://{0.netloc}{0.path}".format(urlsplit(url)))


def get_protocolhost_from_url(url):
    return "{0.scheme}://{0.netloc}".format(urlsplit(url))


def get_list_src_from_tag(html, tag):
    class TagParser(HTMLParser):
        def __init__(self, output_list=None):
            HTMLParser.__init__(self)
            if output_list is None:
                self.output_list = []
            else:
                self.output_list = output_list

        def handle_starttag(self, find_tag, attrs):
            if find_tag == tag:
                self.output_list.append(dict(attrs).get('src'))

    p = TagParser()
    p.feed(html)
    return p.output_list


def check_ssl_tls(host, port):
    # TLS v1.3: https://docs.python.org/3/library/ssl.html#id4

    counter = 0
    attempts = list()
    attempts.append(['SSLv3', ssl.TLSVersion.SSLv3])
    attempts.append(['TLSv1', ssl.TLSVersion.TLSv1])
    attempts.append(['TLSv1.1', ssl.TLSVersion.TLSv1_1])
    attempts.append(['TLSv1.2', ssl.TLSVersion.TLSv1_2])
    attempts.append(['TLSv1.3', ssl.TLSVersion.TLSv1_3])

    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

    data = dict()
    data['display'] = "SSL/TLS"
    data['source'] = "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security"
    data['expected'] = ['TLSv1.2', 'TLSv1.3']    # allowed
    allowed = list()
    denied = list()
    for attempt in attempts:
        ctx.maximum_version = attempt[1]
        try:
            with socket.create_connection((host, port)) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    allowed.append(ssock.version())
        except ssl.SSLError:
            denied.append(attempt[0])
            pass

    for cipher in allowed:
        if cipher not in data['expected']:
            counter -= 1

    data['result'] = dict()
    data['result']['allowed'] = allowed
    data['result']['denied'] = denied

    data['score'] = counter

    if allowed:
        if int(data['score']) >= 0:
            data['pass'] = "pass"
        else:
            data['pass'] = "fail"
    else:
        data['score'] = "Skipped"
        data['pass'] = "skipped"       # One of the reasons is expired TLS certificate
    return data


def check_cert(host, port):
    # Very limited functionality
    # For an extensive work it should use pyOpenSSL or Cryptography (pyCA)

    context = ssl.create_default_context()
    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host, do_handshake_on_connect=False) as ssock:
            data = dict()
            data['display'] = "X.509 Certificate"
            data['source'] = "https://developer.mozilla.org/en-US/docs/Mozilla/Security/x509_Certificates"

            try:
                ssock.do_handshake()
            except ssl.SSLCertVerificationError as e:
                # While testing with expired.badssl.com it became clear that
                # Python itself cannot handle these tests.
                # For version 0.1, HeadCheck will just abort the certificate test.
                # To perform detailed test it should not use ssl module from Python.
                pass
                full_certificate = ""
                data['error'] = dict()
                data['error']['testname'] = 'Error'
                data['error']['result'] = str(e)
                data['error']['score'] = -10
                data['error']['pass'] = 'fail'
            else:
                # Get some information
                full_certificate = ssock.getpeercert()
                subject = dict(x[0] for x in full_certificate['subject'])
                serial = full_certificate['serialNumber']
                issued_to = subject['commonName']
                subject_alt_name = full_certificate['subjectAltName']
                issuer = dict(x[0] for x in full_certificate['issuer'])
                issued_by = issuer['commonName']
                not_before = full_certificate['notBefore']
                not_after = full_certificate['notAfter']
                not_before_date = datetime.strptime(not_before, '%b  %d %H:%M:%S %Y %Z')
                not_after_date = datetime.strptime(not_after, '%b  %d %H:%M:%S %Y %Z')
                today = datetime.now().replace(tzinfo=timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")
                today = datetime.strptime(today, "%Y-%m-%d %H:%M:%S %Z")

                data['ciphers'] = dict()
                data['ciphers']['testname'] = 'Selected ciphers'
                data['ciphers']['result'] = ssock.cipher()
                data['ciphers']['score'] = 0
                data['ciphers']['pass'] = 'info'

                data['issued_to'] = dict()
                altname_list = list()
                if fnmatch.fnmatch(host, issued_to):
                    data['issued_to']['score'] = 0
                    data['issued_to']['pass'] = 'pass'
                else:
                    found = False
                    for altname in subject_alt_name:
                        if fnmatch.fnmatch(host, altname[1]):
                            altname_list.append("<b>" + altname[1] + "</b>")
                            data['issued_to']['score'] = 0
                            data['issued_to']['pass'] = 'pass'
                            found = True
                        else:
                            altname_list.append(altname[1])
                    if not found:
                        data['issued_to']['score'] = -5
                        data['issued_to']['pass'] = 'fail'

                data['issued_to']['testname'] = 'Issued to'
                if altname_list:
                    data['issued_to']['result'] = ', '.join(altname_list)
                else:
                    data['issued_to']['result'] = issued_to

                data['issued_by'] = dict()
                data['issued_by']['testname'] = 'Issued by'
                data['issued_by']['result'] = issued_by
                data['issued_by']['score'] = 0
                data['issued_by']['pass'] = 'info'

                data['not_before'] = dict()
                data['not_before']['testname'] = 'Not Before'
                data['not_before']['result'] = str(not_before_date)
                if (not_before_date - today).days > 0:
                    data['not_before']['score'] = -4  # Certificate date is out of range
                    data['not_before']['pass'] = 'fail'
                else:
                    data['not_before']['score'] = 0
                    data['not_before']['pass'] = 'pass'

                data['not_after'] = dict()
                data['not_after']['testname'] = 'Not After'
                data['not_after']['result'] = str(not_after_date)
                if (today - not_after_date).days > 0:
                    data['not_after']['score'] = -4  # Certificate date is out of range
                    data['not_before']['pass'] = 'fail'
                else:
                    data['not_after']['score'] = 0
                    data['not_after']['pass'] = 'pass'

    return [full_certificate, data]


def check_expect_ct(header):
    if isinstance(header, list):
        header = header[1]

    data = dict()
    data['display'] = "Expect-CT"
    data['source'] = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT"
    data['expected'] = 'enforce, max-age=86400'
    if header:
        # Pre-populate the fields
        data['score'] = 0
        data['result'] = "Unknown"
        m = re.search('max-age="([0-9]{1,8})"', header)
        if m:
            n = re.search('(enforce|report-uri)', header)
            if n:
                if n.group(1) == "enforce":
                    data['score'] = 1
                    data['result'] = "Enforced"
                elif n.group(1) == "report-uri":
                    data['score'] = 1
                    data['result'] = "Report only"
    else:
        data['score'] = 0       # Compatibility is very restricted, so far
        data['result'] = "Not implemented"

    if int(data['score']) >= 0:
        data['pass'] = "pass"
    else:
        data['pass'] = "fail"

    return data


def output_to_stdout(data):
    print_version()
    args.quiet or print(json.dumps(data, indent=4))


def output_to_json(site_report, output_filename):
    with open(output_filename, 'w', encoding='utf-8') as f:
        res = json.dump(site_report, f, ensure_ascii=False, indent=4)
    return res


def output_to_html(site_report, output_filename):
    with open(output_filename, 'w', encoding='utf-8') as f:
        html_doc = generate_html(site_report)
        res = f.write(html_doc)
    args.no_browser or browse_local_html(output_filename)
    return res


def browse_local_html(html_doc):
    import webbrowser
    import os.path
    webbrowser.open("file:///" + os.path.abspath(html_doc))  # elaborated for Mac


def load_from_json(json_filename):
    with open(json_filename, 'r', encoding='utf-8') as f:
        try:
            res = json.loads(f.read())
        except json.decoder.JSONDecodeError:
            args.quiet or print("Could not open {} as JSON data file.".format(json_filename))
            sys.exit(EXIT_FILE_FORMAT)
    return res


def get_data_display_source(data):
    return '<a href =\"' + data['source'] + '">' + data['display'] + '</a>'


def get_data_pass_icon(data):
    if data == 'pass':
        return '<i class="fas fa-check-circle fa text-success"></i>'
    elif data == 'fail':
        return '<i class="fas fa-times-circle fa text-danger"></i>'
    elif data == 'skipped':
        return '<i class="fas fa-exclamation-circle text-warning"></i>'
    else:  # data == "info"
        return '<i class="fas fa-info-circle text-info"></i>'


def get_score(score):
    score_range = {'A': 0, 'B': -2, 'C': -4, 'D': -6, 'E': -8, 'F': -99}
    for k, v in score_range.items():
        if score >= v:
            return k


def generate_html(site_report):
    html_top = """
    <html lang=en>
    <head>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css" 
            integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T" 
            crossorigin="anonymous">
        <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js" 
            integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo" 
            crossorigin="anonymous"></script>
        <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js" 
            integrity="sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM" 
            crossorigin="anonymous"></script>
        <link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.8.1/css/all.css" 
            integrity="sha384-50oBUHEmvpQ+1lW4y57PTFmhCaXp0ML5d60M1M7uH2+nqUivzIebhndOJK28anvf" 
            crossorigin="anonymous">
        <meta charset="utf-8">
        <meta http-equiv="Content-Security-Policy" content="default-src 'self'; 
            object-src 'none'; font-src https://use.fontawesome.com; 
            style-src 'self' 'unsafe-inline'">
        <style>
            .alert-grade {
                padding: 0.1rem 0.6rem;
                margin-bottom: unset;
            }
            .table th.test {
                width: 30%;
            }
            .table th.pass {
                width: 5%;
                text-align: center;
            }
            .table th.score {
                width: 10%;
                text-align: center;
            }
            .table th.result {
                width: 55%;
            }
            .table td.pass {
                text-align: center;
            }
            .table td.score {
                text-align: center;
            }
            
            /* Github triangle */
            .github-corner-svg {
                fill: #151513;
                color: #fff;
                position: absolute;
                top: 0;
                border: 0;
                right: 0;
            }
            
            .octo-arm {
                transform-origin: 130px 106px;
            }
            
            /* Github anim */
            .github-corner:hover .octo-arm {
                animation: octocat-wave 560ms ease-in-out
            }
            @keyframes octocat-wave {
                0%, 100% {
                    transform: rotate(0)
                }
                20%, 60% {
                    transform: rotate(-25deg)
                }
                40%, 80% {
                    transform: rotate(10deg)
                }
            }
            @media (max-width: 500px) {
                .github-corner:hover .octo-arm {
                    animation: none
                }
                .github-corner .octo-arm {
                    animation: octocat-wave 560ms ease-in-out
                }
            }
        </style>
    </head>
    <body>
    <a href="https://github.com/mmartins000/headcheck/" target="_blank" class="github-corner" 
    aria-label="View source on GitHub">
    <svg width="80" height="80" viewBox="0 0 250 250" aria-hidden="true" class="github-corner-svg">
        <path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path>
        <path d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 
        123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2" 
        fill="currentColor" class="octo-arm"></path><path d="M115.0,115.0 C114.9,115.1 118.7,116.5 
        119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 
        C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 
        C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 
        C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 
        C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.5 C139.8,137.7 141.6,141.9 141.8,141.8 Z" 
        fill="currentColor" class="octo-body"></path>
    </svg>
    </a>
    <div class="container">
    <div class="py-5 text-center">
        <i class="fas fa-heading fa-3x"></i>
    """
    html_top += '        <h2>' + site_report['report']['version'] + '</h2>'
    html_top += '<p class="lead">' + site_report['report']['datetime'] + '</p>'
    html_top += '</div> <!-- py-5 -->'

    html_content = '<div class="accordion" id="accordionSites">'

    c = 0   # Counter
    for entry in site_report:
        if entry == 'report':
            continue

        c += 1
        tag_id = "heading" + str(c)
        tag_datatarget = "collapse" + str(c)

        site_grade = site_report[entry]['grade']
        if site_grade in ("A", "B"):
            grade_alert = "alert-success"
        elif site_grade in ("C", "D"):
            grade_alert = "alert-warning"
        else:
            grade_alert = "alert-danger"

        # Begin of each site
        html_content += '<div class="card">'
        html_content += '<div class="card-header d-flex justify-content-between" id="' + tag_id + '">'
        html_content += '<div align = "left">'
        html_content += '  <h2 class="mb-0">'
        html_content += '    <button class="btn btn-link" type="button" data-toggle="collapse"'
        html_content += 'data-target="#' + tag_datatarget + '" aria-expanded="true"'
        html_content += ' aria-controls="' + tag_datatarget + '">'

        html_content += str(re.sub(r'http://|https://', "", entry)).split(':')[0]

        html_content += '    </button>'
        html_content += '  </h2>'
        html_content += '</div>'
        html_content += '<div class="alert alert-grade ' + grade_alert + '" role="alert" align="right">'
        html_content += '  <h2 class="mb-0">' + site_grade + '</h2>'
        html_content += '</div>'
        html_content += '</div> <!-- card-header end -->'

        html_content += '<div id="' + tag_datatarget + '" class="collapse show" aria-labelledby="' + tag_id + '"'
        html_content += 'data-parent="#accordionSites">'
        html_content += '  <div class="card-body">'

        # Begin of Navbar
        html_content += '<nav>'
        html_content += '  <div class="nav nav-tabs" id="nav-tab' + str(c) + '" role="tablist">'
        html_content += '    <a class="nav-item nav-link active" id="tablinkAssessment' + str(c) + '" data-toggle="tab"'
        html_content += '    href="#tabAssessment' + str(c) + '" role="tab" aria-controls="tabAssessment' + str(c) + '"'
        html_content += '                aria-selected="true">Evaluation</a>'
        html_content += '    <a class="nav-item nav-link" id="tablinkRawData' + str(c)
        html_content += '        " data-toggle="tab" href="#tabRawData' + str(c) + '"'
        html_content += '        role="tab" aria-controls="tabRawData' + str(c) + '" aria-selected="true">Raw Data</a>'
        html_content += '    <a class="nav-item nav-link" id="tablinkRec' + str(c)
        html_content += '        " data-toggle="tab" href="#tabRec' + str(c) + '"'
        html_content += '        role="tab" aria-controls="tabRec' + str(c) + '" aria-selected="true">Recommendation</a>'
        html_content += '  </div>'
        html_content += '</nav>'

        html_content += '<div class="tab-content" id="myTabContent' + str(c) + '">'

        # Begin of Evaluation tab
        html_content += '  <div class="tab-pane fade show active" id="tabAssessment' + str(c) + '" role="tabpanel"'
        html_content += '    aria-labelledby="tablinkAssessment' + str(c) + '">'
        html_content += '    <br>'
        html_content += '    <p><i class="fas fa-clock"></i> ' + str(site_report[entry]['datetime'])
        html_content += '    &nbsp&nbsp <i class="fas fa-stopwatch"></i> '
        str_duration = str(timedelta(seconds=int(site_report[entry]['duration'])))
        html_content += str_duration
        html_content += '    </p>'

        # Begin of tests section
        for section in site_report[entry]['tests']:
            if section in ("grade", "score", "display", "source", "source2"):
                continue

            html_content += '     <h3>' + get_data_display_source(site_report[entry]['tests'][section]) + '</h3>'
            html_content += """
                <table class="table table-hover">
                  <thead>
                    <tr>
                      <th scope="col" class="test">Test</th>
                      <th scope="col" class="pass">Pass</th>
                      <th scope="col" class="score">Score</th>
                      <th scope="col" class="result">Result</th>
                    </tr>
                  </thead>
                  <tbody>
            """

            if section == "headers":
                headers = site_report[entry]['tests'][section].keys()
                for key in headers:
                    if key in ("display", "source", "source2", "expected"):
                        continue

                    value_pass = site_report[entry]['tests'][section][key]['pass']
                    value_score = site_report[entry]['tests'][section][key]['score']
                    value_result = site_report[entry]['tests'][section][key]['result']

                    html_content += '        <tr>'
                    html_content += '           <th scope="row">' + \
                                    get_data_display_source(site_report[entry]['tests'][section][key]) + '</th>'
                    html_content += '           <td class="pass">' + get_data_pass_icon(value_pass) + '</td>'
                    html_content += '           <td class="score">' + str(value_score) + '</td>'
                    if key in "Set-Cookie":
                            html_content += '           <td> Set-Cookie: ' + \
                                            '<br>Set-Cookie: '.join(value_result) + '</td>'
                    elif key in "Content-Security-Policy":
                        try:
                            positive = value_result['positive']
                            if not positive:
                                positive = ["None"]
                            negative = value_result['negative']
                            if not negative:
                                negative = ["None"]
                            html_content += '           <td>' + '<b>Positive:</b> ' + ', '.join(positive) + \
                                            '; <br><b>Negative:</b> ' + ', '.join(negative) + '</td>'
                        except TypeError:
                            html_content += '           <td>' + str(value_result) + '</td>'
                    else:
                        html_content += '           <td>' + str(value_result) + '</td>'
                    html_content += '        </tr>'

            elif section != "certificate":  # also, section != headers
                value_pass = site_report[entry]['tests'][section]['pass']
                value_score = site_report[entry]['tests'][section]['score']
                value_result = site_report[entry]['tests'][section]['result']

                if section == "methods":
                    html_content += '        <tr>'
                    html_content += '           <th scope="row">' + "Methods" + '</th>'
                    html_content += '           <td class="pass">' + get_data_pass_icon(value_pass) + '</td>'
                    html_content += '           <td class="score">' + str(value_score) + '</td>'
                    found = value_result['found_methods']
                    if not found:
                        found = ["None"]
                    not_recommended = value_result['not_recommended']
                    if not not_recommended:
                        not_recommended = ["None"]
                    html_content += '           <td>' + '<b>Found:</b> ' + ', '.join(found) + \
                                    '; <br><b>Not recommended:</b> ' + ', '.join(not_recommended) + '</td>'
                    html_content += '        </tr>'

                elif section == "ssl_tls":
                    html_content += '        <tr>'
                    html_content += '           <th scope="row">' + "Ciphers" + '</th>'
                    html_content += '           <td class="pass">' + get_data_pass_icon(value_pass) + '</td>'
                    html_content += '           <td class="score">' + str(value_score) + '</td>'
                    allowed = value_result['allowed']
                    if not allowed:
                        allowed = ["None"]
                    denied = value_result['denied']
                    if not denied:
                        denied = ["None"]
                    expected = site_report[entry]['tests'][section]['expected']
                    if not expected:
                        expected = ["None"]
                    html_content += '           <td>' + '<b>Allowed:</b> ' + ', '.join(allowed) + \
                                    '; <br><b>Denied:</b> ' + ', '.join(denied) + \
                                    '; <br><b>Expected:</b> ' + ', '.join(expected) + '</td>'
                    html_content += '        </tr>'

                elif section == "http_redir":
                    html_content += '        <tr>'
                    html_content += '           <th scope="row">HTTPS Redirect</th>'
                    html_content += '           <td class="pass">' + get_data_pass_icon(value_pass) + '</td>'
                    html_content += '           <td class="score">' + str(value_score) + '</td>'
                    html_content += '           <td>' + str(value_result) + '</td>'
                    html_content += '        </tr>'

                elif section == "sri":
                    html_content += '        <tr>'
                    html_content += '           <th scope="row">SRI Check</th>'
                    html_content += '           <td class="pass">' + get_data_pass_icon(value_pass) + '</td>'
                    html_content += '           <td class="score">' + str(value_score) + '</td>'
                    valid = value_result['valid']
                    if not valid:
                        valid = ["None"]
                    invalid = value_result['invalid']
                    if not invalid:
                        invalid = ["None"]
                    missing = value_result['missing']
                    if not missing:
                        missing = ["None"]
                    html_content += '           <td>' + '<b>Valid:</b> ' + ', '.join(valid) + \
                                    '; <br><b>Invalid:</b> ' + ', '.join(invalid) + \
                                    '; <br><b>Missing:</b> ' + ', '.join(missing) + '</td>'
                    html_content += '        </tr>'

            else:  # section == "certificate"
                cert_keys = site_report[entry]['tests']['certificate'].keys()
                for key in cert_keys:
                    if key in ("display", "source", "source2", "expected"):
                        continue

                    value_testname = site_report[entry]['tests']['certificate'][key]['testname']
                    value_pass = site_report[entry]['tests']['certificate'][key]['pass']
                    value_score = site_report[entry]['tests']['certificate'][key]['score']
                    value_result = site_report[entry]['tests']['certificate'][key]['result']

                    html_content += '        <tr>'
                    html_content += '           <th scope="row">' + value_testname + '</th>'
                    html_content += '           <td class="pass">' + get_data_pass_icon(value_pass) + '</td>'
                    html_content += '           <td class="score">' + str(value_score) + '</td>'
                    html_content += '           <td>' + str(value_result) + '</td>'
                    html_content += '        </tr>'

            # End of section

            html_content += """
                  </tbody>
                </table>
            """

        html_content += '  </div> <!-- tabAssessment end -->'
        # End of Evaluation tab

        ######################
        # Begin of RawData tab
        html_content += '<div class="tab-pane fade" id="tabRawData' + str(c) + '"'
        html_content += '   role="tabpanel" aria-labelledby="tablinkRawData' + str(c) + '">'
        html_content += '<br>'

        for section in site_report[entry]['raw_data']:
            try:
                html_content += '        <h3>' + get_data_display_source(site_report[entry]['raw_data'][section]) \
                                + '</h3>'
                html_content += '<pre><code>'
                html_content += json.dumps(site_report[entry]['raw_data'][section]['data'], indent=4,
                                           ensure_ascii=False)
                html_content += '</code></pre>'
            except AttributeError:
                pass

        html_content += """
          </div> <!-- tabRawData end -->
        """
        # End of RawData tab

        #############################
        # Begin of Recommendation tab
        html_content += '<div class="tab-pane fade" id="tabRec' + str(c) + '"'
        html_content += '   role="tabpanel" aria-labelledby="tablinkRec' + str(c) + '">'
        html_content += '<br>'

        # Begin of sections
        # Begin Warning alert
        if not args.no_warning:
            html_content += """
            <div class="alert alert-warning alert-dismissible fade show" role="alert">
                <strong>Warning!</strong>
            """
            html_content += site_report[entry]['recommendation']['disclaimer']
            html_content += """
                <button type="button" class="close" data-dismiss="alert" aria-label="Close">
                    <span aria-hidden="true">&times;</span>
                </button>
            </div>
            """
        # End Warning alert

        for section in site_report[entry]['recommendation']:
            if section in ("grade", "score", "display", "source", "source2", "disclaimer"):
                continue

            html_content += '     <h3>' + get_data_display_source(
                site_report[entry]['recommendation'][section]) + '</h3>'
            html_content += """
                <table class="table table-hover">
                  <thead>
                    <tr>
                      <th scope="col" class="test">Test</th>
                      <th scope="col" class="result">Recommended Settings</th>
                    </tr>
                  </thead>
                  <tbody>
            """

            if section == "methods":
                value_setting = site_report[entry]['recommendation'][section]['setting']
                html_content += '        <tr>'
                html_content += '           <th scope="row">' + "Methods" + '</th>'
                html_content += '           <td>' + ', '.join(value_setting) + '</td>'
                html_content += '        </tr>'

            elif section == "headers":
                headers = site_report[entry]['recommendation'][section].keys()
                for key in headers:
                    if key in ("display", "source", "source2", "expected"):
                        continue
                    elif key == "set-cookie":
                        value_setting = site_report[entry]['recommendation'][section][key]['setting']

                        # Adds the horizontal rule (<hr>) after each cookie in the list
                        # This is just for display purposes, used below in this section of code.
                        list_len = len(value_setting) - 1
                        for index, x in enumerate(value_setting):
                            if index != list_len:
                                value_setting[index] = value_setting[index] + '<hr>'
                        # End

                        html_content += '        <tr>'
                        html_content += '           <th scope="row">' + \
                                        get_data_display_source(
                                            site_report[entry]['recommendation'][section][key]) + '</th>'
                        html_content += '           <td>Set-Cookie: ' + \
                                        'Set-Cookie: '.join(value_setting) + '</td>'
                        html_content += '        </tr>'
                    else:
                        value_setting = site_report[entry]['recommendation'][section][key]['setting']

                        html_content += '        <tr>'
                        html_content += '           <th scope="row">' + \
                                        get_data_display_source(
                                            site_report[entry]['recommendation'][section][key]) + '</th>'
                        html_content += '           <td>' + str(value_setting) + '</td>'
                        html_content += '        </tr>'

            elif section == "sri":
                value_setting = site_report[entry]['recommendation'][section]['setting']
                if not value_setting:
                    value_setting = ["None"]
                escaped_value_setting = list()
                for item in value_setting:
                    escaped_value_setting.append(html.escape(item))
                html_content += '        <tr>'
                html_content += '           <th scope="row">SRI Check</th>'
                html_content += '           <td>' + '<br>'.join(escaped_value_setting) + '</td>'
                html_content += '        </tr>'

            # End of section

            html_content += """
                  </tbody>
                </table>
            """

        html_content += """
          </div> <!-- tabRec end -->
        """
        # End of Recommendation tab

        html_content += """
        </div> <!-- myTabContent end -->
        """

        # End of site
        html_content += '  </div> <!-- card-body end -->'
        html_content += '</div> <!-- collapse end -->'
        html_content += '</div> <!-- card end -->'

    html_bottom = """
    <p><br></p>
    </div> <!-- accordion end -->
    </div> <!-- container end -->
    </body>
    </html>
    """

    html_doc = html_top + html_content + html_bottom
    return html_doc


def get_method_and_headers(address):
    well_known_methods = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH']
    found_methods = list()
    full_header = dict()
    full_text = ''
    cookiejar = ''

    try:
        # Get Methods
        req_methods = requests.options(address)
        if req_methods.status_code == 204:
            found_methods.append(req_methods.headers['Allow'])
        else:
            for method in well_known_methods:
                rc = requests.request(method, address)
                if rc.status_code == 200:
                    found_methods.append(method)
                    # Get Headers
                    if method == 'GET':
                        full_header = json.loads(json.dumps(rc.headers.__dict__['_store']))
                        full_text = rc.text
                        cookiejar = rc.cookies

    except requests.exceptions.ConnectionError as e:
        pass

    return found_methods, full_header, full_text, cookiejar


def check_methods(methods):
    # well_known_methods = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH']
    recommended = ['GET', 'HEAD', 'POST']

    counter = 0
    data = dict()
    data['display'] = "HTTP Methods"
    data['source'] = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods"
    # found_methods = list()
    not_recommended = list()

    for method in methods:
        if method in recommended:
            continue
        else:
            counter -= 1
            not_recommended.append(method)

    if not not_recommended:
        not_recommended = ['None']
    # if not methods:
    #     found_methods = ['None']
    data['result'] = dict()
    data['result']['found_methods'] = methods
    data['result']['not_recommended'] = not_recommended
    data['score'] = counter

    if methods != not_recommended:
        if int(data['score']) >= 0:
            data['pass'] = "pass"
        else:
            data['pass'] = "fail"
    else:
        data['score'] = "Skipped"
        data['pass'] = "skipped"
    return data


def check_header(full_header, address):
    data = dict()
    data['display'] = "HTTP Headers"
    data['source'] = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers"
    try:
        # Main Checks
        # It seems that 'Expect-CT' is supported only by Google Chrome
        # Not important: 'X-XSS-Protection' is used by Internet Explorer. For the others, CSP
        res = re.search('(Access-Control-Allow-Origin)', str(full_header), re.IGNORECASE)
        if res:
            data['Access-Control-Allow-Origin'] = check_origin(full_header[res.group(1)], address)
        else:
            data['Access-Control-Allow-Origin'] = check_origin("", address)

        res = re.search('(Content-Security-Policy)', str(full_header), re.IGNORECASE)
        if res:
            data['Content-Security-Policy'] = check_csp(full_header[res.group(1)])
        else:
            data['Content-Security-Policy'] = check_csp("")

        res = re.search('(Expect-CT)', str(full_header), re.IGNORECASE)
        if res:
            data['Expect-CT'] = check_expect_ct(full_header[res.group(1)])
        else:
            data['Expect-CT'] = check_expect_ct("")

        if not args.no_check_version:
            res = re.search('(Server)', str(full_header), re.IGNORECASE)
            if res:
                data['Server'] = check_server_version(full_header[res.group(1)])
            else:
                data['Server'] = check_server_version("")

        res = re.search('(Strict-Transport-Security)', str(full_header), re.IGNORECASE)
        if res:
            data['Strict-Transport-Security'] = check_sts(full_header[res.group(1)])
        else:
            data['Strict-Transport-Security'] = check_sts("")

        res = re.search('(X-Content-Type-Options)', str(full_header), re.IGNORECASE)
        if res:
            data['X-Content-Type-Options'] = check_xcont(full_header[res.group(1)])
        else:
            data['X-Content-Type-Options'] = check_xcont("")

        res = re.search('(X-Frame-Options)', str(full_header), re.IGNORECASE)
        if res:
            data['X-Frame-Options'] = check_xframe(full_header[res.group(1)])
        else:
            data['X-Frame-Options'] = check_xframe("")

        res = re.search('(X-XSS-Protection)', str(full_header), re.IGNORECASE)
        if res:
            data['X-XSS-Protection'] = check_xxss(full_header[res.group(1)])
        else:
            data['X-XSS-Protection'] = check_xxss("")

        # Optional Checks
        res = re.search('(Public-Key-Pins)', str(full_header), re.IGNORECASE)
        if res:
            data['Public-Key-Pins'] = check_pkp(full_header[res.group(1)])
        else:
            data['Public-Key-Pins'] = check_pkp("")

        res = re.search('(Referrer-Policy)', str(full_header), re.IGNORECASE)
        if res:
            data['Referrer-Policy'] = check_referrer(full_header[res.group(1)])
        else:
            data['Referrer-Policy'] = check_referrer("")
    except KeyError as e:
        args.quiet or print("check_header(): Error while trying to access", e)
        pass

    return data


def main():
    args.version and print_version() and sys.exit(EXIT_OK)
    check_sanity()  # Includes exit() functions
    site_list = []
    if args.inputScan:
        site_list = input_list(args.inputScan)
    elif args.hostScan:
        site_list = [].append(args.hostScan)
    elif not args.loadFile:
        print("You must use -s, -i or -l to proceed.") and sys.exit(EXIT_ERROR)

    data = dict()
    if not args.loadFile:
        # General information about this execution
        data['report'] = dict()
        data['report']['version'] = "HeadCheck v{}".format(__version__)
        data['report']['format'] = "1"  # Reserved
        data['report']['source'] = "https://github.com/mmartins000/headcheck"
        start = datetime.now().replace(tzinfo=timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")
        data['report']['datetime'] = start
        data['report']['duration'] = ''     # Placeholder
        for entry in site_list:
            # Move on if the entry is empty, has been commented out or is too small
            if not entry or entry.lstrip(' ')[0] == "#" or len(entry.strip(' ')) <= 5:
                continue

            # If the entry has a comment after the website address
            entry = entry.split('#')[0]
            entry = entry.rstrip('/')

            protocol, host, port = split_protocol_host_port(entry)
            # If the entry is understandable
            if check_protocol(protocol) and (check_domain(host) or check_ip(host)) and check_port(port):
                # Is it there?
                if not args.no_check_connection:
                    if not check_connection(address=entry):
                        continue

                site_counter = 0
                site_start = datetime.now().replace(tzinfo=timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")
                args.quiet or print("Evaluating {}".format(host))
                data[entry] = dict()
                # Placeholders
                data[entry]['datetime'] = site_start
                data[entry]['duration'] = ''
                data[entry]['score'] = ''
                data[entry]['grade'] = ''
                data[entry]['tests'] = dict()
                data[entry]['raw_data'] = dict()
                data[entry]['recommendation'] = dict()

                methods, full_header, full_text, cookiejar = get_method_and_headers(address=entry)
                # Security Tests
                if not args.no_check_methods:
                    # res = get_eval_methods(address=entry)
                    res = check_methods(methods)
                    data[entry]['tests']['methods'] = res
                    if isinstance(res['score'], int):
                        site_counter += res['score']

                if not (args.no_check_headers and args.no_check_metatags and args.no_check_sri):
                    # result = get_header(address=entry)
                    # full_header = result[0]
                    # full_text = result[1]

                    if not args.no_check_headers:
                        data[entry]['raw_data']['headers'] = dict()
                        data[entry]['raw_data']['headers']['display'] = 'HTTP Headers'
                        data[entry]['raw_data']['headers']['source'] = \
                            'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers'
                        data[entry]['raw_data']['headers']['data'] = full_header
                        if "SSLError" not in full_header:
                            data[entry]['tests']['headers'] = check_header(full_header=full_header, address=entry)
                            data[entry]['tests']['headers']['Set-Cookie'] = check_cookie(cookiejar)

                            # Calculates the score for every header check
                            for key in data[entry]['tests']['headers']:
                                if key in ("display", "source"):
                                    continue
                                if isinstance(data[entry]['tests']['headers'][key]['score'], int):
                                    site_counter += data[entry]['tests']['headers'][key]['score']

                    if not args.no_check_metatags:
                        res_meta = check_html_meta_tags(full_text=full_text)
                        try:
                            if res_meta['result']:
                                data[entry]['tests']['meta_tags'] = res_meta
                        except KeyError:
                            pass

                    if not args.no_check_sri:
                        res_sri = check_sri(full_text=full_text, address=entry)
                        try:
                            if res_sri['result']:
                                data[entry]['tests']['sri'] = res_sri
                        except KeyError:
                            pass

                    if not args.no_recommendation:
                        data[entry]['recommendation'] = \
                            create_recommendation(full_text=full_text, full_header=full_header, address=entry,
                                                  cookielist=data[entry]['tests']['headers']['Set-Cookie']['result'])

                if not args.no_check_tls:
                    res = check_ssl_tls(host=host, port=port)
                    data[entry]['tests']['ssl_tls'] = res
                    if isinstance(res['score'], int):
                        site_counter += res['score']

                if not args.no_check_certificate:
                    res = check_cert(host=host, port=port)
                    full_certificate = res[0]
                    certificate_test = res[1]
                    data[entry]['tests']['certificate'] = certificate_test
                    data[entry]['raw_data']['certificate'] = dict()
                    data[entry]['raw_data']['certificate']['display'] = 'X.509 Certificate'
                    data[entry]['raw_data']['certificate']['source'] = \
                        'https://developer.mozilla.org/en-US/docs/Mozilla/Security/x509_Certificates'
                    data[entry]['raw_data']['certificate']['data'] = full_certificate
                    for key in data[entry]['tests']['certificate']:
                        if key in ("display", "source", "source2", "expected"):
                            continue
                        if isinstance(data[entry]['tests']['certificate'][key]['score'], int):
                            site_counter += data[entry]['tests']['certificate'][key]['score']

                if not args.no_check_httpredir:
                    res = check_http_redir(host=host)
                    data[entry]['tests']['http_redir'] = res
                    if isinstance(res['score'], int):
                        site_counter += res['score']

                # Optional Tests
                if not args.no_check_optional:
                    data[entry]['raw_data']['securitytxt'] = dict()
                    data[entry]['raw_data']['securitytxt']['display'] = 'Securitytxt'
                    data[entry]['raw_data']['securitytxt']['source'] = 'https://securitytxt.org/'
                    data[entry]['raw_data']['securitytxt']['data'] = check_securitytxt(address=entry)
                    data[entry]['raw_data']['contribute'] = dict()
                    data[entry]['raw_data']['contribute']['display'] = 'Contribute.json'
                    data[entry]['raw_data']['contribute']['source'] = 'https://www.contributejson.org/'
                    data[entry]['raw_data']['contribute']['data'] = check_contribute(address=entry)

                data[entry]['score'] = site_counter
                data[entry]['grade'] = get_score(score=site_counter)

                site_finish = datetime.now().replace(tzinfo=timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")
                site_start_time = datetime.strptime(site_start, "%Y-%m-%d %H:%M:%S %Z")
                site_finish_time = datetime.strptime(site_finish, "%Y-%m-%d %H:%M:%S %Z")
                data[entry]['duration'] = abs((site_finish_time - site_start_time).seconds)

            elif not check_protocol(protocol):
                print("Error: Could not find or understand protocol for", entry)
            elif not (check_domain(host) and check_ip(host)):
                print("Error: Could not find or understand domain or IP address for", entry)
            elif not check_port(port):
                print("Error: Could not find or understand port for", entry)

        finish = datetime.now().replace(tzinfo=timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")
        start_time = datetime.strptime(start, "%Y-%m-%d %H:%M:%S %Z")
        finish_time = datetime.strptime(finish, "%Y-%m-%d %H:%M:%S %Z")
        data['report']['duration'] = abs((finish_time - start_time).seconds)

        args.json and output_to_json(data, args.json)
        args.report and output_to_html(data, args.report)
        (args.json or args.report) or output_to_stdout(data)
    else:
        # Loading existing JSON file from HeadCheck to generate HTML report
        args.quiet or print("Skipping tests. HTML report will be generated from {}.".format(args.loadFile))
        output_to_html(load_from_json(args.loadFile), args.report)

    args.quiet or print("Done in", data['report']['duration'], "seconds.")


if __name__ == "__main__":
    main()
