#!/usr/bin/env python3
'''
Copyright (C) 2020, DomFu Contributors.
See the LICENSE.txt file for copying permission.
'''

import requests
from fake_useragent import UserAgent


def fetchBufferOverRun(domain):
    '''
    string -> list

    This function queries bufferover.run to look for domain names.

    Input  : fetchBufferOverRun("tropyl.com")
    Output : ['tropyl.com', 'www.tropyl.com']

    '''

    subdomain = []
    headers = {'User-Agent': UserAgent().random}

    proxies = {
        'http': 'socks5://127.0.0.1:9050',
        'https': 'socks5://127.0.0.1:9050'
    }

    fetchURL = requests.get(
        "https://dns.bufferover.run/dns?q=.%s" % (domain), headers=headers)

    jsonResponse = fetchURL.json()
    subdomainlst = jsonResponse['FDNS_A']

    if subdomainlst != None:
        for dom in subdomainlst:
            front, mid, end = dom.partition(",")
            subdomain.append(end)

    subdomain = sorted(set(subdomain))

    if subdomain != None:
        return(subdomain)
