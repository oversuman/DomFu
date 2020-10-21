#!/usr/bin/env python3
'''
Copyright (C) 2020, DomFu Contributors.
See the LICENSE.txt file for copying permission.
'''

import requests
from fake_useragent import UserAgent


def fetchHackerTarget(domain):
    '''
    string -> list

    This function queries Hacker Target to look for domain names.

    Input  : fetchHackerTarget("tropyl.com")
    Output : ['tropyl.com', 'www.tropyl.com']

    '''

    subdomainlst = []
    headers = {'User-Agent': UserAgent().random}

    fetchURL = requests.get(
        "https://api.hackertarget.com/hostsearch/?q=%s" % (domain), headers=headers).text

    if 'error' not in fetchURL:
        subdomains = str(fetchURL)
        subdomains = subdomains.split()

        for dom in subdomains:
            front, mid, end = dom.partition(",")
            subdomainlst.append(front)

        if subdomainlst != None:
            return(subdomainlst)
