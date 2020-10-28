#!/usr/bin/env python3
'''
Copyright (C) 2020, DomFu Contributors.
See the LICENSE.txt file for copying permission.
'''

import requests


def fetchShodan(domain, api):
    '''
    string -> list

    This function queries Shodan to look for domain names.

    Input  : fetchShodan("tropyl.com")
    Output : ['tropyl.com', 'www.tropyl.com']
    '''
    subdomains = []

    fetchURL = requests.get(
        'https://api.shodan.io/dns/domain/' + domain + '?key=' + api)

    jsonResponse = fetchURL.json()
    subdomainlst = jsonResponse['subdomains']

    if subdomainlst != None:
        for dom in subdomainlst:
            dom_new = dom + '.' + domain
            subdomains.append(dom_new)

    if subdomains != None:
        return(subdomains)
