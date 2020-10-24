#!/usr/bin/env python3
'''
Copyright (C) 2020, DomFu Contributors.
See the LICENSE.txt file for copying permission.
'''

import requests


def fetchChaos(domain, api):
    '''
    string -> list

    This function queries Chaos to look for domain names.

    Input  : fetchChaos("tropyl.com")
    Output : ['tropyl.com', 'www.tropyl.com']
    '''
    subdomains = []

    headers = {'Authorization': api}

    fetchURL = requests.get(
        "https://dns.projectdiscovery.io/dns/{d}/subdomains".format(d=domain), headers=headers)

    jsonResponse = fetchURL.json()
    subdomainlst = jsonResponse['subdomains']

    if subdomainlst != None:
        for dom in subdomainlst:
            dom_new = dom + '.' + domain
            subdomains.append(dom_new)

    if subdomains != None:
        return(subdomains)
