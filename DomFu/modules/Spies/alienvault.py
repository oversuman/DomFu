#!/usr/bin/env python3
'''
Copyright (C) 2020, DomFu Contributors.
See the LICENSE.txt file for copying permission.
'''

import requests


def fetchAlienv(domain):
    '''
    string -> list

    This function queries AlienVault to look for domain names.

    Input  : fetchAlienv("tropyl.com")
    Output : ['tropyl.com', 'www.tropyl.com']
    '''
    try:
        subdomains = []

        fetchURL = requests.get(
            "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns".format(domain=domain), timeout=25)
        jsonResponse = fetchURL.json()

        for item in jsonResponse['passive_dns']:
            sub = item['hostname']
            if sub not in subdomains:
                subdomains.append(sub)

        return (subdomains)

    except:
        pass
