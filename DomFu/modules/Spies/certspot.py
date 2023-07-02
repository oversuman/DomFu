#!/usr/bin/env python3
'''
Copyright (C) 2020, DomFu Contributors.
See the LICENSE.txt file for copying permission.
'''

import requests


def fetchCertSpot(domain):
    '''
    string -> list

    This function queries CertSpotter to look for domain names.

    Input  : fetchCertSpot("tropyl.com")
    Output : ['tropyl.com', 'www.tropyl.com']
    '''
    try:
        subdomains = []

        fetchURL = requests.get(
            "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names".format(domain=domain), timeout=25)
        jsonResponse = fetchURL.json()

        for item in jsonResponse:
            for sub in item['dns_names']:
                if domain in sub:
                    if sub not in subdomains:
                        subdomains.append(sub)

        return (subdomains)

    except:
        pass
