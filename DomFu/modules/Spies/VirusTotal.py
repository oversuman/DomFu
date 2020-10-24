#!/usr/bin/env python3
'''
Copyright (C) 2020, DomFu Contributors.
See the LICENSE.txt file for copying permission.
'''

import requests


def fetchVirusTotal(domain):
    '''
    string -> list

    This function queries Virus Total to look for domain names.

    Input  : fetchThreatCrowd("tropyl.com")
    Output : ['tropyl.com', 'www.tropyl.com']

    '''
    subdomain = []
    session = requests.Session()
    url = 'https://www.virustotal.com/ui/domains/{d}/subdomains'
    formaturl = url.format(d=domain)

    try:
        resp = session.get(
            formaturl, timeout=25).json()
    except:
        return(subdomain)

    if 'error' in resp:
        return(subdomain)

    if 'links' in resp and 'next' in resp['links']:
        formaturl = resp['links']['next']
    else:
        formaturl = ''

    try:
        for i in resp['data']:
            if i['type'] == 'domain':
                subdom = i['id']
                if not subdom.endswith(domain):
                    continue
                else:
                    subdomain.append(subdom)

    except Exception:
        pass

    return(subdomain)
