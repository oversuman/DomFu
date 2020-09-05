#!/usr/bin/env python3
import requests


def fetchCrtSh(domain):
    '''
    string -> list

    This function queries crt.sh to look for domain names in SSL cert issued by the organization.

    Input  : fetchCrtSh("tropyl.com")
    Output : ['tropyl.com', 'www.tropyl.com']
    '''
    subdomains = []

    fetchURL = requests.get(
        "https://crt.sh/?q=%.{d}&output=json".format(d=domain))

    if fetchURL.status_code == 200:
        for (key, value) in enumerate(fetchURL.json()):
            if '@' not in value['name_value']:
                subdomains.append(value['name_value'])

        subdomains = sorted(set(subdomains))

        return(subdomains)
