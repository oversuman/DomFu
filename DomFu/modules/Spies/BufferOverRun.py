#!/usr/bin/env python3
import requests


def fetchBufferOverRun(domain):
    '''
    string -> list

    This function queries bufferover.run to look for domain names.

    Input  : fetchBufferOverRun("tropyl.com")
    Output : ['tropyl.com', 'www.tropyl.com']

    '''

    subdomain = []

    fetchURL = requests.get(
        "https://dns.bufferover.run/dns?q=.%s" % (domain))

    jsonResponse = fetchURL.json()
    subdomainlst = jsonResponse['FDNS_A']

    if subdomainlst != None:
        for dom in subdomainlst:
            front, mid, end = dom.partition(",")
            subdomain.append(end)

    subdomain = sorted(set(subdomain))

    if subdomain != None:
        return(subdomain)
