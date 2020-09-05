#!/usr/bin/env python3
import requests


def fetchVirusTotal(domain):
    '''
    string -> list

    This function queries Virus Total to look for domain names.

    Input  : fetchThreatCrowd("tropyl.com")
    Output : ['tropyl.com', 'www.tropyl.com']

    '''
    subdomain = []

    fetchURL = requests.get(
        "https://www.virustotal.com/ui/domains/%s/subdomains" % (domain))

    jsonResponse = fetchURL.json()

    for i in jsonResponse["data"]:
        if i["type"] == 'domain':
            subdomain.append(i['id'])

    return(subdomain)
