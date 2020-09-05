#!/usr/bin/env python3
import requests


def fetchThreatCrowd(domain):
    '''
    string -> list

    This function queries Threat Crowd to look for domain names.

    Input  : fetchThreatCrowd("tropyl.com")
    Output : ['tropyl.com', 'www.tropyl.com']

    '''
    fetchURL = requests.get(
        "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s" % (domain))
    jsonResponse = fetchURL.json()

    if int(jsonResponse["response_code"]) == 1:
        subdomains = jsonResponse["subdomains"]
        return(subdomains)
