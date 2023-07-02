#!/usr/bin/env python3
'''
Copyright (C) 2020, DomFu Contributors.
See the LICENSE.txt file for copying permission.
'''

import requests
import re


def fetchWebArchive(domain):
    '''
    string -> list

    This function queries fetchWebArchive to look for domain names.

    Input  : fetchWebArchive("tropyl.com")
    Output : ['tropyl.com', 'www.tropyl.com']
    '''
    try:
        subdomains = []
        
        fetchURL = requests.get(
            "https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=txt&fl=original&collapse=urlkey".format(domain=domain), timeout=10).text
        
        fetchURL = fetchURL.split('\n')
        
        pattern = re.compile("https?://([\w.-]+)")
        
        for domain in fetchURL:
            match = re.findall(pattern, domain)
            
            if match:
                subdomains.append(match[0])
             
        subdomains = sorted(set(subdomains))
        return(subdomains)
    
    except:
        pass