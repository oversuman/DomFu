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
    timeout = 25
    session = requests.Session()
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.8',
        'Accept-Encoding': 'gzip',
    }
    url = 'https://www.virustotal.com/ui/domains/{d}/subdomains'
    formaturl = url.format(d=domain)

    try:
        resp = session.get(
            formaturl, headers=headers, timeout=25).json()
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
