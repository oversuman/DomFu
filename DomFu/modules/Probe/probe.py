#!/usr/bin/env python3
'''
list -> list

This Prober cehcks if a domain is working or not.

Input: ['tropyl.com', 'www.tropyl.com', 'fake.tropyl.com']
Output: ['tropyl.com', 'www.tropyl.com']

Copyright (C) 2020, DomFu Contributors.
See the LICENSE.txt file for copying permission.
'''

import requests
from threading import *

global subdomain
subdomain = []

proxies = {
    'http': 'socks5://127.0.0.1:9050',
    'https': 'socks5://127.0.0.1:9050'
}


def Probe(subdomainList):
    jobs = []
    for domain in subdomainList:
        thread = Thread(target=probe_test, args=(domain,))
        jobs.append(thread)

    for job in jobs:
        job.start()

    for job in jobs:
        job.join()

    return(subdomain)


def probe_test(domain):
    tt = 5

    try:
        # Http ----->
        http_url = 'http://' + '{d}'.format(d=domain)
        http_res = requests.head(
            http_url, timeout=tt, proxies=proxies)

        if http_res.status_code == 200 or http_res.status_code == 301 or http_res.status_code == 302:
            subdomain.append(domain)
            return(None)

        # Https ---->
        https_url = 'https://' + '{d}'.format(d=domain)
        https_res = requests.head(
            https_url, timeout=tt, proxies=proxies)

        if https_res.status_code == 200 or https_res.status_code == 301 or https_res.status_code == 302:
            subdomain.append(domain)
            return(None)

    except:
        pass

    return(None)
