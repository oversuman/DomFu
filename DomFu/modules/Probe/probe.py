#!/usr/bin/env python3
import requests
import socket


def Probe(subdomainList):
    subdomain = []
    for domain in subdomainList:
        try:
            ret = probe_test(domain)
            if ret is not None:
                subdomain.append(ret)
        except:
            pass

    return(subdomain)


def probe_test(domain):
    try:
        socket.gethostbyname(domain)
        dom_valid = True
    except:
        dom_valid = False

    if dom_valid:
        # Http ----->
        http_url = 'http://' + '{d}'.format(d=domain)
        http_res = requests.get(http_url, timeout=5)

        if http_res.status_code == 200 or http_res.status_code == 301 or http_res.status_code == 302:
            return(domain)

        # Https ---->
        https_url = 'https://' + '{d}'.format(d=domain)
        https_res = requests.get(https_url, timeout=5)

        if https_res.status_code == 200 or https_res.status_code == 301 or https_res.status_code == 302:
            return(domain)

    else:
        pass

    return None
