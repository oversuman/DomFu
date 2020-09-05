#!/usr/bin/env python3
import socket
import validators
import requests

from .crtsh import fetchCrtSh
from .BufferOverRun import fetchBufferOverRun
from .HackerTarget import fetchHackerTarget
from .ThreatCrowd import fetchThreatCrowd
from .VirusTotal import fetchVirusTotal


def fetchAll(domain):
    '''
    string -> list

    This function queries all API and tools to look for subdomain(s) of your domain name.

    Input  : DomFu.subdomain("tropyl.com")
    Output : ['tropyl.com', 'www.tropyl.com']

    '''
    try:
        socket.gethostbyname(domain)
        dom_valid = True
    except socket.gaierror:
        dom_valid = False

    subdomain = []

    if validators.domain(domain) and dom_valid:
        try:
            subdomain.extend(fetchCrtSh(domain))
        except:
            pass

        try:
            subdomain.extend(fetchBufferOverRun(domain))
        except:
            pass

        try:
            subdomain.extend(fetchHackerTarget(domain))
        except:
            pass

        try:
            subdomain.extend(fetchThreatCrowd(domain))
        except:
            pass

        try:
            subdomain.extend(fetchVirusTotal(domain))
        except:
            pass

        try:
            subdomain = sorted(set(subdomain))
        except:
            pass

        return(subdomain)

    else:
        return("Error (TPYL_DomFu_INVDOM): Enter a valid domain")
