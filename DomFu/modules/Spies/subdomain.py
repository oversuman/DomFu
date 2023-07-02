#!/usr/bin/env python3
'''
Copyright (C) 2020, DomFu Contributors.
See the LICENSE.txt file for copying permission.
'''

import socket
import requests
from threading import *
import queue
from .crtsh import fetchCrtSh
from .VirusTotal import fetchVirusTotal
from .shodan import fetchShodan
from .chaos import fetchChaos
from .certspot import fetchCertSpot
from .alienVault import fetchAlienv
from .webarchive import fetchWebArchive


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

    if dom_valid:

        que1 = queue.Queue()
        que2 = queue.Queue()
        que3 = queue.Queue()
        que4 = queue.Queue()
        que5 = queue.Queue()
        que6 = queue.Queue()
        que7 = queue.Queue()

        crt_thread = Thread(target=lambda q, arg1: q.put(
            fetchCrtSh(arg1)), args=(que1, domain))

        alienvault_thread = Thread(target=lambda q, arg2: q.put(
            fetchAlienv(arg2)), args=(que2, domain))

        certspot_thread = Thread(target=lambda q, arg3: q.put(
            fetchCertSpot(arg3)), args=(que3, domain))

        webarchive_thread = Thread(target=lambda q, arg4: q.put(
            fetchWebArchive(arg4)), args=(que4, domain))

        vt_thread = Thread(target=lambda q, arg5, arg51: q.put(
            fetchVirusTotal(arg5, arg51)), args=(que5, domain, apiDB_vt))

        shodan_thread = Thread(target=lambda q, arg6, arg61: q.put(
            fetchShodan(arg6, arg61)), args=(que6, domain, apiDB_shodan))

        chaos_thread = Thread(target=lambda q, arg7, arg71: q.put(
            fetchChaos(arg7, arg71)), args=(que7, domain, apiDB_chaos))


        crt_thread.start()
        alienvault_thread.start()
        certspot_thread.start()
        webarchive_thread.start()
        vt_thread.start()
        shodan_thread.start()
        chaos_thread.start()

        crt_thread.join()
        alienvault_thread.join()
        certspot_thread.join()
        webarchive_thread.join()
        vt_thread.join()
        shodan_thread.join()
        chaos_thread.join()

        rcrt_thread = que1.get()
        ralienvault_thread = que2.get()
        rcertspot_thread = que3.get()
        rwebarchive_thread = que4.get()
        rvt_thread = que5.get()
        rshodan_thread = que6.get()
        rchaos_thread = que7.get()

        try:
            subdomain.extend(rcrt_thread)
        except:
            pass

        try:
            subdomain.extend(ralienvault_thread)
        except:
            pass

        try:
            subdomain.extend(rcertspot_thread)
        except:
            pass

        try:
            subdomain.extend(rwebarchive_thread)
        except:
            pass

        try:
            subdomain.extend(rvt_thread)
        except:
            pass
        
        try:
            subdomain.extend(rshodan_thread)
        except:
            pass
        
        try:
            subdomain.extend(rchaos_thread)
        except:
            pass

        subdomain = sorted(set(subdomain))
        return(subdomain)

    else:
        return("Error (TPYL_DomFu_INVDOM): Enter a valid domain")
