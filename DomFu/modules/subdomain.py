#!/usr/bin/env python3
import socket
import requests
from threading import *
import queue
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

    if dom_valid:

        que1 = queue.Queue()
        que2 = queue.Queue()
        que3 = queue.Queue()
        que4 = queue.Queue()
        que5 = queue.Queue()

        crt_thread = Thread(target=lambda q, arg1: q.put(
            fetchCrtSh(arg1)), args=(que1, domain))

        bufferoverrun_thread = Thread(target=lambda q, arg2: q.put(
            fetchBufferOverRun(arg2)), args=(que2, domain))

        hackertarget_thread = Thread(target=lambda q, arg3: q.put(
            fetchHackerTarget(arg3)), args=(que3, domain))

        threatcrowd_thread = Thread(target=lambda q, arg4: q.put(
            fetchThreatCrowd(arg4)), args=(que4, domain))

        vt_thread = Thread(target=lambda q, arg5: q.put(
            fetchVirusTotal(arg5)), args=(que5, domain))

        crt_thread.start()
        bufferoverrun_thread.start()
        hackertarget_thread.start()
        threatcrowd_thread.start()
        vt_thread.start()

        crt_thread.join()
        bufferoverrun_thread.join()
        hackertarget_thread.join()
        threatcrowd_thread.join()
        vt_thread.join()

        rcrt_thread = que1.get()
        rbufferoverrun_thread = que2.get()
        rhackertarget_thread = que3.get()
        rthreatcrowd_thread = que4.get()
        rvt_thread = que5.get()

        try:
            subdomain.extend(rcrt_thread)
        except:
            pass

        try:
            subdomain.extend(rbufferoverrun_thread)
        except:
            pass

        try:
            subdomain.extend(rhackertarget_thread)
        except:
            pass

        try:
            subdomain.extend(rthreatcrowd_thread)
        except:
            pass

        try:
            subdomain.extend(rvt_thread)
        except:
            pass

        subdomain = sorted(set(subdomain))
        return(subdomain)

    else:
        return("Error (TPYL_DomFu_INVDOM): Enter a valid domain")
