#!/usr/bin/env python3

import fire
import time
import os
import validators
import socket
import requests
from yaspin import yaspin, Spinner


def fetchCrtSh(domain):
    subdomains = []

    fetchURL = requests.get(
        "https://crt.sh/?q=%.{d}&output=json".format(d=domain))

    if fetchURL.status_code == 200:
        for (key, value) in enumerate(fetchURL.json()):
            if '@' not in value['name_value']:
                subdomains.append(value['name_value'])

        subdomains = sorted(set(subdomains))

        return(subdomains)


def fetchBufferOverRun(domain):

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


def fetchHackerTarget(domain):

    subdomainlst = []

    fetchURL = requests.get(
        "https://api.hackertarget.com/hostsearch/?q=%s" % (domain)).text

    if 'error' not in fetchURL:
        subdomains = str(fetchURL)
        subdomains = subdomains.split()

        for dom in subdomains:
            front, mid, end = dom.partition(",")
            subdomainlst.append(front)

        if subdomainlst != None:
            return(subdomainlst)


def fetchThreatCrowd(domain):
    fetchURL = requests.get(
        "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s" % (domain))
    jsonResponse = fetchURL.json()

    if int(jsonResponse["response_code"]) == 1:
        subdomains = jsonResponse["subdomains"]
        return(subdomains)


def fetchVirusTotal(domain):
    subdomain = []

    fetchURL = requests.get(
        "https://www.virustotal.com/ui/domains/%s/subdomains" % (domain))

    jsonResponse = fetchURL.json()

    for i in jsonResponse["data"]:
        if i["type"] == 'domain':
            subdomain.append(i['id'])

    return(subdomain)


def version():
    print('''
⣤⣤⣤⡤⣤⣤⣀⠀⠀⠀⠀⣀⢤⣴⣴⣤⣀⠀⠀⣤⣤⣤⡄⢀⣤⣤⣀⠀⢀⣤⣤⣀⠀⢠⣤⣤⣤⠤⣤⣤⣤⢠⣤⣤⣤⠀⢠⣤⣤⣤⠀⠀⠀⠀
⣿⣿⣿⡇⠀⣿⣿⣿⡀⢠⣿⠀⢀⣿⣿⣿⣿⣷⠀⣿⣿⣿⡇⣿⣿⣿⣿⣆⣿⣿⣿⣿⣆⢸⣿⣿⡏⢾⣿⣿⣿⢸⣿⣿⣿⠀⢸⣿⣿⣿⠀⠀⠀⠀
⣿⣿⣿⡇⢀⣿⣿⣿⣷⣿⣿⣄⠀⠉⢻⣿⣿⣿⡇⣿⣿⣿⡟⠈⣿⣿⣿⣟⠈⣿⣿⣿⣇⢸⣿⣿⣿⣤⣭⣩⠉⢸⣿⣿⣿⠀⣸⣿⣿⣿⠀⠀⠀⠀
⣿⣿⣿⢿⣿⣿⣿⣿⠃⠹⣿⣿⣿⣿⣿⣿⣿⣿⠀⣿⣿⣿⡇⠀⣿⣿⣿⣇⠀⣿⣿⣿⡇⢸⣿⣿⣿⠀⠀⠀⠀⢸⣿⣿⣿⣿⢹⣿⣿⣿⠀⠀⠀⠀⠀
⠻⠻⠛⠸⠻⠻⠛⠁⠀⠀⠈⠛⠻⠿⠿⠛⠉⠀⠀⠻⠻⠻⠃⠀⠻⠻⠻⠓⠀⠻⠻⠻⠃⠸⠻⠻⠻⠀⠀⠀⠀⠀⠛⠻⠻⠋⠸⠻⠻⠻⠀⠀v1.0
by txsadhu⠀⠀⠀
---------------------------------------------------------⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ''')


def search(domain, output):
    version()
    sp = Spinner(["[\]", "[|]", "[/]", "[-]"], 200)

    with yaspin(sp, text="Checking if the domain is online or valid"):
        try:
            socket.gethostbyname(domain)
            dom_valid = True
            yaspin().ok("[Valid!] Looks like your domain is valid and online")
        except socket.gaierror:
            dom_valid = False
            yaspin().fail(
                "[Invalid!] Looks like your domain is offline or invalid")

    subdomain = []
    if validators.domain(domain) and dom_valid:
        timenow_start = time.perf_counter()

        with yaspin(sp, text="Looking in SSL Certs"):
            try:
                subdomain.extend(fetchCrtSh(domain))
                yaspin().ok("[Done!] Looking in SSL Certs")
            except:
                pass

        with yaspin(sp, text="Calling BufferOverRun"):
            try:
                subdomain.extend(fetchBufferOverRun(domain))
                yaspin().ok("[Done!] Calling BufferOverRun")
            except:
                pass

        with yaspin(sp, text="Looking in HackerTarget"):
            try:
                subdomain.extend(fetchHackerTarget(domain))
                yaspin().ok("[Done!] Looking in HackerTarget")
            except:
                pass

        with yaspin(sp, text="Looking in ThreatCrowd"):
            try:
                subdomain.extend(fetchThreatCrowd(domain))
                yaspin().ok("[Done!] Looking in ThreatCrowd")
            except:
                pass

        with yaspin(sp, text="Looking in VirusTotal"):
            try:
                subdomain.extend(fetchVirusTotal(domain))
                yaspin().ok("[Done!] Looking in VirusTotal")
            except:
                pass

        subdomain = sorted(set(subdomain))

        fileoutput = open('%s' % output, 'w')
        towrite = '\n'.join(subdomain)
        fileoutput.write(towrite)
        fileoutput.close()

        timenow_end = time.perf_counter()

        print("\n")
        print(
            f"All Done! in {round(timenow_end-timenow_start, 2)} second(s). Check your output file")
        print("\n")

    else:
        print("Error (TPYL_INVDOM): Enter a valid domain")
        print("\n")


def main():
    fire.Fire(search)


if __name__ == '__main__':
    main()
