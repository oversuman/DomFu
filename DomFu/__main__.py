#!/usr/bin/env python3

import fire
import time
import validators
import socket
from yaspin import yaspin, Spinner
from DomFu import fetchCrtSh, fetchBufferOverRun, fetchHackerTarget, fetchThreatCrowd, fetchVirusTotal


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
        print("Error (TPYL_DomFu_INVDOM): Enter a valid domain")
        print("\n")


def main():
    fire.Fire(search)


if __name__ == '__main__':
    main()
