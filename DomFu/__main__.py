#!/usr/bin/env python3

import click
import time
import validators
import socket
from yaspin import yaspin, Spinner
from DomFu import fetchCrtSh, fetchBufferOverRun, fetchHackerTarget, fetchThreatCrowd, fetchVirusTotal


def version():
    return('''
⣤⣤⣤⡤⣤⣤⣀⠀⠀⠀⠀⣀⢤⣴⣴⣤⣀⠀⠀⣤⣤⣤⡄⢀⣤⣤⣀⠀⢀⣤⣤⣀⠀⢠⣤⣤⣤⠤⣤⣤⣤⢠⣤⣤⣤⠀⢠⣤⣤⣤⠀⠀⠀⠀
⣿⣿⣿⡇⠀⣿⣿⣿⡀⢠⣿⠀⢀⣿⣿⣿⣿⣷⠀⣿⣿⣿⡇⣿⣿⣿⣿⣆⣿⣿⣿⣿⣆⢸⣿⣿⡏⢾⣿⣿⣿⢸⣿⣿⣿⠀⢸⣿⣿⣿⠀⠀⠀⠀
⣿⣿⣿⡇⢀⣿⣿⣿⣷⣿⣿⣄⠀⠉⢻⣿⣿⣿⡇⣿⣿⣿⡟⠈⣿⣿⣿⣟⠈⣿⣿⣿⣇⢸⣿⣿⣿⣤⣭⣩⠉⢸⣿⣿⣿⠀⣸⣿⣿⣿⠀⠀⠀⠀
⣿⣿⣿⢿⣿⣿⣿⣿⠃⠹⣿⣿⣿⣿⣿⣿⣿⣿⠀⣿⣿⣿⡇⠀⣿⣿⣿⣇⠀⣿⣿⣿⡇⢸⣿⣿⣿⠀⠀⠀⠀⢸⣿⣿⣿⣿⢹⣿⣿⣿⠀⠀⠀⠀⠀
⠻⠻⠛⠸⠻⠻⠛⠁⠀⠀⠈⠛⠻⠿⠿⠛⠉⠀⠀⠻⠻⠻⠃⠀⠻⠻⠻⠓⠀⠻⠻⠻⠃⠸⠻⠻⠻⠀⠀⠀⠀⠀⠛⠻⠻⠋⠸⠻⠻⠻⠀⠀v1.0
by txsadhu⠀⠀⠀
------------------------------------------------------------⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ''')


@click.command()
@click.option('--domain', '-d', prompt="Enter a domain name", help='Enter your domain name')
@click.option('--output', '-o', help='Specify the output to store your subdomains')
def subdomain(domain, output):
    click.echo(version())
    sp = Spinner(["[\]", "[|]", "[/]", "[-]"], 200)

    with yaspin(sp, text="Checking if the domain is online or valid"):
        try:
            socket.gethostbyname(domain)
            dom_valid = True
            yaspin().ok("[Valid!] Looks like your domain is valid and online")
            print('\n')
        except socket.gaierror:
            dom_valid = False
            yaspin().fail(
                "[Invalid!] Looks like your domain is offline or invalid")
            print('\n')

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
        print('')
        print('-'*60)
        print('')

        if output != None:
            print('\n'.join(subdomain))
            print("")
            print('-'*60)
            fileoutput = open('%s' % output, 'w')
            towrite = '\n'.join(subdomain)
            fileoutput.write(towrite)
            fileoutput.close()
            timenow_end = time.perf_counter()
            print("")
            print(
                f"All Done! in {round(timenow_end-timenow_start, 2)} second(s). Check your output file")
            print("")
        else:
            print('\n'.join(subdomain))
            print("")
            print('-'*60)
            timenow_end = time.perf_counter()
            print("")
            print(
                f"All Done! in {round(timenow_end-timenow_start, 2)} second(s).")
            print("")

    else:
        print("Error (TPYL_DomFu_INVDOM): Enter a valid domain")
        print("\n")

    print('-'*60)


if __name__ == '__main__':
    subdomain()
