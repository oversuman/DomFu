#!/usr/bin/env python3
'''
Copyright (C) 2020, DomFu Contributors.
See the LICENSE.txt file for copying permission.
'''

import click
from pathlib import Path
import requests
import os
import time
import socket
import sqlite3 as lite
from threading import *
import queue
from yaspin import yaspin, Spinner
from DomFu import fetchCrtSh, fetchBufferOverRun, fetchHackerTarget, fetchThreatCrowd, fetchShodan, fetchChaos, fetchVirusTotal, Probe


def version():
    return('''
⣤⣤⣤⡤⣤⣤⣀⠀⠀⠀⠀⣀⢤⣴⣴⣤⣀⠀⠀⣤⣤⣤⡄⢀⣤⣤⣀⠀⢀⣤⣤⣀⠀⢠⣤⣤⣤⠤⣤⣤⣤⢠⣤⣤⣤⠀⢠⣤⣤⣤⠀⠀⠀⠀
⣿⣿⣿⡇⠀⣿⣿⣿⡀⢠⣿⠀⢀⣿⣿⣿⣿⣷⠀⣿⣿⣿⡇⣿⣿⣿⣿⣆⣿⣿⣿⣿⣆⢸⣿⣿⡏⢾⣿⣿⣿⢸⣿⣿⣿⠀⢸⣿⣿⣿⠀⠀⠀⠀
⣿⣿⣿⡇⢀⣿⣿⣿⣷⣿⣿⣄⠀⠉⢻⣿⣿⣿⡇⣿⣿⣿⡟⠈⣿⣿⣿⣟⠈⣿⣿⣿⣇⢸⣿⣿⣿⣤⣭⣩⠉⢸⣿⣿⣿⠀⣸⣿⣿⣿⠀⠀⠀⠀
⣿⣿⣿⢿⣿⣿⣿⣿⠃⠹⣿⣿⣿⣿⣿⣿⣿⣿⠀⣿⣿⣿⡇⠀⣿⣿⣿⣇⠀⣿⣿⣿⡇⢸⣿⣿⣿⠀⠀⠀⠀⢸⣿⣿⣿⣿⢹⣿⣿⣿⠀⠀⠀⠀⠀
⠻⠻⠛⠸⠻⠻⠛⠁⠀⠀⠈⠛⠻⠿⠿⠛⠉⠀⠀⠻⠻⠻⠃⠀⠻⠻⠻⠓⠀⠻⠻⠻⠃⠸⠻⠻⠻⠀⠀⠀⠀⠀⠛⠻⠻⠋⠸⠻⠻⠻⠀⠀v1.2.3
by txsadhu⠀⠀⠀
------------------------------------------------------------⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ''')


@click.group()
@click.version_option()
def domfucli():
    pass

# Passive begins here ----------->


@domfucli.command()
@click.option('--domain', '-d', prompt="Enter a domain name", help='Enter your domain name.')
@click.option('--output', '-o', help='Stores the output in a file.',)
@click.option('--probe / --no-probe', '-p / -np', default=False, help='Validates the output domains')
def passive(domain, output, probe):
    click.echo(version())
    sp = Spinner(["[\]", "[|]", "[/]", "[-]"], 200)
    torthere = True

    home = str(Path.home())
    direc = '{home}/.dfu'.format(home=home)

    if not os.path.exists(direc):
        os.makedirs(direc, exist_ok=True)

    if probe:
        with yaspin(sp, text="Checking if Tor is installed in your system"):
            try:
                proxies = {
                    'http': 'socks5://127.0.0.1:9050',
                    'https': 'socks5://127.0.0.1:9050'
                }
                fetchURL = requests.get(
                    'https://check.torproject.org/api/ip', proxies=proxies).json()

                if fetchURL['IsTor'] == True:
                    torthere = True
                    yaspin().ok(
                        "[Done!] Checking if Tor is installed in your system")
                else:
                    torthere = False
                    yaspin().ok(
                        "[Eww...] Install and Connect to Tor to run prober (May be you forgot to start TOR)")
            except:
                torthere = False
                yaspin().ok(
                    "[Eww...] Install and Connect to Tor to run prober (May be you forgot to start TOR)")
    if torthere:

        with yaspin(sp, text="Checking if the domain is online or valid"):
            try:
                socket.gethostbyname(domain)
                dom_valid = True
                yaspin().ok(
                    "[Valid!] Looks like your domain is valid and online")
            except socket.gaierror:
                dom_valid = False
                yaspin().fail(
                    "[Invalid!] Looks like your domain is offline or invalid")

        with yaspin(sp, text="Fetching your API keys from DB"):
            try:
                home = str(Path.home())
                connection = lite.connect('{home}/.dfu/domfu.db'.format(home=home))
                cur = connection.cursor()
                cur.execute("SELECT * FROM apis")
                api_klst = cur.fetchall()
                apiDB = {}

                for api in api_klst:
                    apiDB[api[0]] = api[1]

                connection.close()
                yaspin().ok("[Done!] Fetching your API keys from DB...")
            except:
                yaspin().fail("[Error!] Fetching your API keys from DB...")

        subdomain = []

        if dom_valid:
            timenow_start = time.perf_counter()

            with yaspin(sp, text="Asking ours spies about your subdomains"):

                que1 = queue.Queue()
                que2 = queue.Queue()
                que3 = queue.Queue()
                que4 = queue.Queue()
                que5 = queue.Queue()
                que6 = queue.Queue()
                que7 = queue.Queue()

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

                shodan_thread = Thread(target=lambda q, arg6, arg7: q.put(
                    fetchShodan(arg6, arg7)), args=(que6, domain, apiDB['shodan']))

                chaos_thread = Thread(target=lambda q, arg8, arg9: q.put(
                    fetchChaos(arg8, arg9)), args=(que7, domain, apiDB['chaos']))

                # INIT: Don't try to loop this threads, it slows down the process --->
                crt_thread.start()
                bufferoverrun_thread.start()
                hackertarget_thread.start()
                threatcrowd_thread.start()
                vt_thread.start()
                shodan_thread.start()
                chaos_thread.start()

                crt_thread.join()
                bufferoverrun_thread.join()
                hackertarget_thread.join()
                threatcrowd_thread.join()
                vt_thread.join()
                shodan_thread.join()
                chaos_thread.join()

                rcrt_thread = que1.get()
                rbufferoverrun_thread = que2.get()
                rhackertarget_thread = que3.get()
                rthreatcrowd_thread = que4.get()
                rvt_thread = que5.get()
                rshodan_thread = que6.get()
                rchaos_thread = que7.get()
                # End: Don't try to loop this threads, it slows down the process --->

                yaspin().ok("[Done!] Asking ours spies about your subdomains")

            with yaspin(sp, text="Processing the data recieved"):
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

                try:
                    subdomain.extend(rshodan_thread)
                except:
                    pass

                try:
                    subdomain.extend(rchaos_thread)
                except:
                    pass

                yaspin().ok("[Done!] Processing the data recieved")

            if probe:
                with yaspin(sp, text="Validating your Domains on our Lab"):
                    subdomain = Probe(subdomain)
                    yaspin().ok("[Done!] Validating your Domains on our Lab")

            timenow_end = time.perf_counter()
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
                print("")
                print(
                    f"All Done! in {round(timenow_end-timenow_start, 2)} second(s). Check your output file")
                print("")
            else:
                print('\n'.join(subdomain))
                print("")
                print('-'*60)
                print("")
                print(
                    f"All Done! in {round(timenow_end-timenow_start, 2)} second(s).")
                print("")

        else:
            print("Error (TPYL_DOMFU_INVDOM): Enter a valid domain")
            print("\n")

    else:
        print('')

    print('-'*60)


# Passive begins here ----------->


# API begins here ----------->


@domfucli.command()
@click.option('--shodan', help="Add Shodan API Key")
@click.option('--chaos', help="Add Chaos API key")
@click.option('--update / --not-update', '-up / -nup', default=False, help="Update the existing keys")
@click.option('--delete / --not-delete', '-del / -ndel', default=False, help="Delete the existing keys")
def api(shodan, chaos, update, delete):

    home = str(Path.home())
    direc = '{home}/.dfu'.format(home=home)

    if not os.path.exists(direc):
        os.makedirs(direc, exist_ok=True)

    click.echo(version())

    home = str(Path.home())
    connection = lite.connect('{home}/.dfu/domfu.db'.format(home=home))
    cur = connection.cursor()
    cur.execute(
        "CREATE TABLE IF NOT EXISTS apis(name TEXT PRIMARY KEY, key TEXT)")

    if shodan:
        if delete:
            try:
                name = 'shodan'
                cur.execute("DELETE FROM apis WHERE name = (?)", (name,))
                connection.commit()
                print('[Done!] Deleted the value in DB')
                print('')
            except:
                print('[X] Failed to delete')
                print('')

        elif update:
            try:
                name = 'shodan'
                api_key = shodan
                cur.execute(
                    "UPDATE apis SET key = (?) WHERE name = (?)", (api_key, name))
                connection.commit()
                print('[Done!] Updated the value in DB')
                print('')
            except:
                print('[x] Failed to Update')
                print('')

        else:
            try:
                name = 'shodan'
                api_key = shodan
                cur.execute("INSERT INTO apis VALUES (?, ?)", (name, api_key))
                connection.commit()
                print('[Done!] Added your api key in DB')
                print('')
            except:
                print('[x] Value already exists in DB')
                print('')

    if chaos:
        if delete:
            try:
                name = 'chaos'
                cur.execute("DELETE FROM apis WHERE id = (?)", (name,))
                connection.commit()
                print('[Done!] Deleted the value in DB')
                print('')
            except:
                print('[X] Failed to delete')
                print('')

        elif update:
            try:
                name = 'chaos'
                api_key = chaos
                cur.execute(
                    "UPDATE apis SET key = (?) WHERE name = (?)", (api_key, name))
                connection.commit()
                print('[Done!] Updated the value in DB')
                print('')
            except:
                print('[x] Failed to Update')
                print('')

        else:
            try:
                name = 'chaos'
                api_key = chaos
                cur.execute("INSERT INTO apis VALUES (?, ?)", (name, api_key))
                connection.commit()
                print('[Done!] Added your api key in DB')
                print('')
            except:
                print('[x] Value already exists in DB')
                print('')

    cur.execute("SELECT name FROM apis")
    api_res = cur.fetchall()

    connection.close()

    av_api = []

    for api in api_res:
        av_api.append(api[0])

    if 'shodan' in av_api:
        sho_key = "available"
        sym = '+'
    else:
        sho_key = "not available"
        sym = '-'

    if 'chaos' in av_api:
        chaos_key = "available"
        sym = '+'
    else:
        chaos_key = "not available"
        sym = '-'

    print(f"[{sym}] Sodan API key: {sho_key}")
    print(f"[{sym}] Chaos API key: {chaos_key}")
    print('')
    print('-'*60)
    print('')


# API ends here ----------->


if __name__ == '__main__':
    domfucli()
