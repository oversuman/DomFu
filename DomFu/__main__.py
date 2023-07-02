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
from DomFu import fetchCrtSh, fetchShodan, fetchChaos, fetchAlienv, fetchCertSpot, fetchVirusTotal, fetchWebArchive, Probe


def version():
    return ('''
------------------------------------------------------------
DomFu v1.4 by TxSadhu
------------------------------------------------------------
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
    # Fetching API keys from DB
    connection = lite.connect('{home}/.dfu/domfu.db'.format(home=home))
    cur = connection.cursor()
    cur.execute("SELECT * FROM apis")
    api_klst = cur.fetchall()
    apiDB = {}

    for api in api_klst:
        apiDB[api[0]] = api[1]

    connection.close()

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

        subdomain = []

        with yaspin(sp, text="Running API pre-processor"):
            if "shodan" in apiDB:
                apiDB_shodan = apiDB['shodan']
            else:
                apiDB_shodan = None

            if "chaos" in apiDB:
                apiDB_chaos = apiDB['chaos']
            else:
                apiDB_chaos = None
                
            if "virustotal" in apiDB:
                apiDB_vt = apiDB['virustotal']
            else:
                apiDB_vt = None

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

                # INIT: Don't try to loop this threads, it slows down the process --->
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
                # End: Don't try to loop this threads, it slows down the process --->

                yaspin().ok("[Done!] Asking ours spies about your subdomains")

            with yaspin(sp, text="Processing the data recieved"):
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
@click.option('--virustotal', '-vt', help="Add VirusTotal API Key")
@click.option('--update / --not-update', '-up / -nup', default=False, help="Update the existing keys")
@click.option('--delete / --not-delete', '-del / -ndel', default=False, help="Delete the existing keys")
def api(shodan, chaos, virustotal, update, delete):

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
                cur.execute("DELETE FROM apis WHERE name = (?)", (name,))
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

    if virustotal:
        if delete:
            try:
                name = 'virustotal'
                cur.execute("DELETE FROM apis WHERE name = (?)", (name,))
                connection.commit()
                print('[Done!] Deleted the value in DB')
                print('')
            except:
                print('[X] Failed to delete')
                print('')

        elif update:
            try:
                name = 'virustotal'
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
                name = 'virustotal'
                api_key = shodan
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
        sho_sym = '+'
    else:
        sho_key = "not available"
        sho_sym = '-'

    if 'chaos' in av_api:
        chaos_key = "available"
        chaos_sym = '+'
    else:
        chaos_key = "not available"
        chaos_sym = '-'
        
    if 'virustotal' in av_api:
        vt_key = "available"
        vt_sym = '+'
    else:
        vt_key = "not available"
        vt_sym = '-'

    print(f"[{sho_sym}] Sodan API key: {sho_key}")
    print(f"[{chaos_sym}] Chaos API key: {chaos_key}")
    print(f"[{vt_sym}] VirusTotal API key: {vt_key}")
    print('')
    print('-'*60)
    print('')


# API ends here ----------->


if __name__ == '__main__':
    domfucli()
