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
