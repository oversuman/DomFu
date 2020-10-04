import requests
import socket


def probe_test(domain):
    try:
        socket.gethostbyname(domain)
        dom_valid = True
    except:
        dom_valid = False

    print(dom_valid)

    if dom_valid:
        # Http ----->
        http_url = 'http://' + '{d}'.format(d=domain)
        http_res = requests.head(http_url, timeout=5)

        print(http_res.status_code)

        if http_res.status_code != 400 or http_res.status_code != 403:
            print(domain)
        # return(None)

        # # Https ---->
        # https_url = 'https://' + '{d}'.format(d=domain)
        # https_res = requests.get(https_url, timeout=5)

        # print(https_res.status_code)

        # if https_res.status_code != 400 or https_res.status_code != 403:
        #     print(domain)
        #     # return(None)

    # return(None)


if __name__ == "__main__":
    probe_test('qpaper.makautwb.ac.in')
